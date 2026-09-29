package main

// processes.py is 34 lines because psutil does the work; this is what
// `proc.as_dict(attrs=[...])` actually means on Linux, spelled out.

import (
	"bytes"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// psutil's PROC_STATUSES (the state letter of /proc/<pid>/stat).
var procStatuses = map[byte]string{
	'R': "running", 'S': "sleeping", 'D': "disk-sleep", 'T': "stopped",
	't': "tracing-stop", 'Z': "zombie", 'X': "dead", 'x': "dead",
	'K': "wake-kill", 'W': "waking", 'I': "idle", 'P': "parked",
}

const clockTicks = 100 // sysconf(_SC_CLK_TCK) on every Linux psutil supports

var pageSize = uint64(os.Getpagesize())

// psutil.process_iter() keeps each Process object between calls, and
// cpu_percent(interval=None) is the delta against the previous call on that
// object -- 0.0 the first time a process is seen. Keyed by pid AND start
// time, as process_iter() is, so a recycled pid starts over.
type procKey struct {
	pid   int
	start uint64
}

type procSample struct {
	cpu  float64 // user + system, seconds
	when time.Time
}

var (
	procMu   sync.Mutex
	procPrev = map[procKey]procSample{}
	memTotal uint64
)

func physMemTotal() uint64 {
	if memTotal == 0 {
		if v, err := memory(); err == nil {
			memTotal = v.(map[string]any)["total"].(uint64)
		}
	}
	return memTotal
}

// name() in psutil: the kernel truncates comm to 15 bytes, so a 15-byte name
// is completed from argv[0] when argv[0]'s basename starts with it.
func procName(pid int, comm string) string {
	if len(comm) < 15 {
		return comm
	}
	cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil || len(cmdline) == 0 {
		return comm
	}
	argv0 := filepath.Base(string(bytes.SplitN(cmdline, []byte{0}, 2)[0]))
	if strings.HasPrefix(argv0, comm) {
		return argv0
	}
	return comm
}

func processes() (any, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	pids := make([]int, 0, len(entries))
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)

	now := time.Now()
	users := map[string]any{} // per-tick uid -> name cache
	total := physMemTotal()
	seen := make(map[procKey]procSample, len(pids))
	out := make([]map[string]any, 0, len(pids))

	procMu.Lock()
	defer procMu.Unlock()
	for _, pid := range pids {
		base := "/proc/" + strconv.Itoa(pid)
		stat, err := os.ReadFile(base + "/stat")
		if err != nil {
			continue // gone since the readdir: psutil's NoSuchProcess
		}
		// comm may contain spaces and parens: it ends at the LAST ')'.
		open, close := bytes.IndexByte(stat, '('), bytes.LastIndexByte(stat, ')')
		if open < 0 || close < open {
			continue
		}
		comm := string(stat[open+1 : close])
		f := strings.Fields(string(stat[close+2:])) // f[0] is field 3 (state)
		if len(f) < 40 {
			continue
		}
		num := func(i int) uint64 { v, _ := strconv.ParseUint(f[i-3], 10, 64); return v }
		ticks := func(i int) float64 { return float64(num(i)) / clockTicks }

		user_, system := ticks(14), ticks(15)
		key := procKey{pid, num(22)}
		sample := procSample{user_ + system, now}
		seen[key] = sample
		cpuPercent := 0.0
		if prev, ok := procPrev[key]; ok {
			if dt := now.Sub(prev.when).Seconds(); dt > 0 {
				cpuPercent = round1((sample.cpu - prev.cpu) / dt * 100)
			}
		}

		var memPercent any
		if statm, err := os.ReadFile(base + "/statm"); err == nil && total > 0 {
			if fields := strings.Fields(string(statm)); len(fields) > 1 {
				rss, _ := strconv.ParseUint(fields[1], 10, 64)
				memPercent = float64(rss*pageSize) / float64(total) * 100
			}
		}

		// username: the REAL uid, first column of "Uid:" in /proc/<pid>/status.
		var username any
		if status, err := os.ReadFile(base + "/status"); err == nil {
			for _, line := range strings.Split(string(status), "\n") {
				if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
					uid := strings.Fields(rest)[0]
					name, cached := users[uid]
					if !cached {
						name = uid // psutil falls back to the uid as a string
						if u, err := user.LookupId(uid); err == nil {
							name = u.Username
						}
						users[uid] = name
					}
					username = name
					break
				}
			}
		}

		out = append(out, map[string]any{
			"pid":            pid,
			"ppid":           num(4),
			"name":           procName(pid, comm),
			"username":       username,
			"memory_percent": memPercent,
			"cpu_percent":    cpuPercent,
			// pcputimes(user, system, children_user, children_system, iowait):
			// a namedtuple, so an ARRAY on the wire.
			"cpu_times":   [5]float64{user_, system, ticks(16), ticks(17), ticks(42)},
			"num_threads": num(20),
			"status":      procStatuses[f[0][0]],
		})
	}
	procPrev = seen // processes that exited are forgotten, as process_iter does
	return out, nil
}
