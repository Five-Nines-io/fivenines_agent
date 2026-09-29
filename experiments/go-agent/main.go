// Prototype: the fivenines agent's collection loop and core collectors in Go,
// to measure what a rewrite would buy. Not production code -- see README.md.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/shirou/gopsutil/v4/host"
)

const version = "0.0.0-go-proto"

// Per-collector wall-clock bound -- the TODOS.md P3 item, for free.
const collectorTimeout = 10 * time.Second

func logf(level, format string, args ...any) {
	if level == "debug" && os.Getenv("LOG_LEVEL") != "debug" {
		return
	}
	fmt.Fprintf(os.Stderr, "[%s] %s\n", strings.ToUpper(level), fmt.Sprintf(format, args...))
}

func apiURL() string { return envOr("API_URL", "api.fivenines.io") }

func configDir() string { return envOr("CONFIG_DIR", "/etc/fivenines_agent") }

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func userContext() map[string]any {
	uid, gid := os.Getuid(), os.Getgid()
	name, group := strconv.Itoa(uid), strconv.Itoa(gid)
	if u, err := user.LookupId(name); err == nil {
		name = u.Username
	}
	if g, err := user.LookupGroupId(group); err == nil {
		group = g.Name
	}
	groups := []string{}
	gids, _ := os.Getgroups()
	for _, id := range gids {
		n := strconv.Itoa(id)
		if g, err := user.LookupGroupId(n); err == nil {
			n = g.Name
		}
		groups = append(groups, n)
	}
	home, _ := os.UserHomeDir()
	return map[string]any{
		"username": name, "uid": uid, "euid": os.Geteuid(), "gid": gid,
		"groupname": group, "groups": groups, "is_root": uid == 0,
		"is_user_install": home != "" && strings.HasPrefix(configDir(), home),
		"config_dir":      configDir(), "home_dir": home,
	}
}

// machineID mirrors machine_id.py: a persisted UUID4, created 0600.
func machineID() any {
	path := filepath.Join(configDir(), "MACHINE_ID")
	if b, err := os.ReadFile(path); err == nil {
		if id, err := uuid.Parse(strings.TrimSpace(string(b))); err == nil {
			return id.String()
		}
	}
	id := uuid.NewString()
	if err := os.WriteFile(path, []byte(id), 0o600); err != nil {
		return nil
	}
	return id
}

func staticData() map[string]any {
	boot, _ := host.BootTime()
	core := map[string]bool{"cpu": true, "memory": true, "load_average": true,
		"io": true, "network": true, "partitions": true, "file_handles": true}
	return map[string]any{
		"version": version, "uname": uname(), "boot_time": float64(boot),
		"capabilities": core, "capability_reasons": map[string]string{},
		"pending_capabilities": []string{}, "user_context": userContext(),
		"machine_id": machineID(),
	}
}

type collector struct {
	key string
	fn  func(cfg any) (any, error) // cfg is config[configKey], the **kwargs of pass_kwargs=True
}

// plain adapts a collector that takes no configuration.
func plain(f func() (any, error)) func(any) (any, error) {
	return func(any) (any, error) { return f() }
}

// docker has its own 25s budget (dockerCollectDeadline); the generic bound
// sits above it so the collector reports its own failure first.
var collectorTimeouts = map[string]time.Duration{"docker": 30 * time.Second}

// The COLLECTORS registry, restricted to what this prototype ports.
var registry = []struct {
	configKey  string
	collectors []collector
}{
	{"cpu", []collector{{"cpu", plain(cpuData)}, {"cpu_usage", plain(cpuUsage)}, {"cpu_model", plain(cpuModel)}, {"cpu_count", plain(cpuCount)}}},
	{"memory", []collector{{"memory", plain(memory)}, {"swap", plain(swap)}}},
	{"network", []collector{{"network", plain(network)}}},
	{"partitions", []collector{{"partitions_metadata", plain(partitionsMetadata)}, {"partitions_usage", plain(partitionsUsage)}}},
	{"io", []collector{{"io", plain(ioCounters)}}},
	{"processes", []collector{{"processes", plain(processes)}}},
	{"docker", []collector{{"docker", dockerMetrics}}},
}

func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case map[string]any:
		return len(t) > 0
	case []any:
		return len(t) > 0
	}
	return true
}

func collectMetrics(cfg map[string]any, data map[string]any) {
	telemetry := map[string]any{}
	run := func(key string, fn func() (any, error)) {
		start := time.Now()
		timeout := collectorTimeout
		if t, ok := collectorTimeouts[key]; ok {
			timeout = t
		}
		v, err := callBounded(key, timeout, fn)
		entry := map[string]any{"duration_ms": float64(time.Since(start).Microseconds()) / 1000}
		if err != nil {
			logf("error", "%s: %v", key, err)
			entry["error"] = err.Error()
			v = nil // a failed collector reports null, never a partial value
		}
		telemetry[key] = entry
		data[key] = v
	}

	run("load_average", loadAverage)
	fh, err := fileHandles()
	if err == nil {
		data["file_handles_used"], data["file_handles_limit"] = fh[0], fh[2]
	} else {
		data["file_handles_used"], data["file_handles_limit"] = nil, nil
	}
	for _, group := range registry {
		if !truthy(cfg[group.configKey]) {
			continue
		}
		for _, c := range group.collectors {
			groupCfg := cfg[group.configKey]
			run(c.key, func() (any, error) { return c.fn(groupCfg) })
		}
	}
	data["_telemetry"] = telemetry
}

func tick(cfg map[string]any, static map[string]any) map[string]any {
	data := make(map[string]any, len(static)+16)
	for k, v := range static {
		data[k] = v
	}
	start := time.Now()
	data["ts"] = float64(time.Now().UnixNano()) / 1e9
	collectMetrics(cfg, data)
	data["running_time"] = time.Since(start).Seconds()
	return data
}

var dryRunConfig = map[string]any{
	"enabled": true, "interval": 60.0, "cpu": true, "memory": true,
	"network": true, "partitions": true, "io": true,
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(version)
		return
	}
	dryRun := os.Getenv("DRY_RUN") == "true" || (len(os.Args) > 1 && os.Args[1] == "--dry-run")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	static := staticData()
	if dryRun {
		out, _ := json.MarshalIndent(tick(dryRunConfig, static), "", "  ")
		fmt.Println(string(out))
		return
	}

	token, err := os.ReadFile(filepath.Join(configDir(), "TOKEN"))
	if err != nil {
		logf("error", "TOKEN not found in %s", configDir())
		os.Exit(2)
	}
	s := NewSynchronizer(strings.TrimSpace(string(token)))

	getConfig := map[string]any{"get_config": true}
	for k, v := range static {
		getConfig[k] = v
	}
	blob, _ := gzipJSON(getConfig)
	for !s.Send(ctx, blob) {
		if ctx.Err() != nil {
			return
		}
	}
	go s.Run(ctx)
	logf("info", "fivenines agent (Go prototype) started")

	for ctx.Err() == nil {
		cfg := s.Config()
		if !truthy(cfg["enabled"]) {
			sleep(ctx, 25*time.Second)
			continue
		}
		data := tick(cfg, static)
		if blob, err := gzipJSON(data); err != nil {
			logf("error", "Payload serialization failed; dropping tick: %v", err)
		} else {
			s.Put(blob)
		}
		interval := 60.0
		if f, ok := cfg["interval"].(float64); ok && f > 0 {
			interval = f
		}
		wait := time.Duration(interval*float64(time.Second)) - time.Duration(data["running_time"].(float64)*float64(time.Second))
		sleep(ctx, max(wait, 100*time.Millisecond))
	}
	logf("info", "fivenines agent shutting down")
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
