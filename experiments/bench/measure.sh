#!/usr/bin/env bash
# usage: measure.sh LABEL PROFILE INTERVAL DURATION -- AGENT_CMD...
# Runs AGENT_CMD against a fresh mock API and samples its /proc footprint
# every second. Prints one summary line; raw samples go to OUT/samples.tsv.
set -u
LABEL=$1 PROFILE=$2 INTERVAL=$3 DURATION=$4
shift 5
BENCH=/tmp/fivenines-bench
OUT=$BENCH/runs/$LABEL
rm -rf "$OUT" && mkdir -p "$OUT/cfg" "$OUT/payloads"
printf '%s' bench-token > "$OUT/cfg/TOKEN" && chmod 600 "$OUT/cfg/TOKEN"
PORT=$((20000 + RANDOM % 20000))

AGENT_SRC=/home/paseo/.paseo/worktrees/34slq8c7/odd-hound \
  python3 "$BENCH/mock.py" "$PORT" "$OUT/payloads" "$PROFILE" "$INTERVAL" &
MOCK=$!
sleep 0.5

CONFIG_DIR="$OUT/cfg" API_URL="localhost:$PORT" LOG_LEVEL=info \
  "$@" >"$OUT/agent.log" 2>&1 &
PID=$!
T0=$(date +%s.%N)
HZ=$(getconf CLK_TCK)

printf 't\trss_kb\tpss_kb\tthreads\tcpu_ticks\n' >"$OUT/samples.tsv"
for _ in $(seq "$DURATION"); do
  sleep 1
  [ -d /proc/$PID ] || break
  RSS=$(awk '/^VmRSS/{print $2}' /proc/$PID/status)
  THR=$(awk '/^Threads/{print $2}' /proc/$PID/status)
  PSS=$(awk '/^Pss:/{print $2}' /proc/$PID/smaps_rollup)
  CPU=$(awk '{print $14+$15+$16+$17}' /proc/$PID/stat)
  printf '%s\t%s\t%s\t%s\t%s\n' "$(awk -v a="$(date +%s.%N)" -v b="$T0" 'BEGIN{printf "%.1f", a-b}')" "$RSS" "$PSS" "$THR" "$CPU" >>"$OUT/samples.tsv"
done
HWM=$(awk '/^VmHWM/{print $2}' /proc/$PID/status 2>/dev/null)
kill -TERM $PID 2>/dev/null; wait $PID 2>/dev/null
kill $MOCK 2>/dev/null; wait $MOCK 2>/dev/null

TICKS=$(ls "$OUT/payloads" | grep -c collect)
python3 - "$OUT/samples.tsv" "$LABEL" "$HZ" "${HWM:-0}" "$TICKS" <<'EOF'
import sys
rows = [l.split("\t") for l in open(sys.argv[1]).read().split("\n")[1:] if l]
label, hz, hwm, ticks = sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
rss = [int(r[1]) for r in rows]; pss = [int(r[2]) for r in rows]
thr = [int(r[3]) for r in rows]; cpu = [int(r[4]) for r in rows]
t = float(rows[-1][0])
# steady state = second half of the run (startup probe and imports excluded)
half = len(rows) // 2
steady_cpu = (cpu[-1] - cpu[half]) / hz / (float(rows[-1][0]) - float(rows[half][0])) * 100
print(f"{label:<28} RSS {rss[-1]/1024:6.1f} MB  PSS {pss[-1]/1024:6.1f} MB  "
      f"pic {hwm/1024:6.1f} MB  threads {thr[-1]:3d}  "
      f"CPU total {cpu[-1]/hz:5.2f}s (dont {cpu[0]/hz:4.2f}s a 1s)  "
      f"CPU regime {steady_cpu:5.2f}%  ticks {ticks}  duree {t:.0f}s")
EOF
