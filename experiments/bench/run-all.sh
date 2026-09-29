#!/usr/bin/env bash
# Same profile, four agents, same 90 seconds.
cd /tmp/fivenines-bench
for profile in core procs; do
  ./measure.sh "py-$profile-final" "$profile" 1 90 -- ./fivenines-agent-linux-amd64/fivenines-agent-linux-amd64 > "f-py-$profile.txt" 2>&1 &
  ./measure.sh "go-$profile-final" "$profile" 1 90 -- ./bin/go-agent-linux-amd64-v3 > "f-go-$profile.txt" 2>&1 &
  ./measure.sh "rsgnu-$profile-final" "$profile" 1 90 -- ./bin/rust-agent-gnu > "f-rsgnu-$profile.txt" 2>&1 &
  ./measure.sh "rsmusl-$profile-final" "$profile" 1 90 -- ./bin/rust-agent-x86_64-unknown-linux-musl > "f-rsmusl-$profile.txt" 2>&1 &
  wait
done
touch run-final.done
