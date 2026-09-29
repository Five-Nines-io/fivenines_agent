#!/usr/bin/env bash
# Each docker port against each mock fault mode; prints what data["docker"] became.
cd /tmp/fivenines-bench
export DOCKER_SOCKET=/tmp/fivenines-bench/docker-f.sock DOCKER_HOST=unix:///tmp/fivenines-bench/docker-f.sock
for mode in normal vanish error500 newstate api1.41; do
  fault=$mode; apiv=1.51
  [ $mode = normal ] && fault=""
  [ $mode = api1.41 ] && { fault=""; apiv=1.41; }
  MOCK_API_VERSION=$apiv timeout 20 python3 mock_docker.py $DOCKER_SOCKET 40 $fault &
  sleep 1
  ./measure.sh f-py-$mode docker 2 9 -- ./fivenines-agent-linux-amd64/fivenines-agent-linux-amd64 >/dev/null 2>&1 &
  ./measure.sh f-go-$mode docker 2 9 -- ./bin/go-agent-docker >/dev/null 2>&1 &
  ./measure.sh f-rs-$mode docker 2 9 -- ./bin/rust-agent-docker-v1 >/dev/null 2>&1 &
  wait
done
python3 - <<'PY'
import glob, json
def summarize(run):
    files = sorted(glob.glob(f"/tmp/fivenines-bench/runs/{run}/payloads/*-collect.json"))
    if len(files) < 3:
        return "no payload"
    d = json.load(open(files[-1])).get("docker", "ABSENT")
    if d is None:
        return "null"
    if d == "ABSENT":
        return "key absent"
    cs = d["containers"]
    odd = [c["status"] for c in cs.values() if c["status"] not in ("running", "exited", "created", "restarting")]
    return f"{len(cs)} containers" + (f" (status {odd[0]!r})" if odd else "")
print(f"{'mode':<10} {'python':<34} {'go':<34} {'rust':<34}")
for mode in ["normal", "vanish", "error500", "newstate", "api1.41"]:
    print(f"{mode:<10} " + " ".join(f"{summarize(f'f-{a}-{mode}'):<34}" for a in ("py", "go", "rs")))
PY
