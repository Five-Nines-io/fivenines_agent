#!/usr/bin/env bash
# core + processes + docker (40 containers on one shared mock daemon), four agents side by side.
cd /tmp/fivenines-bench
export DOCKER_SOCKET=/tmp/fivenines-bench/docker-b.sock DOCKER_HOST=unix:///tmp/fivenines-bench/docker-b.sock
timeout 110 python3 mock_docker.py $DOCKER_SOCKET 40 &
sleep 1
./measure.sh d-py     docker 1 90 -- ./fivenines-agent-linux-amd64/fivenines-agent-linux-amd64 > d-py.txt 2>&1 &
./measure.sh d-go     docker 1 90 -- ./bin/go-agent-docker > d-go.txt 2>&1 &
./measure.sh d-rsgnu  docker 1 90 -- ./bin/rust-agent-docker-v1 > d-rsgnu.txt 2>&1 &
./measure.sh d-rsmusl docker 1 90 -- ./bin/rust-agent-docker-musl > d-rsmusl.txt 2>&1 &
wait
touch run-docker.done
