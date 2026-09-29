#!/usr/bin/env bash
# Go runtime tuning vs the default, core + processes, side by side.
cd /tmp/fivenines-bench
G=./bin/go-agent-linux-amd64-v3
./measure.sh tune-go-default    procs 1 90 -- $G > t-default.txt 2>&1 &
./measure.sh tune-go-maxprocs1  procs 1 90 -- env GOMAXPROCS=1 $G > t-maxprocs1.txt 2>&1 &
./measure.sh tune-go-gogc25     procs 1 90 -- env GOGC=25 $G > t-gogc25.txt 2>&1 &
./measure.sh tune-go-memlimit   procs 1 90 -- env GOMEMLIMIT=4MiB $G > t-memlimit.txt 2>&1 &
./measure.sh tune-go-all        procs 1 90 -- env GOMAXPROCS=1 GOGC=25 GOMEMLIMIT=4MiB $G > t-all.txt 2>&1 &
./measure.sh tune-rust-musl     procs 1 90 -- ./bin/rust-agent-x86_64-unknown-linux-musl > t-rust.txt 2>&1 &
wait
touch run-gotune.done
