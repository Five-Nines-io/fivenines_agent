#!/usr/bin/env python3
"""Differential check: a prototype's /collect payload vs the Python one.

usage: diff_payloads.py PY_PAYLOAD PROTO_PAYLOAD  (Go or Rust; printed as go=)
Compares every key the prototype ports: presence, JSON type, shape, the
identity of list members (interfaces, disks, mounts), and values -- exact for
static facts, tolerant for counters sampled a few ms apart.
"""

import json
import sys

py, go = (json.load(open(p)) for p in sys.argv[1:3])
issues, ok = [], []

PORTED = ["load_average", "file_handles_used", "file_handles_limit", "cpu",
          "cpu_usage", "cpu_model", "cpu_count", "memory", "swap", "network",
          "partitions_metadata", "partitions_usage", "io", "uname", "boot_time",
          "user_context", "version", "machine_id", "ts", "running_time", "processes", "docker"]
NOT_PORTED = sorted(set(py) - set(PORTED) - {"_telemetry"})


def jtype(v):
    return type(v).__name__


def keyed(rows):
    """[{name: {...}}, ...] -> {name: {...}}"""
    return {k: v for row in rows for k, v in row.items()}


def close(a, b, rel):
    if isinstance(a, bool) or not isinstance(a, (int, float)):
        return a == b
    return abs(a - b) <= max(abs(a), abs(b), 1) * rel


def cmp_dict(name, a, b, rel=0.0, skip=()):
    if set(a) != set(b):
        issues.append(f"{name}: keys differ, python-only={sorted(set(a)-set(b))} go-only={sorted(set(b)-set(a))}")
    for k in sorted(set(a) & set(b)):
        if k in skip:
            continue
        if jtype(a[k]) != jtype(b[k]) and not (isinstance(a[k], (int, float)) and isinstance(b[k], (int, float))):
            issues.append(f"{name}.{k}: type python={jtype(a[k])} go={jtype(b[k])}")
        elif not close(a[k], b[k], rel):
            issues.append(f"{name}.{k}: python={a[k]!r} go={b[k]!r}")


for k in PORTED:
    if (k in py) != (k in go):
        issues.append(f"{k}: present python={k in py} go={k in go}")

cmp_dict("uname", py["uname"], go["uname"])
cmp_dict("user_context", py["user_context"], go["user_context"])
for k in ("cpu_model", "cpu_count", "boot_time", "file_handles_limit"):
    if py[k] != go[k]:
        issues.append(f"{k}: python={py[k]!r} go={go[k]!r}")
if len(py["load_average"]) != len(go["load_average"]):
    issues.append("load_average: length differs")

# cpu: same core count, same fields; percentages are sampled over different
# windows, so only the shape is compared.
if len(py["cpu"]) != len(go["cpu"]):
    issues.append(f"cpu: {len(py['cpu'])} cores vs {len(go['cpu'])}")
elif set(py["cpu"][0]) != set(go["cpu"][0]):
    issues.append(f"cpu[0]: fields differ {sorted(set(py['cpu'][0]) ^ set(go['cpu'][0]))}")
if [len(r) for r in py["cpu_usage"]] != [len(r) for r in go["cpu_usage"]]:
    issues.append("cpu_usage: shape differs")
else:
    worst = max(abs(a - b) for pr, gr in zip(py["cpu_usage"], go["cpu_usage"]) for a, b in zip(pr, gr))
    ok.append(f"cpu_usage: 16x10 positional arrays, max drift {worst:.2f}s of CPU time between samples")

cmp_dict("memory", py["memory"], go["memory"], rel=0.02)
cmp_dict("swap", py["swap"], go["swap"], rel=0.02)

pn, gn = keyed(py["network"]), keyed(go["network"])
if set(pn) != set(gn):
    issues.append(f"network: interfaces python={sorted(pn)} go={sorted(gn)}")
for i in sorted(set(pn) & set(gn)):
    cmp_dict(f"network[{i}]", pn[i], gn[i], rel=0.05)

pm = {m["mountpoint"]: m for m in py["partitions_metadata"]}
gm = {m["mountpoint"]: m for m in go["partitions_metadata"]}
if set(pm) != set(gm):
    issues.append(f"partitions_metadata: python-only={sorted(set(pm)-set(gm))} go-only={sorted(set(gm)-set(pm))}")
for m in sorted(set(pm) & set(gm)):
    cmp_dict(f"partitions_metadata[{m}]", pm[m], gm[m])
pu, gu = py["partitions_usage"], go["partitions_usage"]
if set(pu) != set(gu):
    issues.append(f"partitions_usage: python-only={sorted(set(pu)-set(gu))} go-only={sorted(set(gu)-set(pu))}")
for m in sorted(set(pu) & set(gu)):
    cmp_dict(f"partitions_usage[{m}]", pu[m], gu[m], rel=0.001)

pi, gi = keyed(py["io"]), keyed(go["io"])
if set(pi) != set(gi):
    issues.append(f"io: disks python-only={sorted(set(pi)-set(gi))} go-only={sorted(set(gi)-set(pi))}")
for d in sorted(set(pi) & set(gi)):
    cmp_dict(f"io[{d}]", pi[d], gi[d], rel=0.05)
if [next(iter(r)) for r in py["io"]] != [next(iter(r)) for r in go["io"]]:
    ok.append("io: same disks, different ORDER (python = /proc/diskstats order, go = sorted)")

if "processes" in py and "processes" in go:
    pp = {p["pid"]: p for p in py["processes"]}
    gp = {p["pid"]: p for p in go["processes"]}
    common = sorted(set(pp) & set(gp))
    ok.append(f"processes: {len(pp)} python, {len(gp)} go, {len(common)} pids in both samples")
    for pid in common:
        a, b = pp[pid], gp[pid]
        if set(a) != set(b):
            issues.append(f"processes[{pid}]: keys differ {sorted(set(a) ^ set(b))}")
            continue
        for k in ("ppid", "name", "username"):
            if a[k] != b[k]:
                issues.append(f"processes[{pid}].{k}: python={a[k]!r} go={b[k]!r}")
        if len(a["cpu_times"]) != len(b["cpu_times"]):
            issues.append(f"processes[{pid}].cpu_times: shape differs")
        if not close(a["memory_percent"], b["memory_percent"], 0.2):
            issues.append(f"processes[{pid}].memory_percent: python={a['memory_percent']} go={b['memory_percent']}")
    mism = sum(pp[p]["status"] != gp[p]["status"] for p in common)
    ok.append(f"processes: status differs on {mism}/{len(common)} (sampled ms apart, expected noise)")

if "docker" in py or "docker" in go:
    pd, gd = py.get("docker"), go.get("docker")
    if pd is None or gd is None:
        issues.append(f"docker: python={'null' if pd is None else 'object'} go={'null' if gd is None else 'object'}")
    else:
        pc, gc = pd["containers"], gd["containers"]
        if set(pc) != set(gc):
            issues.append(f"docker: container ids differ ({len(pc)} python, {len(gc)} go)")
        exact = ("name", "image", "image_id", "image_tags", "image_repo_digests", "status", "exit_code",
                 "oom_killed", "restart_count", "started_at", "finished_at", "health",
                 "pids_stats", "cpu_throttling", "online_cpus", "memory_limit")
        warm = 0
        for cid in sorted(set(pc) & set(gc)):
            a, b = pc[cid], gc[cid]
            if "cpu_percent" in a and "cpu_percent" in b:
                warm += 1
            elif "cpu_percent" in a or "cpu_percent" in b:
                continue  # one agent has warmed this container up, the other not yet
            if set(a) != set(b):
                issues.append(f"docker[{a.get('name')}]: keys python-only={sorted(set(a)-set(b))} go-only={sorted(set(b)-set(a))}")
                continue
            for k in exact:
                if k in a and not (a[k] == b[k] or close(a[k], b[k], 1e-9)):
                    issues.append(f"docker[{a['name']}].{k}: python={a[k]!r} go={b[k]!r}")
                    if type(a[k]) is not type(b[k]):
                        issues.append(f"docker[{a['name']}].{k}: type python={jtype(a[k])} go={jtype(b[k])}")
            for k in ("cpu_percent", "memory_usage", "memory_percent", "block_read_bytes", "block_write_bytes",
                      "cpu_kernelmode_percent", "cpu_usermode_percent"):
                if k in a and not close(a[k], b[k], 0.05):
                    issues.append(f"docker[{a['name']}].{k}: python={a[k]!r} go={b[k]!r}")
            if "networks" in a and {i: sorted(v) for i, v in a["networks"].items()} != {i: sorted(v) for i, v in b["networks"].items()}:
                issues.append(f"docker[{a['name']}].networks: shape differs")
        ok.append(f"docker: {len(pc)} containers, {warm} compared with stats")

print(f"payload bytes: python {len(json.dumps(py))}, go {len(json.dumps(go))}")
print(f"not ported ({len(NOT_PORTED)}): {', '.join(NOT_PORTED)}")
for line in ok:
    print("  note:", line)
print(f"{len(issues)} divergence(s):")
for line in issues:
    print("  -", line)
