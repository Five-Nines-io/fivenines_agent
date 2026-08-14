"""Cross-repo VPN contract round-trip (#508 / agent #127).

SHARED FIXTURE: fixtures/vpn_contract_payload.json, byte-identical with the
server's spec/fixtures/vpn_contract_payload.json. The agent repo is the source
of truth; the two copies change only in lockstep.

Asserted on both sides:
- here: each scenario's `raw` is fed back through the real collectors with ONLY
  the subprocess boundary mocked, and must produce scenario["payload"];
- fivenines-server: spec/requests/api_collect_vpn_spec.rb posts the same
  scenario["payload"] under data["wireguard"] / data["tailscale"] through
  /collect and asserts Ingesters::Agent handles the object / empty / null
  shapes.
"""

import json
import os
import subprocess

import pytest

from fivenines_agent import tailscale, wireguard

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "vpn_contract_payload.json"
)

SCENARIOS = [
    "healthy_and_stale",
    "key_expiring",
    "needs_login",
    "no_expiry",
    "zero_peers",
    "collection_failure",
]

# What a real unprivileged / missing-interface `wg` invocation looks like. The
# fixture expresses the failure as wg_show_all_dump: null; this is the stdout /
# stderr / exit code that produces it.
_WG_FAILURE_STDERR = "Unable to access interface wg0: Operation not permitted\n"
_TS_FAILURE_STDERR = (
    "failed to connect to local tailscaled; it doesn't appear to be running\n"
)


def _load_fixture():
    with open(_FIXTURE_PATH) as f:
        return json.load(f)


def _completed(cmd, returncode, stdout, stderr):
    return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)


def _fake_run(expected_argv0, result):
    """A subprocess.run stand-in pinned to one binary.

    `wireguard.subprocess` and `tailscale.subprocess` are the SAME module
    object, so patching one patches both. The helpers below re-patch
    immediately before each call, which is correct but leaves the ordering
    implicit -- this assertion makes it explicit, so a future refactor that
    hoists both patches fails on the wrong-binary assert instead of on a
    confusing payload mismatch.
    """

    def run(cmd, *_args, **_kwargs):
        assert cmd[0] == expected_argv0, f"expected {expected_argv0}, got {cmd[0]}"
        return result

    return run


def _run_wireguard(scenario, monkeypatch, tmp_path):
    raw = scenario["raw"]
    dump = raw.get("wg_show_all_dump")

    for name, text in (raw.get("wg_quick_configs") or {}).items():
        (tmp_path / f"{name}.conf").write_text(text)

    if dump is None:
        result = _completed(["wg"], 1, "", _WG_FAILURE_STDERR)
    else:
        result = _completed(["wg"], 0, dump, "")

    monkeypatch.setattr(wireguard.shutil, "which", lambda _: "/usr/bin/wg")
    monkeypatch.setattr(wireguard.time, "time", lambda: raw["now"])
    monkeypatch.setattr(wireguard, "_WG_CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(wireguard.subprocess, "run", _fake_run("wg", result))
    return wireguard.wireguard_metrics()


def _run_tailscale(scenario, monkeypatch):
    document = scenario["raw"].get("tailscale_status_json")

    if document is None:
        result = _completed(["tailscale"], 1, "", _TS_FAILURE_STDERR)
    else:
        result = _completed(["tailscale"], 0, json.dumps(document), "")

    monkeypatch.setattr(tailscale.shutil, "which", lambda _: "/usr/bin/tailscale")
    monkeypatch.setattr(
        tailscale.subprocess, "run", _fake_run("/usr/bin/tailscale", result)
    )
    return tailscale.tailscale_metrics()


@pytest.mark.parametrize("name", SCENARIOS)
def test_contract_fixture_round_trip(name, monkeypatch, tmp_path):
    scenario = _load_fixture()["scenarios"][name]
    config = scenario["config"]
    payload = scenario["payload"]

    # An enabled collector must contribute its key (even as null); a disabled
    # one must be absent from the payload entirely.
    assert ("wireguard" in payload) == bool(config["wireguard"])
    assert ("tailscale" in payload) == bool(config["tailscale"])

    if config["wireguard"]:
        assert _run_wireguard(scenario, monkeypatch, tmp_path) == payload["wireguard"]
    if config["tailscale"]:
        assert _run_tailscale(scenario, monkeypatch) == payload["tailscale"]


def test_fixture_agent_min_version():
    # Frozen literal, never the live pyproject version: the fixture documents
    # the agent that FIRST ships the collectors, and later releases must not
    # drag it forward.
    assert _load_fixture()["agent_min_version"] == "1.16.0"


def test_fixture_covers_every_scenario():
    assert sorted(_load_fixture()["scenarios"]) == sorted(SCENARIOS)


def test_fixture_config_is_two_top_level_booleans():
    """Both keys are TOP-LEVEL plain booleans, so an agent without the
    collectors just ignores them -- no splat hazard (the image_inventory
    lesson)."""
    for scenario in _load_fixture()["scenarios"].values():
        assert set(scenario["config"]) == {"wireguard", "tailscale"}
        assert all(isinstance(v, bool) for v in scenario["config"].values())


def test_fixture_keys_match_the_field_contract():
    fixture = _load_fixture()
    documented = set(fixture["field_contract"])

    seen = set()
    for scenario in fixture["scenarios"].values():
        wg = scenario["payload"].get("wireguard")
        if wg:
            for entry in wg["interfaces"]:
                seen.update(f"wireguard.interfaces[].{k}" for k in entry)
            for entry in wg["peers"]:
                seen.update(f"wireguard.peers[].{k}" for k in entry)
        ts = scenario["payload"].get("tailscale")
        if ts:
            for key, value in ts.items():
                if key == "self":
                    seen.update(f"tailscale.self.{k}" for k in value)
                else:
                    seen.add(f"tailscale.{key}")

    assert seen == documented


def test_fixture_peer_key_order_is_stable():
    expected = [
        "interface",
        "public_key",
        "name",
        "endpoint",
        "allowed_ips",
        "last_handshake_age_seconds",
        "rx_bytes",
        "tx_bytes",
        "persistent_keepalive",
    ]
    peers = _load_fixture()["scenarios"]["healthy_and_stale"]["payload"]["wireguard"][
        "peers"
    ]
    for peer in peers:
        assert list(peer) == expected


def _secrets_in(dump):
    """Every interface PRIVATE KEY and peer PRESHARED KEY in a `wg` dump."""
    secrets = set()
    for line in (dump or "").splitlines():
        fields = line.split("\t")
        if len(fields) == 5:
            secrets.add(fields[1])
        elif len(fields) == 9 and fields[2] != "(none)":
            secrets.add(fields[2])
    return secrets


def test_fixture_exercises_secret_stripping():
    """The raw dumps must actually carry secrets, or the round-trip proves
    nothing about stripping them."""
    dump = _load_fixture()["scenarios"]["healthy_and_stale"]["raw"]["wg_show_all_dump"]
    assert len(_secrets_in(dump)) == 3  # one private key, two preshared keys


@pytest.mark.parametrize("name", SCENARIOS)
def test_no_secret_reaches_the_payload(name, monkeypatch, tmp_path):
    """Neither the interface PRIVATE KEY nor any peer PRESHARED KEY may appear
    anywhere in what gets sent -- not from the `wg` dump, and not from the
    wg-quick config the alias parse reads."""
    scenario = _load_fixture()["scenarios"][name]
    if not scenario["config"]["wireguard"]:
        pytest.skip("no wireguard half in this scenario")

    raw = scenario["raw"]
    secrets = _secrets_in(raw.get("wg_show_all_dump"))
    for text in (raw.get("wg_quick_configs") or {}).values():
        for line in text.splitlines():
            if line.strip().lower().startswith(("privatekey", "presharedkey")):
                secrets.add(line.split("=", 1)[1].strip())

    emitted = json.dumps(_run_wireguard(scenario, monkeypatch, tmp_path))
    for secret in secrets:
        assert secret not in emitted
    # Also assert against the frozen payload, so a future fixture edit that
    # pasted a secret in would fail even without running the collector.
    assert all(s not in json.dumps(scenario["payload"]) for s in secrets)
