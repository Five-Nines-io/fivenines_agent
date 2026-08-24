"""Cross-repo Ubuntu Pro contract round-trip (server #746 / agent #125).

SHARED FIXTURE: fixtures/ubuntu_pro_contract_payload.json, byte-identical with
the server's spec/fixtures/ubuntu_pro_contract_payload.json. Authored
server-first as the specification; the agent repo is the source of truth from
here on and the two copies change only in lockstep.

Asserted on both sides:
- here: each scenario's `raw` is fed back through the real collector with ONLY
  the subprocess / status-file boundary mocked, and must produce
  scenario["payload"] -- from EITHER collection source;
- fivenines-server: spec/requests/api_collect_ubuntu_pro_spec.rb posts the same
  scenario["payload"] under data["ubuntu_pro"] through /collect and asserts the
  resulting hosts.ubuntu_pro_* columns.
"""

import json
import os
import subprocess

import pytest

from fivenines_agent import ubuntu_pro

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "ubuntu_pro_contract_payload.json"
)

SCENARIOS = [
    "attached_full",
    "attached_fips_only",
    "attached_no_services",
    "detached",
    "collection_failure",
]


def _load_fixture():
    with open(_FIXTURE_PATH) as f:
        return json.load(f)


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    """Module-level cache emptied, status file pointed somewhere absent."""
    monkeypatch.setattr(ubuntu_pro, "_cache", ubuntu_pro.TTLCache())
    monkeypatch.setattr(
        ubuntu_pro, "_STATUS_CACHE_FILE", str(tmp_path / "no-such-status.json")
    )


def _run_via_pro_api(scenario, monkeypatch):
    """Feed raw["pro_api"] back through the `pro api` path.

    The status cache stays absent (the autouse fixture), so a payload produced
    here provably came from the CLI. An endpoint missing from the map is a hard
    failure rather than a null: the detached scenario omits enabled_services on
    purpose, and the collector must not reach for it.
    """
    responses = scenario["raw"]["pro_api"]
    if responses is None:
        monkeypatch.setattr(ubuntu_pro.shutil, "which", lambda _: None)
        return ubuntu_pro.ubuntu_pro_status()

    def fake_run(cmd, *_args, **_kwargs):
        assert cmd[:2] == ["/usr/bin/pro", "api"]
        endpoint = cmd[2]
        assert endpoint in responses, f"unexpected `pro api {endpoint}` call"
        return subprocess.CompletedProcess(cmd, 0, json.dumps(responses[endpoint]), "")

    monkeypatch.setattr(ubuntu_pro.shutil, "which", lambda _: "/usr/bin/pro")
    monkeypatch.setattr(ubuntu_pro.subprocess, "run", fake_run)
    return ubuntu_pro.ubuntu_pro_status()


def _run_via_status_cache(scenario, monkeypatch, tmp_path):
    """Feed raw["status_json"] back through the fallback path, with `pro` off
    PATH so the CLI cannot contribute."""
    monkeypatch.setattr(ubuntu_pro.shutil, "which", lambda _: None)
    content = scenario["raw"]["status_json"]
    if content is None:
        return ubuntu_pro.ubuntu_pro_status()

    path = tmp_path / "status.json"
    path.write_text(json.dumps(content))
    monkeypatch.setattr(ubuntu_pro, "_STATUS_CACHE_FILE", str(path))
    return ubuntu_pro.ubuntu_pro_status()


@pytest.mark.parametrize("name", SCENARIOS)
@pytest.mark.parametrize("source", ["pro_api", "status_json"])
def test_contract_fixture_round_trip(name, source, monkeypatch, tmp_path):
    """Both sources must produce the identical payload. The fallback exists for
    hosts the CLI path cannot answer, so it is not allowed to be a lossier
    reading of the same machine."""
    scenario = _load_fixture()["scenarios"][name]
    if source == "pro_api":
        produced = _run_via_pro_api(scenario, monkeypatch)
    else:
        produced = _run_via_status_cache(scenario, monkeypatch, tmp_path)
    assert produced == scenario["payload"]


def test_fixture_agent_min_version():
    # Frozen literal, never the live pyproject version: the fixture documents
    # the agent that FIRST ships the collector, and later releases must not
    # drag it forward.
    assert _load_fixture()["agent_min_version"] == "1.16.1"


def test_fixture_covers_every_scenario():
    assert sorted(_load_fixture()["scenarios"]) == sorted(SCENARIOS)


def test_fixture_payload_shape_matches_the_field_contract():
    """Only `attached` and `services` travel, `attached` is a real boolean, and
    every service name is a lowercase non-empty string. The server refuses
    anything else and preserves rather than guessing."""
    documented = set(_load_fixture()["field_contract"])
    assert documented == {"ubuntu_pro", "ubuntu_pro.attached", "ubuntu_pro.services"}

    for scenario in _load_fixture()["scenarios"].values():
        payload = scenario["payload"]
        if payload is None:
            continue
        assert set(payload) == {"attached", "services"}
        assert isinstance(payload["attached"], bool)
        assert all(
            isinstance(s, str) and s and s == s.strip().lower()
            for s in payload["services"]
        )
        assert payload["services"] == sorted(set(payload["services"]))


def test_fixture_pins_the_never_fabricate_shape():
    """`{"attached": true, "services": []}` has to be a real scenario, because
    it is exactly what an unread service list would look like. The collector
    reports null for that case (test_ubuntu_pro.py); the contract needs the
    genuine article on record so the two are never conflated."""
    scenarios = _load_fixture()["scenarios"]
    assert scenarios["attached_no_services"]["payload"] == {
        "attached": True,
        "services": [],
    }
    assert scenarios["collection_failure"]["payload"] is None


def test_fixture_detached_scenario_omits_the_services_endpoint():
    """Pins the one-call fast path in the contract itself: a detached machine
    must be answerable from the attachment call alone."""
    pro_api = _load_fixture()["scenarios"]["detached"]["raw"]["pro_api"]
    assert set(pro_api) == {ubuntu_pro._IS_ATTACHED_ENDPOINT}
