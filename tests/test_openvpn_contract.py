"""Cross-repo OpenVPN contract round-trip (agent #145 / server #1103).

SHARED FIXTURE: fixtures/openvpn_contract_payload.json, byte-identical with the
server's copy. The agent repo is the source of truth; the two change only in
lockstep.

Asserted on both sides:
- here: each scenario's `raw` is replayed back through the real collector with
  the socket transport, socket discovery and the process scan mocked -- every
  parser, bound and reducer is the real one -- and must produce
  scenario["payload"];
- fivenines-server: the same scenario["payload"] is posted under
  data["openvpn"] through /collect, and Ingesters::Agent must handle the
  instances / empty / null / per-instance-error shapes.

The transport is mocked rather than driven over a real AF_UNIX socket for two
reasons: the payload carries the socket PATH, so the fixture's real
/run/openvpn-* paths have to survive into the assertion, and the full suite runs
on windows-latest where AF_UNIX does not exist. The real-socket transport is
exercised separately in test_openvpn.py.
"""

import json
import os

import pytest

from fivenines_agent import openvpn

_FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "fixtures", "openvpn_contract_payload.json"
)

SCENARIOS = [
    "server_with_duplicate_cn",
    "username_auth_server",
    "older_daemon_missing_columns",
    "client_connected",
    "client_reconnecting",
    "one_instance_unreadable",
    "no_openvpn",
    "running_without_socket",
]


def _load_fixture():
    with open(_FIXTURE_PATH) as f:
        return json.load(f)


class _ScriptedSocket:
    """A management connection replaying one fixture socket's captured bytes.

    Answers are keyed by the command the collector sends, so a collector that
    sent the WRONG command (or sent `state` to a server instance, which the
    contract says it must not) gets an explicit KeyError rather than a quietly
    plausible payload.
    """

    def __init__(self, spec):
        self._answers = spec.get("answers") or {}
        self._refuse = bool(spec.get("refuse"))
        self._pending = bytearray()
        self.sent = []
        self.closed = False
        if not self._refuse:
            self._pending += (spec.get("greeting") or "").encode()

    def settimeout(self, _timeout):
        pass

    def sendall(self, data):
        command = data.decode().strip()
        self.sent.append(command)
        # A refused peer is never answered: the daemon has already closed its
        # side, so the write lands in the void and the read that follows sees
        # EOF. Modelling it as "no answers scripted" rather than raising keeps
        # the KeyError below meaningful for every OTHER socket -- it then means
        # the collector sent a command the contract does not allow.
        if self._refuse or command == "quit":
            return
        self._pending += self._answers[command].encode()

    def recv(self, size):
        chunk = bytes(self._pending[:size])
        del self._pending[:size]
        # Empty means EOF, which is exactly what a refused peer sees.
        return chunk

    def close(self):
        self.closed = True


def _run(scenario, monkeypatch):
    raw = scenario["raw"]
    specs = {spec["path"]: spec for spec in raw["sockets"]}
    sockets = {}

    def fake_connect(path, _deadline):
        sockets[path] = _ScriptedSocket(specs[path])
        return sockets[path]

    monkeypatch.setattr(openvpn.time, "time", lambda: raw["now"])
    monkeypatch.setattr(openvpn, "_discover_sockets", lambda: (list(specs), []))
    monkeypatch.setattr(openvpn, "_connect", fake_connect)
    monkeypatch.setattr(openvpn, "_openvpn_is_running", lambda: raw["openvpn_running"])
    result = openvpn.openvpn_metrics()
    return result, sockets


@pytest.mark.parametrize("name", SCENARIOS)
def test_contract_fixture_round_trip(name, monkeypatch):
    scenario = _load_fixture()["scenarios"][name]
    config = scenario["config"]
    payload = scenario["payload"]

    # An enabled collector always contributes its key, even when the value is
    # null. That is the whole point of listing openvpn in
    # collectors.CAPABILITY_GATE_EXEMPT, and it is what makes `null` a
    # distinguishable signal rather than an absent key.
    assert config["openvpn"] is True
    assert "openvpn" in payload

    result, _sockets = _run(scenario, monkeypatch)
    assert result == payload["openvpn"]

    # Dict equality above is order-insensitive, so it would not notice the
    # collector reordering its keys -- which changes the JSON the server
    # actually receives. Pin the emitted order against the fixture's.
    if result is not None:
        expected = payload["openvpn"]["instances"]
        for got, want in zip(result["instances"], expected):
            assert list(got) == list(want)
            for got_client, want_client in zip(
                got.get("clients", []), want.get("clients", [])
            ):
                assert list(got_client) == list(want_client)


@pytest.mark.parametrize("name", SCENARIOS)
def test_contract_sockets_are_always_closed(name, monkeypatch):
    _result, sockets = _run(_load_fixture()["scenarios"][name], monkeypatch)
    assert all(sock.closed for sock in sockets.values())


def test_fixture_agent_min_version():
    # Frozen literal, never the live pyproject version: the fixture documents
    # which agent first shipped this shape, and reading it from pyproject would
    # make the assertion drift with every release (agent #101 -> PR #116).
    assert _load_fixture()["agent_min_version"] == "1.18.0"


def test_fixture_covers_every_scenario():
    assert sorted(_load_fixture()["scenarios"]) == sorted(SCENARIOS)


def test_fixture_config_is_one_top_level_boolean():
    # The splat hazard: collectors.py unpacks a dict config value as **kwargs,
    # and openvpn_metrics takes no parameters. A nested dict would be a
    # TypeError on this agent, so the contract pins a plain boolean.
    for scenario in _load_fixture()["scenarios"].values():
        assert set(scenario["config"]) == {"openvpn"}
        assert all(isinstance(v, bool) for v in scenario["config"].values())


def test_fixture_keys_match_the_field_contract():
    """Every key any scenario emits must be documented, and vice versa."""
    fixture = _load_fixture()
    documented = set(fixture["field_contract"])
    seen = set()

    for scenario in fixture["scenarios"].values():
        block = scenario["payload"]["openvpn"]
        if block is None:
            continue
        for instance in block["instances"]:
            for key in instance:
                seen.add(f"openvpn.instances[].{key}")
            for client in instance.get("clients", []):
                for key in client:
                    seen.add(f"openvpn.instances[].clients[].{key}")
            for key in instance.get("state") or {}:
                seen.add(f"openvpn.instances[].state.{key}")

    assert seen == documented


def test_fixture_error_entry_has_no_clients_key():
    """A per-instance null must be ABSENT, never an empty client list.

    `clients: []` on an unreadable instance would assert "this instance is up
    and nobody is connected" -- the false all-clear that resolves the incident
    the error exists to preserve.
    """
    instances = _load_fixture()["scenarios"]["one_instance_unreadable"]["payload"][
        "openvpn"
    ]["instances"]
    errored = [i for i in instances if "error" in i]
    assert errored, "the scenario must carry an errored instance"
    for instance in errored:
        assert "clients" not in instance
        assert "state" not in instance
        assert "mode" not in instance


def test_fixture_client_key_order_is_stable():
    """The server reads these positionally in its spec fixture copy."""
    expected = [
        "common_name",
        "identity_source",
        "real_address",
        "virtual_address",
        "username",
        "sessions",
        "connected_age_s",
        "bytes_received",
        "bytes_sent",
        "cipher",
    ]
    instances = _load_fixture()["scenarios"]["server_with_duplicate_cn"]["payload"][
        "openvpn"
    ]["instances"]
    for client in instances[0]["clients"]:
        assert list(client) == expected


def test_fixture_covers_an_unhealthy_tunnel():
    """A dropped tunnel is a healthy READ of an unhealthy instance.

    `state` is the whole reason a client instance is polled, so the fixture must
    carry a non-CONNECTED one -- otherwise the server's ingester spec only ever
    sees the happy shape. It must NOT look like an instance-level error: an
    error entry freezes the rows, while this one is a real reading the server
    should ingest and alert on.
    """
    instance = _load_fixture()["scenarios"]["client_reconnecting"]["payload"][
        "openvpn"
    ]["instances"][0]
    assert "error" not in instance
    assert instance["mode"] == "client"
    assert instance["clients"] == []
    assert instance["state"]["name"] == "RECONNECTING"
    # The daemon's own reason travels verbatim -- it is what names the outage.
    assert instance["state"]["description"] == "tls-error"
    # A client mid-reconnect has no addresses yet; null, never a stale value.
    assert instance["state"]["local_ip"] is None
    assert instance["state"]["remote"] is None


def test_fixture_pins_the_two_empty_shapes_apart():
    """The distinction the whole process scan exists for."""
    scenarios = _load_fixture()["scenarios"]
    assert scenarios["no_openvpn"]["raw"]["openvpn_running"] is False
    assert scenarios["no_openvpn"]["payload"]["openvpn"] == {"instances": []}
    assert scenarios["running_without_socket"]["raw"]["openvpn_running"] is True
    assert scenarios["running_without_socket"]["payload"]["openvpn"] is None


def test_fixture_duplicate_cn_collapse_is_exercised():
    """Pin that the fixture really contains a collapsed pair, and that the
    OLDER of the two sessions is listed SECOND.

    Without the ordering the scenario would pass even if the collector simply
    kept the first row it saw, so it would stop testing the rule it is here for.
    """
    scenario = _load_fixture()["scenarios"]["server_with_duplicate_cn"]
    rows = [
        line.split("\t")
        for line in scenario["raw"]["sockets"][0]["answers"]["status 3"].splitlines()
        if line.startswith("CLIENT_LIST\t")
    ]
    lyon = [r for r in rows if r[1] == "site-lyon"]
    assert len(lyon) == 2
    # Row layout, with the CLIENT_LIST tag at index 0: Common Name 1, Real
    # Address 2, Virtual Address 3, Virtual IPv6 4, Bytes Received 5, Bytes
    # Sent 6, Connected Since 7, Connected Since (time_t) 8.
    # Older == smaller timestamp, and it must come last.
    assert int(lyon[0][8]) > int(lyon[1][8])

    collapsed = scenario["payload"]["openvpn"]["instances"][0]["clients"][0]
    assert collapsed["sessions"] == 2
    # Bytes SUMMED across both sessions.
    assert collapsed["bytes_received"] == int(lyon[0][5]) + int(lyon[1][5])
    assert collapsed["bytes_sent"] == int(lyon[0][6]) + int(lyon[1][6])
    # Descriptive fields from the OLDEST (second) session.
    assert collapsed["real_address"] == lyon[1][2]
    assert collapsed["virtual_address"] == lyon[1][3]


def test_contract_never_sends_state_to_a_server_instance(monkeypatch):
    """A server's state machine carries no signal, so the command is not sent.

    Pinned because the fixture's server scenario declares no `state` answer at
    all: an agent that sent it would KeyError rather than silently drifting from
    the contract.
    """
    scenario = _load_fixture()["scenarios"]["server_with_duplicate_cn"]
    _result, sockets = _run(scenario, monkeypatch)
    sent = sockets["/run/openvpn-server/server.sock"].sent
    assert sent == ["version", "status 3", "quit"]


def test_contract_client_instance_is_asked_for_state(monkeypatch):
    scenario = _load_fixture()["scenarios"]["client_connected"]
    _result, sockets = _run(scenario, monkeypatch)
    sent = sockets["/run/openvpn-client/office.sock"].sent
    assert sent == ["version", "status 3", "state", "quit"]


def test_fixture_version_banner_is_trimmed():
    """The full build banner must never reach the payload."""
    fixture = _load_fixture()
    for scenario in fixture["scenarios"].values():
        for spec in scenario["raw"]["sockets"]:
            banner = (spec.get("answers") or {}).get("version")
            if banner is None:
                continue
            # The raw answer really does carry the platform + feature flags...
            assert "x86_64-pc-linux-gnu" in banner
    # ...and none of it survives into any payload (the raw side is
    # intentionally allowed to contain it -- that is the input we trim).
    for scenario in fixture["scenarios"].values():
        block = scenario["payload"]["openvpn"]
        if block is None:
            continue
        for instance in block["instances"]:
            version = instance.get("version")
            if version is not None:
                assert version.count(" ") == 1
                assert "[" not in version


def test_fixture_pins_the_identity_source_discriminator():
    """A certificate CN and a login name can spell the same thing.

    common_name alone is therefore NOT a unique row key -- the key is
    (socket, common_name, identity_source). The username-auth scenario exists so
    the server sees a payload whose identity came from the Username column.
    """
    scenarios = _load_fixture()["scenarios"]
    users = scenarios["username_auth_server"]["payload"]["openvpn"]["instances"][0]
    assert [c["identity_source"] for c in users["clients"]] == ["user", "user"]
    # ...and its raw really does carry OpenVPN's UNDEF sentinel in the CN column,
    # which is what makes the fallback necessary rather than decorative.
    raw = scenarios["username_auth_server"]["raw"]["sockets"][0]["answers"]["status 3"]
    assert "\tUNDEF\t" in raw

    certs = scenarios["server_with_duplicate_cn"]["payload"]["openvpn"]["instances"][0]
    assert {c["identity_source"] for c in certs["clients"]} == {"cn"}
