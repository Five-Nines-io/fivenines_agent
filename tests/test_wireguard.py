"""Tests for the WireGuard peer health collector (#508 / agent #127).

Only the subprocess boundary is mocked: every case feeds canned `wg show all
dump` stdout back through the real parse -> payload pipeline, and the wg-quick
alias parse reads real files from tmp_path. The cross-repo round-trip lives in
test_vpn_contract.py.
"""

import subprocess

import pytest

from fivenines_agent import wireguard
from fivenines_agent.wireguard import wireguard_metrics

NOW = 1786708800  # 2026-08-14T12:00:00Z

PRIVATE_KEY = "YWdlbnQtbXVzdC1uZXZlci10cmFuc21pdC10aGlzISE="
IFACE_PUBLIC = "d2cwLWludGVyZmFjZS1wdWJsaWMta2V5LTMyYnl0ZXM="
PSK = "cHJlc2hhcmVkLWtleS1tdXN0LW5ldmVyLXRyYXZlbDE="
PEER_KEY = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
OTHER_KEY = "B" * 43 + "="


def _iface_line(name="wg0", port="51820"):
    return "\t".join([name, PRIVATE_KEY, IFACE_PUBLIC, port, "off"])


def _peer_line(
    iface="wg0",
    key=PEER_KEY,
    psk=PSK,
    endpoint="203.0.113.5:51820",
    allowed="10.100.0.2/32",
    handshake=str(NOW - 42),
    rx="1",
    tx="2",
    keepalive="25",
):
    return "\t".join([iface, key, psk, endpoint, allowed, handshake, rx, tx, keepalive])


def _dump(*lines):
    return "\n".join(lines) + "\n"


@pytest.fixture
def wg(monkeypatch, tmp_path):
    """Pin the clock, point the alias parse at tmp_path, install a fake `wg`.

    Returns a callable that arms the next `wg show all dump` invocation.
    """
    monkeypatch.setattr(wireguard.shutil, "which", lambda _: "/usr/bin/wg")
    monkeypatch.setattr(wireguard.time, "time", lambda: NOW)
    monkeypatch.setattr(wireguard, "_WG_CONFIG_DIR", str(tmp_path))

    def install(stdout="", returncode=0, stderr="", raises=None):
        def fake_run(*_args, **_kwargs):
            if raises is not None:
                raise raises
            return subprocess.CompletedProcess(
                ["wg", "show", "all", "dump"], returncode, stdout=stdout, stderr=stderr
            )

        monkeypatch.setattr(wireguard.subprocess, "run", fake_run)

    return install


# --- collection failure vs honest empty ------------------------------------


def test_missing_wg_binary_is_a_collection_failure(monkeypatch):
    monkeypatch.setattr(wireguard.shutil, "which", lambda _: None)
    assert wireguard_metrics() is None


def test_spawn_error_is_a_collection_failure(wg):
    wg(raises=OSError("no fork for you"))
    assert wireguard_metrics() is None


def test_timeout_is_a_collection_failure(wg):
    wg(raises=subprocess.TimeoutExpired(cmd="wg", timeout=10))
    assert wireguard_metrics() is None


def test_nonzero_exit_is_a_collection_failure(wg):
    wg(returncode=1, stderr="Unable to access interface wg0")
    assert wireguard_metrics() is None


def test_nonzero_exit_without_stderr_is_a_collection_failure(wg):
    wg(returncode=2)
    assert wireguard_metrics() is None


def test_stderr_on_a_zero_exit_is_a_collection_failure(wg):
    """The privilege trap this collector is shaped around.

    Without CAP_NET_ADMIN `wg` can still enumerate interface NAMES (an
    unprivileged rtnetlink call) but not read them, so it prints a per-interface
    EPERM line and can still exit 0 having emitted a PARTIAL dump. The server
    reads a non-empty peers array as the FULL current set, so shipping that
    partial view would vanish-prune every peer we could not read -- mass
    false-resolving live wireguard_peer_stale incidents. Any stderr means null.
    """
    wg(
        stdout=_dump(_iface_line()),
        stderr="Unable to access interface wg1: Operation not permitted\n",
    )
    assert wireguard_metrics() is None


def test_none_stdout_is_treated_as_empty(wg):
    wg(stdout=None)
    assert wireguard_metrics() == {"interfaces": [], "peers": []}


def test_no_wireguard_interfaces_is_an_honest_empty(wg):
    """`wg` installed, kernel module loaded, zero interfaces configured. A clean
    read of nothing -- not a failure."""
    wg(stdout="")
    assert wireguard_metrics() == {"interfaces": [], "peers": []}


# --- parsing ---------------------------------------------------------------


def test_secrets_are_stripped(wg):
    wg(stdout=_dump(_iface_line(), _peer_line()))
    payload = wireguard_metrics()
    flat = repr(payload)
    assert PRIVATE_KEY not in flat
    assert PSK not in flat
    assert IFACE_PUBLIC not in flat
    assert payload["peers"][0]["public_key"] == PEER_KEY


def test_interface_and_peer_shape(wg):
    wg(stdout=_dump(_iface_line(), _peer_line()))
    payload = wireguard_metrics()
    assert payload["interfaces"] == [
        {"name": "wg0", "listen_port": 51820, "peer_count": 1}
    ]
    assert payload["peers"] == [
        {
            "interface": "wg0",
            "public_key": PEER_KEY,
            "name": None,
            "endpoint": "203.0.113.5:51820",
            "allowed_ips": "10.100.0.2/32",
            "last_handshake_age_seconds": 42,
            "rx_bytes": 1,
            "tx_bytes": 2,
            "persistent_keepalive": 25,
        }
    ]


def test_zero_peer_interface_still_reports(wg):
    """interfaces[] is the ONLY source of names for the per-interface rollup
    gauges when there are no peer rows, so it must survive a zero-peer tick."""
    wg(stdout=_dump(_iface_line()))
    assert wireguard_metrics() == {
        "interfaces": [{"name": "wg0", "listen_port": 51820, "peer_count": 0}],
        "peers": [],
    }


def test_client_interface_without_a_fixed_port(wg):
    wg(stdout=_dump(_iface_line(port="0")))
    assert wireguard_metrics()["interfaces"][0]["listen_port"] is None


def test_unparseable_listen_port_is_null(wg):
    wg(stdout=_dump("\t".join(["wg0", PRIVATE_KEY, IFACE_PUBLIC, "-", "off"])))
    assert wireguard_metrics()["interfaces"][0]["listen_port"] is None


def test_never_handshaked_peer_reports_null_not_zero(wg):
    """latest-handshake=0 means "never since the interface came up". 0 would
    chart as a handshake that had just happened."""
    wg(stdout=_dump(_iface_line(), _peer_line(handshake="0")))
    assert wireguard_metrics()["peers"][0]["last_handshake_age_seconds"] is None


def test_unparseable_handshake_reports_null(wg):
    wg(stdout=_dump(_iface_line(), _peer_line(handshake="soon")))
    assert wireguard_metrics()["peers"][0]["last_handshake_age_seconds"] is None


def test_future_handshake_reports_null_not_zero(wg):
    """A handshake timestamp in the future (clock stepped backwards by NTP or a
    VM snapshot restore) is nonsense, and 0 is the WORST way to report it: the
    server keeps the newest of `received_at - age` and the stored anchor, so 0
    overwrites a real older handshake with "just now" and resolves an open
    wireguard_peer_stale incident on a tunnel that is actually dead. None means
    "no reading", the true anchor survives, and the age keeps growing."""
    wg(stdout=_dump(_iface_line(), _peer_line(handshake=str(NOW + 500))))
    assert wireguard_metrics()["peers"][0]["last_handshake_age_seconds"] is None


def test_handshake_exactly_now_is_zero(wg):
    wg(stdout=_dump(_iface_line(), _peer_line(handshake=str(NOW))))
    assert wireguard_metrics()["peers"][0]["last_handshake_age_seconds"] == 0


@pytest.mark.parametrize(
    "value,expected",
    [
        ("off", None),
        ("(none)", None),
        ("", None),
        ("0", None),
        ("nope", None),
        ("25", 25),
    ],
)
def test_persistent_keepalive_values(wg, value, expected):
    wg(stdout=_dump(_iface_line(), _peer_line(keepalive=value)))
    assert wireguard_metrics()["peers"][0]["persistent_keepalive"] == expected


def test_roaming_peer_has_no_endpoint(wg):
    wg(stdout=_dump(_iface_line(), _peer_line(endpoint="(none)")))
    assert wireguard_metrics()["peers"][0]["endpoint"] is None


def test_blank_allowed_ips_is_null(wg):
    wg(stdout=_dump(_iface_line(), _peer_line(allowed="  ")))
    assert wireguard_metrics()["peers"][0]["allowed_ips"] is None


def test_unparseable_transfer_counters_fall_back_to_zero(wg):
    wg(stdout=_dump(_iface_line(), _peer_line(rx="x", tx="y")))
    peer = wireguard_metrics()["peers"][0]
    assert (peer["rx_bytes"], peer["tx_bytes"]) == (0, 0)


def test_blank_and_malformed_lines_are_skipped(wg):
    wg(
        stdout=_dump(
            "",
            "   ",
            "not\ta\tdump\tline",
            _iface_line(),
            "\t".join(["", PRIVATE_KEY, IFACE_PUBLIC, "51821", "off"]),
            _peer_line(),
            _peer_line(iface=""),
            _peer_line(key=""),
        )
    )
    payload = wireguard_metrics()
    assert [i["name"] for i in payload["interfaces"]] == ["wg0"]
    assert len(payload["peers"]) == 1


def test_peer_on_an_undeclared_interface_still_travels(wg):
    """A peer whose interface line never printed is still a real peer; only the
    (RESERVED) peer_count rollup misses it."""
    wg(stdout=_dump(_iface_line(), _peer_line(iface="wg9")))
    payload = wireguard_metrics()
    assert payload["interfaces"][0]["peer_count"] == 0
    assert payload["peers"][0]["interface"] == "wg9"


def test_multiple_interfaces_count_their_own_peers(wg):
    wg(
        stdout=_dump(
            _iface_line("wg0", "51820"),
            _peer_line("wg0", key=PEER_KEY),
            _peer_line("wg0", key=OTHER_KEY),
            _iface_line("wg1", "51821"),
            _peer_line("wg1", key="C" * 43 + "="),
        )
    )
    payload = wireguard_metrics()
    assert [(i["name"], i["peer_count"]) for i in payload["interfaces"]] == [
        ("wg0", 2),
        ("wg1", 1),
    ]
    assert len(payload["peers"]) == 3


# --- wg-quick alias parse --------------------------------------------------


CONFIG = f"""[Interface]
Address = 10.100.0.1/24
PrivateKey = {PRIVATE_KEY}

# Name = office-router
[Peer]
PublicKey = {PEER_KEY}
PresharedKey = {PSK}
AllowedIPs = 10.100.0.2/32
"""


def test_alias_is_read_from_the_wg_quick_config(wg, tmp_path):
    (tmp_path / "wg0.conf").write_text(CONFIG)
    wg(stdout=_dump(_iface_line(), _peer_line()))
    assert wireguard_metrics()["peers"][0]["name"] == "office-router"


def test_alias_inside_the_peer_block(wg, tmp_path):
    (tmp_path / "wg0.conf").write_text(
        f"[Peer]\n# Name = branch-nyc\nPublicKey = {PEER_KEY}\n"
    )
    wg(stdout=_dump(_iface_line(), _peer_line()))
    assert wireguard_metrics()["peers"][0]["name"] == "branch-nyc"


def test_alias_absent_leaves_name_null(wg, tmp_path):
    (tmp_path / "wg0.conf").write_text(f"[Peer]\nPublicKey = {PEER_KEY}\n")
    wg(stdout=_dump(_iface_line(), _peer_line()))
    assert wireguard_metrics()["peers"][0]["name"] is None


def test_unreadable_config_leaves_name_null(wg):
    """The normal case for an agent running as `fivenines` with only
    CAP_NET_ADMIN: /etc/wireguard is 0700 root. Aliases degrade, peers do not."""
    wg(stdout=_dump(_iface_line(), _peer_line()))
    assert wireguard_metrics()["peers"][0]["name"] is None


def test_config_secrets_never_reach_the_payload(wg, tmp_path):
    (tmp_path / "wg0.conf").write_text(CONFIG)
    wg(stdout=_dump(_iface_line(), _peer_line()))
    flat = repr(wireguard_metrics())
    assert PRIVATE_KEY not in flat
    assert PSK not in flat


def test_config_is_read_once_per_interface(wg, tmp_path, monkeypatch):
    (tmp_path / "wg0.conf").write_text(CONFIG)
    reads = []
    real = wireguard._read_wg_quick_config
    monkeypatch.setattr(
        wireguard,
        "_read_wg_quick_config",
        lambda iface: (reads.append(iface), real(iface))[1],
    )
    wg(stdout=_dump(_iface_line(), _peer_line(), _peer_line(key=OTHER_KEY)))
    wireguard_metrics()
    assert reads == ["wg0"]


def test_interface_name_with_a_separator_is_refused():
    assert wireguard._read_wg_quick_config("../../etc/shadow") is None
    assert wireguard._read_wg_quick_config("") is None


def test_oversized_config_is_truncated(wg, tmp_path, monkeypatch):
    (tmp_path / "wg0.conf").write_text("x" * 4096)
    monkeypatch.setattr(wireguard, "_MAX_CONFIG_BYTES", 16)
    assert wireguard._read_wg_quick_config("wg0") == "x" * 16


def test_alias_after_a_public_key_belongs_to_the_next_peer():
    """The de-facto convention puts the comment immediately BEFORE the header,
    which is textually the same as "trailing the previous block". Getting the
    tie-break wrong mislabels every peer in the file by one."""
    aliases = wireguard._parse_peer_aliases(
        "\n".join(
            [
                "[Peer]",
                f"PublicKey = {PEER_KEY}",
                "AllowedIPs = 10.0.0.2/32",
                "",
                "# Name = bob",
                "[Peer]",
                f"PublicKey = {OTHER_KEY}",
            ]
        )
    )
    assert aliases == {OTHER_KEY: "bob"}


def test_alias_parse_ignores_everything_but_name_and_public_key():
    aliases = wireguard._parse_peer_aliases(
        "\n".join(
            [
                "# a plain comment",
                "; another one",
                "# Name = orphan-before-interface",
                "[Interface]",
                f"PrivateKey = {PRIVATE_KEY}",
                f"PublicKey = {IFACE_PUBLIC}",
                "",
                "# Name = header-name",
                "[Peer]",
                "; Name = in-block-name",
                f"PublicKey = {PEER_KEY}",
                f"PresharedKey = {PSK}",
                "[Peer]",
                "AllowedIPs = 10.0.0.9/32",
                f"PublicKey = {OTHER_KEY}",
            ]
        )
    )
    # The [Interface] PublicKey is never harvested (an alias keyed by the
    # interface's own key would collide with a peer), the [Interface] header
    # drops the orphan pending name, an in-block name wins over the header one,
    # and the unnamed peer is simply absent.
    assert aliases == {PEER_KEY: "in-block-name"}


def test_alias_parse_handles_a_blank_name():
    aliases = wireguard._parse_peer_aliases(
        "\n".join(["# Name =", "[Peer]", f"PublicKey = {PEER_KEY}"])
    )
    assert aliases == {}


def test_alias_parse_keeps_the_first_of_a_duplicated_key():
    aliases = wireguard._parse_peer_aliases(
        "\n".join(
            [
                "# Name = first",
                "[Peer]",
                f"PublicKey = {PEER_KEY}",
                "# Name = second",
                "[Peer]",
                f"PublicKey = {PEER_KEY}",
            ]
        )
    )
    assert aliases == {PEER_KEY: "first"}
