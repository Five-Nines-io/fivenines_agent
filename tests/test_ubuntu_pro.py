"""Tests for the Ubuntu Pro attachment collector (agent #125 / server #746).

Only the two boundaries are mocked: the `pro` subprocess and the on-disk status
cache. Everything between them is the real parse -> payload pipeline. The
cross-repo round-trip lives in test_ubuntu_pro_contract.py.

The single rule most of these cases are really testing: an ambiguous outcome is
``None``, never ``{"attached": False}`` and never a short service list.
"""

import json
import subprocess

import pytest

from fivenines_agent import ubuntu_pro
from fivenines_agent.ubuntu_pro import ubuntu_pro_status

IS_ATTACHED = ubuntu_pro._IS_ATTACHED_ENDPOINT
ENABLED_SERVICES = ubuntu_pro._ENABLED_SERVICES_ENDPOINT


def _envelope(attributes, result="success", type_="IsAttached"):
    return {
        "_schema_version": "v1",
        "data": {
            "attributes": attributes,
            "meta": {"environment_vars": []},
            "type": type_,
        },
        "errors": [],
        "result": result,
        "version": "35.1",
        "warnings": [],
    }


def _attached(value=True):
    return _envelope(
        {
            "contract_remaining_days": 360,
            "contract_status": "active",
            "is_attached": value,
            "is_attached_and_contract_valid": value,
        }
    )


def _services(names):
    entries = [
        {"name": name, "variant_enabled": False, "variant_name": None} for name in names
    ]
    return _envelope({"enabled_services": entries}, type_="EnabledServices")


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    """Empty the module cache and point the status file somewhere absent.

    Both matter: the cache is module-level state that would otherwise leak a
    reading into the next test, and an unpatched path would make results depend
    on whether the machine running the suite is itself an attached Ubuntu box.
    """
    monkeypatch.setattr(ubuntu_pro, "_cache", ubuntu_pro.TTLCache())
    monkeypatch.setattr(
        ubuntu_pro, "_STATUS_CACHE_FILE", str(tmp_path / "no-such-status.json")
    )


@pytest.fixture
def pro(monkeypatch):
    """Install a fake `pro` CLI. Returns a callable arming the next run.

    *responses* maps an endpoint to what `pro api <endpoint>` prints: a dict is
    JSON-encoded, a string is served verbatim, a tuple is (returncode, stdout).
    An endpoint absent from the map fails the test rather than answering, since
    several cases turn on the collector NOT making a call. The arming call
    returns the list every invocation is recorded in.
    """
    monkeypatch.setattr(ubuntu_pro.shutil, "which", lambda _: "/usr/bin/pro")

    def install(responses=None, raises=None):
        responses = responses or {}
        calls = []

        def fake_run(cmd, *_args, **_kwargs):
            calls.append(cmd)
            if raises is not None:
                raise raises
            assert cmd[:2] == ["/usr/bin/pro", "api"]
            endpoint = cmd[2]
            assert endpoint in responses, f"unexpected `pro api {endpoint}` call"
            response = responses[endpoint]
            if isinstance(response, tuple):
                returncode, stdout = response
            else:
                returncode, stdout = 0, response
            if isinstance(stdout, (dict, list)):
                stdout = json.dumps(stdout)
            return subprocess.CompletedProcess(cmd, returncode, stdout, "")

        monkeypatch.setattr(ubuntu_pro.subprocess, "run", fake_run)
        return calls

    return install


@pytest.fixture
def status_cache(monkeypatch, tmp_path):
    """Write a status cache file and make it the only available source."""
    monkeypatch.setattr(ubuntu_pro.shutil, "which", lambda _: None)

    def install(content):
        path = tmp_path / "status.json"
        path.write_text(content if isinstance(content, str) else json.dumps(content))
        monkeypatch.setattr(ubuntu_pro, "_STATUS_CACHE_FILE", str(path))

    return install


# --- the `pro api` path ----------------------------------------------------


def test_attached_reports_its_enabled_services(pro):
    pro(
        {
            IS_ATTACHED: _attached(),
            ENABLED_SERVICES: _services(["esm-apps", "esm-infra"]),
        }
    )
    assert ubuntu_pro_status() == {
        "attached": True,
        "services": ["esm-apps", "esm-infra"],
    }


def test_detached_answers_without_a_second_spawn(pro):
    """The enabled_services endpoint short-circuits on the same check, so
    skipping the spawn is equivalent -- and it keeps every non-Pro Ubuntu host
    in the fleet at one subprocess per cache window."""
    calls = pro({IS_ATTACHED: _attached(False)})
    assert ubuntu_pro_status() == {"attached": False, "services": []}
    assert len(calls) == 1


def test_attached_with_everything_disabled_is_an_empty_list(pro):
    pro({IS_ATTACHED: _attached(), ENABLED_SERVICES: _services([])})
    assert ubuntu_pro_status() == {"attached": True, "services": []}


def test_unreadable_service_list_is_null_not_an_empty_one(pro):
    """THE load-bearing case. `{"attached": true, "services": []}` is a real
    state, so sending it for a list we could not read would tell the server we
    checked and found no open pocket -- silently keeping a Pro customer's
    installable fixes filed as unfixable, with nothing saying why."""
    pro({IS_ATTACHED: _attached(), ENABLED_SERVICES: (1, "")})
    assert ubuntu_pro_status() is None


def test_legacy_plain_string_service_entries_are_accepted(pro):
    """Older clients emitted the names directly rather than objects."""
    pro(
        {
            IS_ATTACHED: _attached(),
            ENABLED_SERVICES: _envelope({"enabled_services": ["esm-infra", "usg"]}),
        }
    )
    assert ubuntu_pro_status() == {"attached": True, "services": ["esm-infra", "usg"]}


def test_service_names_are_lowercased_deduped_and_sorted(pro):
    pro(
        {
            IS_ATTACHED: _attached(),
            ENABLED_SERVICES: _envelope(
                {"enabled_services": [" ESM-Infra ", "esm-infra", "esm-apps", "  "]}
            ),
        }
    )
    assert ubuntu_pro_status() == {
        "attached": True,
        "services": ["esm-apps", "esm-infra"],
    }


def test_overlong_service_name_is_truncated_not_dropped(pro):
    pro(
        {
            IS_ATTACHED: _attached(),
            ENABLED_SERVICES: _envelope({"enabled_services": ["x" * 200]}),
        }
    )
    assert ubuntu_pro_status() == {
        "attached": True,
        "services": ["x" * ubuntu_pro._MAX_SERVICE_CHARS],
    }


def test_absurd_service_count_is_capped(pro):
    names = [f"svc-{i:03d}" for i in range(50)]
    pro(
        {
            IS_ATTACHED: _attached(),
            ENABLED_SERVICES: _envelope({"enabled_services": names}),
        }
    )
    result = ubuntu_pro_status()
    assert result is not None
    assert result["services"] == sorted(names)[: ubuntu_pro._MAX_SERVICES]


@pytest.mark.parametrize(
    "entries",
    ["esm-infra", [42], [None], [{"variant_enabled": False}]],
    ids=["not-a-list", "int-entry", "null-entry", "object-without-name"],
)
def test_unparseable_service_entry_fails_the_whole_list(pro, entries):
    """A silently short list is a wrong answer the server cannot detect: it
    reads as "that pocket is closed"."""
    pro(
        {
            IS_ATTACHED: _attached(),
            ENABLED_SERVICES: _envelope({"enabled_services": entries}),
        }
    )
    assert ubuntu_pro_status() is None


@pytest.mark.parametrize(
    "attributes",
    [{}, {"is_attached": "true"}, {"is_attached": 1}, {"is_attached": None}],
    ids=["absent", "truthy-string", "int", "null"],
)
def test_non_boolean_attachment_is_null(pro, attributes):
    """A truthy string must never read as attached, and "could not tell" must
    never read as detached."""
    pro({IS_ATTACHED: _envelope(attributes)})
    assert ubuntu_pro_status() is None


@pytest.mark.parametrize(
    "response",
    [
        (1, ""),
        "not json",
        "[]",
        {"result": "failure", "data": {}, "errors": [{"code": "boom"}]},
        {"result": "success", "data": []},
        {"result": "success", "data": {"attributes": "nope"}},
    ],
    ids=[
        "non-zero-exit",
        "unparseable",
        "not-an-object",
        "result-failure",
        "data-not-an-object",
        "attributes-not-an-object",
    ],
)
def test_broken_envelope_is_null(pro, response):
    pro({IS_ATTACHED: response})
    assert ubuntu_pro_status() is None


def test_envelope_without_a_result_field_is_still_read(pro):
    """`result` defaults to "success" client-side and no released envelope
    omits it, but a future shape that dropped a redundant field must not blank
    the reading."""
    envelope = _attached()
    del envelope["result"]
    pro({IS_ATTACHED: envelope, ENABLED_SERVICES: _services(["esm-infra"])})
    assert ubuntu_pro_status() == {"attached": True, "services": ["esm-infra"]}


@pytest.mark.parametrize(
    "error",
    [OSError("no such file"), subprocess.TimeoutExpired("pro", 10)],
    ids=["spawn-error", "timeout"],
)
def test_subprocess_failure_is_null(pro, error):
    pro(raises=error)
    assert ubuntu_pro_status() is None


def test_missing_pro_binary_is_null(monkeypatch):
    monkeypatch.setattr(ubuntu_pro.shutil, "which", lambda _: None)
    assert ubuntu_pro_status() is None


# --- the status-cache fallback ---------------------------------------------


def test_status_cache_answers_when_pro_api_is_unavailable(status_cache):
    status_cache(
        {
            "attached": True,
            "services": [
                {"name": "esm-infra", "status": "enabled"},
                {"name": "esm-apps", "status": "enabled"},
                {"name": "usg", "status": "disabled"},
                {"name": "fips", "status": "n/a"},
                {"name": "livepatch", "status": "warning"},
            ],
        }
    )
    assert ubuntu_pro_status() == {
        "attached": True,
        "services": ["esm-apps", "esm-infra"],
    }


def test_status_cache_detached(status_cache):
    status_cache(
        {"attached": False, "services": [{"name": "esm-infra", "status": "n/a"}]}
    )
    assert ubuntu_pro_status() == {"attached": False, "services": []}


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        {"services": []},
        {"attached": "yes", "services": []},
        {"attached": True, "services": "esm-infra"},
        {"attached": True, "services": ["esm-infra"]},
        {"attached": True, "services": [{"status": "enabled"}]},
    ],
    ids=[
        "unparseable",
        "not-an-object",
        "attached-absent",
        "attached-not-a-boolean",
        "services-not-a-list",
        "service-entry-not-an-object",
        "enabled-entry-without-a-name",
    ],
)
def test_broken_status_cache_is_null(status_cache, content):
    status_cache(content)
    assert ubuntu_pro_status() is None


def test_pro_api_wins_over_a_contradicting_status_cache(pro, monkeypatch, tmp_path):
    """The cache is a fallback, not a cross-check: a live `pro api` answer is
    always the fresher one."""
    path = tmp_path / "status.json"
    path.write_text(json.dumps({"attached": False, "services": []}))
    monkeypatch.setattr(ubuntu_pro, "_STATUS_CACHE_FILE", str(path))
    pro({IS_ATTACHED: _attached(), ENABLED_SERVICES: _services(["esm-infra"])})
    assert ubuntu_pro_status() == {"attached": True, "services": ["esm-infra"]}


def test_a_timed_out_pro_falls_back_to_the_status_cache(pro, monkeypatch, tmp_path):
    """A stale reading of a value that changes once in a machine's lifetime
    beats a null that teaches the server nothing."""
    path = tmp_path / "status.json"
    path.write_text(
        json.dumps(
            {"attached": True, "services": [{"name": "esm-infra", "status": "enabled"}]}
        )
    )
    monkeypatch.setattr(ubuntu_pro, "_STATUS_CACHE_FILE", str(path))
    pro(raises=subprocess.TimeoutExpired("pro", 10))
    assert ubuntu_pro_status() == {"attached": True, "services": ["esm-infra"]}


def _record_levels(monkeypatch):
    levels = []
    monkeypatch.setattr(
        ubuntu_pro, "log", lambda message, level="info": levels.append(level)
    )
    return levels


def test_installed_pro_that_cannot_answer_logs_an_error(pro, monkeypatch):
    """A non-Ubuntu host reporting null is routine and stays at debug level; a
    host that HAS `pro` and still cannot be read is an anomaly worth surfacing
    in the collector telemetry."""
    levels = _record_levels(monkeypatch)
    pro({IS_ATTACHED: (1, "")})
    assert ubuntu_pro_status() is None
    assert "error" in levels


def test_absent_pro_does_not_log_an_error(monkeypatch):
    levels = _record_levels(monkeypatch)
    monkeypatch.setattr(ubuntu_pro.shutil, "which", lambda _: None)
    assert ubuntu_pro_status() is None
    assert "error" not in levels


# --- caching ---------------------------------------------------------------


def test_reading_is_cached_across_ticks(pro):
    calls = pro({IS_ATTACHED: _attached(False)})
    for _ in range(10):
        assert ubuntu_pro_status() == {"attached": False, "services": []}
    assert len(calls) == 1


def test_failures_are_cached_too(pro):
    """A `pro` that hangs for the whole timeout must not be re-spawned on the
    next tick 15 seconds later."""
    calls = pro(raises=subprocess.TimeoutExpired("pro", 10))
    assert ubuntu_pro_status() is None
    assert ubuntu_pro_status() is None
    assert len(calls) == 1


def test_a_re_attached_host_is_picked_up_once_the_window_closes(pro):
    pro({IS_ATTACHED: _attached(False)})
    assert ubuntu_pro_status() == {"attached": False, "services": []}

    # Age the stored entry past the TTL rather than moving the clock: the cache
    # reads time.monotonic() from its own module, and patching that globally
    # would reach well beyond this collector.
    entries = ubuntu_pro._cache._entries
    stored_at, value, ttl = entries[ubuntu_pro._CACHE_KEY]
    entries[ubuntu_pro._CACHE_KEY] = (stored_at - ubuntu_pro._CACHE_TTL - 1, value, ttl)

    calls = pro({IS_ATTACHED: _attached(), ENABLED_SERVICES: _services(["esm-infra"])})
    assert ubuntu_pro_status() == {"attached": True, "services": ["esm-infra"]}
    assert len(calls) == 2
