"""Tests for the clean child environment (#172) and the privileged subprocess
runner (#144).

`run_privileged` exists because `subprocess.run(timeout=...)` does NOT bound a
sudo child: sudo switches to full root before its sudoers lookup, so the kill
CPython issues after the timeout comes back EPERM, the PermissionError escapes
the TimeoutExpired handler, and `Popen.__exit__` waits with no timeout at all.
On the single-threaded collection loop that is a watchdog SIGABRT and, with
Restart=always, a restart loop.
"""

import ast
import inspect
import os
import pathlib
import subprocess
import sys
import threading
import time

import pytest

from fivenines_agent.subprocess_utils import get_clean_env, run_privileged

# getoutput/getstatusoutput run a shell command and take no env= at all, so the
# "no env=" rule below refuses them like any other spawn without one.
_SPAWNS = {
    "run",
    "Popen",
    "check_output",
    "check_call",
    "call",
    "getoutput",
    "getstatusoutput",
}
# What a module may import from subprocess by name: anything that is not a way
# to start a process.
_SUBPROCESS_NON_SPAWNS = {
    "CalledProcessError",
    "CompletedProcess",
    "DEVNULL",
    "PIPE",
    "STDOUT",
    "SubprocessError",
    "TimeoutExpired",
}
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


def _is_locale_key(node):
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and (node.value.startswith("LC_") or node.value in ("LANG", "LANGUAGE"))
    )


def _locale_override(node):
    """A write that undoes the pin on a clean env: env["LC_ALL"] = "C.UTF-8",
    env["LANGUAGE"] = ..., del env["LC_ALL"], env.pop("LC_ALL"). Only the
    literal "C" may be written (packages.py re-pins dpkg and rpm that way)."""
    if isinstance(node, ast.Assign):
        return any(
            isinstance(t, ast.Subscript)
            and _is_locale_key(t.slice)
            and not (isinstance(node.value, ast.Constant) and node.value.value == "C")
            for t in node.targets
        )
    if isinstance(node, ast.Delete):
        return any(
            isinstance(t, ast.Subscript) and _is_locale_key(t.slice)
            for t in node.targets
        )
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "pop"
        and bool(node.args)
        and _is_locale_key(node.args[0])
    )


def _is_subprocess_spawn(node):
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "subprocess"
        and node.attr in _SPAWNS
    )


def _spawn_name(call):
    if isinstance(call.func, ast.Name) and call.func.id == "run_privileged":
        return "run_privileged"
    if _is_subprocess_spawn(call.func):
        return "subprocess." + call.func.attr
    return None


def _is_clean_env_call(node):
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "get_clean_env"
    )


def _own_nodes(fn):
    """Nodes of fn's own scope: nested functions, lambdas and classes excluded."""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (*_FUNCTIONS, ast.Lambda, ast.ClassDef)):
            stack.extend(ast.iter_child_nodes(node))


def _names_in(target):
    return [n.id for n in ast.walk(target) if isinstance(n, ast.Name)]


def _bindings(fn):
    """{name: True if EVERY binding of it in fn's own scope is get_clean_env()}.

    Parameters, for/with/comprehension targets and tuple unpacking are not
    provably clean. Item assignment (env["MYSQL_PWD"] = ...) does not rebind
    the name and is allowed: that is how mysql adds its password."""
    bound = {}

    def bind(name, clean):
        bound[name] = bound.get(name, True) and clean

    args = fn.args
    for arg in [
        *args.posonlyargs,
        *args.args,
        *args.kwonlyargs,
        args.vararg,
        args.kwarg,
    ]:
        if arg is not None:
            bind(arg.arg, False)
    for node in _own_nodes(fn):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bind(target.id, _is_clean_env_call(node.value))
                elif not isinstance(target, (ast.Subscript, ast.Attribute)):
                    for name in _names_in(target):
                        bind(name, False)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            if isinstance(node.target, ast.Name):
                bind(node.target.id, False)
        elif isinstance(node, ast.NamedExpr):
            bind(node.target.id, _is_clean_env_call(node.value))
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            for name in _names_in(node.target):
                bind(name, False)
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            for name in _names_in(node.optional_vars):
                bind(name, False)
    return bound


def _spawn_offenders(path):
    """(["file:line (reason)", ...], spawn sites checked) for one module."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parents = {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }

    def enclosing_functions(node):
        node = parents.get(node)
        while node is not None:
            if isinstance(node, _FUNCTIONS):
                yield node
            node = parents.get(node)

    offenders, checked = [], 0

    def refuse(node, reason):
        offenders.append(f"{path.name}:{node.lineno} ({reason})")

    for node in ast.walk(tree):
        # An aliased module or a by-name import would hide a spawn from the
        # `subprocess.<name>(...)` match below.
        if isinstance(node, ast.Import) and any(
            a.name == "subprocess" and a.asname for a in node.names
        ):
            refuse(node, "aliased subprocess import")
        if isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            if any(a.name not in _SUBPROCESS_NON_SPAWNS for a in node.names):
                refuse(node, "spawn imported by name")
        if _locale_override(node):
            refuse(node, "locale key overridden")
        # subprocess.run handed around (functools.partial, call_bounded) is a
        # spawn whose env= this walk cannot see.
        if _is_subprocess_spawn(node) and not (
            isinstance(parents.get(node), ast.Call) and parents[node].func is node
        ):
            refuse(node, "spawn referenced, not called")
        if not isinstance(node, ast.Call) or not _spawn_name(node):
            continue
        checked += 1
        scopes = list(enclosing_functions(node))
        env = next((k.value for k in node.keywords if k.arg == "env"), None)
        if not scopes:
            refuse(node, "spawn outside any function")
        elif any(k.arg is None for k in node.keywords):
            refuse(node, "env may hide in **kwargs")
        elif env is None:
            if _spawn_name(node) != "run_privileged":  # it defaults to the clean env
                refuse(node, "no env=")
        elif not _is_clean_env_call(env):
            # Python's closure lookup: the nearest enclosing function that
            # binds the name decides.
            owner = None
            if isinstance(env, ast.Name):
                owner = next((b for b in map(_bindings, scopes) if env.id in b), None)
            if owner is None or not owner[env.id]:
                refuse(node, "env not provably get_clean_env()")
    return offenders, checked


@pytest.mark.parametrize(
    "source, refused",
    [
        ("import subprocess as sp\ndef f():\n    sp.run(['x'])\n", True),
        ("from subprocess import run\ndef f():\n    run(['x'])\n", True),
        ("import subprocess\ndef f():\n    subprocess.getoutput('x')\n", True),
        ("import subprocess\ndef f(**kw):\n    subprocess.run(['x'], **kw)\n", True),
        ("import subprocess\nsubprocess.run(['x'], env=get_clean_env())\n", True),
        ("import subprocess\ndef f():\n    subprocess.run(['x'])\n", True),
        (
            "import subprocess\ndef f():\n    env = get_clean_env()\n"
            "    env = dict()\n    subprocess.run(['x'], env=env)\n",
            True,
        ),
        (
            "import subprocess\ndef f(cmd, env=None):\n    if env is None:\n"
            "        env = get_clean_env()\n    subprocess.run(cmd, env=env)\n",
            True,
        ),
        (
            "import functools, subprocess\ndef f():\n"
            "    return functools.partial(subprocess.run, ['x'])\n",
            True,
        ),
        (
            "import subprocess\ndef f():\n    env = get_clean_env()\n"
            "    env['MYSQL_PWD'] = 'p'\n    subprocess.run(['x'], env=env)\n",
            False,
        ),
        (
            "import subprocess\ndef f(cmd):\n    env = get_clean_env()\n"
            "    def read():\n        return subprocess.run(cmd, env=env)\n"
            "    return read()\n",
            False,
        ),
        (
            "import subprocess\ndef f():\n    env = get_clean_env()\n"
            "    env['LC_ALL'] = 'C.UTF-8'\n    subprocess.run(['x'], env=env)\n",
            True,
        ),
        ("def f():\n    env = get_clean_env()\n    env['LANGUAGE'] = 'fr'\n", True),
        ("def f():\n    env = get_clean_env()\n    env.pop('LC_ALL')\n", True),
        ("def f():\n    env = get_clean_env()\n    del env['LANG']\n", True),
        (
            "import subprocess\ndef f():\n    env = get_clean_env()\n"
            "    env['LC_ALL'] = 'C'\n    subprocess.run(['x'], env=env)\n",
            False,
        ),
        ("def f():\n    run_privileged(['sudo'], timeout=1)\n", False),
        ("from subprocess import TimeoutExpired\n", False),
    ],
)
def test_the_spawn_guard_refuses_what_it_claims_to(tmp_path, source, refused):
    """The guard below only ever sees a clean package, so without this its
    refusals could all break and it would still pass. Each shape here is one
    it promises to refuse -- or a legitimate one it must accept."""
    path = tmp_path / "module.py"
    path.write_text(source, encoding="utf-8")
    offenders, _ = _spawn_offenders(path)
    assert bool(offenders) is refused, offenders


def test_every_spawn_site_passes_the_clean_env():
    """#172: the C locale lives in get_clean_env(), so "every child runs in C"
    holds only while every spawn site passes that env -- or a name every
    binding in its scope sets to it, like mysql's copy that adds MYSQL_PWD. A
    hand-built env, or a dropped env=, silently puts that command back in the
    host's language (and drops the PyInstaller library-path strip with it).
    Before this test, mutating raid_storage, fail2ban, systemd, snmp,
    permissions, logs or ceph that way left the whole suite green.
    run_privileged with no env= is fine: it defaults to get_clean_env(). The
    shapes it refuses are pinned by the test above. Out of scope: the two
    os.popen calls in cpu.py/network.py, constant macOS-only dev paths that
    cannot take an env."""
    package = pathlib.Path(inspect.getfile(get_clean_env)).parent
    offenders, checked = [], 0
    for path in sorted(package.glob("*.py")):
        if path.name == "subprocess_utils.py":
            continue
        found, count = _spawn_offenders(path)
        offenders += found
        checked += count
    assert offenders == [], offenders
    # Not vacuous: 30 spawn sites when this test was written. A lower count
    # means sites went missing from the walk, not that the agent spawns less.
    assert checked >= 30, checked


def test_clean_env_pins_every_child_to_the_c_locale(monkeypatch):
    """#172: children used to inherit the host's language, so the same disk's
    smartctl `User Capacity` read "500,107,862,016 bytes" or
    "500.107.862.016 bytes" depending on LANG, and a pre-2.0 zpool wrote
    "45,67% done", which the zfs parser reads as 67.

    The literal "C", not the constant: "C.UTF-8" looks equivalent and is not.
    gettext still honours LANGUAGE under C.UTF-8, so a LANGUAGE=fr host would
    keep translated sudo messages, and C.UTF-8 does not exist on CentOS 7.
    LANGUAGE itself goes too: Python's gettext module reads it BEFORE LC_ALL,
    even under C, and `pro` is a Python child that translates."""
    monkeypatch.setenv("LANG", "de_DE.UTF-8")
    monkeypatch.setenv("LC_ALL", "fr_FR.UTF-8")
    monkeypatch.setenv("LANGUAGE", "fr")
    env = get_clean_env()
    assert env["LC_ALL"] == "C"
    assert "LANGUAGE" not in env
    # A copy: the agent's own locale, and its own environment, are untouched.
    assert os.environ["LC_ALL"] == "fr_FR.UTF-8"


def test_clean_env_adds_the_pin_when_the_host_sets_only_lang(monkeypatch):
    """The shape systemd actually hands the agent (#172): LANG, and possibly a
    single LC_* category, from /etc/locale.conf -- and no LC_ALL. The pin has
    to be ADDED there, not only substituted for an LC_ALL the host already
    set: LC_ALL is what outranks LANG and LC_NUMERIC in the child, so a helper
    that only rewrote an existing LC_ALL would leave smartctl and zpool in the
    host's language on exactly the hosts the issue is about."""
    monkeypatch.delenv("LC_ALL", raising=False)
    monkeypatch.setenv("LANG", "de_DE.UTF-8")
    monkeypatch.setenv("LC_NUMERIC", "de_DE.UTF-8")
    env = get_clean_env()
    assert env["LC_ALL"] == "C"
    assert "LC_ALL" not in os.environ


def test_clean_env_strips_every_bundled_library_path(monkeypatch):
    """The PyInstaller sanitization still runs next to the pin. Each of these
    points a child (sudo, smartctl, mdadm) at the bundle's own libraries;
    only LD_LIBRARY_PATH was asserted before, and only through run_privileged.
    Everything else passes through untouched -- a child still needs the
    agent's PATH to find its tools."""
    bundled = (
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "LIBPATH",
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
    )
    for var in bundled:
        monkeypatch.setenv(var, "/opt/fivenines/_internal")
    monkeypatch.setenv("FIVENINES_TEST_PASSTHROUGH", "kept")
    env = get_clean_env()
    for var in bundled:
        assert var not in env, var
    assert env["FIVENINES_TEST_PASSTHROUGH"] == "kept"
    assert env["LC_ALL"] == "C"


def test_returns_the_completed_process_on_the_normal_path():
    # sys.executable, not /bin/echo: the Windows job runs this whole suite.
    result = run_privileged(
        [sys.executable, "-c", "print('hello')"],
        timeout=30,
        stdout=subprocess.PIPE,
        text=True,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "hello"


def test_supplies_a_clean_env_by_default(monkeypatch):
    """Callers must not have to remember: a PyInstaller LD_LIBRARY_PATH leaking
    into a sudo child is the documented breaker for every sudo collector."""
    seen = {}

    def fake_run(cmd, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setenv("LD_LIBRARY_PATH", "/opt/fivenines/_internal")
    run_privileged(["sudo", "-n", "wg", "show", "all", "dump"], timeout=3)
    assert "LD_LIBRARY_PATH" not in seen["env"]
    # smartctl runs behind sudo: the pinned locale has to be in the env sudo
    # gets (its default env_check list carries LC_* across env_reset).
    assert seen["env"]["LC_ALL"] == "C"
    assert seen["timeout"] == 3


def test_an_explicit_env_is_not_overwritten(monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    run_privileged(["sudo", "-n", "true"], timeout=1, env={"PATH": "/usr/bin"})
    assert seen["env"] == {"PATH": "/usr/bin"}


def test_a_normal_timeout_still_reaches_the_caller(monkeypatch):
    """A killable child times out the ordinary way; the caller's existing
    TimeoutExpired handling must keep working unchanged."""

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(subprocess.TimeoutExpired):
        run_privileged(["sudo", "-n", "true"], timeout=1)


def test_other_exceptions_are_re_raised_on_the_callers_thread(monkeypatch):
    """A worker thread that swallowed OSError would turn "sudo is not
    installed" into a silent success."""

    def fake_run(cmd, **kwargs):
        raise FileNotFoundError(2, "No such file or directory: 'sudo'")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(FileNotFoundError):
        run_privileged(["sudo", "-n", "true"], timeout=1)


def test_an_unkillable_child_is_abandoned_instead_of_blocking(monkeypatch):
    """THE reason this helper exists.

    The stand-in models a wedged sudo: `subprocess.run` does not return when
    its own timeout expires, because the root-owned child cannot be killed.
    The caller must still be freed, and must see the timeout it was promised.
    """
    released = threading.Event()

    def wedged_run(cmd, **kwargs):
        released.wait(30)  # far past the caller's deadline
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", wedged_run)
    started = time.monotonic()
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            run_privileged(["sudo", "-n", "wg", "show", "all", "dump"], timeout=1)
        waited = time.monotonic() - started
        # timeout + the 2s abandon grace, not the 30s the child would take.
        assert waited < 10
    finally:
        released.set()


def test_a_command_finishing_just_past_its_own_timeout_is_not_abandoned(monkeypatch):
    """The caller waits the command's timeout PLUS the abandon grace: a
    killable child whose teardown runs a moment past its own timeout returns
    normally instead of being reported as a wedged, abandoned sudo."""

    def slow_teardown_run(cmd, **kwargs):
        time.sleep(kwargs["timeout"] + 0.3)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", slow_teardown_run)
    result = run_privileged(["sudo", "-n", "true"], timeout=1)
    assert result.returncode == 0


def test_the_abandoned_worker_is_a_daemon(monkeypatch):
    """An abandoned worker must never keep the process alive at shutdown: the
    agent has to be able to exit while a wedged sudo is still out there."""
    released = threading.Event()
    captured = {}
    real_thread = threading.Thread

    def recording_thread(*args, **kwargs):
        thread = real_thread(*args, **kwargs)
        captured["thread"] = thread
        return thread

    def wedged_run(cmd, **kwargs):
        released.wait(30)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", wedged_run)
    monkeypatch.setattr(threading, "Thread", recording_thread)
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            run_privileged(["sudo", "-n", "true"], timeout=1)
        assert captured["thread"].daemon is True
        assert captured["thread"].is_alive()
    finally:
        released.set()
