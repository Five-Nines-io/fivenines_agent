import importlib

from fivenines_agent.cli import VERSION, parse_args


def check_imports(optional):
    """Import what importing the agent does not: the modules the agent imports
    only inside a function (snmp; tests/test_main_entry.py checks that no
    module of the package is left out), then each optional module the build
    says it bundles. An ImportError propagates, so the frozen binary exits
    non-zero."""
    lazy = ("fivenines_agent.snmp",)
    for name in lazy + tuple(optional):
        importlib.import_module(name)


def start():
    # Parse args first: --version prints and exits here, BEFORE the agent is
    # imported. fivenines_agent.agent pulls in the whole collector graph
    # (requests, docker, pg8000, psutil, libvirt, ...): about 70% of the frozen
    # binary's --version time (~210ms -> ~60ms measured). The import stays in
    # this function so nothing can drag the graph back in at module import.
    args = parse_args()

    from fivenines_agent.agent import Agent

    if args.check_imports is not None:
        # Build/install smoke check. The import above loaded the agent and
        # every module it imports at load time, so in a frozen binary a
        # missing hidden import, an unloadable extension module or package
        # metadata a dependency reads at import (pg8000) has already raised.
        # check_imports() adds what that import does not prove: the modules
        # the agent imports lazily (snmp), and each optional module the build
        # names on the command line -- the ones the agent imports under
        # try/except ImportError and would otherwise silently go without
        # (libvirt, pynvml, proxmoxer, systemd_watchdog; wmi and win32pdh on
        # Windows). Still not proven: the agent's own metadata (cli.py falls
        # back to 0.0.0+unknown; py2exe.sh checks the --version string for
        # it). The import also ran agent.py's module-level load of
        # <config_dir>/.env, so an unreadable .env fails this check too. Stop
        # before Agent(), which probes permissions, reads TOKEN and starts
        # the agent.
        check_imports(args.check_imports)
        print(
            f"fivenines-agent {VERSION}: imported "
            + ", ".join(["agent", *args.check_imports])
        )
        return

    agent = Agent()
    agent.run()


if __name__ == "__main__":
    start()
