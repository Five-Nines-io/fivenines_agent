from fivenines_agent.cli import VERSION, parse_args


def start():
    # Parse args first: --version prints and exits here, BEFORE the agent is
    # imported. fivenines_agent.agent pulls in the whole collector graph
    # (requests, docker, pg8000, psutil, libvirt, ...): about 70% of the frozen
    # binary's --version time (~210ms -> ~60ms measured). The import stays in
    # this function so nothing can drag the graph back in at module import.
    args = parse_args()

    from fivenines_agent.agent import Agent

    if args.check_imports:
        # Build/install smoke check: the import above loaded the agent and
        # every module it imports at load time, so in a frozen binary a
        # missing hidden import, an unloadable extension module or package
        # metadata a dependency reads at import (pg8000) has already raised.
        # NOT proven: what the agent imports lazily (snmp) or under
        # try/except ImportError (libvirt, pynvml, proxmoxer,
        # systemd_watchdog; wmi and win32pdh on Windows), which fail soft at
        # runtime, nor the agent's own metadata (cli.py falls back to
        # 0.0.0+unknown; py2exe.sh checks the --version string for it). The
        # import also ran agent.py's module-level load of <config_dir>/.env,
        # so an unreadable .env fails this check too. Stop before Agent(),
        # which probes permissions, reads TOKEN and starts the agent.
        print(f"fivenines-agent {VERSION}: agent imported")
        return

    agent = Agent()
    agent.run()


if __name__ == "__main__":
    start()
