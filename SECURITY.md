# Security policy

## Reporting a vulnerability

Please report a suspected vulnerability privately rather than in a public
issue or pull request:

- email [sebastien@fivenines.io](mailto:sebastien@fivenines.io) with
  `SECURITY` in the subject, or
- use **Report a vulnerability** on this repository's
  [Security tab](https://github.com/Five-Nines-io/fivenines_agent/security),
  which opens a private advisory only the maintainers can see.

Include the agent version (`/opt/fivenines/fivenines_agent --version` on a
standard Linux install, `~/.local/fivenines/fivenines-agent-*/fivenines-agent-* --version`
on a user-level one), the platform and how you installed it, and the steps to
reproduce. You will get an acknowledgement and updates as the fix progresses.
Fixes ship as a new release, and the release notes name the vulnerability they
fix. Tell us if you would like to be credited.

## Supported versions

Security fixes go into the latest release. The install and update scripts
always install the latest release, so updating is how a fix reaches a host (see
[Update](README.md#update)).

## Scope

This repository covers the agent, its install, update and uninstall scripts,
the service definitions it installs, and the pipeline that builds and publishes
its releases. Reports about the fivenines service itself are welcome at the
same address.

## Related documentation

- [Permissions](README.md#permissions): what the agent can read on a host, and
  what each optional capability requires.
- [Verifying a release artifact](README.md#verifying-a-release-artifact):
  signed checksums and build provenance for every release asset.
- [Security evidence](README.md#security-evidence): the automated checks this
  project runs, what each covers, and where to see the latest results.
