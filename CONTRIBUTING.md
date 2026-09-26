# Contributing

Bug reports, feature requests and pull requests are welcome as
[issues](https://github.com/Five-Nines-io/fivenines_agent/issues) and pull
requests. For a security issue, follow [SECURITY.md](SECURITY.md) instead of
opening a public issue.

## Development

```bash
make install   # dependencies, via Poetry
make lint      # isort, black, flake8, mypy, bandit
make format    # isort + black
make test      # the test suite, with the coverage gate

poetry run pytest tests/test_collectors.py -v   # one file
```

The agent supports Python 3.10 to 3.13. Source files are ASCII-only, which CI
enforces.

The linters are not Poetry dependencies, so `make install` does not provide
them: install isort, black, flake8, mypy and bandit yourself. CI runs Bandit
at the version pinned in `.github/bandit-requirements.txt`; the suppression
check (`ci/check-nosec.sh`, run by `make lint`) needs Python 3.11 or later.

## Tests

A change comes with tests for what it changes, and new functionality comes
with tests that cover it. `make test` fails below 100% line coverage of
`fivenines_agent`. CI runs the whole suite on Windows (`windows.yml`) and runs
the built Linux binaries across a matrix of distributions (`build-release.yml`).

## Security checks

These run on every pull request and every push to `main`:

| Check | Workflow | Fails when |
|-------|----------|------------|
| Bandit (Python security lint) | [`bandit.yml`](.github/workflows/bandit.yml) | any finding the policy below does not cover |
| CodeQL (Python and the workflows, `security-extended` queries) | [`codeql.yml`](.github/workflows/codeql.yml) | any result at all (on a pull request, any result in the lines it changes) |

CodeQL also runs weekly, so new queries reach code that has not changed.
[OpenSSF Scorecard](.github/workflows/scorecard.yml) scores the repository's
practices weekly and on every push to `main`.

### Findings and suppressions

1. **Fix it.** A finding is fixed in the code whenever that is possible.
2. **Bandit, not a real issue:** suppress it on the line, naming the one test
   and giving the reason, as `# nosec B110  # best-effort close`. A bare
   `# nosec` silences every test on the line, including ones added later, so
   CI rejects it. Every Bandit run lists all suppressions and their reasons in
   its run summary.
3. **Bandit, global skips:** `[tool.bandit]` in `pyproject.toml` skips B404,
   B603 and B607, each with its reason there. `ci/check-nosec.sh` pins that
   table to exactly this and rejects any `.bandit` file, so widening the
   policy -- a skip, a `tests` allowlist, an excluded directory, a second
   config file -- fails CI until the script is changed too: a deliberate,
   reviewed edit with a reason.
4. **CodeQL:** fix it, or exclude the query in `codeql.yml`'s `config` with a
   comment giving the reason. Do not dismiss the alert in GitHub's UI: only
   repository writers can see code scanning alerts, so a dismissal there is a
   decision nobody outside the project can check. Keeping every exception in
   this repository keeps it public.
5. **Dependencies:** Dependabot opens security-update PRs for the Python
   lockfile and keeps the pinned GitHub Actions current. When a transitive
   dependency needs a patched minimum, add it to `pyproject.toml` with the
   advisory ID, like the existing security floors there.

### Workflows

Actions are pinned to a full commit SHA with the version in a comment
(`uses: actions/checkout@<sha> # v5.1.0`), and Dependabot updates both
together. Workflows start from `permissions: contents: read` and a job asks for
more only when it needs it. Never download and run a script in a workflow
(`curl ... | sh`): the release jobs hold the release signing key and the
download mirror's credentials.

Those secrets live in the `release` environment, which only `v*` tag builds can
use, never in repository-level secrets. A job that needs them declares
`environment: release`; a job that runs for branches must not need them.

What the builds download is pinned too: the libvirt, libtirpc and Python
source tarballs by SHA-256 in the Dockerfiles, and every Python build tool by
hash in `ci/requirements/` (installed with `pip install --require-hashes`). Two
inputs are still pinned by tag or version only: the Dockerfile base images, and
the WiX toolchain the Windows MSI is built with. To change a
build tool, edit the `.in` file and run `sh ci/requirements/compile.sh`
(needs [uv](https://docs.astral.sh/uv/)); Dependabot does not update these
files. A weekly cold build of `main` checks that every download still resolves.

Dependabot's pull requests for action updates run only CodeQL and Bandit: the
build and release workflows run on pushes to `feature/**`, `fix/**` and
`release/**` branches, not on pull requests. Before tagging a release that
includes an action update, push it on a `feature/**` branch so the build, the
pre-release and its attestation run once with the new version.
