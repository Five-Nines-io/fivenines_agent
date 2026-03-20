# TODOS

## P3: Docker image caching for CI resilience

Mirror the 14 distro base images used in `test-distro-matrix` to ghcr.io or use
a Docker pull-through cache. Currently, all distro tests pull from Docker Hub
directly. A Docker Hub outage or rate-limit event would block the entire CI
pipeline.

- **Effort:** M (human) / S (CC)
- **Depends on:** #30 (distro regression testing) shipping first
- **Files:** `.github/workflows/build-release.yml`

## P3: Nightly distro matrix runs

Add a `schedule` trigger to the distro regression testing workflow to run the
matrix nightly or weekly. This catches upstream distro changes (new Alpine
minor release changing BusyBox behavior, new Ubuntu release changing adduser
flags) before users do.

- **Effort:** S (human) / S (CC)
- **Depends on:** #30 (distro regression testing) shipping first
- **Files:** `.github/workflows/build-release.yml` (add `schedule:` trigger)

## P2: Promote Rocky 10 to blocking

The `rockylinux:10` test matrix entry runs with `allow_failure: "1"` because the
Docker image does not exist yet. When Rocky Linux 10 GA ships and the Docker image
is available on Docker Hub, remove `allow_failure` from the matrix entry so that
RHEL 10 generation regressions block releases.

- **Effort:** S (human) / S (CC)
- **Depends on:** Rocky Linux 10 GA release
- **Files:** `.github/workflows/build-release.yml` (remove `allow_failure: "1"` from rockylinux:10 entry)
