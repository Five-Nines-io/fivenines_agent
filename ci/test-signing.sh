#!/bin/sh
# Release-signature verification tests.
#
# Checks the ARMED shipped state (a real key is embedded, on the right curve,
# and stripping a signature is fatal), then generates a throwaway ECDSA P-256
# keypair and drives the real verify_sums_signature from fivenines_common.sh
# through the genuine, tampered, wrong-key and missing-signature cases.
# The embedded release key is a hard constant in the install scripts with no
# override hook - deliberately - so the test substitutes the trust anchor by
# redefining release_signing_pubkey after sourcing, rather than by adding an
# env var that would weaken the shipped scripts.
#
# It also lints the download commands an operator is told to paste -- every
# wget in README.md and in the UNRAID hint fivenines_update.sh prints -- so
# the command always runs the file wget just wrote, never a copy left by an
# earlier attempt (issue #160).
#
# And it runs the uname -m -> artifact mapping of the installers and of the
# UNRAID boot script with a faked uname (and getconf), so an architecture or a
# 32-bit userland no release ships for is refused instead of handed a build it
# cannot run (issue #170).
#
# And it runs the helpers that move an installation between the user-level
# and the system installers (--from-user, --from-system) and pick the tools
# --with-sudoers writes rules for, on the cases ci/test-distro.sh and
# ci/test-sudo-mail.sh cannot reach without root, with su, sudo, crontab,
# pgrep and pkill stubbed on PATH.
#
# Usage: sh ci/test-signing.sh

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMMON="$ROOT/fivenines_common.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

print_success() { printf '%s\n' "[+] $1"; }
print_warning() { printf '%s\n' "[!] $1"; }
print_error()   { printf '%s\n' "[-] $1"; }

# Source the verification chain under test: the signature check, the manifest
# policy built on it, and the helper that installs a startup definition only
# once it verified -- plus the uname -m -> artifact mapping
# (select_agent_binary, issue #170).
sed -n '/^release_signing_pubkey()/,/^}/p
        /^verify_sums_signature()/,/^}/p
        /^verification_preflight()/,/^}/p
        /^compute_sha256()/,/^}/p
        /^sha256_from_sums()/,/^}/p
        /^verify_sha256()/,/^}/p
        /^verify_from_manifest()/,/^}/p
        /^verify_agent_tarball()/,/^}/p
        /^install_verified_release_file()/,/^}/p
        /^select_agent_binary()/,/^}/p' "$COMMON" > "$WORK/funcs.sh"
# shellcheck source=/dev/null
. "$WORK/funcs.sh"

PASS=0
FAIL=0
check() {
  if [ "$2" = "$3" ]; then
    PASS=$((PASS + 1))
    echo "  ok   $1"
  else
    FAIL=$((FAIL + 1))
    echo "  FAIL $1: got '$2' want '$3'"
  fi
}

printf 'deadbeef  fivenines-agent-linux-amd64.tar.gz\n' > "$WORK/SHA256SUMS"
: > "$WORK/SHA256SUMS.sig"

# Signature verification is ARMED: a real key must be embedded. Losing this
# block would silently drop every host back to checksum-only, which is the
# one regression the loud runtime warning cannot catch (nobody reads a
# warning that was always there).
EMBEDDED=$(release_signing_pubkey)
check "a release signing key is embedded" \
  "$(printf '%s' "$EMBEDDED" | grep -c 'BEGIN PUBLIC KEY')" "1"

# ---------------------------------------------------------------------------
# Copy-paste download commands (issue #160). Checked here, ahead of the
# openssl gate below, because it needs nothing but awk and sed.
#
# Without -O, GNU wget never overwrites: a fivenines_setup.sh left in the
# directory by an earlier attempt makes it save the fresh copy as
# fivenines_setup.sh.1 and exit 0, and the `&&` then runs the OLD file as
# root. Every wget an operator is told to paste must pin its output name,
# fetch exactly one URL (-O would concatenate several into one file), and run
# the very file it wrote. That is all this proves. -O does not make a shared
# directory such as /tmp safe -- a file, named pipe or symlink another user
# plants under the name is written into or through, not replaced -- which is
# what the README note under the standard install is for: keep it.
# ---------------------------------------------------------------------------

# Every wget in every logical line (backslash continuations joined), each
# printed from itself to the end of its line, so a second wget chained after a
# first is judged on its own. wget counts as a command wherever it appears as a
# word -- after a `cd ... &&`, behind a `$ ` prompt, inside inline code or a
# `su -c '...'` / `sh -c "..."` string, spelled /usr/bin/wget or \wget -- but
# only when an option, a URL, or a quoted or $-built argument follows it, so
# prose that merely names wget is not one. The file may be - for stdin.
wget_commands() {
  awk '{ sub(/^[ \t]+/, "") }
       /\\$/ { sub(/\\+$/, ""); buf = buf $0 " "; next }
       { line = buf $0; buf = ""
         n = split(line, f, /[ \t]+/)
         for (i = 1; i < n; i++) {
           w = f[i]; sub(/^[`$(\\"\047]+/, "", w); sub(/.*\//, "", w)
           c = substr(f[i + 1], 1, 1)
           if (w == "wget" && (c == "-" || c == "\"" || c == "$" || index(f[i + 1], "://"))) {
             s = w
             for (k = i + 1; k <= n; k++) s = s " " f[k]
             gsub(/[`\047]/, "", s)
             print s
           }
         }
       }' "$1"
}

# Prints every command on stdin that breaks the rule, nothing when all hold.
# Deliberately literal, and closed on anything it does not know:
#   - the only options are -q, -T N and -O NAME, NAME a bare file name (no
#     `/`, so neither ./NAME nor a path into /tmp). Anything else is reported:
#     -qO and --output-document for being spelled differently, -c because it
#     keeps an existing file and exits 0, which is #160 all over again;
#   - every other word before the first separator is the one URL;
#   - the command stops there, or continues with
#     `&& [VAR=value...] [sudo [-opt | VAR=value]...] bash|sh NAME` running
#     that same NAME.
#     A `;`, `||` or `|`, a runner with no file, or any other runner is
#     reported.
unpinned_wgets() {
  awk '{
    out = ""; urls = 0; bad = 0; ran = ""
    for (i = 2; i <= NF; i++) {
      if ($i == "&&" || $i == "||" || $i == ";" || $i == "|") break
      if ($i == "-O") { out = $(i + 1); i++; continue }
      if ($i == "-T") { i++; continue }
      if ($i == "-q") continue
      if (substr($i, 1, 1) == "-") bad = 1; else urls++
    }
    if (i <= NF && $i == "&&") {
      j = i + 1
      while (j < NF && index($j, "=") && substr($j, 1, 1) != "-") j++
      if ($j == "sudo") {
        j++
        while (j < NF && (substr($j, 1, 1) == "-" || index($j, "="))) j++
      }
      if (($j == "bash" || $j == "sh") && j < NF) ran = $(j + 1); else ran = "&& " $j
    } else if (i <= NF) ran = $i
    if (bad || out == "" || index(out, "/") || urls != 1 || (ran != "" && ran != out)) print
  }'
}

# Canaries first. The real checks compare against "", which an awk that
# errors out or never prints would produce too, so every leg of both awk
# programs has to be seen firing on a line that breaks it, and the rule has
# to be seen staying quiet on lines that keep it. Each argument is one line.
flagged() { printf '%s\n' "$@" | wget_commands - | unpinned_wgets | wc -l | tr -d ' '; }
check "the wget lint flags the #160 command (no -O)" \
  "$(flagged 'wget -T 3 -q https://example.invalid/fivenines_setup.sh && sudo bash fivenines_setup.sh TOKEN')" "1"
check "the wget lint flags a download with no -O and nothing after it" \
  "$(flagged 'wget -q https://example.invalid/SHA256SUMS')" "1"
check "the wget lint sees a wget with no options at all" \
  "$(flagged 'wget https://example.invalid/fivenines_setup.sh && sudo bash fivenines_setup.sh TOKEN')" "1"
check "the wget lint flags a -O name the command does not run" \
  "$(flagged 'wget -T 3 -q -O new.sh https://example.invalid/fivenines_setup.sh && sudo bash fivenines_setup.sh TOKEN')" "1"
check "the wget lint flags one -O over two URLs" \
  "$(flagged 'wget -q -O SHA256SUMS https://example.invalid/SHA256SUMS https://example.invalid/SHA256SUMS.sig')" "1"
check "the wget lint flags an option that keeps an existing file (-c)" \
  "$(flagged 'wget -c -T 3 -q -O fivenines_setup.sh https://example.invalid/fivenines_setup.sh && sudo bash fivenines_setup.sh TOKEN')" "1"
check "the wget lint flags a -O path, even one the command runs" \
  "$(flagged 'wget -T 3 -q -O /tmp/fivenines_setup.sh https://example.invalid/fivenines_setup.sh && sudo bash /tmp/fivenines_setup.sh TOKEN')" "1"
check "the wget lint flags a mismatch behind sudo options" \
  "$(flagged 'wget -T 3 -q -O new.sh https://example.invalid/fivenines_update.sh && sudo -E FIVENINES_ALLOW_UNSIGNED=1 bash fivenines_update.sh')" "1"
check "the wget lint flags a runner it does not know" \
  "$(flagged 'wget -T 3 -q -O fivenines_setup.sh https://example.invalid/fivenines_setup.sh && doas sh fivenines_setup.sh TOKEN')" "1"
check "the wget lint flags a runner with no file" \
  "$(flagged 'wget -T 3 -q -O fivenines_setup.sh https://example.invalid/fivenines_setup.sh && sudo bash')" "1"
check "the wget lint flags a download the next command does not wait for" \
  "$(flagged 'wget -T 3 -q -O fivenines_setup.sh https://example.invalid/fivenines_setup.sh ; sudo bash fivenines_setup.sh TOKEN')" "1"
check "the wget lint sees a second wget chained on the same line" \
  "$(flagged 'wget -T 3 -q -O fivenines_uninstall.sh https://example.invalid/fivenines_uninstall.sh && sudo bash fivenines_uninstall.sh && wget -T 3 -q https://example.invalid/fivenines_setup.sh && sudo bash fivenines_setup.sh TOKEN')" "1"
check "the wget lint flags a mismatch behind an environment prefix" \
  "$(flagged 'wget -T 3 -q -O new.sh https://example.invalid/fivenines_setup.sh && FIVENINES_ALLOW_UNSIGNED=1 sh fivenines_setup.sh TOKEN')" "1"
check "the wget lint sees a wget inside su -c '...'" \
  "$(flagged "su -c 'wget -T 3 -q https://example.invalid/fivenines_setup.sh && bash fivenines_setup.sh TOKEN'")" "1"
check "the wget lint sees a wget inside sh -c \"...\"" \
  "$(flagged 'sudo sh -c "wget -T 3 -q https://example.invalid/fivenines_setup.sh && bash fivenines_setup.sh TOKEN"')" "1"
check "the wget lint sees \\wget" \
  "$(flagged '\wget -q https://example.invalid/fivenines_setup.sh && sudo bash fivenines_setup.sh TOKEN')" "1"
check "the wget lint sees a wget behind a cd prefix" \
  "$(flagged 'cd ~ && wget -T 3 -q https://example.invalid/fivenines_setup.sh && sudo bash fivenines_setup.sh TOKEN')" "1"
# The literal $... and backticks in the checks below are the input under
# test, and so is the backslash that ends the continued line.
# shellcheck disable=SC2016
check "the wget lint sees a wget in inline code" \
  "$(flagged 'Run `wget -T 3 -q https://example.invalid/fivenines_setup.sh && sudo bash fivenines_setup.sh TOKEN` as root.')" "1"
# shellcheck disable=SC2016
check "the wget lint passes a pinned command in inline code" \
  "$(flagged 'Run `wget -T 3 -q -O fivenines_setup.sh https://example.invalid/fivenines_setup.sh && sudo bash fivenines_setup.sh` as root.')" "0"
# shellcheck disable=SC2016
check "the wget lint sees /usr/bin/wget with a quoted \$-built URL" \
  "$(flagged '/usr/bin/wget "$URL" && sudo bash fivenines_setup.sh TOKEN')" "1"
# shellcheck disable=SC2016
check "the wget lint sees a wget with a bare \$-built URL" \
  "$(flagged 'wget $URL && sudo bash fivenines_setup.sh TOKEN')" "1"
# shellcheck disable=SC2016
check "the wget lint sees a wget in a command substitution" \
  "$(flagged '$(wget -q https://example.invalid/SHA256SUMS)')" "1"
# shellcheck disable=SC1003
check "the wget lint joins a continued line before comparing" \
  "$(flagged 'wget -T 3 -q -O new.sh \' '  https://example.invalid/fivenines_setup.sh && sudo bash fivenines_setup.sh TOKEN')" "1"
# shellcheck disable=SC2016
check "the wget lint passes a pinned command" \
  "$(flagged 'cd "$(mktemp -d)" && wget -T 3 -q -O fivenines_setup.sh https://example.invalid/fivenines_setup.sh && sudo FIVENINES_REQUIRE_SIGNATURE=1 bash fivenines_setup.sh TOKEN')" "0"
check "the wget lint passes a pinned command inside su -c '...'" \
  "$(flagged "su -c 'wget -T 3 -q -O fivenines_setup.sh https://example.invalid/fivenines_setup.sh && bash fivenines_setup.sh'")" "0"
check "the wget lint passes a pinned command behind an environment prefix" \
  "$(flagged 'wget -T 3 -q -O fivenines_setup.sh https://example.invalid/fivenines_setup.sh && FIVENINES_ALLOW_UNSIGNED=1 sh fivenines_setup.sh TOKEN')" "0"
check "the wget lint passes a pinned command behind sudo options" \
  "$(flagged 'wget -T 3 -q -O fivenines_update.sh https://example.invalid/fivenines_update.sh && sudo -E FIVENINES_ALLOW_UNSIGNED=1 bash fivenines_update.sh')" "0"
# shellcheck disable=SC2016
check "the wget lint ignores prose that names wget" \
  "$(flagged 'wget is the only prerequisite, and `wget` ships everywhere.')" "0"

check "every README wget pins -O, fetches one URL and runs what it wrote" \
  "$(wget_commands "$ROOT/README.md" | unpinned_wgets)" ""
# A floor, not an exact count: the check above passes vacuously if the
# extraction ever stops matching, while a new README example must not turn
# CI red just for existing.
check "the README still carries its install, update and uninstall commands" \
  "$([ "$(wget_commands "$ROOT/README.md" | grep -c ' && ')" -ge 8 ] && echo yes || echo no)" "yes"

# The UNRAID refusal in fivenines_update.sh prints a paste-able command too.
# Its source text is scanned as written, never executed: the message breaks
# the command with escaped `\\` continuations, which wget_commands joins like
# the README's single ones.
sed -n '/^if \[ -f \/etc\/unraid-version \]/,/^fi$/p' "$ROOT/fivenines_update.sh" \
  > "$WORK/unraid_hint.txt"
check "the UNRAID update hint pins -O and runs what it wrote" \
  "$(wget_commands "$WORK/unraid_hint.txt" | unpinned_wgets)" ""
check "the UNRAID update hint still carries a wget command" \
  "$(wget_commands "$WORK/unraid_hint.txt" | wc -l | tr -d ' ')" "1"

# ---------------------------------------------------------------------------
# Architecture mapping (issue #170). Also ahead of the openssl gate: it needs
# nothing but sh.
#
# The system installers and the UNRAID boot script used to hand every
# architecture but aarch64 the amd64 build, which verified against SHA256SUMS,
# installed, and then failed at exec with "Exec format error" on every
# restart. uname, getconf and detect_libc are the mapping's only inputs, so
# each case fakes all three in a subshell and reads back the status and the
# BINARY_NAME.
# ---------------------------------------------------------------------------

# Prints "<status>:<BINARY_NAME>" for a faked `uname -m` ($1), libc ($2) and
# `getconf LONG_BIT` ($3, 64 unless given; "none" for a host with no getconf).
binary_for() {
  (
    FAKE_UNAME_M="$1"
    FAKE_LIBC="$2"
    FAKE_LONG_BIT="${3-64}"
    # shellcheck disable=SC2317,SC2329
    uname() { [ "$1" = "-m" ] && printf '%s\n' "$FAKE_UNAME_M"; }
    # shellcheck disable=SC2317,SC2329
    detect_libc() { printf '%s\n' "$FAKE_LIBC"; }
    # shellcheck disable=SC2317,SC2329
    getconf() {
      [ "$FAKE_LONG_BIT" = "none" ] && return 127
      [ "$1" = "LONG_BIT" ] && printf '%s\n' "$FAKE_LONG_BIT"
    }
    select_agent_binary > /dev/null 2>&1
    printf '%s:%s\n' "$?" "${BINARY_NAME:-}"
  )
}

check "x86_64 on glibc gets the linux amd64 build" \
  "$(binary_for x86_64 glibc)" "0:fivenines-agent-linux-amd64"
check "aarch64 on glibc gets the linux arm64 build" \
  "$(binary_for aarch64 glibc)" "0:fivenines-agent-linux-arm64"
check "x86_64 on musl gets the alpine amd64 build" \
  "$(binary_for x86_64 musl)" "0:fivenines-agent-alpine-amd64"
check "aarch64 on musl gets the alpine arm64 build" \
  "$(binary_for aarch64 musl)" "0:fivenines-agent-alpine-arm64"

# amd64 and arm64 are what FreeBSD and macOS report, never Linux; aarch64_be
# is big-endian. The empty string (a uname that printed nothing) cannot live
# in a word list, so every loop over this one adds it as a literal word.
UNSUPPORTED_ARCHES="armv7l armv6l i686 i386 ppc64le s390x riscv64 aarch64_be amd64 arm64"
# The list is deliberately word-split into separate architectures.
# shellcheck disable=SC2086
for _arch in $UNSUPPORTED_ARCHES ""; do
  for _libc in glibc musl; do
    check "'${_arch}' on ${_libc} is refused, with no binary chosen" \
      "$(binary_for "$_arch" "$_libc")" "1:"
  done
done

# uname -m names the kernel. 32-bit Raspberry Pi OS on a Pi 4 or 5 boots a
# 64-bit kernel by default, so it reports aarch64 over an armhf userland that
# has no loader for the arm64 build; getconf is what tells the two apart.
for _arch in aarch64 x86_64; do
  for _libc in glibc musl; do
    check "a 32-bit userland on a 64-bit ${_arch} kernel (${_libc}) is refused" \
      "$(binary_for "$_arch" "$_libc" 32)" "1:"
  done
done
check "a host with no getconf is not guessed at" \
  "$(binary_for aarch64 glibc none)" "0:fivenines-agent-linux-arm64"
check "a getconf that prints nothing is not guessed at" \
  "$(binary_for x86_64 musl "")" "0:fivenines-agent-alpine-amd64"
check "the 32-bit userland refusal says what it found and what is needed" \
  "$(
    # shellcheck disable=SC2317,SC2329
    uname() { printf 'aarch64\n'; }
    # shellcheck disable=SC2317,SC2329
    detect_libc() { printf 'glibc\n'; }
    # shellcheck disable=SC2317,SC2329
    getconf() { printf '32\n'; }
    select_agent_binary 2>&1 | grep -c '32-bit userland on a 64-bit aarch64 kernel\|64-bit x86_64 and aarch64 systems'
  )" "2"

check "the refusal names the detected and the supported architectures" \
  "$(
    # shellcheck disable=SC2317,SC2329
    uname() { printf 'armv7l\n'; }
    # shellcheck disable=SC2317,SC2329
    detect_libc() { printf 'glibc\n'; }
    select_agent_binary 2>&1 | grep -c 'armv7l\|x86_64 and aarch64'
  )" "2"

# The exact line, so the success path is seen printing nothing else either.
check "an accepted host is told its architecture, libc and build" \
  "$(
    # shellcheck disable=SC2317,SC2329
    uname() { printf 'aarch64\n'; }
    # shellcheck disable=SC2317,SC2329
    detect_libc() { printf 'musl\n'; }
    # shellcheck disable=SC2317,SC2329
    getconf() { printf '64\n'; }
    select_agent_binary 2>&1
  )" "[+] Detected architecture: aarch64, libc: musl (fivenines-agent-alpine-arm64)"

# The system installers run without set -e, so a success line that cannot be
# written (stdout closed, or a full disk behind a redirect) must not turn a
# supported host into a refusal.
check "a success line that cannot be written is not a refusal" \
  "$(
    # shellcheck disable=SC2317,SC2329
    uname() { printf 'x86_64\n'; }
    # shellcheck disable=SC2317,SC2329
    detect_libc() { printf 'glibc\n'; }
    # shellcheck disable=SC2317,SC2329
    getconf() { printf '64\n'; }
    # shellcheck disable=SC2317,SC2329
    print_success() { return 1; }
    select_agent_binary > /dev/null 2>&1
    printf '%s:%s' "$?" "$BINARY_NAME"
  )" "0:fivenines-agent-linux-amd64"

# binary_for starts from an unset BINARY_NAME, so on its own it cannot tell a
# refusal that clears the name from one that merely never set it.
check "a refusal clears a BINARY_NAME that was set before it ran" \
  "$(
    BINARY_NAME=fivenines-agent-linux-amd64
    # shellcheck disable=SC2317,SC2329
    uname() { printf 'armv7l\n'; }
    # shellcheck disable=SC2317,SC2329
    detect_libc() { printf 'glibc\n'; }
    select_agent_binary > /dev/null 2>&1
    printf '%s' "$BINARY_NAME"
  )" ""

# The call sites. Every installer must choose its binary through the shared
# mapping and nowhere else (ci/build-scripts.sh keeps the copies identical),
# exit when it refuses, and do so before the preflight -- which is itself
# ahead of every download, stop and user or directory creation.
for _script in fivenines_setup.sh fivenines_update.sh fivenines_setup_user.sh fivenines_update_user.sh; do
  check "${_script} chooses its binary through select_agent_binary, and exits on a refusal" \
    "$(grep -c '^select_agent_binary || exit_with_' "$ROOT/${_script}")" "1"
  # Comments may name it; only a line of code that runs it counts.
  check "${_script} reads uname -m nowhere but in the shared mapping" \
    "$(grep -v '^[[:space:]]*#' "$ROOT/${_script}" | grep -c 'uname -m')" "1"
  # Not reading uname is not enough: a BINARY_NAME hard-coded further down
  # would bypass the mapping without reading anything at all.
  check "${_script} sets BINARY_NAME nowhere but in the shared mapping" \
    "$(awk '/^select_agent_binary\(\)/ {inside = 1}
            inside && /^}/ {inside = 0; next}
            !inside && /(^|[^A-Za-z0-9_])BINARY_NAME=/' "$ROOT/${_script}" | wc -l | tr -d ' ')" "0"
  check "${_script} refuses an unsupported architecture before the preflight" \
    "$(awk '/^select_agent_binary / {sab = NR}
            /^verification_preflight / {print (sab && sab < NR) ? "yes" : "no"; exit}' "$ROOT/${_script}")" "yes"
done

# The UNRAID boot script cannot source the shared function (it is a
# standalone startup definition), so its own case is run with the same faked
# uname. Only that block is extracted and run: the script as a whole kills
# every running agent before it gets there. Every $ in the block below is
# meant for the extracted script, not for this one.
# shellcheck disable=SC2016
{
  printf '%s\n' 'uname() { [ "$1" = "-m" ] && printf "%s\n" "$FAKE_UNAME_M"; }'
  sed -n '/^CURRENT_ARCH=\$(uname -m)$/,/^esac$/p' "$ROOT/fivenines_script.sh"
  printf '%s\n' 'printf "%s\n" "$BINARY_NAME"'
} > "$WORK/boot_arch.sh"
check "the UNRAID boot script runs x86_64 on the amd64 build" \
  "$(FAKE_UNAME_M=x86_64 sh "$WORK/boot_arch.sh" 2>/dev/null)" "fivenines-agent-linux-amd64"
check "the UNRAID boot script runs aarch64 on the arm64 build" \
  "$(FAKE_UNAME_M=aarch64 sh "$WORK/boot_arch.sh" 2>/dev/null)" "fivenines-agent-linux-arm64"
for _arch in armv7l i686; do
  FAKE_UNAME_M="$_arch" sh "$WORK/boot_arch.sh" > /dev/null 2>&1
  check "the UNRAID boot script refuses ${_arch}" "$?" "1"
done

# Its case is a second copy of the mapping that ci/build-scripts.sh cannot
# compare, so hold it to the shared one on every architecture above. UNRAID is
# glibc, and the boot script only knows the linux builds.
# Prints "<status>:<BINARY_NAME>" like binary_for, the name only on success.
boot_for() {
  if _name=$(FAKE_UNAME_M="$1" sh "$WORK/boot_arch.sh" 2>/dev/null); then
    printf '0:%s\n' "$_name"
  else
    printf '%s:\n' "$?"
  fi
}
_disagree=""
# shellcheck disable=SC2086
for _arch in x86_64 aarch64 $UNSUPPORTED_ARCHES ""; do
  [ "$(boot_for "$_arch")" = "$(binary_for "$_arch" glibc)" ] || _disagree="${_disagree}'${_arch}' "
done
check "the UNRAID boot script maps every architecture as select_agent_binary does" \
  "$_disagree" ""
check "the UNRAID boot script's refusal names the detected and the supported architectures" \
  "$(FAKE_UNAME_M=armv7l sh "$WORK/boot_arch.sh" 2>&1 | grep -c 'armv7l.*x86_64 and aarch64')" "1"

# The installers' call-site guards, held to the boot script too: a second
# uname read or a BINARY_NAME set after its case would bypass the block the
# checks above run, and bring the amd64 fallback back without failing them.
check "the UNRAID boot script reads uname -m once, in its architecture case" \
  "$(grep -v '^[[:space:]]*#' "$ROOT/fivenines_script.sh" | grep -c 'uname -m')" "1"
check "the UNRAID boot script sets BINARY_NAME nowhere but in its architecture case" \
  "$(awk '/^case "\$CURRENT_ARCH" in$/ {inside = 1}
          inside && /^esac$/ {inside = 0; next}
          !inside && /(^|[^A-Za-z0-9_])BINARY_NAME=/' "$ROOT/fivenines_script.sh" | wc -l | tr -d ' ')" "0"

# The identity check itself: the harness only ever runs the canonical copy in
# fivenines_common.sh, so the four inlined copies are held to it by
# ci/build-scripts.sh -- which checks only the functions it lists.
check "ci/build-scripts.sh holds all four copies of select_agent_binary to the canonical one" \
  "$(sh "$ROOT/ci/build-scripts.sh" 2>/dev/null | grep -c '^OK: select_agent_binary() in ')" "4"

# End to end: every installer, run on a faked armv7l, has to stop at the
# refusal having touched nothing. Each run is a scratch copy, started from a
# scratch working directory (the installers delete themselves on success,
# fivenines_update.sh by name from the working directory), and every command
# that could change the host is on PATH as a stub that records its name and
# fails -- so a regression that lets a script carry on past the refusal is
# reported by name instead of acting. `id -u` answers 0, or
# fivenines_setup.sh would stop at its root check and never reach the
# refusal; `uname -s` answers Linux, which fivenines_setup_user.sh checks
# first.
ARCH_BOX="$WORK/archbox"
mkdir -p "$ARCH_BOX/bin" "$ARCH_BOX/run" "$ARCH_BOX/install" "$ARCH_BOX/config"
printf 'test-token-arch-170' > "$ARCH_BOX/config/TOKEN"
REAL_UNAME=$(command -v uname)
ARCH_STUBS="mkdir useradd adduser addgroup usermod getent chown chmod tee cp mv rm ln tar
wget curl systemctl rc-service rc-update pkill pgrep su sudo ping mktemp
restorecon semodule sleep bash nohup crontab visudo"
for _stub in $ARCH_STUBS; do
  printf '#!/bin/sh\necho %s >> "%s"\nexit 1\n' "$_stub" "$ARCH_BOX/touched" > "$ARCH_BOX/bin/$_stub"
done
# shellcheck disable=SC2016
printf '#!/bin/sh\ncase "$1" in\n  -m) echo armv7l ;;\n  -s) echo Linux ;;\n  *) exec "%s" "$@" ;;\nesac\n' \
  "$REAL_UNAME" > "$ARCH_BOX/bin/uname"
# shellcheck disable=SC2016
printf '#!/bin/sh\n[ "$*" = "-u" ] && { echo 0; exit 0; }\necho id >> "%s"\nexit 1\n' \
  "$ARCH_BOX/touched" > "$ARCH_BOX/bin/id"
# fivenines_update_user.sh stops the agent through the install's own stop.sh
# when there is one, and PATH cannot shadow a path: plant a recording one.
printf '#!/bin/sh\necho stop.sh >> "%s"\nexit 1\n' "$ARCH_BOX/touched" > "$ARCH_BOX/install/stop.sh"
chmod 755 "$ARCH_BOX/bin/"* "$ARCH_BOX/install/stop.sh"

# Canary: the checks below expect an EMPTY record, which a stub box that
# shadows nothing or records nothing would produce too. Every name is only
# looked up through the box's PATH, never run through it, and the one stub
# that is run is called by its absolute path, so a broken box cannot reach a
# real command here, and neither can the planted stop.sh. A name that is a
# shell builtin (kill, echo) cannot be shadowed from PATH at all, which is why
# none is on the list.
: > "$ARCH_BOX/touched"
# The stub list is deliberately word-split into separate arguments, and the
# $ in the inline script is meant for the child shell.
# shellcheck disable=SC2016,SC2086
_unshadowed=$(PATH="$ARCH_BOX/bin:$PATH" sh -c '
  for _stub in "$@"; do
    [ "$(command -v "$_stub")" = "$0/$_stub" ] || printf "%s " "$_stub"
  done' "$ARCH_BOX/bin" $ARCH_STUBS uname id)
"$ARCH_BOX/bin/useradd"
_rc=$?
"$ARCH_BOX/install/stop.sh"
check "the stub box shadows every host-changing command, and a stub records its name" \
  "${_unshadowed}|rc=${_rc}|$(tr '\n' ' ' < "$ARCH_BOX/touched")" "|rc=1|useradd stop.sh "

for _script in fivenines_setup.sh fivenines_update.sh fivenines_setup_user.sh fivenines_update_user.sh; do
  cp "$ROOT/$_script" "$ARCH_BOX/run/$_script"
  : > "$ARCH_BOX/touched"
  (
    cd "$ARCH_BOX/run" || exit 99
    HOME="$ARCH_BOX" FIVENINES_INSTALL_DIR="$ARCH_BOX/install" FIVENINES_CONFIG_DIR="$ARCH_BOX/config" \
      PATH="$ARCH_BOX/bin:$PATH" sh "./$_script" test-token-arch-170 > "$ARCH_BOX/out" 2>&1
  )
  _rc=$?
  check "${_script} on armv7l refuses and touches nothing" \
    "exit=$_rc refused=$(grep -c 'Unsupported architecture: armv7l' "$ARCH_BOX/out") touched=$(tr '\n' ' ' < "$ARCH_BOX/touched")" \
    "exit=1 refused=1 touched="
done

# The same refusal, before any su, sudo, crontab or visudo, when an installer
# is asked to move an installation (--from-user, --from-system) or to write
# sudoers rules (--with-sudoers).
for _run in "fivenines_setup.sh --from-user someone --with-sudoers" \
  "fivenines_update.sh --with-sudoers" \
  "fivenines_setup_user.sh --from-system"; do
  _script=${_run%% *}
  cp "$ROOT/$_script" "$ARCH_BOX/run/$_script"
  : > "$ARCH_BOX/touched"
  (
    cd "$ARCH_BOX/run" || exit 99
    # The arguments after the script name are deliberately word-split.
    # shellcheck disable=SC2086
    HOME="$ARCH_BOX" FIVENINES_INSTALL_DIR="$ARCH_BOX/install" FIVENINES_CONFIG_DIR="$ARCH_BOX/config" \
      PATH="$ARCH_BOX/bin:$PATH" sh "./$_script" ${_run#* } > "$ARCH_BOX/out" 2>&1
  )
  _rc=$?
  check "${_run} on armv7l refuses and touches nothing" \
    "exit=$_rc refused=$(grep -c 'Unsupported architecture: armv7l' "$ARCH_BOX/out") touched=$(tr '\n' ' ' < "$ARCH_BOX/touched")" \
    "exit=1 refused=1 touched="
done

# The argument parsers of the same three scripts, in the same box: each run
# stops at its usage text or at the armv7l refusal, the latter proving the
# parser let it through, and touches nothing either way.
# Value: protects=only the exact option words are options (a token may start with a dash), --from-user takes one word at most, --from-system none;
#   fails_when=a getopts-style parser rejects a dash token, --from-user or --from-system accepts extra words, or the update stops on an argument it does not know;
#   why_new=the loops above pass only well-formed argument lists; seam=none;
#   no_claim=what a script does once past its parser
for _case in "fivenines_setup.sh -token-with-a-dash-170|refused" \
  "fivenines_setup.sh --from-user someone extra|usage" \
  "fivenines_setup.sh --with-sudoers|usage" \
  "fivenines_setup_user.sh -token-with-a-dash-170|refused" \
  "fivenines_setup_user.sh --from-system test-token-arch-170|usage" \
  "fivenines_update.sh --bogus --with-sudoers|ignored"; do
  _run=${_case%|*}
  _script=${_run%% *}
  case ${_case##*|} in
    usage) _want="exit=1 usage=1 refused=0 ignored=0 echoed=0 touched=" ;;
    refused) _want="exit=1 usage=0 refused=1 ignored=0 echoed=0 touched=" ;;
    *) _want="exit=1 usage=0 refused=1 ignored=1 echoed=0 touched=" ;;
  esac
  cp "$ROOT/$_script" "$ARCH_BOX/run/$_script"
  : > "$ARCH_BOX/touched"
  (
    cd "$ARCH_BOX/run" || exit 99
    # The arguments after the script name are deliberately word-split.
    # shellcheck disable=SC2086
    HOME="$ARCH_BOX" FIVENINES_INSTALL_DIR="$ARCH_BOX/install" FIVENINES_CONFIG_DIR="$ARCH_BOX/config" \
      PATH="$ARCH_BOX/bin:$PATH" sh "./$_script" ${_run#* } > "$ARCH_BOX/out" 2>&1
  )
  _rc=$?
  check "${_run}: ${_case##*|}" \
    "exit=$_rc usage=$(grep -c '^Usage:' "$ARCH_BOX/out") refused=$(grep -c 'Unsupported architecture: armv7l' "$ARCH_BOX/out") ignored=$(grep -c "Ignoring an argument this script does not take" "$ARCH_BOX/out") echoed=$(grep -c -e '--bogus' "$ARCH_BOX/out") touched=$(tr '\n' ' ' < "$ARCH_BOX/touched")" \
    "$_want"
done

# fivenines_update.sh past its parser: --with-sudoers is recognised among
# words it does not know, and write_sudoers_rules runs, its failure noted but
# never fatal. Both blocks are top-level code, run from the script itself
# (found by their first lines; a block that is no longer found runs nothing,
# and every check below fails).
# Value: protects=the update recognises --with-sudoers among unknown words and calls write_sudoers_rules only then, noting a failure without stopping;
#   fails_when=the --with-sudoers case or the call is dropped, the call ignores the flag, or a failed write stops the update;
#   why_new=the parser check above asserts only the --bogus warning; seam=none;
#   no_claim=what write_sudoers_rules writes (test-sudo-mail, test-distro)
UPD_ARGS=$(sed -n '/^WITH_SUDOERS=0$/,/^done$/p' "$ROOT/fivenines_update.sh")
UPD_CALL=$(sed -n '/^SUDOERS_SKIPPED=0$/,/^fi$/p' "$ROOT/fivenines_update.sh")
# Runs the two blocks with ARGS; write_sudoers_rules returns STATUS.
upd_run() {
  _upd_status=$1
  shift
  (
    # Both are called through the evaluated blocks.
    # shellcheck disable=SC2317,SC2329
    print_warning() { echo "warning: $1"; }
    # shellcheck disable=SC2317,SC2329
    write_sudoers_rules() { echo "write_sudoers_rules called"; return "$_upd_status"; }
    eval "$UPD_ARGS"
    eval "$UPD_CALL"
    echo "with=${WITH_SUDOERS:-unset} skipped=${SUDOERS_SKIPPED:-unset}"
  ) 2>&1 | tr '\n' '|'
}
check "fivenines_update.sh --bogus --with-sudoers: one warning, then the rules are written" \
  "$(upd_run 0 --bogus --with-sudoers)" \
  "warning: Ignoring an argument this script does not take (usage: sudo bash fivenines_update.sh [--with-sudoers])|write_sudoers_rules called|with=1 skipped=0|"
check "fivenines_update.sh --with-sudoers: a failed write is noted, not fatal" \
  "$(upd_run 1 --with-sudoers)" "write_sudoers_rules called|with=1 skipped=1|"
check "fivenines_update.sh without --with-sudoers writes no rule" "$(upd_run 0)" "with=0 skipped=0|"

# Where each step sits: test mode, which ci/test-distro.sh runs, skips every
# service start and stop, so only the scripts' own order shows it.
# Value: protects=the rules are written before the agent (re)starts, --from-user stops and reads the user agent only after every check and removes it only once the service started, and the user update rewrites its control scripts before stopping the agent and never writes start.sh;
#   fails_when=a refactor moves one of these steps, or the update writes start.sh; seam=none;
#   why_new=test mode hides the order from every other test; no_claim=what each step does
# Prints yes when every pattern in $2... is found in file $1, each on a later
# line than the one before.
in_order() {
  _in_file=$1
  shift
  _in_line=0
  for _in_pat in "$@"; do
    _in_found=$(awk -v start="$_in_line" -v pat="$_in_pat" 'NR > start && index($0, pat) { print NR; exit }' "$_in_file")
    if [ -z "$_in_found" ]; then
      echo "no (missing after line $_in_line: $_in_pat)"
      return
    fi
    _in_line=$_in_found
  done
  echo yes
}
check "fivenines_update.sh writes the sudoers rules before it restarts the agent" \
  "$(in_order "$ROOT/fivenines_update.sh" 'write_sudoers_rules || SUDOERS_SKIPPED=1' 'Restarting fivenines-agent service')" "yes"
check "fivenines_setup.sh --from-user: checks, stop, state, sudoers rules, service, then removal" \
  "$(in_order "$ROOT/fivenines_setup.sh" 'Testing connectivity...' '    stop_user_agent ||' '  import_user_state ||' '  write_sudoers_rules || SUDOERS_SKIPPED=1' '      setup_systemd' '  remove_user_installation')" "yes"
check "fivenines_update_user.sh rewrites its control scripts before it stops the agent" \
  "$(in_order "$ROOT/fivenines_update_user.sh" 'print_success "Created refresh.sh"' 'write_control_scripts' 'echo "Stopping agent..."')" "yes"
# In an AND-OR list (|| exit_with_error, || true) set -e would no longer stop
# the update at a control script it failed to write.
check "fivenines_update_user.sh calls write_control_scripts as a plain command, under set -e" \
  "$(grep -cx 'write_control_scripts' "$ROOT/fivenines_update_user.sh")" "1"
# The $INSTALL_DIR in the pattern is the literal text of a redirection.
# shellcheck disable=SC2016
check "fivenines_update_user.sh never writes start.sh" \
  "$(grep -c '> "\$INSTALL_DIR/start.sh"' "$ROOT/fivenines_update_user.sh")" "0"

# ---------------------------------------------------------------------------
# Moving an installation (--from-user, --from-system) and --with-sudoers.
# Also ahead of the openssl gate: they need nothing but sh and base64, plus
# bash, pgrep and ps for the control scripts.
#
# ci/test-distro.sh plays both moves for real but in test mode, which skips
# every agent start and stop, with nothing unusual in either config
# directory; ci/test-sudo-mail.sh runs write_sudoers_rules with root-owned
# tools only. The helpers are run here, from the scripts themselves, on what
# those cannot reach without root: what a move reads, carries and removes,
# which processes the control scripts signal, and which tool paths may get a
# sudoers rule. su, sudo, crontab, pgrep and pkill are stubs on PATH (none is
# a shell builtin), and nothing runs unless each is the one found: the real
# crontab would rewrite this user's own, and the pgrep and pkill stubs pass
# on only a pattern anchored inside this run's scratch directory, so a broken
# pattern can never reach another process.
# ---------------------------------------------------------------------------
MOVE_NAME="move$$x"
MOVE="$WORK/$MOVE_NAME"
MOVE_BIN="$MOVE/bin"
mkdir -p "$MOVE_BIN"
: > "$MOVE/refused"
REAL_PGREP=$(command -v pgrep 2>/dev/null || true)
REAL_PKILL=$(command -v pkill 2>/dev/null || true)
# Every $ below is meant for the stubs, except the paths baked into them.
for _tool in pgrep pkill; do
  if [ "$_tool" = pgrep ]; then _real=$REAL_PGREP; else _real=$REAL_PKILL; fi
  cat > "$MOVE_BIN/$_tool" << EOF
#!/bin/sh
for _last; do :; done
case "\$_last" in
  "^/"*"/${MOVE_NAME}/"*) [ -n "$_real" ] && exec "$_real" "\$@" ;;
esac
echo "$_tool \$_last" >> "$MOVE/refused"
exit 3
EOF
done
# su -s SHELL -c COMMAND USER [ARG...], the way as_user calls it: COMMAND runs
# with sh, as this user, the ARGs as its \$0, \$1... A PAM session module may
# print first (RHEL's pam_lastlog showfailed), so this one does.
cat > "$MOVE_BIN/su" << 'EOF'
#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    -s) shift 2 ;;
    -c) _cmd=$2; shift 2 ;;
    *) shift; break ;;
  esac
done
echo "There was 1 failed login attempt since the last successful login."
exec /bin/sh -c "$_cmd" "$@"
EOF
cat > "$MOVE_BIN/sudo" << 'EOF'
#!/bin/sh
echo "We trust you have received the usual lecture from the local System Administrator."
exec "$@"
EOF
cat > "$MOVE_BIN/crontab" << EOF
#!/bin/sh
case "\$1" in
  -l) [ -f "$MOVE/crontab" ] || { echo "no crontab for this user" >&2; exit 1; }; cat "$MOVE/crontab" ;;
  -) cat > "$MOVE/crontab" ;;
  *) exit 1 ;;
esac
EOF
chmod 755 "$MOVE_BIN/"*
# The stub list is deliberately word-split, and the $ in the inline script is
# meant for the child shell.
# shellcheck disable=SC2016
MOVE_UNSHADOWED=$(PATH="$MOVE_BIN:$PATH" sh -c '
  for _stub in su sudo crontab pgrep pkill; do
    [ "$(command -v "$_stub")" = "$0/$_stub" ] || printf "%s " "$_stub"
  done' "$MOVE_BIN")
PATH="$MOVE_BIN:$PATH" pgrep -f "" > /dev/null 2>&1
_rc=$?
PATH="$MOVE_BIN:$PATH" pkill -f "$MOVE/" > /dev/null 2>&1
_rc="$_rc $?"
check "the move stubs shadow su, sudo, crontab, pgrep and pkill, which refuse an empty or unanchored pattern" \
  "${MOVE_UNSHADOWED}|rc=${_rc}|$(tr '\n' ' ' < "$MOVE/refused")" "|rc=3 3|pgrep  pkill $MOVE/ "
: > "$MOVE/refused"

if [ -n "$MOVE_UNSHADOWED" ]; then
  echo "  (the move helpers are not run: a stub is not the command found)"
else
MOVE_SAVED_PATH=$PATH
PATH="$MOVE_BIN:$PATH"

# --from-system: copy_system_state, as fivenines_setup_user.sh runs it, with
# its own lists of what to carry.
# Value: protects=--from-system carries TOKEN, MACHINE_ID and the journal allowlist byte-exact, owner-only, .env only as the unread .env.system, and nothing else;
#   fails_when=a carried list changes, decode_state stops cutting at its markers, the root-side read follows a symlink or skips it as absent, or an empty TOKEN passes;
#   why_new=test-distro Test 13 copies plain files through a sudo that prints nothing, and never meets a link or an empty TOKEN; seam=none;
#   no_claim=that the reads run as root, or that the system agent was stopped first
sed -n '/^STATE_FILES=/p;/^SYSTEM_ENV_COPY=/p;/^COPIED_STATE_FILES=/p;/^STATE_FILE_MAX=/p
        /^as_root()/,/^}/p;/^decode_state()/,/^}/p;/^copy_system_state()/,/^}/p' \
  "$ROOT/fivenines_setup_user.sh" > "$MOVE/from_system.sh"
# The names in a directory, dot files included, in byte order.
move_names() {
  for _n in "$1"/.[!.]* "$1"/*; do
    if [ -e "$_n" ] || [ -L "$_n" ]; then printf '%s\n' "${_n##*/}"; fi
  done | LC_ALL=C sort | tr '\n' ' '
}
# GNU stat first, BSD stat second.
move_mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null; }
# Runs copy_system_state from $MOVE/sys into an empty $MOVE/cfg, and prints
# its status.
from_system_copy() {
  rm -rf "$MOVE/cfg" "$MOVE/stage"
  mkdir -p "$MOVE/cfg" "$MOVE/stage"
  (
    # shellcheck source=/dev/null
    . "$MOVE/from_system.sh"
    SYSTEM_CONFIG_DIR="$MOVE/sys"
    CONFIG_DIR="$MOVE/cfg"
    WORK_DIR="$MOVE/stage"
    copy_system_state > "$MOVE/out" 2>&1
  )
  echo "$?"
}
mkdir -p "$MOVE/sys"
printf 'per-host-token-0001' > "$MOVE/sys/TOKEN"
printf '0b5e2d5c-6f1a-4c3e-9d2b-7a8f1e4c5d6a\n' > "$MOVE/sys/MACHINE_ID"
printf 'nginx\n*.timer\n' > "$MOVE/sys/journal_units.allow"
printf 'API_URL=https://api.example.invalid\n' > "$MOVE/sys/.env"
printf '{"sha256:ab":true}' > "$MOVE/sys/image_inventory_done"
printf '{}' > "$MOVE/sys/sudo_refusals"
_rc=$(from_system_copy)
_differ=""
_modes=""
for _f in TOKEN MACHINE_ID journal_units.allow .env:.env.system; do
  cmp -s "$MOVE/sys/${_f%%:*}" "$MOVE/cfg/${_f##*:}" || _differ="${_differ}${_f} "
  _modes="${_modes}$(move_mode "$MOVE/cfg/${_f##*:}") "
done
check "--from-system carries the identity and the allowlist, .env only as .env.system, and nothing else" \
  "rc=$_rc|$(move_names "$MOVE/cfg")" \
  "rc=0|.env.system MACHINE_ID TOKEN journal_units.allow "
check "--from-system carries each file byte for byte, past what sudo printed first" "$_differ" ""
check "--from-system writes each file owner-only" "$_modes" "600 600 600 600 "
check "--from-system says why .env was not carried as .env" "$(grep -c 'which the agent does not read' "$MOVE/out")" "1"

mv "$MOVE/sys/journal_units.allow" "$MOVE/allow.real"
printf 'not the allowlist\n' > "$MOVE/elsewhere"
ln -s "$MOVE/elsewhere" "$MOVE/sys/journal_units.allow"
check "--from-system stops at a symlinked allowlist, and carries nothing" \
  "$(from_system_copy)|$(grep -c 'journal_units.allow is not a regular file' "$MOVE/out")|$(move_names "$MOVE/cfg")" \
  "1|1|"
rm -f "$MOVE/sys/journal_units.allow"
mv "$MOVE/allow.real" "$MOVE/sys/journal_units.allow"

: > "$MOVE/sys/TOKEN"
check "--from-system stops at an empty TOKEN, and carries nothing" \
  "$(from_system_copy)|$(grep -c 'TOKEN is empty' "$MOVE/out")|$(move_names "$MOVE/cfg")" \
  "1|1|"

# A transfer cut short (su or sudo killed mid-way) has no end marker: it must
# not decode as a shorter file.
printf 'fivenines-state-begin\n%s\n' "$(printf 'per-host-token-0001' | base64)" > "$MOVE/cut.b64"
(
  # shellcheck source=/dev/null
  . "$MOVE/from_system.sh"
  decode_state "$MOVE/cut.b64" "$MOVE/cut.out"
)
check "decode_state refuses a transfer with no end marker" "$?" "1"
# Output printed before the data with no newline: the begin marker is not on
# a line of its own, and the file must not decode as an empty one.
printf 'Last login: somewhere%s\n%s\nfivenines-state-end\n' 'fivenines-state-begin' \
  "$(printf 'per-host-token-0001' | base64)" > "$MOVE/nobegin.b64"
(
  # shellcheck source=/dev/null
  . "$MOVE/from_system.sh"
  decode_state "$MOVE/nobegin.b64" "$MOVE/nobegin.out"
)
check "decode_state refuses a transfer whose begin marker is not on a line of its own" "$?" "1"

# --from-system: take_over_system_install, when the release's uninstaller
# leaves the system TOKEN behind (it failed half-way), and when it removes it.
# Value: protects=a --from-system whose uninstaller leaves the system TOKEN takes back every file it copied, so one identity never lives in two places;
#   fails_when=the TOKEN-gone check after the uninstaller is dropped, or abort_system_takeover stops removing what was copied;
#   why_new=test-distro Test 13 only runs the real uninstaller, which removes the TOKEN; seam=none;
#   no_claim=the stop and restart of the system agent (skipped in test mode), or an interrupted move
sed -n '/^STATE_FILES=/p;/^SYSTEM_ENV_COPY=/p;/^COPIED_STATE_FILES=/p;/^STATE_FILE_MAX=/p
        /^exit_with_error()/,/^}/p;/^as_root()/,/^}/p;/^decode_state()/,/^}/p
        /^copy_system_state()/,/^}/p;/^restart_system_agent()/,/^}/p
        /^abort_system_takeover()/,/^}/p;/^take_over_system_install()/,/^}/p' \
  "$ROOT/fivenines_setup_user.sh" > "$MOVE/takeover.sh"
# Runs take_over_system_install, in test mode, with $1 as the body of the
# release's uninstaller, and prints its status.
from_system_takeover() {
  rm -rf "$MOVE/cfg" "$MOVE/stage"
  mkdir -p "$MOVE/cfg" "$MOVE/stage"
  printf '%s\n' "$1" > "$MOVE/stage/fivenines_uninstall.sh"
  (
    # shellcheck source=/dev/null
    . "$MOVE/takeover.sh"
    FIVENINES_TEST_MODE=1
    SYSTEM_CONFIG_DIR="$MOVE/sys"
    CONFIG_DIR="$MOVE/cfg"
    WORK_DIR="$MOVE/stage"
    INSTALL_DIR="$MOVE/inst"
    # This subshell's PID, for an uninstaller that interrupts the move.
    MOVE_RUNNER=$(sh -c 'echo "$PPID"')
    export MOVE_RUNNER
    take_over_system_install > "$MOVE/out" 2>&1
  )
  echo "$?"
}
printf 'per-host-token-0001' > "$MOVE/sys/TOKEN"
check "--from-system takes back what it copied when the uninstaller leaves the system TOKEN" \
  "$(from_system_takeover 'echo pretend uninstall')|$(grep -c 'did not remove the system installation' "$MOVE/out")|$(move_names "$MOVE/cfg")|$(cat "$MOVE/sys/TOKEN")" \
  "1|1||per-host-token-0001"
check "--from-system keeps what it copied once the uninstaller removed the system TOKEN" \
  "$(from_system_takeover "rm -f '$MOVE/sys/TOKEN'")|$(cat "$MOVE/cfg/TOKEN" 2>/dev/null)" \
  "0|per-host-token-0001"
# Interrupted once the uninstaller removed the system TOKEN: the copy is then
# the agent's only identity, and must stay (it was deleted before).
# Value: protects=an interrupted --from-system never deletes the copy once the system TOKEN is gone, and says how to start the agent;
#   fails_when=abort_system_takeover takes the copy back without checking that the system TOKEN still exists;
#   why_new=the checks above end without a signal; seam=none; no_claim=a signal during the system agent's stop (ignored there)
printf 'per-host-token-0001' > "$MOVE/sys/TOKEN"
# The $ are for the uninstaller's shell.
# shellcheck disable=SC2016
check "--from-system interrupted after the uninstaller keeps the only identity, and says how to start it" \
  "$(from_system_takeover "rm -f '$MOVE/sys/TOKEN'; kill -INT \"\$MOVE_RUNNER\"")|$(cat "$MOVE/cfg/TOKEN" 2>/dev/null)|$(grep -c "the agent's identity is now in" "$MOVE/out")" \
  "1|per-host-token-0001|1"

# A systemctl that logs each call, fails a stop when MOVE_STOP_FAILS is set,
# and interrupts the move during a stop when MOVE_STOP_SIGNAL is set. A stop
# logs whether $MOVE/etc still holds a TOKEN.
mkdir -p "$MOVE/svcbin"
cat > "$MOVE/svcbin/systemctl" << EOF
#!/bin/sh
_t=""
[ -e "$MOVE/etc/TOKEN" ] && _t=" with TOKEN"
echo "systemctl \$*\$_t" >> "$MOVE/svc.log"
if [ "\$1" = stop ]; then
  [ -n "\${MOVE_STOP_SIGNAL:-}" ] && kill -INT "\$MOVE_RUNNER"
  [ -z "\${MOVE_STOP_FAILS:-}" ]
fi
EOF
chmod 755 "$MOVE/svcbin/systemctl"

# --from-system outside test mode: the system agent's stop, with the unit and
# the agent's path moved into the scratch directory.
# Value: protects=a --from-system whose system agent stop fails moves nothing, and a signal during that stop neither cuts the move nor leaves the agent stopped with nothing armed;
#   fails_when=a failed stop goes on to copy the identity, or take_over_system_install stops ignoring INT/TERM/HUP during the stop;
#   why_new=every other run of the move is in test mode, which skips the stop; seam=/etc/systemd/system and ^/opt/fivenines/ are rewritten to the scratch directory;
#   no_claim=the OpenRC branch, a real systemd, or the restart after an abort
sed "s|/etc/systemd/system/|$MOVE/units/|g;s|\"^/opt/fivenines/\"|\"^$MOVE/opt/\"|g" \
  "$MOVE/takeover.sh" > "$MOVE/takeover_stop.sh"
# Runs take_over_system_install outside test mode; $1 is fail, signal or
# nothing, for the stop, or after, for a TERM once it returned; $2 is the
# uninstaller's body (default: it removes the TOKEN and the unit). Prints its
# status.
from_system_stop() {
  rm -rf "$MOVE/cfg" "$MOVE/stage" "$MOVE/units"
  mkdir -p "$MOVE/cfg" "$MOVE/stage" "$MOVE/units"
  : > "$MOVE/svc.log"
  : > "$MOVE/units/fivenines-agent.service"
  printf 'per-host-token-0001' > "$MOVE/sys/TOKEN"
  _uninstaller="rm -f '$MOVE/sys/TOKEN' '$MOVE/units/fivenines-agent.service'"
  if [ -n "${2:-}" ]; then _uninstaller=$2; fi
  printf '%s\n' "$_uninstaller" > "$MOVE/stage/fivenines_uninstall.sh"
  (
    # shellcheck source=/dev/null
    . "$MOVE/takeover_stop.sh"
    unset FIVENINES_TEST_MODE
    case "$1" in
      fail) MOVE_STOP_FAILS=1 && export MOVE_STOP_FAILS ;;
      signal) MOVE_STOP_SIGNAL=1 && export MOVE_STOP_SIGNAL ;;
    esac
    SYSTEM_CONFIG_DIR="$MOVE/sys"
    CONFIG_DIR="$MOVE/cfg"
    WORK_DIR="$MOVE/stage"
    INSTALL_DIR="$MOVE/inst"
    # The systemctl stub, for this run only.
    # shellcheck disable=SC2030,SC2031
    PATH="$MOVE/svcbin:$PATH"
    MOVE_RUNNER=$(sh -c 'echo "$PPID"')
    export MOVE_RUNNER
    take_over_system_install > "$MOVE/out" 2>&1
    if [ "$1" = after ]; then
      kill -TERM "$MOVE_RUNNER"
      echo "survived" >> "$MOVE/out"
    fi
  )
  echo "$?"
}
check "--from-system moves nothing when the system agent's stop fails" \
  "$(from_system_stop fail)|$(grep -c 'Could not stop the system agent: nothing was moved' "$MOVE/out")|$(move_names "$MOVE/cfg")|$(cat "$MOVE/sys/TOKEN" 2>/dev/null)|$(tr '\n' '|' < "$MOVE/svc.log")" \
  "1|1||per-host-token-0001|systemctl stop fivenines-agent.service|"
check "--from-system ignores a signal during the system agent's stop, and completes the move" \
  "$(from_system_stop signal)|$(cat "$MOVE/cfg/TOKEN" 2>/dev/null)|$(test -e "$MOVE/sys/TOKEN" && echo kept)|$(tr '\n' '|' < "$MOVE/svc.log")" \
  "0|per-host-token-0001||systemctl stop fivenines-agent.service|"
# Value: protects=once the system installation is gone, a signal cannot cut the start of the moved agent or its @reboot line, nor print a message saying to start it a second time;
#   fails_when=take_over_system_install returns with the abort trap still armed;
#   why_new=the checks above signal before the uninstaller ran; seam=none; no_claim=start_agent itself (skipped here)
check "--from-system ignores a signal once the system installation is gone" \
  "$(from_system_stop after)|$(grep -c '^survived$' "$MOVE/out")|$(grep -c 'Stopped after' "$MOVE/out")" "0|1|0"
# Value: protects=an uninstaller that removed the unit but not the TOKEN leaves the copy taken back and a warning that the system agent was not started again, which says to re-run the move, never to remove the system installation (it holds the only TOKEN left);
#   fails_when=restart_system_agent goes back to an if/elif that succeeds when neither service definition exists, or its advice names the uninstaller;
#   why_new=the other checks keep the unit or remove both; seam=as above; no_claim=the OpenRC branch
# Value: protects=an undone --from-system enables the system agent again before starting it (the uninstaller disables it before it removes the TOKEN);
#   fails_when=restart_system_agent only starts the service;
#   why_new=the other checks run in test mode, or stop before the restart; seam=as above; no_claim=the OpenRC branch
check "--from-system enables and starts the system agent again when its TOKEN stays" \
  "$(from_system_stop "" "echo pretend uninstall")|$(grep -c 'did not remove the system installation' "$MOVE/out")|$(tr '\n' '|' < "$MOVE/svc.log")" \
  "1|1|systemctl stop fivenines-agent.service|systemctl enable fivenines-agent.service|systemctl start fivenines-agent.service|"
check "--from-system says the system agent is not started again once its unit is gone" \
  "$(from_system_stop "" "rm -f '$MOVE/units/fivenines-agent.service'")|$(grep 'its service definition is gone' "$MOVE/out" | grep -c 'Re-run --from-system')|$(grep 'its service definition is gone' "$MOVE/out" | grep -c 'uninstall')|$(move_names "$MOVE/cfg")|$(cat "$MOVE/sys/TOKEN")" \
  "1|1|0||per-host-token-0001"
rm -rf "$MOVE/units"

# --from-system preflight: an installation, or any state file, already in
# this user's directories is refused before anything changes.
# Value: protects=--from-system never overwrites a user-level start.sh or state file, nor deletes one when it is undone;
#   fails_when=the preflight goes back to checking only CONFIG_DIR/TOKEN, or refuses the start.sh an undone move left for this config directory;
#   why_new=no test ran the preflight's refusals; seam=none; no_claim=the sudo and verification steps after them
sed -n '/^STATE_FILES=/p;/^SYSTEM_ENV_COPY=/p;/^exit_with_error()/,/^}/p;/^preflight_system_takeover()/,/^}/p' \
  "$ROOT/fivenines_setup_user.sh" > "$MOVE/presys.sh"
# Runs the preflight with FILE ($1, under the install or config directory)
# holding the line $2, and prints its status, whether it refused FILE, and
# whether it went on to sudo (a stub that fails).
from_system_preflight() {
  rm -rf "$MOVE/pinst" "$MOVE/pcfg"
  mkdir -p "$MOVE/pinst" "$MOVE/pcfg"
  printf '%s\n' "${2:-}" > "$MOVE/$1"
  (
    # shellcheck source=/dev/null
    . "$MOVE/presys.sh"
    # Called by the preflight once its refusals passed.
    # shellcheck disable=SC2317,SC2329
    sudo() { return 1; }
    INSTALL_DIR="$MOVE/pinst"
    CONFIG_DIR="$MOVE/pcfg"
    preflight_system_takeover > "$MOVE/out" 2>&1
  )
  printf '%s|%s|%s' "$?" "$(grep -c "$MOVE/$1 exists" "$MOVE/out")" "$(grep -c 'sudo did not authenticate' "$MOVE/out")"
}
if [ "$(id -u)" != "0" ]; then
  check "--from-system refuses a start.sh for another config directory" \
    "$(from_system_preflight pinst/start.sh 'export CONFIG_DIR="/elsewhere"')" "1|1|0"
  check "--from-system goes on over the start.sh an undone move left" \
    "$(from_system_preflight pinst/start.sh "export CONFIG_DIR=\"$MOVE/pcfg\"")" "1|0|1"
  check "--from-system refuses a MACHINE_ID already in its config directory" \
    "$(from_system_preflight pcfg/MACHINE_ID)" "1|1|0"
  check "--from-system refuses a .env.system already in its config directory" \
    "$(from_system_preflight pcfg/.env.system)" "1|1|0"
fi

# --from-user: rollback_user_takeover outside test mode, as exit_with_contact
# runs it when the import or the service failed, signalled again during the
# service stop.
# Value: protects=a failed --from-user removes only the files it installed, before it stops and disables the service, then starts the user-level agent again, even when signalled meanwhile;
#   fails_when=the rollback deletes a state file it did not install, stops the service before removing what it installed, stops ignoring INT/TERM/HUP, or no longer restarts the user-level agent;
#   why_new=the harness and test-distro roll back only in test mode, which skips the service and the restart; seam=/etc/fivenines_agent is rewritten to the scratch directory;
#   no_claim=the OpenRC branch, a real systemd, or that the restart runs as the user (su is a stub)
sed -n '/^STATE_FILES=/p;/^as_user()/,/^}/p;/^rollback_user_takeover()/,/^}/p' "$ROOT/fivenines_setup.sh" \
  | sed "s|/etc/fivenines_agent|$MOVE/etc|g" > "$MOVE/rollback.sh"
mkdir -p "$MOVE/etc" "$MOVE/rbinst"
for _f in TOKEN MACHINE_ID last_capture_id .env; do
  printf '%s\n' "$_f" > "$MOVE/etc/$_f"
done
printf '#!/bin/sh\necho start.sh >> %s\n' "'$MOVE/svc.log'" > "$MOVE/rbinst/start.sh"
chmod 755 "$MOVE/rbinst/start.sh"
: > "$MOVE/svc.log"
(
  # shellcheck source=/dev/null
  . "$MOVE/rollback.sh"
  unset FIVENINES_TEST_MODE
  MOVE_STOP_SIGNAL=1
  export MOVE_STOP_SIGNAL
  SYSTEM_TYPE=systemd
  FROM_USER_NAME=alice
  USER_INSTALL_DIR="$MOVE/rbinst"
  IMPORTED_STATE_FILES=" TOKEN MACHINE_ID"
  # The systemctl stub, for this run only.
  # shellcheck disable=SC2030,SC2031
  PATH="$MOVE/svcbin:$PATH"
  MOVE_RUNNER=$(sh -c 'echo "$PPID"')
  export MOVE_RUNNER
  rollback_user_takeover > "$MOVE/out" 2>&1
)
_rc=$?
check "--from-user rolls back what it installed, then the service, then restarts the user-level agent, through a second signal" \
  "$_rc|$(move_names "$MOVE/etc")|$(tr '\n' '|' < "$MOVE/svc.log")|$(grep -c 'runs again, unchanged' "$MOVE/out")" \
  "0|.env last_capture_id |systemctl stop fivenines-agent.service|systemctl disable fivenines-agent.service|start.sh||1"

# --from-user preflight: the argument it was given is never printed (a token
# passed out of habit would land in a job log), and the user side must have
# pgrep, which the stop needs to wait for the agent.
# Value: protects=--from-user never echoes a token given in place of a user name, and refuses a user with no pgrep before anything stops;
#   fails_when=an error message repeats FROM_USER_NAME, or the pgrep check is dropped (the state would be read while the agent may still write it);
#   why_new=the parser checks above stop at the usage line; seam=as_user is a function here;
#   no_claim=the checks after pgrep, or that the user's PATH under env -i is the one su gives
sed -n '/^STATE_FILES=/p;/^exit_with_contact()/,/^}/p;/^resolve_takeover_user()/,/^}/p
        /^preflight_user_takeover()/,/^}/p' "$ROOT/fivenines_setup.sh" > "$MOVE/preuser.sh"
# Runs the preflight for user $1, with as_user failing on a command that
# names pgrep when $2 is nopgrep. Prints its status and output on one line.
from_user_preflight() {
  (
    # shellcheck source=/dev/null
    . "$MOVE/preuser.sh"
    # Called by the preflight.
    # shellcheck disable=SC2317,SC2329
    as_user() {
      case "$1" in *pgrep*) [ "$_preuser_pgrep" != nopgrep ] ;; *) return 0 ;; esac
    }
    _preuser_pgrep=${2:-}
    FROM_USER_NAME=$1
    SYSTEM_TYPE=systemd
    # Test mode skips the stop, and so the check: $3 sets it.
    FIVENINES_TEST_MODE=${3:-}
    preflight_user_takeover
  ) 2>&1 | tr '\n' ' '
}
check "--from-user never repeats an argument that is not a user name" \
  "$(from_user_preflight 'tok:ab12cd34ef56' | grep -c 'ab12cd34ef56')|$(from_user_preflight 'tok-ab12cd34ef56' | grep -c 'ab12cd34ef56')" "0|0"
if [ ! -e /etc/fivenines_agent ] && command -v base64 > /dev/null 2>&1 && command -v setsid > /dev/null 2>&1; then
  check "--from-user refuses a user with no pgrep, and goes on with one, or in test mode" \
    "$(from_user_preflight "$(id -un)" nopgrep | grep -c 'needs pgrep')|$(from_user_preflight "$(id -un)" | grep -c 'Moving the user-level installation')|$(from_user_preflight "$(id -un)" nopgrep 1 | grep -c 'Moving the user-level installation')" "1|1|1"
fi

# --from-user: exit_with_contact, the exit of every failure, rolls the move
# back once the user-level agent was stopped.
# Value: protects=a failure after the user-level agent stopped puts it back;
#   fails_when=exit_with_contact stops calling rollback_user_takeover when TAKEOVER_ROLLBACK=1, or calls it before;
#   why_new=the check above calls rollback_user_takeover directly; seam=rollback_user_takeover is a stub here; no_claim=what it does
sed -n '/^exit_with_contact()/,/^}/p' "$ROOT/fivenines_setup.sh" > "$MOVE/ewc.sh"
ewc_run() {
  (
    # shellcheck source=/dev/null
    . "$MOVE/ewc.sh"
    # Called through exit_with_contact.
    # shellcheck disable=SC2317,SC2329
    rollback_user_takeover() { echo "rolled back"; }
    TAKEOVER_ROLLBACK=$1
    exit_with_contact "failed"
  ) 2>&1 | grep -c '^rolled back$'
}
check "a --from-user failure rolls back once the user-level agent was stopped, and only then" \
  "$(ewc_run 1)|$(ewc_run 0)" "1|0"

# --from-user: import_user_state outside test mode, through the su stub (it
# prints a PAM line first), with /etc/fivenines_agent rewritten to a scratch
# directory and chown stubbed: a test that is not root cannot give a file away.
# Value: protects=--from-user writes the user's state with the directory root's alone, gives it back, records each file before writing it so a rollback takes back a TOKEN whose chown failed, and refuses a symlinked or empty state file;
#   fails_when=IMPORTED_STATE_FILES is appended after the writes again, the directory is not made root-only around them or not given back, or a symlink or an empty TOKEN is carried;
#   why_new=the harness and test-distro import only plain files through a real chown; seam=/etc/fivenines_agent rewritten, chown stubbed;
#   no_claim=that the files end up owned by fivenines, or the ownership semantics a real chown enforces
sed -n '/^STATE_FILES=/p;/^STATE_FILE_MAX=/p;/^as_user()/,/^}/p;/^decode_state()/,/^}/p
        /^import_user_state()/,/^}/p;/^rollback_user_takeover()/,/^}/p' "$ROOT/fivenines_setup.sh" \
  | sed "s|/etc/fivenines_agent|$MOVE/etc2|g" > "$MOVE/import.sh"
mkdir -p "$MOVE/chownbin" "$MOVE/iuc"
cat > "$MOVE/chownbin/chown" << EOF
#!/bin/sh
echo "chown \$*" >> "$MOVE/chown.log"
[ "\$2" != "\${MOVE_CHOWN_FAILS:-}" ]
EOF
chmod 755 "$MOVE/chownbin/chown"
# Runs import_user_state from $MOVE/iuc into an empty $MOVE/etc2, and the
# rollback when it fails; a chown of $1 fails. Prints its status.
from_user_import() {
  rm -rf "$MOVE/etc2" "$MOVE/istage"
  mkdir -p "$MOVE/etc2" "$MOVE/istage"
  : > "$MOVE/chown.log"
  (
    # shellcheck source=/dev/null
    . "$MOVE/import.sh"
    FIVENINES_TEST_MODE=1
    FROM_USER_NAME=alice
    USER_CONFIG_DIR="$MOVE/iuc"
    USER_INSTALL_DIR="$MOVE/rbinst"
    WORK_DIR="$MOVE/istage"
    IMPORTED_STATE_FILES=""
    MOVE_CHOWN_FAILS="${1:-}"
    export MOVE_CHOWN_FAILS
    # The chown stub, for this run only.
    # shellcheck disable=SC2030,SC2031
    PATH="$MOVE/chownbin:$PATH"
    import_user_state > "$MOVE/out" 2>&1 || rollback_user_takeover >> "$MOVE/out" 2>&1
  )
  echo "$?"
}
printf 'per-host-token-0001' > "$MOVE/iuc/TOKEN"
printf '0b5e2d5c-6f1a-4c3e-9d2b-7a8f1e4c5d6a\n' > "$MOVE/iuc/MACHINE_ID"
printf 'nginx\n' > "$MOVE/iuc/journal_units.allow"
_rc=$(from_user_import)
check "--from-user writes the user's state with the directory root's alone, then gives it back" \
  "$_rc|$(move_names "$MOVE/etc2")|$(cat "$MOVE/etc2/TOKEN")|$(head -n 1 "$MOVE/chown.log")|$(tail -n 1 "$MOVE/chown.log")|$(move_mode "$MOVE/etc2")" \
  "0|MACHINE_ID TOKEN journal_units.allow |per-host-token-0001|chown 0:0 $MOVE/etc2|chown fivenines:fivenines $MOVE/etc2|750"
check "--from-user takes back a TOKEN whose chown failed, and gives the directory back" \
  "$(from_user_import "$MOVE/etc2/TOKEN")|$(move_names "$MOVE/etc2")|$(move_mode "$MOVE/etc2")|$(grep -c 'Could not install' "$MOVE/out")" \
  "0||750|1"
mv "$MOVE/iuc/journal_units.allow" "$MOVE/iuc.allow"
ln -s "$MOVE/iuc.allow" "$MOVE/iuc/journal_units.allow"
check "--from-user stops at a symlinked allowlist, and carries nothing" \
  "$(from_user_import)|$(move_names "$MOVE/etc2")|$(grep -c 'journal_units.allow is not a regular file' "$MOVE/out")" \
  "0||1"
rm -f "$MOVE/iuc/journal_units.allow"
: > "$MOVE/iuc/TOKEN"
check "--from-user stops at an empty TOKEN, and carries nothing" \
  "$(from_user_import)|$(move_names "$MOVE/etc2")|$(grep -c 'TOKEN is empty' "$MOVE/out")" \
  "0||1"

# --from-user: remove_user_installation, as fivenines_setup.sh runs it once
# the service started, on an installation whose directories hold other files.
# Value: protects=--from-user removes only what fivenines_setup_user.sh created, keeps .env and other files, and drops only the crontab lines starting it;
#   fails_when=the removal goes back to rm -rf of a directory, removes .env, or the crontab filter misses a spelling of start.sh or drops a line naming fivenines;
#   why_new=test-distro Test 12 removes an installation that holds nothing else, on an image with no crontab; seam=none;
#   no_claim=that it runs as the user (su is a stub here), or that the service started first
sed -n '/^STATE_FILES=/p;/^as_user()/,/^}/p;/^start_spellings()/,/^}/p
        /^remove_user_installation()/,/^}/p' "$ROOT/fivenines_setup.sh" > "$MOVE/from_user.sh"
MOVE_HOME="$MOVE/home/alice"
MOVE_UI="$MOVE_HOME/.local/fivenines"
MOVE_UC="$MOVE_HOME/.config/fivenines_agent"
mkdir -p "$MOVE_UI/fivenines-agent-linux-amd64" "$MOVE_UC"
for _f in start.sh stop.sh status.sh logs.sh refresh.sh agent.pid agent.log \
  fivenines-agent-linux-amd64/fivenines-agent-linux-amd64; do
  : > "$MOVE_UI/$_f"
done
printf 'the operator keeps notes here\n' > "$MOVE_UI/notes.txt"
for _f in TOKEN MACHINE_ID last_capture_id journal_units.allow image_inventory_done sudo_refusals .env; do
  printf '%s\n' "$_f" > "$MOVE_UC/$_f"
done
# The ~, $HOME and ${HOME} spellings are the literal text of crontab lines.
# shellcheck disable=SC2016
printf '%s\n' '0 * * * * echo other' "@reboot $MOVE_UI/start.sh" \
  '@reboot ~/.local/fivenines/start.sh' '@reboot $HOME/.local/fivenines/start.sh' \
  '@reboot ${HOME}/.local/fivenines/start.sh' '0 3 * * * /usr/local/bin/fivenines-db-backup' \
  > "$MOVE/crontab"
(
  # shellcheck source=/dev/null
  . "$MOVE/from_user.sh"
  FROM_USER_NAME=alice
  FROM_USER_HOME="$MOVE_HOME"
  USER_INSTALL_DIR="$MOVE_UI"
  USER_CONFIG_DIR="$MOVE_UC"
  remove_user_installation > "$MOVE/out" 2>&1
)
check "--from-user removes the installer's files only, and keeps .env" \
  "$(move_names "$MOVE_UI")|$(move_names "$MOVE_UC")|$(grep -c '^Kept ' "$MOVE/out")" \
  "notes.txt |.env |2"
check "--from-user drops the crontab lines that start it, however spelled, and only those" \
  "$(tr '\n' '|' < "$MOVE/crontab")" "0 * * * * echo other|0 3 * * * /usr/local/bin/fivenines-db-backup|"
# Value: protects=--from-user removes every file the user-level scripts write in their install directory;
#   fails_when=fivenines_setup_user.sh or fivenines_update_user.sh starts writing another $INSTALL_DIR file and remove_user_installation's list is not updated;
#   why_new=the removal check above creates its files from the same list it checks; seam=none;
#   no_claim=a file named through another variable than $INSTALL_DIR
# $INSTALL_DIR is the literal text searched for.
# shellcheck disable=SC2016
_written=$(grep -ho '\$INSTALL_DIR/[A-Za-z0-9_.-]*' "$ROOT/fivenines_setup_user.sh" "$ROOT/fivenines_update_user.sh" \
  | sed 's|^\$INSTALL_DIR/||;s|\.*$||' | grep . | LC_ALL=C sort -u | tr '\n' ' ')
_removed=$(sed -n '/^remove_user_installation()/,/^}/s/^ *for name in \(start\.sh .*\); do$/\1/p' "$ROOT/fivenines_setup.sh" \
  | tr ' ' '\n' | grep . | LC_ALL=C sort -u | tr '\n' ' ')
check "--from-user removes every file the user-level scripts write in their install directory" "$_removed" "$_written"

# --from-system: add_reboot_entry, the @reboot line that starts the moved
# agent at boot, as the system service did.
# Value: protects=--from-system adds one @reboot line for its start.sh after the user's own lines, and none when one (any spelling) is already there;
#   fails_when=the already-there check is dropped (two agents with one identity at boot), or the user's lines are lost or a blank line is added;
#   why_new=no test-distro image has a crontab command, so Test 13 takes the no-crontab branch; seam=none;
#   no_claim=what cron does with the line at boot
sed -n '/^start_spellings()/,/^}/p;/^add_reboot_entry()/,/^}/p' \
  "$ROOT/fivenines_setup_user.sh" > "$MOVE/reboot.sh"
# Runs add_reboot_entry for an installation in ~/.local/fivenines over the
# crontab $1 (- for none), and prints its status and the crontab after it.
reboot_entry() {
  rm -f "$MOVE/crontab"
  if [ "$1" != "-" ]; then printf '%s\n' "$1" > "$MOVE/crontab"; fi
  (
    # shellcheck source=/dev/null
    . "$MOVE/reboot.sh"
    HOME="$MOVE_HOME"
    INSTALL_DIR="$MOVE_HOME/.local/fivenines"
    add_reboot_entry > /dev/null 2>&1
  )
  printf '%s|%s' "$?" "$(tr '\n' '|' < "$MOVE/crontab" 2>/dev/null)"
}
check "--from-system starts the agent at boot for a user with no crontab" \
  "$(reboot_entry -)" "0|@reboot $MOVE_HOME/.local/fivenines/start.sh|"
check "--from-system adds its @reboot line after the user's own" \
  "$(reboot_entry '0 * * * * echo other')" "0|0 * * * * echo other|@reboot $MOVE_HOME/.local/fivenines/start.sh|"
# The ${HOME} is the literal text of the crontab line.
# shellcheck disable=SC2016
check "--from-system adds no second line for a start.sh the crontab already runs" \
  "$(reboot_entry '@reboot ${HOME}/.local/fivenines/start.sh')" '0|@reboot ${HOME}/.local/fivenines/start.sh|'
check "--from-system adds its line when the crontab has it only commented out" \
  "$(reboot_entry '#@reboot ~/.local/fivenines/start.sh')" "0|#@reboot ~/.local/fivenines/start.sh|@reboot $MOVE_HOME/.local/fivenines/start.sh|"

# fivenines_uninstall_user.sh, run whole from a scratch copy (it deletes
# itself) and confirmed with y, on an installation under a scratch HOME.
# Value: protects=the user uninstaller drops only this installation's crontab lines and signals only an agent run from its own directory;
#   fails_when=it goes back to grep -v fivenines on the crontab, or to pkill -f on the binary name or another unanchored pattern;
#   why_new=test-distro Test 11 runs it in test mode, which skips the stop, on an image with no crontab; seam=none;
#   no_claim=the removal of its two directories, which this branch does not change
MOVE_CAROL="$MOVE/home/carol"
mkdir -p "$MOVE_CAROL/.local/fivenines" "$MOVE_CAROL/.config/fivenines_agent" "$MOVE/run"
printf 'per-host-token-0001' > "$MOVE_CAROL/.config/fivenines_agent/TOKEN"
printf '#!/bin/sh\necho stop.sh >> "%s"\n' "$MOVE/stopped" > "$MOVE_CAROL/.local/fivenines/stop.sh"
printf '#!/bin/bash\nexport CONFIG_DIR="%s"\n' "$MOVE_CAROL/.config/fivenines_agent" > "$MOVE_CAROL/.local/fivenines/start.sh"
chmod 755 "$MOVE_CAROL/.local/fivenines/stop.sh" "$MOVE_CAROL/.local/fivenines/start.sh"
# Without a start.sh where it looks (an installation made with another
# FIVENINES_INSTALL_DIR), it refuses before touching anything.
# Value: protects=the user uninstaller never deletes a config dir (TOKEN) when it cannot find the installation that uses it;
#   fails_when=the start.sh check is dropped; why_new=new refusal; seam=none; no_claim=the message text
cp "$ROOT/fivenines_uninstall_user.sh" "$MOVE/run/fivenines_uninstall_user.sh"
(
  cd "$MOVE/run" || exit 99
  printf 'y\n' | HOME="$MOVE_CAROL" FIVENINES_TEST_MODE="" \
    FIVENINES_INSTALL_DIR="$MOVE_CAROL/elsewhere" FIVENINES_CONFIG_DIR="$MOVE_CAROL/.config/fivenines_agent" \
    sh ./fivenines_uninstall_user.sh > "$MOVE/out" 2>&1
)
check "fivenines_uninstall_user.sh refuses an install dir with no start.sh, and keeps the TOKEN" \
  "$?|$(cat "$MOVE_CAROL/.config/fivenines_agent/TOKEN" 2>/dev/null)" "1|per-host-token-0001"
# shellcheck disable=SC2016
printf '%s\n' '0 * * * * echo other' "@reboot $MOVE_CAROL/.local/fivenines/start.sh" \
  '@reboot ~/.local/fivenines/start.sh' '@reboot $HOME/.local/fivenines/start.sh' \
  '0 3 * * * /usr/local/bin/fivenines-db-backup' > "$MOVE/crontab"
cp "$ROOT/fivenines_uninstall_user.sh" "$MOVE/run/fivenines_uninstall_user.sh"
: > "$MOVE/refused"
(
  cd "$MOVE/run" || exit 99
  printf 'y\n' | HOME="$MOVE_CAROL" FIVENINES_TEST_MODE="" \
    FIVENINES_INSTALL_DIR="$MOVE_CAROL/.local/fivenines" FIVENINES_CONFIG_DIR="$MOVE_CAROL/.config/fivenines_agent" \
    sh ./fivenines_uninstall_user.sh > "$MOVE/out" 2>&1
)
check "fivenines_uninstall_user.sh drops the crontab lines that start it, and only those" \
  "$?|$(tr '\n' '|' < "$MOVE/crontab")" "0|0 * * * * echo other|0 3 * * * /usr/local/bin/fivenines-db-backup|"
check "fivenines_uninstall_user.sh stops its agent with an anchored pattern only" \
  "$(cat "$MOVE/stopped" 2>/dev/null)|$(cat "$MOVE/refused")" "stop.sh|"

# The control scripts write_control_scripts generates (fivenines_setup_user.sh,
# and fivenines_update_user.sh over an existing installation), run against a
# fake agent in a directory whose name holds a space, a +, a dot, both quotes
# and a dollar sign, beside what an unanchored or unescaped pattern would also
# have matched: the same agent where the + reads as "a" (+ unescaped) and
# where the dot reads as "x" (. unescaped), and a tail -f of a file in the
# agent's own directory (no anchor).
# Value: protects=stop.sh, status.sh and refresh.sh act only on the agent run from their own install dir, whatever its path holds;
#   fails_when=the scripts match the binary name anywhere again, the pattern loses its anchor or an escape, or its quoting breaks on a space or a quote;
#   why_new=no repo test runs the control scripts: test-distro checks only the update's exit code and the TOKEN; seam=none;
#   no_claim=start.sh, or stop.sh's fallback to agent.pid on a host without pgrep
if [ -z "$REAL_PGREP" ] || ! command -v bash > /dev/null 2>&1 || ! command -v ps > /dev/null 2>&1; then
  echo "  (the control scripts are not run: no pgrep, bash or ps here)"
else
  sed -n '/^agent_pattern()/,/^}/p;/^write_control_scripts()/,/^}/p' \
    "$ROOT/fivenines_setup_user.sh" > "$MOVE/control.sh"
  MOVE_PIDS=""
  trap 'kill $MOVE_PIDS 2> /dev/null; rm -rf "$WORK"' EXIT
  # Starts DIR's fake agent, or a tail -f of FILE, detached (so a stopped one
  # is reaped at once), and prints its PID once its command line is in place.
  # The agent ignores SIGHUP, which refresh.sh sends, and runs under its own
  # path as argv[0], as start.sh runs the real one.
  move_start() {
    # The $ in the single-quoted scripts are meant for the child shells.
    # shellcheck disable=SC2016
    if [ "$1" = agent ]; then
      _cmd="$2/fivenines-agent-linux-amd64/fivenines-agent-linux-amd64"
      mkdir -p "$2/fivenines-agent-linux-amd64"
      printf '#!/bin/bash\ntrap "" HUP\nexec -a "$0" sleep 300\n' > "$_cmd"
      chmod 755 "$_cmd"
      _pid=$(sh -c '"$0" > /dev/null 2>&1 & echo $!' "$_cmd")
      _cmd="$_cmd 300"
    else
      : > "$2"
      _pid=$(sh -c 'tail -f "$0" > /dev/null 2>&1 & echo $!' "$2")
      _cmd="tail -f $2"
    fi
    _tries=0
    while [ "$(ps -ww -o args= -p "$_pid" 2>/dev/null)" != "$_cmd" ] && [ "$_tries" -lt 10 ]; do
      sleep 1
      _tries=$((_tries + 1))
    done
    printf '%s' "$_pid"
  }
  # A PID still running, not a zombie waiting to be reaped.
  move_alive() {
    kill -0 "$1" 2> /dev/null && [ "$(ps -o stat= -p "$1" 2>/dev/null | cut -c1)" != "Z" ]
  }
  CTL_DIR="$MOVE/inst a+b.c o'b\"\$x"
  : > "$MOVE/refused"
  (
    # shellcheck source=/dev/null
    . "$MOVE/control.sh"
    INSTALL_DIR="$CTL_DIR"
    mkdir -p "$INSTALL_DIR"
    write_control_scripts > /dev/null
  )
  MOVE_AGENT=$(move_start agent "$CTL_DIR")
  MOVE_TWIN=$(move_start agent "$MOVE/inst aab.c o'b\"\$x")
  MOVE_ODD=$(move_start agent "$MOVE/inst a+bxc o'b\"\$x")
  MOVE_DECOY=$(move_start tail "$CTL_DIR/fivenines-agent-linux-amd64/agent.log")
  MOVE_PIDS="$MOVE_AGENT $MOVE_TWIN $MOVE_ODD $MOVE_DECOY"
  check "status.sh finds its own agent" \
    "$(bash "$CTL_DIR/status.sh" 2>&1 | head -n 1)" "Agent is running (PID: $MOVE_AGENT)"
  check "refresh.sh signals its own agent" \
    "$(bash "$CTL_DIR/refresh.sh" 2>&1)" \
    "Sent SIGHUP to agent (PID: $MOVE_AGENT) - capabilities will refresh"
  check "stop.sh stops its own agent" \
    "$(bash "$CTL_DIR/stop.sh" 2>&1)" "Agent stopped (PID: $MOVE_AGENT)"
  _tries=0
  while move_alive "$MOVE_AGENT" && [ "$_tries" -lt 5 ]; do
    sleep 1
    _tries=$((_tries + 1))
  done
  _alive=""
  for _pid in $MOVE_PIDS; do
    if move_alive "$_pid"; then _alive="${_alive}yes "; else _alive="${_alive}no "; fi
  done
  check "stop.sh spares the other installations and a tail -f of its own directory" \
    "$_alive" "no yes yes yes "
  check "status.sh then reports no agent" \
    "$(bash "$CTL_DIR/status.sh" 2>&1)" "Agent is not running"
  check "the control scripts asked pgrep only for anchored patterns" "$(cat "$MOVE/refused")" ""

  # An agent start.sh started under another spelling of the install dir (a
  # trailing slash here; a symlink does the same): its command line escapes
  # the path pattern, so only the PID start.sh recorded finds it.
  # fivenines_update_user.sh rewrites stop.sh with the spelling it was given,
  # while start.sh keeps its own, and the update then starts the agent again.
  # Value: protects=stop.sh stops the agent start.sh recorded even when it was started under another spelling of the install dir;
  #   fails_when=stop.sh trusts only the path pattern when pgrep exists (the update then starts a second agent with the same identity);
  #   why_new=the checks above start every agent under the dir's own spelling; seam=none;
  #   no_claim=a symlinked dir (same mechanism, not set up here)
  # The PID start.sh recorded is read through /proc (Linux only, like the
  # agent); elsewhere both checks are left out, not failed.
  if [ -r /proc/self/cmdline ]; then
    MOVE_SPELLED=$(move_start agent "$CTL_DIR/")
    MOVE_PIDS="$MOVE_PIDS $MOVE_SPELLED"
    printf '%s\n' "$MOVE_SPELLED" > "$CTL_DIR/agent.pid"
    check "stop.sh stops the agent start.sh recorded under another spelling of its directory" \
      "$(bash "$CTL_DIR/stop.sh" 2>&1)" "Agent stopped (PID: $MOVE_SPELLED)"
    _tries=0
    while move_alive "$MOVE_SPELLED" && [ "$_tries" -lt 5 ]; do
      sleep 1
      _tries=$((_tries + 1))
    done
    check "that agent is gone" "$(move_alive "$MOVE_SPELLED" && echo alive)" ""
    # A recorded PID the system has reused: a tail -f whose last argument reads
    # like an agent binary's path, which only the argv[0]-only check tells apart.
    # Value: protects=stop.sh never signals a recorded PID whose argv[0] is not an agent binary;
    #   fails_when=the /proc check is dropped or widened to the whole command line;
    #   why_new=the fallback above is new, and a PID file outlives its process; seam=none;
    #   no_claim=a reused PID that is another fivenines agent
    mkdir -p "$CTL_DIR/fivenines-agent-decoy"
    MOVE_REUSED=$(move_start tail "$CTL_DIR/fivenines-agent-decoy/fivenines-agent-decoy")
    MOVE_PIDS="$MOVE_PIDS $MOVE_REUSED"
    printf '%s\n' "$MOVE_REUSED" > "$CTL_DIR/agent.pid"
    check "stop.sh spares a reused PID whose argv[0] is not an agent" \
      "$(bash "$CTL_DIR/stop.sh" 2>&1)|$(move_alive "$MOVE_REUSED" && echo alive)" "Agent not running|alive"
  else
    echo "  (the agent.pid checks are not run: no /proc here)"
  fi

  # --from-user: stop_user_agent, which must stop every agent run from the
  # installation before its state is read, including one start.sh did not
  # record (there is no stop.sh here at all).
  # Value: protects=--from-user stops every agent run from the user's install dir, spares a tail -f of it, and never signals with a pattern not anchored on a path;
  #   fails_when=the pgrep/pkill loop or its anchored-pattern guard is dropped;
  #   why_new=test-distro Test 12 runs the move in test mode, which skips this stop; seam=none;
  #   no_claim=the refusal when an agent survives SIGKILL, or that it runs as the user (su is a stub here)
  sed -n '/^as_user()/,/^}/p;/^agent_pattern()/,/^}/p;/^stop_user_agent()/,/^}/p' \
    "$ROOT/fivenines_setup.sh" > "$MOVE/stop_user.sh"
  STOP_DIR="$MOVE/home/bob/.local/fivenines"
  : > "$MOVE/refused"
  MOVE_STRAY=$(move_start agent "$STOP_DIR")
  MOVE_STRAY_DECOY=$(move_start tail "$STOP_DIR/fivenines-agent-linux-amd64/agent.log")
  MOVE_PIDS="$MOVE_PIDS $MOVE_STRAY $MOVE_STRAY_DECOY"
  # Runs stop_user_agent on the installation $1, and prints its status.
  stop_user() {
    (
      # shellcheck source=/dev/null
      . "$MOVE/stop_user.sh"
      FROM_USER_NAME=bob
      USER_INSTALL_DIR="$1"
      stop_user_agent > /dev/null 2>&1
    )
    echo "$?"
  }
  _rc=$(stop_user "$STOP_DIR")
  _alive=""
  for _pid in $MOVE_STRAY $MOVE_STRAY_DECOY; do
    if move_alive "$_pid"; then _alive="${_alive}yes "; else _alive="${_alive}no "; fi
  done
  check "--from-user stops an agent start.sh did not record, and spares a tail -f of its directory" \
    "rc=$_rc|$_alive|$(cat "$MOVE/refused")" "rc=0|no yes |"
  check "--from-user stops nothing for an installation path that is not absolute" \
    "$(stop_user relative/fivenines)|$(cat "$MOVE/refused")" "1|"
  # Only the PIDs started above.
  # shellcheck disable=SC2086
  kill $MOVE_PIDS 2> /dev/null
  trap 'rm -rf "$WORK"' EXIT
fi

PATH=$MOVE_SAVED_PATH
fi

# --with-sudoers: write_sudoers_rules's exact entries for the md arrays
# /proc/mdstat lists (md0 among them, for sudo-rs), with /proc/mdstat,
# /etc/sudoers and /etc/sudoers.d rewritten to scratch files.
# Value: protects=an md array named with a dash or a dot gets its exact --detail entry, a name with a character a rule cannot carry gets none;
#   fails_when=the name check goes back to [A-Za-z0-9_] only, or lets a comma or a wildcard into a rule;
#   why_new=no test image has an md array; seam=paths rewritten, visudo, chown and sudoers_tool_path overridden;
#   no_claim=that a real visudo accepts the entries (test-sudo-mail checks the md0-md999 patterns on classic sudo)
SUD="$WORK/sudoers-md"
mkdir -p "$SUD/sudoers.d" "$SUD/work"
printf '%s\n' 'Personalities : [raid1]' 'md0 : active raid1 sdb1[1] sda1[0]' \
  'md_data-1 : active raid1 sdd1[1] sdc1[0]' 'md_home.0 : active raid1 sdf1[1] sde1[0]' \
  'md_a,b : active raid1 sdh1[1] sdg1[0]' 'unused devices: <none>' > "$SUD/mdstat"
: > "$SUD/sudoers"
sed -n '/^write_sudoers_rules()/,/^}/p' "$ROOT/fivenines_common.sh" \
  | sed "s|/proc/mdstat|$SUD/mdstat|g; s|/etc/sudoers.d|$SUD/sudoers.d|g; s|/etc/sudoers|$SUD/sudoers|g" \
  > "$SUD/write.sh"
# Runs the rewritten write_sudoers_rules, mdadm the only tool found, or no
# tool at all with $1 none.
md_rules_run() {
  _md_tools=${1:-}
  (
    # shellcheck source=/dev/null
    . "$SUD/write.sh"
    # Called by write_sudoers_rules.
    # shellcheck disable=SC2317,SC2329
    sudoers_tool_path() { [ "$1" = mdadm ] && [ "$_md_tools" != none ] && echo /sbin/mdadm; }
    # shellcheck disable=SC2317,SC2329
    visudo() { return 0; }
    # shellcheck disable=SC2317,SC2329
    chown() { return 0; }
    WORK_DIR="$SUD/work"
    write_sudoers_rules > "$SUD/out" 2>&1
  )
}
md_rules_run
check "--with-sudoers gives every command of the account root's HOME, before its rules" \
  "$(grep -v '^#' "$SUD/sudoers.d/fivenines" 2>/dev/null | head -n 1)" "Defaults:fivenines always_set_home"
# Value: protects=every listed array gets its exact --detail entry, md0 included, which is all sudo-rs can match (no [0-9] class);
#   fails_when=md0-md999 names are skipped again because the [0-9] patterns cover them on classic sudo;
#   why_new=sudo-rs ignores the patterns; seam=as above; no_claim=what sudo-rs matches (ci/test-sudo-mail.sh)
check "--with-sudoers gives md0 its exact --detail entry too, for sudo-rs" \
  "$(grep '^fivenines' "$SUD/sudoers.d/fivenines" 2>/dev/null | grep -c ', /sbin/mdadm --detail /dev/md0,\|, /sbin/mdadm --detail /dev/md0$')" "1"
check "--with-sudoers gives an md array named with a dash or a dot its exact --detail entry, and none to a name with a comma" \
  "$(grep '^fivenines' "$SUD/sudoers.d/fivenines" 2>/dev/null | grep -o ', /sbin/mdadm --detail /dev/md_[^,]*' | tr '\n' '|')|$(grep -c 'No sudoers entry for /dev/md_a,b' "$SUD/out")" \
  ", /sbin/mdadm --detail /dev/md_data-1|, /sbin/mdadm --detail /dev/md_home.0||1"
# Value: protects=a rerun that finds no tool it may grant withdraws the file an earlier run wrote, whose rules may name a tool that is no longer root's alone;
#   fails_when=the no-rule branch leaves /etc/sudoers.d/fivenines in place;
#   why_new=the check above writes a file; seam=as above; no_claim=an operator's file, which the marker check before it already leaves alone
md_rules_run none
check "--with-sudoers removes its earlier file when no tool may be granted any more" \
  "$([ -e "$SUD/sudoers.d/fivenines" ] && echo kept)|$(grep -c 'removed .*which an earlier run wrote' "$SUD/out")" "|1"

# warn_unpinned_sudoers_rules, over a fixed sudo -l -U listing.
# Value: protects=a bare mdadm or fail2ban-client rule sudo lists for the fivenines account is named at every install and update, a pinned one never;
#   fails_when=a bare item at the end of a line, before a comma or right after another bare one is missed, or an item with arguments is named;
#   why_new=new function; seam=sudo and id overridden; no_claim=real sudo's listing format (ci/test-sudo-mail.sh checks it)
sed -n '/^warn_unpinned_sudoers_rules()/,/^}/p' "$ROOT/fivenines_common.sh" > "$SUD/unpinned.sh"
# Prints what warn_unpinned_sudoers_rules says over the listing in $1.
unpinned_run() {
  _listing=$1
  (
    # shellcheck source=/dev/null
    . "$SUD/unpinned.sh"
    # Called by warn_unpinned_sudoers_rules.
    # shellcheck disable=SC2317,SC2329
    sudo() {
      printf '%s\n' 'Matching Defaults entries for fivenines on host:' \
        '    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/sbin\:/sbin' '' \
        'User fivenines may run the following commands on host:'
      cat "$_listing"
    }
    # shellcheck disable=SC2317,SC2329
    id() { return 0; }
    # timeout runs the sudo above, not a sudo binary.
    # shellcheck disable=SC2317,SC2329
    timeout() { shift; "$@"; }
    warn_unpinned_sudoers_rules
  ) 2>&1
}
printf '%s\n' '    (ALL) NOPASSWD: /usr/sbin/smartctl' '    (ALL) NOPASSWD: /sbin/mdadm' \
  '    (ALL) NOPASSWD: /usr/sbin/smartctl, /usr/bin/fail2ban-client ' > "$SUD/bare"
printf '%s\n' '    (ALL) NOPASSWD: /sbin/mdadm, /usr/bin/fail2ban-client' > "$SUD/adjacent"
printf '%s\n' '    (ALL) NOPASSWD: /usr/sbin/smartctl' \
  '    (ALL) NOPASSWD: /sbin/mdadm --version, /sbin/mdadm --detail /dev/md[0-9], /sbin/mdadm --detail /dev/md_data-1' \
  '    (ALL) NOPASSWD: /usr/bin/fail2ban-client version, /usr/bin/fail2ban-client status, /usr/bin/fail2ban-client status *' \
  '    (root) NOPASSWD: NOLOG_OUTPUT: /usr/bin/wg show all dump' > "$SUD/pinned"
check "the bare mdadm and fail2ban-client rules sudo lists are named, the pinned ones are not" \
  "$(unpinned_run "$SUD/bare" | grep -c 'run /sbin/mdadm /usr/bin/fail2ban-client with any arguments')|$(unpinned_run "$SUD/adjacent" | grep -c 'run /sbin/mdadm /usr/bin/fail2ban-client with any arguments')|$(unpinned_run "$SUD/pinned")" "1|1|"

# --with-sudoers: the paths a rule may name (fivenines_common.sh, held to its
# copies in fivenines_setup.sh and fivenines_update.sh by ci/build-scripts.sh).
# Value: protects=a sudoers rule never names a tool whose link chain or directories a user other than root can change, nor one found through the caller's PATH;
#   fails_when=root_only_chain resolves links first (readlink -f), root_only_path drops its write-bit tests, or sudoers_tool_path searches the caller's PATH;
#   why_new=test-sudo-mail and test-distro only ever offer it root-owned tools in root-only directories; seam=none;
#   no_claim=either write bit on its own, or a non-root link or file inside root-only directories (each needs root to set up)
sed -n '/^root_only_path()/,/^}/p;/^root_only_chain()/,/^}/p;/^sudoers_tool_path()/,/^}/p' \
  "$COMMON" > "$MOVE/sudoers_paths.sh"
mkdir -p "$MOVE/userbin"
ln -s /bin/sh "$MOVE/userbin/sh-link"
printf '#!/bin/sh\n' > "$MOVE/userbin/sh"
chmod 755 "$MOVE/userbin/sh"
(
  # shellcheck source=/dev/null
  . "$MOVE/sudoers_paths.sh"
  if [ -n "$(find / -prune -user 0 2>/dev/null)" ] && [ -n "$(find /bin/sh -prune -user 0 2>/dev/null)" ]; then
    root_only_chain /bin/sh
    check "a root-owned tool in root-only directories may get a rule" "$?" "0"
    _found=$(PATH="$MOVE/userbin:$PATH" sudoers_tool_path sh 2> /dev/null)
    case "$_found" in
      "$MOVE"/*|"") _found="not found in secure_path: '$_found'" ;;
      /usr/local/sbin/sh|/usr/local/bin/sh|/usr/sbin/sh|/usr/bin/sh|/sbin/sh|/bin/sh) _found=secure_path ;;
    esac
    check "sudoers_tool_path looks in sudo's secure_path, not the caller's PATH" "$_found" "secure_path"
  else
    echo "  (the root-owned cases are not run: / or /bin/sh is not owned by root here)"
  fi
  root_only_chain "$MOVE/userbin/sh-link"
  check "a link another user owns gets no rule, though its target is root's" "$?" "1"
  if [ ! -L /tmp ] && [ -n "$(find /tmp -prune -user 0 -perm -002 2>/dev/null)" ]; then
    root_only_chain /tmp
    check "a root-owned directory anyone can write to gets no rule" "$?" "1"
  else
    echo "  (the world-writable case is not run: /tmp is not a root-owned, world-writable directory here)"
  fi
  _out=$(sudoers_tool_path fivenines-no-such-tool-170 2>&1)
  check "a tool that is not installed gets no rule" "$?|$_out" "1|"
  # A host with no find (rockylinux:8's image ships no findutils): nothing
  # can be checked, so nothing is granted, and the warning says why. PATH is
  # empty only for that call; the lookup tests the files themselves.
  _out=$(PATH=/nonexistent sudoers_tool_path sh 2>&1)
  check "a host with no find gets no rule, and is told find is missing" \
    "$?|$(printf '%s' "$_out" | grep -c 'find (findutils) is not installed')" "1|1"
  # The checks above ran in this subshell: carry their counts out.
  echo "$PASS $FAIL" > "$MOVE/counts"
)
read -r PASS FAIL < "$MOVE/counts"

if ! command -v openssl > /dev/null 2>&1; then
  echo "openssl not available - skipping the signed cases"
  echo ""
  echo "PASS=$PASS FAIL=$FAIL"
  [ "$FAIL" -eq 0 ] || exit 1
  exit 0
fi

# The embedded key has to be something OpenSSL will actually load, on the
# right curve: a mangled paste would fail closed on every host in the fleet.
printf '%s\n' "$EMBEDDED" > "$WORK/embedded.pub"
openssl pkey -pubin -in "$WORK/embedded.pub" -noout 2>/dev/null
check "the embedded key parses as a public key" "$?" "0"
check "the embedded key is on the P-256 curve" \
  "$(openssl pkey -pubin -in "$WORK/embedded.pub" -text -noout 2>/dev/null | grep -c prime256v1)" "1"

# With a key armed, a stripped signature must be FATAL. If it degraded to
# "cannot check" an attacker would downgrade the release by deleting one file.
verify_sums_signature "$WORK/SHA256SUMS" "$WORK/SHA256SUMS.sig" > /dev/null 2>&1
check "stripping the signature is fatal, not a downgrade" "$?" "1"

# Emptying the block is the documented rotation escape hatch, and it must
# report "cannot check" (2) rather than "verified" (0).
# Both codes: shellcheck 0.9 (what CI installs from apt) reports SC2317 here,
# newer releases report SC2329. Either way the override IS reached - through
# verify_sums_signature, which shellcheck cannot follow.
# shellcheck disable=SC2317,SC2329
release_signing_pubkey() { :; }
verify_sums_signature "$WORK/SHA256SUMS" "$WORK/SHA256SUMS.sig" > /dev/null 2>&1
check "an empty key reports 'cannot check', never 'ok'" "$?" "2"

openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/test.key" 2>/dev/null
openssl ec -in "$WORK/test.key" -pubout -out "$WORK/test.pub" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/other.key" 2>/dev/null
openssl ec -in "$WORK/other.key" -pubout -out "$WORK/other.pub" 2>/dev/null

# Arm the trust anchor with the throwaway key.
TEST_PUBKEY=$(cat "$WORK/test.pub")
release_signing_pubkey() { printf '%s\n' "$TEST_PUBKEY"; }

openssl dgst -sha256 -sign "$WORK/test.key" -out "$WORK/SHA256SUMS.sig" "$WORK/SHA256SUMS"

verify_sums_signature "$WORK/SHA256SUMS" "$WORK/SHA256SUMS.sig" > /dev/null 2>&1
check "a genuine signature verifies" "$?" "0"

check "the scratch public key is cleaned up" \
  "$(ls "$WORK/SHA256SUMS.pub" 2>/dev/null || echo gone)" "gone"

# A mirror that rewrote the manifest but cannot re-sign it.
cp "$WORK/SHA256SUMS" "$WORK/SHA256SUMS.orig"
printf 'cafebabe  fivenines-agent-linux-amd64.tar.gz\n' > "$WORK/SHA256SUMS"
verify_sums_signature "$WORK/SHA256SUMS" "$WORK/SHA256SUMS.sig" > /dev/null 2>&1
check "a tampered manifest is rejected" "$?" "1"
cp "$WORK/SHA256SUMS.orig" "$WORK/SHA256SUMS"

# A manifest signed with some other key.
openssl dgst -sha256 -sign "$WORK/other.key" -out "$WORK/SHA256SUMS.sig" "$WORK/SHA256SUMS"
verify_sums_signature "$WORK/SHA256SUMS" "$WORK/SHA256SUMS.sig" > /dev/null 2>&1
check "a signature from another key is rejected" "$?" "1"

# Stripping the signature must not silently downgrade to checksum-only once
# the key is armed.
: > "$WORK/SHA256SUMS.sig"
verify_sums_signature "$WORK/SHA256SUMS" "$WORK/SHA256SUMS.sig" > /dev/null 2>&1
check "an empty signature file is fatal, not a downgrade" "$?" "1"

rm -f "$WORK/SHA256SUMS.sig"
verify_sums_signature "$WORK/SHA256SUMS" "$WORK/SHA256SUMS.sig" > /dev/null 2>&1
check "a missing signature file is fatal, not a downgrade" "$?" "1"

# ---------------------------------------------------------------------------
# A host with no openssl (issue #154)
#
# "I could not check the signature" used to be reported as the same outcome as
# "there is no key to check it against", and both fell back to the checksum.
# The first is now its own status and is fatal by default: a digest read out
# of a manifest nobody authenticated proves only that the mirror agrees with
# itself.
# ---------------------------------------------------------------------------

# `command` is a regular built-in, so a function shadows it. Defined inside a
# subshell per case so the override never leaks into a later check.
no_openssl_command() {
  [ "$1" = "-v" ] || return 127
  [ "$2" = "openssl" ] && return 1
  for dir in $(printf '%s' "$PATH" | tr ':' ' '); do
    if [ -x "$dir/$2" ]; then printf '%s\n' "$dir/$2"; return 0; fi
  done
  return 1
}

openssl dgst -sha256 -sign "$WORK/test.key" -out "$WORK/SHA256SUMS.sig" "$WORK/SHA256SUMS"

(
  # shellcheck disable=SC2317,SC2329
  command() { no_openssl_command "$@"; }
  verify_sums_signature "$WORK/SHA256SUMS" "$WORK/SHA256SUMS.sig" > /dev/null 2>&1
)
check "no openssl is its own status, not 'no key embedded'" "$?" "3"

# ---------------------------------------------------------------------------
# verify_from_manifest: the shared policy both the tarball and the startup
# definitions go through.
# ---------------------------------------------------------------------------

MIRROR="$WORK/mirror"
mkdir -p "$MIRROR"
DOWNLOAD_SOURCE="r2"

# A mirror double: download_with_fallback / download_release_file are the two
# seams every installer fills in with wget or curl.
# shellcheck disable=SC2317,SC2329
download_release_file() { cp "$MIRROR/$1" "$2" 2>/dev/null; }
# shellcheck disable=SC2317,SC2329
download_with_fallback() {
  DOWNLOAD_SOURCE="r2"
  cp "$MIRROR/$1" "$2" 2>/dev/null
}

publish_mirror() {
  ( cd "$MIRROR" && find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' -exec sha256sum {} + \
      | sed 's| \./| |' > SHA256SUMS )
  openssl dgst -sha256 -sign "$WORK/test.key" -out "$MIRROR/SHA256SUMS.sig" "$MIRROR/SHA256SUMS"
}

printf 'ExecStart=/opt/fivenines/fivenines_agent\n' > "$MIRROR/fivenines-agent.service"
printf 'agent bytes\n' > "$MIRROR/fivenines-agent-linux-amd64.tar.gz"
publish_mirror

cp "$MIRROR/fivenines-agent.service" "$WORK/staged.service"
verify_from_manifest "$WORK/staged.service" "fivenines-agent.service" > /dev/null 2>&1
check "a genuine artifact verifies against the signed manifest" "$?" "0"

printf 'ExecStart=/tmp/evil\n' > "$WORK/staged.service"
verify_from_manifest "$WORK/staged.service" "fivenines-agent.service" > /dev/null 2>&1
check "a swapped artifact is rejected" "$?" "1"

cp "$MIRROR/fivenines-agent.service" "$WORK/staged.service"
verify_from_manifest "$WORK/staged.service" "not-in-the-manifest" > /dev/null 2>&1
check "an artifact missing from the manifest is rejected" "$?" "1"

# A mirror that rewrote both the file and the manifest, but cannot re-sign.
cp "$MIRROR/SHA256SUMS.sig" "$WORK/genuine.sig"
printf 'ExecStart=/tmp/evil\n' > "$MIRROR/fivenines-agent.service"
publish_mirror
cp "$WORK/genuine.sig" "$MIRROR/SHA256SUMS.sig"
cp "$MIRROR/fivenines-agent.service" "$WORK/staged.service"
verify_from_manifest "$WORK/staged.service" "fivenines-agent.service" > /dev/null 2>&1
check "a rewritten manifest with a stale signature is rejected" "$?" "1"

# Back to a consistent, genuinely signed mirror.
printf 'ExecStart=/opt/fivenines/fivenines_agent\n' > "$MIRROR/fivenines-agent.service"
publish_mirror

cp "$MIRROR/fivenines-agent.service" "$WORK/staged.service"
(
  # shellcheck disable=SC2317,SC2329
  command() { no_openssl_command "$@"; }
  verify_from_manifest "$WORK/staged.service" "fivenines-agent.service" > /dev/null 2>&1
)
check "without openssl the install fails closed by default" "$?" "1"

cp "$MIRROR/fivenines-agent.service" "$WORK/staged.service"
(
  # shellcheck disable=SC2317,SC2329
  command() { no_openssl_command "$@"; }
  FIVENINES_ALLOW_UNSIGNED=1 verify_from_manifest "$WORK/staged.service" "fivenines-agent.service" > /dev/null 2>&1
)
check "FIVENINES_ALLOW_UNSIGNED=1 is the documented way through" "$?" "0"

# ---------------------------------------------------------------------------
# verification_preflight: the check that has to fail BEFORE the updater stops
# the agent. "No openssl" is deterministic per host, so without this every
# update on a minimal image would stop the agent and then refuse.
# ---------------------------------------------------------------------------

verification_preflight > /dev/null 2>&1
check "an openssl-capable host passes preflight" "$?" "0"

(
  # shellcheck disable=SC2317,SC2329
  command() { no_openssl_command "$@"; }
  verification_preflight > /dev/null 2>&1
)
check "a host with no openssl is refused before anything is touched" "$?" "1"

(
  # shellcheck disable=SC2317,SC2329
  command() { no_openssl_command "$@"; }
  FIVENINES_ALLOW_UNSIGNED=1 verification_preflight > /dev/null 2>&1
)
check "FIVENINES_ALLOW_UNSIGNED=1 passes preflight without openssl" "$?" "0"

(
  # shellcheck disable=SC2317,SC2329
  command() { no_openssl_command "$@"; }
  FIVENINES_AGENT_SHA256=deadbeef verification_preflight > /dev/null 2>&1
)
check "an operator-pinned digest needs no openssl" "$?" "0"

(
  # shellcheck disable=SC2317,SC2329
  command() { no_openssl_command "$@"; }
  # shellcheck disable=SC2317,SC2329
  release_signing_pubkey() { :; }
  verification_preflight > /dev/null 2>&1
)
check "no embedded key needs no openssl" "$?" "0"

(
  # shellcheck disable=SC2317,SC2329
  command() { no_openssl_command "$@"; }
  FIVENINES_AGENT_SHA256=deadbeef verification_preflight "with-startup-files" > /dev/null 2>&1
)
check "a pinned digest does NOT exempt a host that installs startup files" "$?" "1"

# ...but test mode installs no startup definition at all, so demanding openssl
# there would only turn the release matrix red on images without the CLI.
(
  # shellcheck disable=SC2317,SC2329
  command() { no_openssl_command "$@"; }
  FIVENINES_TEST_MODE=1 FIVENINES_AGENT_SHA256=deadbeef verification_preflight "with-startup-files" > /dev/null 2>&1
)
check "test mode installs no startup files, so a pinned digest is enough" "$?" "0"

(
  # shellcheck disable=SC2317,SC2329
  command() { no_openssl_command "$@"; }
  FIVENINES_TEST_MODE=1 verification_preflight "with-startup-files" > /dev/null 2>&1
)
check "test mode without a pinned digest still needs a verifiable release" "$?" "1"

for _script in fivenines_setup.sh fivenines_update.sh fivenines_setup_user.sh fivenines_update_user.sh; do
  check "${_script} runs the preflight" \
    "$(grep -c '^verification_preflight ' "$ROOT/${_script}")" "1"
done

check "the update script preflights BEFORE it stops the agent" \
  "$(awk '/^verification_preflight / {pf=NR} /Stopping fivenines-agent service/ {if (pf && pf < NR) print "yes"; exit}' "$ROOT/fivenines_update.sh")" "yes"

# ---------------------------------------------------------------------------
# verify_agent_tarball: the tarball's three early returns, which bypass the
# manifest entirely. The last one is deliberately the OPPOSITE of
# install_verified_release_file's answer to the same condition (a tarball from
# an unknown source warns and installs, a startup definition is refused), so
# both sides need pinning or a future edit flips one silently.
# ---------------------------------------------------------------------------

cp "$MIRROR/fivenines-agent-linux-amd64.tar.gz" "$WORK/agent.tgz"
GOOD_SHA=$(sha256sum "$WORK/agent.tgz" | cut -d' ' -f1)

FIVENINES_AGENT_SHA256="$GOOD_SHA" verify_agent_tarball "$WORK/agent.tgz" "x" > /dev/null 2>&1
check "an operator-pinned digest that matches is accepted" "$?" "0"

FIVENINES_AGENT_SHA256=deadbeef verify_agent_tarball "$WORK/agent.tgz" "x" > /dev/null 2>&1
check "an operator-pinned digest that mismatches is fatal" "$?" "1"

FIVENINES_SKIP_VERIFY=1 verify_agent_tarball "$WORK/agent.tgz" "x" > /dev/null 2>&1
check "FIVENINES_SKIP_VERIFY=1 waives the tarball check" "$?" "0"

(
  DOWNLOAD_SOURCE=""
  verify_agent_tarball "$WORK/agent.tgz" "x" > /dev/null 2>&1
)
check "a tarball from no known mirror warns but installs" "$?" "0"

verify_agent_tarball "$WORK/agent.tgz" "fivenines-agent-linux-amd64.tar.gz" > /dev/null 2>&1
check "a mirror-served tarball goes through the manifest" "$?" "0"

# ---------------------------------------------------------------------------
# install_verified_release_file: the systemd unit / OpenRC script / UNRAID
# boot script path. A startup definition runs as root at every boot, so an
# unverified one must never reach its destination (issue #154).
# ---------------------------------------------------------------------------

WORK_DIR="$WORK/stage"
mkdir -p "$WORK_DIR"
GITHUB_RELEASES_URL="https://example.invalid/releases"
DEST="$WORK/dest/fivenines-agent.service"

# A destination directory that does not exist is a clean refusal, not an
# invented /etc/systemd/system on a host that runs no systemd.
install_verified_release_file "fivenines-agent.service" "$DEST" 644 > /dev/null 2>&1
check "a missing destination directory is refused" "$?" "1"

mkdir -p "$WORK/dest"
install_verified_release_file "fivenines-agent.service" "$DEST" 644 > /dev/null 2>&1
check "a verified unit is installed" "$?" "0"
check "the installed unit is the published one" \
  "$(cat "$DEST" 2>/dev/null)" "ExecStart=/opt/fivenines/fivenines_agent"
# GNU stat first, BSD stat second, so the harness runs on either.
file_mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null; }
check "the installed unit is mode 644" "$(file_mode "$DEST")" "644"

# The mirror now serves a unit the manifest does not cover.
printf 'ExecStart=/tmp/evil\n' > "$MIRROR/fivenines-agent.service"
install_verified_release_file "fivenines-agent.service" "$DEST" 644 > /dev/null 2>&1
check "a tampered unit is refused" "$?" "1"
check "a refused unit leaves the installed one untouched" \
  "$(cat "$DEST" 2>/dev/null)" "ExecStart=/opt/fivenines/fivenines_agent"
check "a refused unit leaves nothing staged" \
  "$(find "$WORK_DIR" -mindepth 1 2>/dev/null | wc -l | tr -d ' ')" "0"

# ---------------------------------------------------------------------------
# verify_from_manifest: the remaining policy branches.
#
# Every one of these decides whether root installs bytes it could not
# authenticate, so each outcome is pinned rather than inferred from the two
# happy cases above.
# ---------------------------------------------------------------------------

# Back to a clean, consistently signed mirror (the install checks above left
# a tampered unit behind on purpose).
printf 'ExecStart=/opt/fivenines/fivenines_agent\n' > "$MIRROR/fivenines-agent.service"
publish_mirror
cp "$MIRROR/fivenines-agent.service" "$WORK/staged.service"

# A mirror that serves the artifact but not the manifest cannot prove
# anything, so there is nothing to fall back to.
(
  # shellcheck disable=SC2317,SC2329
  download_release_file() { [ "$1" = "SHA256SUMS" ] && return 1; cp "$MIRROR/$1" "$2" 2>/dev/null; }
  verify_from_manifest "$WORK/staged.service" "fivenines-agent.service" > /dev/null 2>&1
)
check "an unreachable manifest is fatal" "$?" "1"

# Deleting one file must not be a downgrade: the signature is fetched
# unconditionally and its absence is fatal, not "cannot check".
mv "$MIRROR/SHA256SUMS.sig" "$WORK/parked.sig"
verify_from_manifest "$WORK/staged.service" "fivenines-agent.service" > /dev/null 2>&1
check "a mirror that drops SHA256SUMS.sig is rejected" "$?" "1"
mv "$WORK/parked.sig" "$MIRROR/SHA256SUMS.sig"

# The rotation escape hatch, at the policy layer: no key embedded degrades to
# checksum-only rather than bricking every install mid-rotation.
cp "$MIRROR/fivenines-agent.service" "$WORK/staged.service"
(
  # shellcheck disable=SC2317,SC2329
  release_signing_pubkey() { :; }
  verify_from_manifest "$WORK/staged.service" "fivenines-agent.service" > /dev/null 2>&1
)
check "no embedded key degrades to checksum-only" "$?" "0"

# ...but an operator who demands a signature gets a refusal instead.
(
  # shellcheck disable=SC2317,SC2329
  release_signing_pubkey() { :; }
  FIVENINES_REQUIRE_SIGNATURE=1 verify_from_manifest "$WORK/staged.service" "fivenines-agent.service" > /dev/null 2>&1
)
check "FIVENINES_REQUIRE_SIGNATURE=1 refuses an unsigned install" "$?" "1"

# The opt-out skips the SIGNATURE, never the checksum. If it returned early
# instead, a host with no openssl would install whatever the mirror served.
printf 'ExecStart=/tmp/evil\n' > "$WORK/staged.service"
(
  # shellcheck disable=SC2317,SC2329
  command() { no_openssl_command "$@"; }
  FIVENINES_ALLOW_UNSIGNED=1 verify_from_manifest "$WORK/staged.service" "fivenines-agent.service" > /dev/null 2>&1
)
check "FIVENINES_ALLOW_UNSIGNED=1 still enforces the checksum" "$?" "1"

# The downloaded manifest and signature are scratch: they live next to the
# staged file inside the work dir, and every path removes them.
cp "$MIRROR/fivenines-agent.service" "$WORK/staged.service"
verify_from_manifest "$WORK/staged.service" "fivenines-agent.service" > /dev/null 2>&1
check "a verified artifact leaves no manifest droppings" \
  "$(ls "$WORK/staged.service.SHA256SUMS" "$WORK/staged.service.SHA256SUMS.sig" 2>/dev/null || echo gone)" "gone"

# ---------------------------------------------------------------------------
# install_verified_release_file: the remaining branches.
# ---------------------------------------------------------------------------

# Restore the destination to the published unit: the tamper check above left
# it in place, which is exactly what the next checks compare against.
printf 'ExecStart=/opt/fivenines/fivenines_agent\n' > "$MIRROR/fivenines-agent.service"
publish_mirror
install_verified_release_file "fivenines-agent.service" "$DEST" 644 > /dev/null 2>&1

# A mirror that serves nothing at all: no install, and the working unit that
# is already on disk is left alone.
install_verified_release_file "not-published-at-all" "$DEST" 644 > /dev/null 2>&1
check "a failed download installs nothing" "$?" "1"
check "a failed download leaves the installed unit untouched" \
  "$(cat "$DEST" 2>/dev/null)" "ExecStart=/opt/fivenines/fivenines_agent"

# A download that succeeded from no known mirror cannot be verified against
# any manifest, so it must be refused rather than trusted.
(
  # shellcheck disable=SC2317,SC2329
  download_with_fallback() { DOWNLOAD_SOURCE=""; cp "$MIRROR/$1" "$2" 2>/dev/null; }
  install_verified_release_file "fivenines-agent.service" "$DEST" 644 > /dev/null 2>&1
)
check "an artifact from no known mirror is refused" "$?" "1"

# The documented escape hatch installs without a check, and says so.
printf 'ExecStart=/tmp/unverified\n' > "$MIRROR/fivenines-agent.service"
FIVENINES_SKIP_VERIFY=1 install_verified_release_file "fivenines-agent.service" "$DEST" 644 > /dev/null 2>&1
check "FIVENINES_SKIP_VERIFY=1 installs without verifying" "$?" "0"
check "the skipped-verify install really wrote the file" \
  "$(cat "$DEST" 2>/dev/null)" "ExecStart=/tmp/unverified"

# UNRAID's /boot is vfat: chmod there fails, and a verified, correctly
# installed boot script must not be reported as a failed install because of
# a mode the filesystem cannot represent.
printf 'ExecStart=/opt/fivenines/fivenines_agent\n' > "$MIRROR/fivenines-agent.service"
publish_mirror
(
  # shellcheck disable=SC2317,SC2329
  chmod() { return 1; }
  install_verified_release_file "fivenines-agent.service" "$DEST" 644 > /dev/null 2>&1
)
check "a filesystem that cannot chmod is still a successful install" "$?" "0"
check "the un-chmod-able install still wrote the verified bytes" \
  "$(cat "$DEST" 2>/dev/null)" "ExecStart=/opt/fivenines/fivenines_agent"

# ---------------------------------------------------------------------------
# Wiring: the call sites, not just the helper.
#
# ci/test-distro.sh runs the installers with FIVENINES_TEST_MODE=1, which
# skips service setup entirely, so nothing else in CI ever looks at HOW a
# startup definition gets installed. These two checks are the #154 regression
# guard: the fix unwinds silently if a raw-branch URL comes back, or if one
# definition goes back to being written straight to its final path.
# ---------------------------------------------------------------------------

# Nothing signs a moving branch, so a startup definition fetched from raw
# main could never be verified - that URL is gone on purpose.
printf 'ExecStart=/opt/fivenines/fivenines_agent\n' > "$MIRROR/fivenines-agent.service"
publish_mirror
(
  # shellcheck disable=SC2317,SC2329
  mv() { return 1; }
  install_verified_release_file "fivenines-agent.service" "$DEST" 644 > /dev/null 2>&1
)
check "a destination that cannot be written is a failed install" "$?" "1"
check "a failed mv leaves nothing staged" \
  "$(find "$WORK_DIR" -mindepth 1 2>/dev/null | wc -l | tr -d ' ')" "0"

# T9: the release workflow is what puts the three startup definitions under
# SHA256SUMS in the first place. The mirror double above is synthetic, so
# dropping a cp or an upload line would leave this harness at 40/40 while
# every GitHub-fallback install hard-fails on "not listed in the published
# SHA256SUMS". fivenines_uninstall.sh likewise: fivenines_setup_user.sh
# --from-system verifies it before running it as root.
WORKFLOW="$ROOT/.github/workflows/build-release.yml"
for asset in fivenines-agent.service fivenines-agent.openrc fivenines_script.sh fivenines_uninstall.sh; do
  check "${asset} is staged into both release jobs" \
    "$(grep -c "cp ${asset} release/" "$WORKFLOW")" "2"
  check "${asset} is uploaded by both release jobs" \
    "$(grep -c "release/${asset}\$" "$WORKFLOW")" "2"
done

check "no installer fetches from the unsigned main-branch URL" \
  "$(grep -l 'GITHUB_RAW_URL' "$ROOT/fivenines_setup.sh" "$ROOT/fivenines_update.sh" \
       "$ROOT/fivenines_setup_user.sh" "$ROOT/fivenines_update_user.sh" 2>/dev/null \
     | wc -l | tr -d ' ')" "0"

# Every startup definition the system installers place must go through the
# verified helper, at the right destination, and be guarded: an unguarded
# call would install nothing and carry on to restart the agent anyway.
verified_installs=0
for spec in \
  "fivenines_setup.sh fivenines-agent.service /etc/systemd/system/fivenines-agent.service" \
  "fivenines_setup.sh fivenines-agent.openrc /etc/init.d/fivenines-agent" \
  "fivenines_setup.sh fivenines_script.sh /boot/config/custom/fivenines_agent/fivenines_boot" \
  "fivenines_update.sh fivenines-agent.service /etc/systemd/system/fivenines-agent.service" \
  "fivenines_update.sh fivenines-agent.openrc /etc/init.d/fivenines-agent"; do
  # The specs are deliberately word-split into script/asset/destination.
  # shellcheck disable=SC2086
  set -- $spec
  block=$(grep -A3 "install_verified_release_file \"$2\"" "$ROOT/$1" 2>/dev/null)
  if printf '%s\n' "$block" | grep -q -- "$3" \
     && printf '%s\n' "$block" | grep -q '||'; then
    verified_installs=$((verified_installs + 1))
  fi
done
check "every startup definition lands through the verified installer" \
  "$verified_installs" "5"

echo ""
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
