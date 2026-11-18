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
  "fivenines_setup.sh --yes test-token-arch-170|usage" \
  "fivenines_setup.sh --from-user someone --yes --with-sudoers|refused" \
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

# Not root: fivenines_setup.sh refuses before the architecture check, the
# lock or anything else (#314). The same box, with an id answering a uid
# that is not 0.
# Value: protects=fivenines_setup.sh run by a user who is not root changes nothing, a move included;
#   fails_when=the root check moves after a step that changes the host, or is dropped;
#   why_new=the armv7l box answers id -u with 0; seam=id stubbed; no_claim=what root's run does
mkdir -p "$ARCH_BOX/notroot"
# shellcheck disable=SC2016
printf '#!/bin/sh\n[ "$*" = "-u" ] && { echo 1000; exit 0; }\necho id >> "%s"\nexit 1\n' \
  "$ARCH_BOX/touched" > "$ARCH_BOX/notroot/id"
chmod 755 "$ARCH_BOX/notroot/id"
for _run in "fivenines_setup.sh --from-user someone --with-sudoers" "fivenines_setup.sh test-token-arch-170"; do
  _script=${_run%% *}
  cp "$ROOT/$_script" "$ARCH_BOX/run/$_script"
  : > "$ARCH_BOX/touched"
  (
    cd "$ARCH_BOX/run" || exit 99
    # The arguments after the script name are deliberately word-split.
    # shellcheck disable=SC2086
    HOME="$ARCH_BOX" PATH="$ARCH_BOX/notroot:$ARCH_BOX/bin:$PATH" sh "./$_script" ${_run#* } > "$ARCH_BOX/out" 2>&1
  )
  _rc=$?
  check "${_run} run by a user who is not root refuses and touches nothing" \
    "exit=$_rc refused=$(grep -c 'This script must be run as root' "$ARCH_BOX/out") touched=$(tr '\n' ' ' < "$ARCH_BOX/touched")" \
    "exit=1 refused=1 touched="
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
# Every script prints its messages as they are: through printf %b, a
# backslash sequence in a path a message names (a directory another account
# chose, read by root) became an escape.
# Value: protects=no message of the installers turns a backslash sequence of a path it names into an escape;
#   fails_when=a print_* helper passes its message through %b again;
#   why_new=every other message here holds no backslash; seam=none; no_claim=the colours
_print_raw=""
for _script in fivenines_setup.sh fivenines_setup_user.sh fivenines_update.sh fivenines_update_user.sh \
  fivenines_uninstall_user.sh fivenines_common.sh; do
  sed -n '/^RED=/p;/^GREEN=/p;/^YELLOW=/p;/^NC=/p;/^print_success()/,/^}/p;/^print_warning()/,/^}/p;/^print_error()/,/^}/p' \
    "$ROOT/$_script" > "$WORK/print.sh"
  for _helper in print_success print_warning print_error; do
    grep -q "^$_helper()" "$WORK/print.sh" || continue
    # The $ are for the child shell.
    # shellcheck disable=SC2016
    _printed=$(sh -c '. "$1"; "$2" "$3"' sh "$WORK/print.sh" "$_helper" 'C:\new\x41\033[2J')
    case "$_printed" in
      *' C:\new\x41\033[2J') ;;
      *) _print_raw="$_print_raw$_script:$_helper " ;;
    esac
  done
done
check "every script prints its messages as they are, backslashes included" "$_print_raw" ""
# And no other printf %b in them takes anything but the colour variables.
check "no script passes anything but its colour variables through printf %b" \
  "$(grep -n "printf '%b" "$ROOT"/fivenines_*.sh | grep "printf '%b\\\\n'" \
    | sed -E 's/\$\{(RED|GREEN|YELLOW|BLUE|NC)\}//g' | grep '\$')" ""
check "fivenines_update.sh writes the sudoers rules before it restarts the agent" \
  "$(in_order "$ROOT/fivenines_update.sh" 'write_sudoers_rules || SUDOERS_SKIPPED=1' 'Restarting fivenines-agent service')" "yes"
check "fivenines_setup.sh --from-user: checks, stop, state, sudoers rules, service, then removal" \
  "$(in_order "$ROOT/fivenines_setup.sh" 'Testing connectivity...' '    if ! stop_user_agent; then' '  import_user_state ||' '  write_sudoers_rules || SUDOERS_SKIPPED=1' '      setup_systemd' '  remove_user_installation')" "yes"
# Value: protects=the setup lock is taken after the checks that touch nothing (a refused host leaves no lock) and before the preflight looks at the destination (#322); --from-system runs the extracted agent before the system installation is touched (#315);
#   fails_when=either call moves or is dropped; seam=none; why_new=new steps; no_claim=what each does
check "fivenines_setup.sh takes its lock after the architecture and verification checks, before the move's preflight" \
  "$(in_order "$ROOT/fivenines_setup.sh" 'select_agent_binary || exit_with_contact' 'verification_preflight "with-startup-files" ||' 'acquire_setup_lock' '  preflight_user_takeover')" "yes"
check "fivenines_setup_user.sh --from-system runs the extracted agent before it takes over the system installation" \
  "$(in_order "$ROOT/fivenines_setup_user.sh" 'download_agent' '    check_agent_runs' '    take_over_system_install')" "yes"
# Value: protects=fivenines_update.sh and --from-system take the setup lock before they change anything (an update stopped and restarted the agent a move had stopped), --from-system once sudo authenticated; the removal of the user-level installation gets its own bound, given back after; the user update reads the agent it started by its PID and binary, never by a pgrep of the path;
#   fails_when=a lock moves after the first change or is dropped, the removal's bound is not restored, or the post-start check goes back to pgrep;
#   why_new=new; seam=none; no_claim=what each step does
check "fivenines_update.sh takes the setup lock after its checks, before it stops the agent" \
  "$(in_order "$ROOT/fivenines_update.sh" 'verification_preflight "with-startup-files" ||' 'acquire_setup_lock' 'Stopping fivenines-agent service')" "yes"
# The $ are the scripts' own text.
# shellcheck disable=SC2016
check "fivenines_setup_user.sh --from-system takes the setup lock once sudo authenticated, before it reads the system installation" \
  "$(in_order "$ROOT/fivenines_setup_user.sh" '    sudo -v ||' '    acquire_setup_lock' '"$SYSTEM_CONFIG_DIR/TOKEN"; then')" "yes"
# The $ are the scripts' own text.
# shellcheck disable=SC2016
check "--from-user removes the user-level installation under its own bound, and gives the usual one back" \
  "$(in_order "$ROOT/fivenines_setup.sh" '  AS_USER_TIMEOUT=$AS_USER_REMOVAL_TIMEOUT' '    for name in $3; do' '  AS_USER_TIMEOUT=$as_user_bound' 'Removed the user-level installation of')" "yes"
# The $ are the scripts' own text.
# shellcheck disable=SC2016
check "fivenines_update_user.sh reads the agent it started by agent.pid and its binary, never by a pgrep of its path" \
  "$(in_order "$ROOT/fivenines_update_user.sh" 'echo $! > "$INSTALL_DIR/agent.pid"' '  if agent_started; then')|$(grep -c 'pgrep -f "$(agent_pattern' "$ROOT/fivenines_update_user.sh")" "yes|0"
# Value: protects=a --from-user that fails takes back what it created: the records are made before each piece, the undo is armed from the preflight until the service runs, and a failed stop arms the rollback (#311, #316); a --from-system whose agent did not start ends in an error once its @reboot line is added (#315);
#   fails_when=a record, an arming or a disarming moves or is dropped (test mode, which CI runs, skips the stop and the service);
#   why_new=the functions are unit-tested, their call sites in the main flow are not; seam=none; no_claim=what each step does
check "fivenines_setup.sh --from-user: undo armed after the preflight, records before what they record, rollback on a failed stop, disarmed once the service runs" \
  "$(in_order "$ROOT/fivenines_setup.sh" '  preflight_user_takeover' '  UNDO_SYSTEM_INSTALL=1' '    CREATED_INSTALL_DIR=1' '    CREATED_CONFIG_DIR=1' '    CREATED_ACCOUNT=1' '      CREATED_GROUP=1' '    useradd --system --user-group --key' 'mkdir -p /etc/fivenines_agent' '    if ! stop_user_agent; then' '      TAKEOVER_ROLLBACK=1' '      exit_with_contact "Could not stop the user-level agent' '    CREATED_SUDOERS=1' '  write_sudoers_rules || SUDOERS_SKIPPED=1' '          CREATED_UNIT=/etc/systemd/system/fivenines-agent.service' '  SERVICE_SET_UP=1' '      setup_systemd' '  UNDO_SYSTEM_INSTALL=0' '  remove_user_installation')" "yes"
# The $ are the literal text searched for.
# shellcheck disable=SC2016
check "fivenines_setup_user.sh --from-system: an agent that did not start fails the run, after its @reboot line" \
  "$(in_order "$ROOT/fivenines_setup_user.sh" '  if ! start_agent; then' '      AGENT_START_FAILED=1' 'add_reboot_entry; then' 'if [ "$FROM_SYSTEM" = "1" ] && [ "$AGENT_START_FAILED" = "1" ]; then' '        exit_with_error "The system installation was removed, but this agent did not start' 'print_final_instructions')" "yes"
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
# What the command prints goes to the caller AND to sudo-io.log, as sudo's
# I/O log keeps it under "Defaults log_output" (#318). -n is taken, -v
# authenticates, and every command's arguments go to sudo-args.log.
cat > "$MOVE_BIN/sudo" << EOF
#!/bin/sh
while [ "\${1:-}" = -n ]; do shift; done
[ "\${1:-}" = -v ] && exit 0
printf '%s\n' "\$*" >> "$MOVE/sudo-args.log"
echo "We trust you have received the usual lecture from the local System Administrator."
_out=\$(mktemp)
"\$@" > "\$_out"
_rc=\$?
cat "\$_out" >> "$MOVE/sudo-io.log"
cat "\$_out"
rm -f "\$_out"
exit "\$_rc"
EOF
# crontab -l with no crontab fails as BusyBox's does ("No such file or
# directory"), or as cronie's and Vixie cron's with MOVE_CRONTAB_VIXIE set,
# and with MOVE_CRONTAB_FAIL set as a user cron.deny refuses.
cat > "$MOVE_BIN/crontab" << EOF
#!/bin/sh
case "\$1" in
  -l)
    if [ -n "\${MOVE_CRONTAB_FAIL:-}" ]; then
      echo "You (someone) are not allowed to use this program (crontab)" >&2
      exit 1
    fi
    if [ ! -f "$MOVE/crontab" ] && [ -n "\${MOVE_CRONTAB_VIXIE:-}" ]; then
      echo "no crontab for someone" >&2
      exit 1
    fi
    [ -f "$MOVE/crontab" ] || { echo "crontab: can't open 'someone': No such file or directory" >&2; exit 1; }
    cat "$MOVE/crontab"
    ;;
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

# Fake agents: a copy of sleep run from <dir>/fivenines-agent-linux-amd64/,
# so its command line starts with that path, as start.sh runs the real agent,
# and /proc/PID/exe resolves into that directory, as the control scripts and
# the moves read it. MOVE_SLEEP stays empty where sleep cannot run under
# another name (a BusyBox applet), and the checks needing one are left out.
MOVE_SLEEP=""
if [ -n "$REAL_PGREP" ] && command -v ps > /dev/null 2>&1 && [ -r /proc/self/exe ]; then
  _sleep=$(command -v sleep 2> /dev/null)
  if [ -n "$_sleep" ] && cp "$_sleep" "$MOVE/sleep-copy" 2> /dev/null && "$MOVE/sleep-copy" 0 2> /dev/null; then
    MOVE_SLEEP="$MOVE/sleep-copy"
  fi
fi
MOVE_PIDS=""
trap 'kill $MOVE_PIDS 2> /dev/null; rm -rf "$WORK"' EXIT
# move_start agent DIR [VAR=VALUE]: starts DIR's fake agent, with VAR=VALUE
# in its environment; move_start tail FILE: a tail -f of FILE. Detached (so
# a stopped one is reaped at once); prints its PID once its command line is in
# place. The agent ignores SIGHUP, which refresh.sh sends.
move_start() {
  # The $ in the single-quoted scripts are meant for the child shells.
  # shellcheck disable=SC2016
  if [ "$1" = agent ]; then
    _cmd="$2/fivenines-agent-linux-amd64/fivenines-agent-linux-amd64"
    mkdir -p "$2/fivenines-agent-linux-amd64"
    rm -f "$_cmd"
    cp "$MOVE_SLEEP" "$_cmd"
    chmod 755 "$_cmd"
    _pid=$(env ${3:+"$3"} sh -c 'trap "" HUP; "$0" 300 > /dev/null 2>&1 & echo $!' "$_cmd")
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
  MOVE_PIDS="$MOVE_PIDS $_pid"
  printf '%s' "$_pid"
}
# A PID still running, not a zombie waiting to be reaped.
move_alive() {
  kill -0 "$1" 2> /dev/null && [ "$(ps -o stat= -p "$1" 2>/dev/null | cut -c1)" != "Z" ]
}
# Waits up to 5s for PID $1 to be gone.
move_gone() {
  _tries=0
  while move_alive "$1" && [ "$_tries" -lt 5 ]; do
    sleep 1
    _tries=$((_tries + 1))
  done
  ! move_alive "$1"
}

# --from-system: copy_system_state, as fivenines_setup_user.sh runs it, with
# its own lists of what to carry.
# Value: protects=--from-system carries TOKEN, MACHINE_ID and the journal allowlist byte-exact, owner-only, .env only as the unread .env.system, and nothing else, without any of it crossing sudo's output (#318);
#   fails_when=a carried list changes, the state goes back to sudo's stdout, the root-side read follows a symlink or skips it as absent, an oversized file or an empty TOKEN passes;
#   why_new=test-distro Test 13 copies plain files through a sudo that prints nothing, and never meets a link or an empty TOKEN; seam=none;
#   no_claim=that the reads run as root, or that the system agent was stopped first
sed -n '/^STATE_FILES=/p;/^SYSTEM_ENV_COPY=/p;/^COPIED_STATE_FILES=/p;/^STATE_FILE_MAX=/p
        /^as_root()/,/^}/p;/^copy_system_state()/,/^}/p;/^copy_system_state_files()/,/^}/p' \
  "$ROOT/fivenines_setup_user.sh" | sed "s|/tmp/fivenines-state\.|$MOVE/rs/fivenines-state.|g" > "$MOVE/from_system.sh"
mkdir -p "$MOVE/rs"
# The names in a directory, dot files included, in byte order.
move_names() {
  for _n in "$1"/.[!.]* "$1"/*; do
    if [ -e "$_n" ] || [ -L "$_n" ]; then printf '%s\n' "${_n##*/}"; fi
  done | LC_ALL=C sort | tr '\n' ' '
}
# GNU stat first, BSD stat second.
move_mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null; }
# A readlink that cannot read another process's exe link, as the kernel
# answers for a process of the user's started under another group (newgrp,
# sg): it shows the link only to a reader with the process's gid too. Its
# own (/proc/self/exe) stays readable.
mkdir -p "$MOVE/noexebin"
cat > "$MOVE/noexebin/readlink" << EOF
#!/bin/sh
for _arg; do
  case "\$_arg" in
    /proc/self/exe) ;;
    /proc/*/exe) exit 1 ;;
  esac
done
exec $(command -v readlink) "\$@"
EOF
chmod 755 "$MOVE/noexebin/readlink"
# And a tr that cannot read another process's environment, as the kernel
# answers for such a process too.
mkdir -p "$MOVE/noenvbin"
cat > "$MOVE/noenvbin/tr" << EOF
#!/bin/sh
case "\$(readlink /proc/\$\$/fd/0 2> /dev/null)" in
  /proc/self/*) ;;
  /proc/*/environ) exit 1 ;;
esac
exec $(command -v tr) "\$@"
EOF
chmod 755 "$MOVE/noenvbin/tr"
mkdir -p "$MOVE/growbin"
# A wc that reads the user's MACHINE_ID, and the system's, as 1 byte long: a
# file that grew past STATE_FILE_MAX once its size was read. Every other
# file, a copy included, is counted for real.
cat > "$MOVE/growbin/wc" << EOF
#!/bin/sh
case "\$(readlink /proc/\$\$/fd/0)" in
  "$MOVE/iuc/MACHINE_ID" | "$MOVE/sys/MACHINE_ID") echo 1; exit 0 ;;
esac
exec $(command -v wc) "\$@"
EOF
chmod 755 "$MOVE/growbin/wc"
# Runs copy_system_state from $MOVE/sys into an empty $MOVE/cfg, with
# STATE_FILE_MAX $1 when given (and with $2 grown, MACHINE_ID growing once
# its size was read), and prints its status.
from_system_copy() {
  rm -rf "$MOVE/cfg" "$MOVE/stage"
  mkdir -p "$MOVE/cfg" "$MOVE/stage"
  : > "$MOVE/sudo-io.log"
  : > "$MOVE/sudo-args.log"
  (
    # shellcheck source=/dev/null
    . "$MOVE/from_system.sh"
    SYSTEM_CONFIG_DIR="$MOVE/sys"
    CONFIG_DIR="$MOVE/cfg"
    WORK_DIR="$MOVE/stage"
    if [ -n "${1:-}" ]; then STATE_FILE_MAX=$1; fi
    # The growing wc, for this run only.
    # shellcheck disable=SC2030,SC2031
    if [ "${2:-}" = grown ]; then PATH="$MOVE/growbin:$PATH"; fi
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
check "--from-system carries each file byte for byte, whatever sudo printed" "$_differ" ""
check "--from-system writes each file owner-only" "$_modes" "600 600 600 600 "
check "--from-system says why .env was not carried as .env" "$(grep -c 'which the agent does not read' "$MOVE/out")" "1"
# Root writes, and hands over, each copy in a directory it made itself, never
# by name in this user's work directory, where a link planted between two of
# root's steps (by any process of the user's) chose what root wrote or
# chowned; that directory is gone once the copy is done.
# Value: protects=no root write or chown of --from-system names a path in the user's directories, and root's own directory for the copies is removed;
#   fails_when=root copies straight into the user's work directory again, or the stage is left behind;
#   why_new=the checks above look only at what lands; seam=sudo logs every command it runs (the stub runs it as this user);
#   no_claim=that root made the directory (mktemp -d as root, 0711)
check "--from-system makes root copy into a directory of its own, never into the user's, and removes it" \
  "$(grep -c "$MOVE/stage" "$MOVE/sudo-args.log")|$(grep -c "$MOVE/rs/fivenines-state" "$MOVE/sudo-args.log" | grep -c '^[1-9]')|$(move_names "$MOVE/rs")" "0|1|"
check "--from-system carries no state through sudo's output, which sudo's I/O log keeps (#318)" \
  "$(grep -c -e 'per-host-token-0001' -e "$(printf 'per-host-token-0001' | base64)" -e 'API_URL' "$MOVE/sudo-io.log")" "0"
# A file larger than any state file stops the move before it is copied.
check "--from-system stops at a state file larger than STATE_FILE_MAX, and carries nothing" \
  "$(from_system_copy 30)|$(grep -c 'MACHINE_ID is larger than any agent state file' "$MOVE/out")|$(move_names "$MOVE/cfg")" \
  "1|1|"
# Value: protects=root refuses a system state file grown past STATE_FILE_MAX since its size was read, as too large, and keeps no copy of it;
#   fails_when=root's copy loses its check after head -c (an unbounded cp reads the whole file, and the copy is then refused only as unreadable), or keeps the copy;
#   why_new=the check above refuses a file at its size check; seam=a wc on PATH that reads the system's MACHINE_ID as 1 byte;
#   no_claim=a real concurrent writer
check "--from-system stops at a state file grown past STATE_FILE_MAX since its size was read, and copies none of it" \
  "$(from_system_copy 30 grown)|$(grep -c 'MACHINE_ID is larger than any agent state file' "$MOVE/out")|$(move_names "$MOVE/cfg")|$([ -e "$MOVE/stage/system_state/MACHINE_ID" ] && echo copied)|$(move_names "$MOVE/rs")" \
  "1|1|||"

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

# A transfer cut short (su killed mid-way, or a read that failed) has no end
# marker: it must not decode as a shorter file. decode_state is
# fivenines_setup.sh's (--from-user, through su).
sed -n '/^decode_state()/,/^}/p' "$ROOT/fivenines_setup.sh" > "$MOVE/decode.sh"
printf 'fivenines-state-begin\n%s\n' "$(printf 'per-host-token-0001' | base64)" > "$MOVE/cut.b64"
(
  # shellcheck source=/dev/null
  . "$MOVE/decode.sh"
  decode_state "$MOVE/cut.b64" "$MOVE/cut.out"
)
check "decode_state refuses a transfer with no end marker" "$?" "1"
# Output printed before the data with no newline: the begin marker is not on
# a line of its own, and the file must not decode as an empty one.
printf 'Last login: somewhere%s\n%s\nfivenines-state-end\n' 'fivenines-state-begin' \
  "$(printf 'per-host-token-0001' | base64)" > "$MOVE/nobegin.b64"
(
  # shellcheck source=/dev/null
  . "$MOVE/decode.sh"
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
        /^exit_with_error()/,/^}/p;/^as_root()/,/^}/p;/^shell_quote()/,/^}/p;/^reboot_line()/,/^}/p;/^reboot_advice()/,/^}/p
        /^copy_system_state()/,/^}/p;/^copy_system_state_files()/,/^}/p;/^restart_system_agent()/,/^}/p
        /^abort_system_takeover()/,/^}/p;/^take_over_system_install()/,/^}/p' \
  "$ROOT/fivenines_setup_user.sh" | sed "s|/tmp/fivenines-state\.|$MOVE/rs/fivenines-state.|g" > "$MOVE/takeover.sh"
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
  "$(from_system_takeover 'echo pretend uninstall')|$(grep -c 'did not remove the system installation' "$MOVE/out")|$(move_names "$MOVE/cfg")|$(cat "$MOVE/sys/TOKEN")|$(grep -c 'put back as it was' "$MOVE/out")" \
  "1|1||per-host-token-0001|1"
# What --from-system tells the user to add to the crontab when it cannot: the
# @reboot line, or, for a path a crontab line cannot carry (a %), to start it
# from a script of their own.
# Value: protects=the advice --from-system prints ends every failure message with a line that works, or says why there is none;
#   fails_when=reboot_advice prints a line for a path cron would cut at its %, or loses its fallback;
#   why_new=no test read the advice; seam=none; no_claim=the messages built around it
reboot_advice_for() {
  (
    # shellcheck source=/dev/null
    . "$MOVE/takeover.sh"
    INSTALL_DIR=$1
    reboot_advice
  )
}
check "--from-system advises the @reboot line, or a script of the user's own for a path with a %" \
  "$(reboot_advice_for /home/u/agent)#$(reboot_advice_for '/home/u/50%agent')" \
  "add this line to your crontab (crontab -e): @reboot /home/u/agent/start.sh#start /home/u/50%agent/start.sh at boot from a script of your own (its path holds a % or a new line, which a crontab line cannot carry)"
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
# logs whether $MOVE/etc still holds a TOKEN. is-enabled and is-active answer
# no when MOVE_DISABLED and MOVE_INACTIVE are set, and is-active too once a
# stop succeeded (svc.stopped, removed by each run), printing the state as
# systemctl does without --quiet; show -p ActiveState prints it as
# ActiveState=... With MOVE_ISACTIVE_BROKEN set (a systemctl that cannot
# reach systemd) both print nothing and fail -- except is-active under
# MOVE_SYSTEMD219, which says "unknown" for a bus error as for a unit it no
# longer has loaded, as systemd 219 does; their calls are not logged. rc-service logs its calls too; a stop fails with
# MOVE_STOP_FAILS, and status answers 3 once a stop succeeded.
# An id that answers MOVE_FIVENINES_UID for the fivenines account, which this
# host need not have.
mkdir -p "$MOVE/svcbin"
cat > "$MOVE/svcbin/systemctl" << EOF
#!/bin/sh
case "\$1" in
  is-enabled) [ -z "\${MOVE_DISABLED:-}" ]; exit ;;
  is-active)
    if [ -n "\${MOVE_ISACTIVE_BROKEN:-}" ]; then
      [ -n "\${MOVE_SYSTEMD219:-}" ] && [ "\$2" != --quiet ] && echo unknown
      exit 1
    fi
    if [ -z "\${MOVE_INACTIVE:-}" ] && [ ! -e "$MOVE/svc.stopped" ]; then
      [ "\$2" = --quiet ] || echo active
      exit 0
    fi
    if [ "\$2" != --quiet ]; then
      if [ -n "\${MOVE_SYSTEMD219:-}" ]; then echo unknown; else echo inactive; fi
    fi
    exit 3
    ;;
  show)
    [ -n "\${MOVE_ISACTIVE_BROKEN:-}" ] && exit 1
    if [ -z "\${MOVE_INACTIVE:-}" ] && [ ! -e "$MOVE/svc.stopped" ]; then
      echo ActiveState=active
    else
      echo ActiveState=inactive
    fi
    exit 0
    ;;
esac
_t=""
[ -e "$MOVE/etc/TOKEN" ] && _t=" with TOKEN"
echo "systemctl \$*\$_t" >> "$MOVE/svc.log"
if [ "\$1" = stop ]; then
  [ -n "\${MOVE_STOP_SIGNAL:-}" ] && kill -INT "\$MOVE_RUNNER"
  [ -z "\${MOVE_STOP_FAILS:-}" ] || exit 1
  : > "$MOVE/svc.stopped"
fi
EOF
cat > "$MOVE/svcbin/rc-service" << EOF
#!/bin/sh
echo "rc-service \$*" >> "$MOVE/svc.log"
case "\$2" in
  stop)
    [ -z "\${MOVE_STOP_FAILS:-}" ] || exit 1
    : > "$MOVE/svc.stopped"
    ;;
  status) [ -e "$MOVE/svc.stopped" ] && exit 3 ;;
esac
exit 0
EOF
printf '#!/bin/sh\necho "rc-update $*" >> "%s"\n' "$MOVE/svc.log" > "$MOVE/svcbin/rc-update"
chmod 755 "$MOVE/svcbin/rc-service" "$MOVE/svcbin/rc-update"
cat > "$MOVE/svcbin/id" << EOF
#!/bin/sh
if [ "\$*" = "-u fivenines" ]; then
  [ -n "\${MOVE_FIVENINES_UID:-}" ] || exit 1
  echo "\$MOVE_FIVENINES_UID"
  exit 0
fi
exec $(command -v id) "\$@"
EOF
chmod 755 "$MOVE/svcbin/systemctl" "$MOVE/svcbin/id"

# --from-system outside test mode: the system agent's stop, with the unit and
# the agent's path moved into the scratch directory.
# Value: protects=a --from-system whose system agent stop fails moves nothing, and a signal during that stop neither cuts the move nor leaves the agent stopped with nothing armed;
#   fails_when=a failed stop goes on to copy the identity, or take_over_system_install stops ignoring INT/TERM/HUP during the stop;
#   why_new=every other run of the move is in test mode, which skips the stop; seam=/etc/systemd/system and ^/opt/fivenines/ are rewritten to the scratch directory;
#   no_claim=the OpenRC branch, a real systemd, or the restart after an abort
sed "s|/etc/systemd/system/|$MOVE/units/|g;s|\"^/opt/fivenines/\"|\"^$MOVE/opt/\"|g" \
  "$MOVE/takeover.sh" > "$MOVE/takeover_stop.sh"
# Runs take_over_system_install outside test mode; $1 is fail, signal or
# nothing, for the stop, or after, for a TERM once it returned, or disabled
# or inactive, for the service's state before the move; $2 is the
# uninstaller's body (default: it removes the TOKEN and the unit); $3 the uid
# id answers for the fivenines account (default: none). Prints its status.
from_system_stop() {
  rm -rf "$MOVE/cfg" "$MOVE/stage" "$MOVE/units"
  mkdir -p "$MOVE/cfg" "$MOVE/stage" "$MOVE/units"
  : > "$MOVE/svc.log"
  rm -f "$MOVE/svc.stopped"
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
      disabled) MOVE_DISABLED=1 && export MOVE_DISABLED ;;
      inactive) MOVE_INACTIVE=1 && export MOVE_INACTIVE ;;
    esac
    MOVE_FIVENINES_UID=${3:-}
    export MOVE_FIVENINES_UID
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
# Value: protects=an undone --from-system enables the system agent again only if it was enabled, and starts it only if it ran (#325);
#   fails_when=restart_system_agent enables or starts unconditionally again, or the state is no longer read before the stop;
#   why_new=the check above has the service enabled and running; seam=as above; no_claim=the OpenRC branch
check "--from-system leaves a system agent the operator had disabled disabled when the move is undone" \
  "$(from_system_stop disabled "echo pretend uninstall")|$(tr '\n' '|' < "$MOVE/svc.log")" \
  "1|systemctl stop fivenines-agent.service|systemctl start fivenines-agent.service|"
check "--from-system leaves a system agent that was not running stopped when the move is undone, and says so" \
  "$(from_system_stop inactive "echo pretend uninstall")|$(tr '\n' '|' < "$MOVE/svc.log")|$(grep -c 'was not running before the move' "$MOVE/out")" \
  "1|systemctl stop fivenines-agent.service|systemctl enable fivenines-agent.service||1"
check "--from-system says the system agent is not started again once its unit is gone" \
  "$(from_system_stop "" "rm -f '$MOVE/units/fivenines-agent.service'")|$(grep 'its service definition is gone' "$MOVE/out" | grep -c 'Re-run --from-system')|$(grep 'its service definition is gone' "$MOVE/out" | grep -c 'uninstall')|$(move_names "$MOVE/cfg")|$(cat "$MOVE/sys/TOKEN")" \
  "1|1|0||per-host-token-0001"
# A process left under /opt/fivenines/ once the system installation is gone:
# the system agent's (its account's uid, recorded before the uninstaller)
# keeps this one from starting; any other user's is not the system agent
# (#306). A test cannot start a process of another uid, so id answers this
# user's uid, or another, for the fivenines account.
# Value: protects=--from-system takes only a process of the fivenines account under /opt/fivenines/ for a surviving system agent;
#   fails_when=the check goes back to any process whose command line starts with the path;
#   why_new=no other check leaves a process there; seam=id stubbed for the fivenines account, /opt/fivenines rewritten;
#   no_claim=a real second user, or that the uninstaller kills the system agent
if [ -n "$MOVE_SLEEP" ]; then
  MOVE_LEFT=$(move_start agent "$MOVE/opt")
  check "--from-system completes beside a process under /opt/fivenines/ that is not the system agent's account's" \
    "$(from_system_stop "" "" 4242424)|$(grep -c 'The system agent still runs' "$MOVE/out")" "0|0"
  check "--from-system does not start beside a process of the system agent's account under /opt/fivenines/" \
    "$(from_system_stop "" "" "$(id -u)")|$(grep -c 'The system agent still runs' "$MOVE/out")" "1|1"
  kill "$MOVE_LEFT" 2> /dev/null
fi
rm -rf "$MOVE/units"

# --from-system: the extracted agent must run as this user before anything of
# the system installation is touched (#315), and the agent start.sh started
# is the one recorded in agent.pid running this installation's binary.
# Value: protects=--from-system never removes the system installation for an agent that cannot run here (a noexec home), and a run whose agent did not start is not reported as a success;
#   fails_when=check_agent_runs is dropped or stops failing on an exec error, or agent_started goes back to a pgrep of the path;
#   why_new=test-distro runs the move in test mode, which never starts the agent; seam=a script and a copy of sleep stand for the binary;
#   no_claim=a real noexec mount
sed -n '/^USER_INSTALL_FILES=/p;/^exit_with_error()/,/^}/p;/^first_missing_dir()/,/^}/p;/^remove_made_dirs()/,/^}/p
        /^check_agent_runs()/,/^}/p;/^agent_started()/,/^}/p' \
  "$ROOT/fivenines_setup_user.sh" > "$MOVE/agent_runs.sh"
AR_DIR="$MOVE/arinst"
mkdir -p "$AR_DIR/fivenines-agent-linux-amd64"
# Prints check_agent_runs's status and whether it said why, for the
# installation in $1 (default AR_DIR) and its config directory ($AR_CFG, or
# $1.cfg); $2 and $3, when given, are the topmost directories this run made
# for each.
agent_runs() {
  (
    # shellcheck source=/dev/null
    . "$MOVE/agent_runs.sh"
    INSTALL_DIR="${1:-$AR_DIR}"
    CONFIG_DIR="${AR_CFG:-${1:-$AR_DIR}.cfg}"
    CREATED_USER_INSTALL_TOP=${2:-}
    CREATED_USER_CONFIG_TOP=${3:-}
    BINARY_NAME=fivenines-agent-linux-amd64
    check_agent_runs > "$MOVE/out" 2>&1
  )
  printf '%s|%s' "$?" "$(grep -c 'does not run as' "$MOVE/out")"
}
printf '#!/bin/sh\nexit 0\n' > "$AR_DIR/fivenines-agent-linux-amd64/fivenines-agent-linux-amd64"
chmod 755 "$AR_DIR/fivenines-agent-linux-amd64/fivenines-agent-linux-amd64"
check "--from-system goes on when the extracted agent runs" "$(agent_runs)" "0|0"
chmod 644 "$AR_DIR/fivenines-agent-linux-amd64/fivenines-agent-linux-amd64"
check "--from-system stops, before the system installation, when the extracted agent cannot run" "$(agent_runs)" "1|1"
# And takes back what it wrote of an installation that cannot run here: the
# agent and the control scripts, and the directories it made, once empty;
# a file of the user's stays, and so does its directory.
# Value: protects=a --from-system stopped by an agent that cannot run leaves no installation behind that cannot run;
#   fails_when=check_agent_runs stops removing the agent or the control scripts, or removes a directory it did not make or a file it did not write;
#   why_new=the check above looks only at the refusal; seam=a non-executable script stands for the binary;
#   no_claim=a real noexec mount
rm -rf "$MOVE/arbase" "$MOVE/armade-cfg" "$MOVE/arkeep" "$MOVE/arkeep.cfg" "$MOVE/arshared"
# Made under an empty directory that was there before (arbase): the chain
# stops at the topmost one this run made. Its config directory elsewhere,
# made before: only the install chain can take armade away.
mkdir -p "$MOVE/arbase" "$MOVE/armade-cfg" "$MOVE/arkeep.cfg" "$MOVE/arshared/cfg"
for _ar in "$MOVE/arbase/armade/sub/inst" "$MOVE/arkeep" "$MOVE/arshared/inst"; do
  mkdir -p "$_ar/fivenines-agent-linux-amd64"
  : > "$_ar/fivenines-agent-linux-amd64/fivenines-agent-linux-amd64"
  for _f in start.sh stop.sh status.sh logs.sh refresh.sh; do : > "$_ar/$_f"; done
done
: > "$MOVE/arkeep/notes.txt"
: > "$MOVE/arkeep/agent.log"
check "--from-system takes back the installation it wrote when its agent cannot run, and only that" \
  "$(AR_CFG="$MOVE/armade-cfg" agent_runs "$MOVE/arbase/armade/sub/inst" "$MOVE/arbase/armade")|$([ -e "$MOVE/arbase/armade" ] && echo made)$([ -d "$MOVE/arbase" ] && echo base)$([ -d "$MOVE/armade-cfg" ] && echo cfg)|$(agent_runs "$MOVE/arkeep")|$(move_names "$MOVE/arkeep")|$([ -d "$MOVE/arkeep.cfg" ] && echo cfg)" \
  "1|1|basecfg|1|1|agent.log notes.txt |cfg"
# Both directories made under one parent this run made too: it goes once
# both are gone, whichever is removed first.
check "--from-system takes back a parent it made for both directories" \
  "$(AR_CFG="$MOVE/arshared/cfg" agent_runs "$MOVE/arshared/inst" "$MOVE/arshared" "$MOVE/arshared/cfg")|$([ -e "$MOVE/arshared" ] && echo shared)" \
  "1|1|"
if [ -n "$MOVE_SLEEP" ]; then
  # Prints agent_started's status.
  agent_started_status() {
    (
      # shellcheck source=/dev/null
      . "$MOVE/agent_runs.sh"
      INSTALL_DIR="$AR_DIR"
      BINARY_NAME=fivenines-agent-linux-amd64
      agent_started
    )
    echo "$?"
  }
  MOVE_AR=$(move_start agent "$AR_DIR")
  printf '%s\n' "$MOVE_AR" > "$AR_DIR/agent.pid"
  check "the agent start.sh recorded counts as started while it runs this installation's binary" "$(agent_started_status)" "0"
  MOVE_AR_TAIL=$(move_start tail "$MOVE/ar.log")
  printf '%s\n' "$MOVE_AR_TAIL" > "$AR_DIR/agent.pid"
  check "a recorded PID that runs another binary is no agent started" "$(agent_started_status)" "1"
  kill "$MOVE_AR" "$MOVE_AR_TAIL" 2> /dev/null
  move_gone "$MOVE_AR"
  printf '%s\n' "$MOVE_AR" > "$AR_DIR/agent.pid"
  check "an agent that exited is no agent started" "$(agent_started_status)" "1"
fi

# fivenines_setup.sh's lock (#322), with /run and /etc rewritten to scratch
# directories.
# Value: protects=two runs of fivenines_setup.sh never overlap: a held lock refuses a second run, a dead run's lock is taken over, and a run releases its own lock (and work directory) on exit;
#   fails_when=the lock stops being atomic, a live holder is overridden, a dead one's lock blocks for good, or the EXIT trap no longer releases it;
#   why_new=new lock; seam=paths rewritten; no_claim=a reused PID (the message says how to remove the lock)
sed -n '/^exit_with_contact()/,/^}/p;/^cleanup_on_exit()/,/^}/p;/^setup_lock_script()/,/^}/p;/^acquire_setup_lock()/,/^}/p' \
  "$ROOT/fivenines_setup.sh" \
  | sed "s|/run|$MOVE/lockrun|g;s|/etc/fivenines_setup.lock|$MOVE/locketc/fivenines_setup.lock|g" > "$MOVE/lock.sh"
mkdir -p "$MOVE/lockrun" "$MOVE/locketc"
MOVE_LOCK="$MOVE/lockrun/fivenines_setup.lock"
# Takes the lock in a subshell with a work directory, and prints its status,
# what the lock pointed to while held, and whether the work directory and the
# lock are left once it exited.
lock_run() {
  mkdir -p "$MOVE/lockwork"
  (
    # shellcheck source=/dev/null
    . "$MOVE/lock.sh"
    WORK_DIR="$MOVE/lockwork"
    acquire_setup_lock > "$MOVE/out" 2>&1
    readlink "$MOVE_LOCK" > "$MOVE/lockheld"
  )
  printf '%s|%s|%s|%s' "$?" "$([ "$(cat "$MOVE/lockheld" 2>/dev/null)" = "$$" ] && echo ours)" \
    "$([ -e "$MOVE/lockwork" ] && echo work)" "$([ -L "$MOVE_LOCK" ] && readlink "$MOVE_LOCK")"
}
rm -f "$MOVE_LOCK" "$MOVE/lockheld"
check "fivenines_setup.sh takes a free lock, and releases it and its work directory on exit" "$(lock_run)" "0|ours||"
rm -f "$MOVE/lockheld"
sh -c 'exit 0' &
_dead=$!
wait "$_dead"
ln -s "$_dead" "$MOVE_LOCK"
check "fivenines_setup.sh takes over a lock its holder left when it died" "$(lock_run)" "0|ours||"
rm -f "$MOVE/lockheld"
# A live holder: this test itself.
ln -s "$$" "$MOVE_LOCK"
_held=$(lock_run)
check "fivenines_setup.sh refuses while another run holds the lock, and leaves it" \
  "$_held|$(grep -c "Another fivenines installer holds $MOVE_LOCK (PID $$)" "$MOVE/out")" "1||work|$$|1"
rm -rf "$MOVE_LOCK" "$MOVE/lockwork"
# Two runs that find the same dead holder: the takeover is made under its own
# link, so while one run holds it the other takes nothing over -- it used to
# remove the lock the first had just taken, and both ran.
# Value: protects=a stale lock is taken over by one run only, and a takeover in progress is never undone by a second run;
#   fails_when=the takeover goes back to a bare rm -f, or ignores the .takeover link;
#   why_new=the checks above have one run at a time; seam=paths rewritten, the other run's takeover link made by hand;
#   no_claim=the interleaving itself (the re-check under the takeover link is read, not raced)
ln -s "$_dead" "$MOVE_LOCK"
ln -s "$$" "$MOVE_LOCK.takeover"
_held=$(lock_run)
check "fivenines_setup.sh takes over no stale lock while another run's takeover is in progress" \
  "$_held|$(readlink "$MOVE_LOCK.takeover")" "1||work|$_dead|$$"
rm -rf "$MOVE_LOCK" "$MOVE_LOCK.takeover" "$MOVE/lockwork"
# A directory at the lock's path would take the link inside it (ln -s DIR),
# and every run believe it held the lock: refused, nothing made inside.
# Value: protects=a directory at the lock's path never lets two runs believe they hold the lock;
#   fails_when=both the directory check before ln and the read-back after it are dropped (either alone refuses it);
#   why_new=the lock's path was a link or nothing in every check above; seam=paths rewritten;
#   no_claim=a directory that appears between the check and ln (the read-back covers it, like the case below)
mkdir -p "$MOVE_LOCK"
_held=$(lock_run)
check "fivenines_setup.sh refuses a directory at the lock's path, and makes nothing inside it" \
  "$_held|$(grep -c "Could not take the setup lock $MOVE_LOCK: it could not be made" "$MOVE/out")|$(move_names "$MOVE_LOCK")" "1||work||1|"
rm -rf "$MOVE_LOCK" "$MOVE/lockwork"
# A symbolic link to a directory there passes the directory check (it is a
# link), and ln makes its link inside the directory: only the read-back
# after ln sees that, removes it, and refuses.
# Value: protects=a link to a directory at the lock's path never lets a run believe it holds the lock, and leaves nothing in that directory;
#   fails_when=the read-back after ln, or its removal of the link made inside, is dropped;
#   why_new=the directory check above refuses a plain directory before ln; seam=paths rewritten;
#   no_claim=the race it also covers
mkdir -p "$MOVE/locktarget"
ln -s "$MOVE/locktarget" "$MOVE_LOCK"
_held=$(lock_run)
check "fivenines_setup.sh refuses a link to a directory at the lock's path, and leaves nothing in that directory" \
  "$_held|$(grep -c "Could not take the setup lock $MOVE_LOCK: it could not be made" "$MOVE/out")|$(move_names "$MOVE/locktarget")" "1||work|$MOVE/locktarget|1|"
rm -rf "$MOVE_LOCK" "$MOVE/locktarget" "$MOVE/lockwork"
# A lock that cannot be made at all (not root, a read-only /run) is said as
# such, not as a run that holds it.
# Value: protects=a lock that cannot be made is never reported as one another installer holds;
#   fails_when=the two refusals share one message again;
#   why_new=the checks above can always make the lock; seam=the lock's directory made read-only;
#   no_claim=a real read-only /run
if [ "$(id -u)" != "0" ]; then
  chmod 555 "$MOVE/lockrun"
  _held=$(lock_run)
  chmod 755 "$MOVE/lockrun"
  check "fivenines_setup.sh says when it cannot make the lock at all" \
    "$_held|$(grep -c "Could not take the setup lock $MOVE_LOCK: it could not be made" "$MOVE/out")|$(grep -c 'Another fivenines installer holds' "$MOVE/out")" "1||work||1|0"
  rm -rf "$MOVE/lockwork"
fi
# fivenines_setup_user.sh --from-system takes the same lock through sudo,
# and releases it through sudo -n on exit, only while it is still its own.
# Value: protects=--from-system and fivenines_setup.sh never run at once, and --from-system releases the lock it took;
#   fails_when=--from-system stops taking the lock, takes it as the user, or leaves it behind;
#   why_new=the lock was fivenines_setup.sh's alone; seam=sudo is the stub (it runs as this user), paths rewritten;
#   no_claim=that sudo runs it as root
sed -n '/^exit_with_error()/,/^}/p;/^as_root()/,/^}/p;/^cleanup_on_exit()/,/^}/p;/^setup_lock_script()/,/^}/p;/^acquire_setup_lock()/,/^}/p' \
  "$ROOT/fivenines_setup_user.sh" \
  | sed "s|/run|$MOVE/lockrun|g;s|/etc/fivenines_setup.lock|$MOVE/locketc/fivenines_setup.lock|g" > "$MOVE/lock_user.sh"
lock_user_run() {
  : > "$MOVE/sudo-args.log"
  rm -f "$MOVE/lockheld"
  (
    # shellcheck source=/dev/null
    . "$MOVE/lock_user.sh"
    WORK_DIR=""
    ROOT_STAGE=""
    SETUP_LOCK=""
    # The sudo stub, for this run only.
    # shellcheck disable=SC2030,SC2031
    PATH="$MOVE_BIN:$PATH"
    acquire_setup_lock > "$MOVE/out" 2>&1
    readlink "$MOVE_LOCK" > "$MOVE/lockheld"
  )
  # The $1 is the release command's own text.
  # shellcheck disable=SC2016
  printf '%s|%s|%s|%s' "$?" "$([ -s "$MOVE/lockheld" ] && echo held)" \
    "$([ -L "$MOVE_LOCK" ] && readlink "$MOVE_LOCK")" "$(grep -cF '&& rm -f "$1"' "$MOVE/sudo-args.log")"
}
rm -f "$MOVE_LOCK" "$MOVE/lockheld"
check "fivenines_setup_user.sh takes the setup lock through sudo, and releases it through sudo on exit" "$(lock_user_run)" "0|held||1"
ln -s "$$" "$MOVE_LOCK"
check "fivenines_setup_user.sh refuses while another run holds the setup lock, and leaves it" \
  "$(lock_user_run)|$(grep -c 'Another fivenines installer holds' "$MOVE/out")" "1||$$|0|1"
rm -f "$MOVE_LOCK"
# A sudo that will not run the lock's script: said as such.
mkdir -p "$MOVE/nosudobin"
printf '#!/bin/sh\nexit 1\n' > "$MOVE/nosudobin/sudo"
chmod 755 "$MOVE/nosudobin/sudo"
_held=$(MOVE_BIN="$MOVE/nosudobin" lock_user_run)
check "fivenines_setup_user.sh says when sudo did not run the setup lock" \
  "$_held|$(grep -c 'sudo did not run it' "$MOVE/out")|$(grep -c 'Another fivenines installer holds' "$MOVE/out")" "1|||0|1|0"

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
#   why_new=the harness and test-distro roll back only in test mode, which skips the service and the restart; seam=/etc/fivenines_agent, /opt/fivenines, /etc/sudoers.d/fivenines and /etc/group are rewritten to the scratch directory;
#   no_claim=the OpenRC branch, a real systemd, or that the restart runs as the user (su is a stub)
sed -n '/^STATE_FILES=/p;/^AS_USER_TIMEOUT=/p;/^as_user()/,/^}/p;/^OWN_AGENTS_FN=/,/^'"'"'$/p
        /^undo_system_install()/,/^}/p;/^rollback_user_takeover()/,/^}/p' \
  "$ROOT/fivenines_setup.sh" \
  | sed "s|/etc/fivenines_agent|$MOVE/etc|g;s|/opt/fivenines|$MOVE/rbopt|g;s|/etc/sudoers.d/fivenines|$MOVE/rbsudoers|g;s|/etc/group|$MOVE/rbgroup|g;s|/etc/init.d/fivenines-agent|$MOVE/rbinit|g;s|/run/systemd/system|$MOVE/rbbooted|g" \
  > "$MOVE/rollback.sh"
mkdir -p "$MOVE/rbinst" "$MOVE/acctbin"
printf '#!/bin/sh\necho start.sh >> %s\n' "'$MOVE/svc.log'" > "$MOVE/rbinst/start.sh"
chmod 755 "$MOVE/rbinst/start.sh"
# userdel and groupdel log their calls and succeed; the group file then loses
# its line.
for _tool in userdel groupdel; do
  printf '#!/bin/sh\necho "%s $*" >> "%s"\n' "$_tool" "$MOVE/svc.log" > "$MOVE/acctbin/$_tool"
done
printf 'sed -i "/^fivenines:/d" "%s"\n' "$MOVE/rbgroup" >> "$MOVE/acctbin/groupdel"
chmod 755 "$MOVE/acctbin/"*
# Runs rollback_user_takeover outside test mode, signalled during the service
# stop; $1 is how far the move went (imported: state files installed and the
# service set up; created: also what undo_system_install takes back; stopping:
# only the user-level agent stopped).
rollback_run() {
  rm -rf "${MOVE:?}/etc" "$MOVE/rbopt" "$MOVE/rbsudoers" "$MOVE/rbunit"
  mkdir -p "$MOVE/etc" "$MOVE/rbopt"
  for _f in TOKEN MACHINE_ID last_capture_id .env; do
    printf '%s\n' "$_f" > "$MOVE/etc/$_f"
  done
  : > "$MOVE/rbsudoers"
  : > "$MOVE/rbunit"
  printf 'root:x:0:\nfivenines:x:999:\n' > "$MOVE/rbgroup"
  : > "$MOVE/svc.log"
  rm -f "$MOVE/svc.stopped" "$MOVE/rbinit"
  # Booted with systemd, but for notbooted.
  rm -rf "$MOVE/rbbooted"
  [ "$1" = notbooted ] || mkdir -p "$MOVE/rbbooted"
  (
    # shellcheck source=/dev/null
    . "$MOVE/rollback.sh"
    unset FIVENINES_TEST_MODE
    MOVE_STOP_SIGNAL=1
    export MOVE_STOP_SIGNAL
    SYSTEM_TYPE=systemd
    case "$1" in
      openrc-*) SYSTEM_TYPE=openrc ;;
    esac
    # The init script landed, for the OpenRC branch.
    if [ "$1" = openrc-stuck ]; then : > "$MOVE/rbinit"; fi
    FROM_USER_NAME=alice
    USER_INSTALL_DIR="$MOVE/rbinst"
    IMPORTED_STATE_FILES=""
    SERVICE_SET_UP=0
    UNDO_SYSTEM_INSTALL=0
    CREATED_UNIT=""
    CREATED_SUDOERS=0
    CREATED_CONFIG_DIR=0
    CREATED_INSTALL_DIR=0
    CREATED_ACCOUNT=0
    CREATED_GROUP=0
    case "$1" in
      imported | created | stuck | broken | unloaded | broken219 | notbooted | openrc-*)
        IMPORTED_STATE_FILES=" TOKEN MACHINE_ID"
        SERVICE_SET_UP=1
        ;;
    esac
    case "$1" in
      stuck | broken | broken219 | notbooted | openrc-*)
        MOVE_STOP_FAILS=1
        export MOVE_STOP_FAILS
        ;;
    esac
    case "$1" in
      unloaded | broken219)
        MOVE_SYSTEMD219=1
        export MOVE_SYSTEMD219
        ;;
    esac
    case "$1" in
      broken | broken219 | notbooted)
        MOVE_ISACTIVE_BROKEN=1
        export MOVE_ISACTIVE_BROKEN
        ;;
    esac
    if [ "$1" = created ] || [ "$1" = stuck ] || [ "$1" = broken ]; then
      UNDO_SYSTEM_INSTALL=1
      CREATED_UNIT="$MOVE/rbunit"
      CREATED_SUDOERS=1
      CREATED_CONFIG_DIR=1
      CREATED_INSTALL_DIR=1
      CREATED_ACCOUNT=1
      CREATED_GROUP=1
    fi
    # The systemctl, userdel and groupdel stubs, for this run only.
    # shellcheck disable=SC2030,SC2031
    PATH="$MOVE/svcbin:$MOVE/acctbin:$PATH"
    MOVE_RUNNER=$(sh -c 'echo "$PPID"')
    export MOVE_RUNNER
    rollback_user_takeover > "$MOVE/out" 2>&1
  )
  echo "$?"
}
check "--from-user rolls back what it installed, then the service, then restarts the user-level agent, through a second signal" \
  "$(rollback_run imported)|$(move_names "$MOVE/etc")|$(tr '\n' '|' < "$MOVE/svc.log")|$(grep -c 'runs again, unchanged' "$MOVE/out")" \
  "0|.env last_capture_id |systemctl stop fivenines-agent.service|systemctl disable fivenines-agent.service|start.sh||1"
# Value: protects=an undone --from-user leaves no system installation behind: the unit, the sudoers file, the config and install directories, the account and its group it created (#311);
#   fails_when=undo_system_install is not called, or removes a piece the run did not create;
#   why_new=the rollback used to leave them all; seam=as above, userdel and groupdel stubbed;
#   no_claim=the SELinux module (left to the uninstaller), or the OpenRC branch
check "--from-user rolls back what the move created of the system installation, and only that" \
  "$(rollback_run created)|$([ -e "$MOVE/etc" ] && echo etc)$([ -e "$MOVE/rbopt" ] && echo opt)$([ -e "$MOVE/rbsudoers" ] && echo sudoers)$([ -e "$MOVE/rbunit" ] && echo unit)|$(tr '\n' '|' < "$MOVE/svc.log")" \
  "0||systemctl stop fivenines-agent.service|systemctl disable fivenines-agent.service|systemctl daemon-reload|userdel fivenines|groupdel fivenines|start.sh|"
# A service that does not stop runs with the identity: no user-level agent
# is started beside it, nothing is taken back from under it, and the
# operator is told what to do.
# Value: protects=a rollback never leaves two agents with one identity, nor removes a running service's files;
#   fails_when=the rollback stops checking that the service stopped;
#   why_new=every rollback above stops the service; seam=a systemctl stop that fails;
#   no_claim=the OpenRC branch
check "--from-user restarts nothing and takes nothing back when the service does not stop, and says so" \
  "$(rollback_run stuck)|$([ -e "$MOVE/rbopt" ] && echo opt)$([ -e "$MOVE/rbunit" ] && echo unit)|$(tr '\n' '|' < "$MOVE/svc.log")|$(grep -c 'service did not stop' "$MOVE/out")" \
  "0|optunit|systemctl stop fivenines-agent.service|systemctl disable fivenines-agent.service||1"
# A systemctl that cannot reach systemd fails the stop and the state read
# alike: that is no stopped service.
# Value: protects=an unreadable service state is never read as a stopped service;
#   fails_when=the check goes back to is-active's exit code;
#   why_new=the check above reads a state systemctl reported; seam=an is-active that prints nothing and fails;
#   no_claim=the OpenRC branch (exit 3 alone reads as stopped there)
check "--from-user reads a service whose state systemctl cannot read as one that did not stop" \
  "$(rollback_run broken)|$([ -e "$MOVE/rbopt" ] && echo opt)|$(grep -c 'start.sh' "$MOVE/svc.log")|$(grep -c 'service did not stop' "$MOVE/out")" \
  "0|opt|0|1"
# systemd 219 (CentOS 7) says "unknown" of a unit it no longer has loaded,
# as after the disable: a stopped service, the rollback goes on. OpenRC:
# status 3 alone is stopped, unless the init script never landed.
# Value: protects=the rollback reads a stopped service as stopped on systemd 219 and on an OpenRC host whose init script never landed, and a running one as running;
#   fails_when=unknown or a missing init script reads as a service that did not stop (the user-level agent is then left stopped), or a failed OpenRC stop as a stopped one;
#   why_new=the checks above are systemd's inactive and an unreadable state; seam=systemctl, rc-service and rc-update stubs, the init script's path rewritten;
#   no_claim=a real systemd 219 or OpenRC
check "--from-user reads a unit systemd 219 calls unknown as stopped, and goes on" \
  "$(rollback_run unloaded)|$(grep -c 'start.sh' "$MOVE/svc.log")|$(grep -c 'service did not stop' "$MOVE/out")" "0|1|0"
# systemd 219's is-active says "unknown" for a bus error too: the state is
# read with show, which prints nothing then. A host not booted with systemd
# (a container, a chroot) runs nothing as the service.
# Value: protects=a bus error on systemd 219 never reads as a stopped service, and a host not booted with systemd never as a running one;
#   fails_when=the state goes back to is-active's output, or the booted check is dropped;
#   why_new=the checks above are a reachable systemd; seam=as above, /run/systemd/system rewritten;
#   no_claim=a real systemd 219
check "--from-user reads a systemd 219 bus error as a service that did not stop" \
  "$(rollback_run broken219)|$(grep -c 'start.sh' "$MOVE/svc.log")|$(grep -c 'service did not stop' "$MOVE/out")" "0|0|1"
check "--from-user on a host not booted with systemd reads the service as stopped, and goes on" \
  "$(rollback_run notbooted)|$(grep -c 'start.sh' "$MOVE/svc.log")|$(grep -c 'service did not stop' "$MOVE/out")" "0|1|0"
check "--from-user on OpenRC reads a service whose init script never landed as stopped, and one that does not stop as running" \
  "$(rollback_run openrc-gone)|$(grep -c 'start.sh' "$MOVE/svc.log")|$(grep -c 'service did not stop' "$MOVE/out")#$(rollback_run openrc-stuck)|$(grep -c 'start.sh' "$MOVE/svc.log")|$(grep -c 'service did not stop' "$MOVE/out")" \
  "0|1|0#0|0|1"
check "--from-user keeps what the move did not create, and leaves alone a service it did not set up" \
  "$(rollback_run stopping)|$(move_names "$MOVE/etc")|$([ -e "$MOVE/rbopt" ] && echo opt)$([ -e "$MOVE/rbsudoers" ] && echo sudoers)$([ -e "$MOVE/rbunit" ] && echo unit)|$(tr '\n' '|' < "$MOVE/svc.log")" \
  "0|.env MACHINE_ID TOKEN last_capture_id |optsudoersunit|start.sh|"
# Value: protects=a stop that gave up with an agent still running (stuck in the kernel) never gets a second agent started beside it, and says how to start it once it has exited (#316);
#   fails_when=the rollback starts the user-level agent without checking that none still runs;
#   why_new=the stop's failure used to exit with nothing armed; seam=as above; no_claim=an agent in D state (a sleeping one stands for it)
if [ -n "$MOVE_SLEEP" ]; then
  MOVE_STUCK=$(move_start agent "$MOVE/rbinst")
  check "--from-user starts no second user-level agent while one has not exited, and says how to start it" \
    "$(rollback_run stopping)|$(tr '\n' '|' < "$MOVE/svc.log")|$(grep -c 'has not exited' "$MOVE/out")" "0||1"
  kill "$MOVE_STUCK" 2> /dev/null
fi

# --from-user preflight: the argument it was given is never printed (a token
# passed out of habit would land in a job log), and the user side must be
# able to read its processes in /proc, which the stop needs to find the agent
# and wait for it.
# Value: protects=--from-user never echoes a token given in place of a user name, and refuses a user who cannot read its processes in /proc before anything stops;
#   fails_when=an error message repeats FROM_USER_NAME, or the /proc check is dropped (the state would be read while the agent may still write it);
#   why_new=the parser checks above stop at the usage line; seam=as_user is a function here;
#   no_claim=the checks after it, or a real /proc mounted with hidepid
sed -n '/^STATE_FILES=/p;/^exit_with_contact()/,/^}/p;/^resolve_takeover_user()/,/^}/p
        /^OWN_AGENTS_FN=/,/^'"'"'$/p;/^preflight_user_takeover()/,/^}/p' "$ROOT/fivenines_setup.sh" > "$MOVE/preuser.sh"
# Runs the preflight for user $1, with as_user failing on a command that
# reads /proc/self/exe when $2 is noproc. Prints its status and output on one
# line.
from_user_preflight() {
  (
    # shellcheck source=/dev/null
    . "$MOVE/preuser.sh"
    # Called by the preflight.
    # shellcheck disable=SC2317,SC2329
    as_user() {
      case "$1" in */proc/self/exe*) [ "$_preuser_proc" != noproc ] ;; *) return 0 ;; esac
    }
    _preuser_proc=${2:-}
    FROM_USER_NAME=$1
    # The user who ran sudo: no confirmation is asked (#312).
    SUDO_USER=$(id -un)
    ASSUME_YES=0
    SYSTEM_TYPE=systemd
    # Test mode skips the stop, and so the check: $3 sets it.
    FIVENINES_TEST_MODE=${3:-}
    preflight_user_takeover
  ) 2>&1 | tr '\n' ' '
}
check "--from-user never repeats an argument that is not a user name" \
  "$(from_user_preflight 'tok:ab12cd34ef56' | grep -c 'ab12cd34ef56')|$(from_user_preflight 'tok-ab12cd34ef56' | grep -c 'ab12cd34ef56')" "0|0"
if [ ! -e /etc/fivenines_agent ] && command -v base64 > /dev/null 2>&1 && command -v setsid > /dev/null 2>&1; then
  check "--from-user refuses a user who cannot read its processes in /proc, and goes on otherwise, or in test mode" \
    "$(from_user_preflight "$(id -un)" noproc | grep -c 'cannot read .* processes in /proc')|$(from_user_preflight "$(id -un)" | grep -c 'Moving the user-level installation')|$(from_user_preflight "$(id -un)" noproc 1 | grep -c 'Moving the user-level installation')" "1|1|1"
fi

# --from-user preflight, its refusals run for real: as_user through the su
# stub, as this user, on an installation in the scratch directory, with
# /etc/fivenines_agent rewritten (#314).
# Value: protects=--from-user refuses, before anything changes, an existing system TOKEN or state file, a start.sh naming another config directory, a user name that is not one, another user's installation unconfirmed (#312), and another agent using the same config directory (#317);
#   fails_when=a refusal is dropped or its test inverted, the confirmation no longer applies to another user than SUDO_USER, or the scan for other agents misses one whose binary is elsewhere;
#   why_new=test-distro runs only the successful move, and the armv7l stub box stops before the preflight; seam=/etc/fivenines_agent rewritten;
#   no_claim=the confirmation prompt at a terminal (no terminal here), or root's su
sed -n '/^STATE_FILES=/p;/^AS_USER_TIMEOUT=/p;/^as_user()/,/^}/p;/^exit_with_contact()/,/^}/p
        /^OWN_AGENTS_FN=/,/^'"'"'$/p;/^resolve_takeover_user()/,/^}/p;/^preflight_user_takeover()/,/^}/p' "$ROOT/fivenines_setup.sh" \
  | sed "s|/etc/fivenines_agent|$MOVE/petc|g" > "$MOVE/preuser_real.sh"
PRE_UI="$MOVE/preinst"
PRE_UC="$MOVE/precfg"
# Runs the preflight for user $1 (default: this one), with SUDO_USER $2
# (unset: this user; empty: none, root's own shell) and ASSUME_YES $3, stdin
# from /dev/null. Prints its status and output on one line.
from_user_preflight_real() {
  (
    # shellcheck source=/dev/null
    . "$MOVE/preuser_real.sh"
    FROM_USER_NAME=${1:-$(id -un)}
    SUDO_USER=${2-$(id -un)}
    ASSUME_YES=${3:-0}
    SYSTEM_TYPE=systemd
    FIVENINES_INSTALL_DIR="$PRE_UI"
    FIVENINES_CONFIG_DIR="$PRE_UC"
    unset FIVENINES_TEST_MODE
    preflight_user_takeover < /dev/null
    echo "rc=$?"
  ) 2>&1 | tr '\n' ' '
}
# A fresh user-level installation, and an empty system config directory.
from_user_preflight_reset() {
  rm -rf "$PRE_UI" "$PRE_UC" "$MOVE/petc"
  mkdir -p "$PRE_UI" "$PRE_UC" "$MOVE/petc"
  printf 'per-host-token-0001' > "$PRE_UC/TOKEN"
  printf '#!/bin/bash\nexport CONFIG_DIR="%s"\n' "$PRE_UC" > "$PRE_UI/start.sh"
}
if command -v base64 > /dev/null 2>&1 && command -v setsid > /dev/null 2>&1; then
  from_user_preflight_reset
  _out=$(from_user_preflight_real)
  check "--from-user goes on with this user's own installation, and says the system agent keeps its token" \
    "$(printf '%s' "$_out" | grep -c 'Moving the user-level installation')|$(printf '%s' "$_out" | grep -c 'The system agent keeps the token')" "1|1"
  printf 'per-host-token-0002' > "$MOVE/petc/TOKEN"
  check "--from-user refuses when a system installation exists" \
    "$(from_user_preflight_real | grep -c 'A system installation already exists')" "1"
  from_user_preflight_reset
  printf 'x\n' > "$MOVE/petc/MACHINE_ID"
  check "--from-user refuses when an earlier installation left a state file" \
    "$(from_user_preflight_real | grep -c "$MOVE/petc/MACHINE_ID exists")" "1"
  from_user_preflight_reset
  printf '#!/bin/bash\nexport CONFIG_DIR="%s"\n' "$MOVE/elsewhere-cfg" > "$PRE_UI/start.sh"
  check "--from-user refuses a start.sh that names another config directory" \
    "$(from_user_preflight_real | grep -c 'No user-level installation of')" "1"
  from_user_preflight_reset
  check "--from-user refuses a user name of two words" \
    "$(from_user_preflight_real 'alice bob' | grep -c 'No user of the name given')" "1"
  # Another user's installation: a terminal to confirm at, or --yes (#312).
  _out=$(from_user_preflight_real "" "someone-else")
  check "--from-user moving another user's installation with no terminal and no --yes is refused, and names --yes" \
    "$(printf '%s' "$_out" | grep -c 'Re-run with --yes')|$(printf '%s' "$_out" | grep -c 'Moving the user-level installation')" "1|0"
  check "--from-user moving another user's installation goes on with --yes" \
    "$(from_user_preflight_real "" "someone-else" 1 | grep -c 'Moving the user-level installation')" "1"
  check "--from-user run as root itself (no SUDO_USER) is another user's move" \
    "$(from_user_preflight_real "" "" | grep -c 'Re-run with --yes')" "1"
  # Another agent of the user with the same config directory, run from
  # another install directory (#317); one with another config directory is
  # none of the move's business.
  if [ -n "$MOVE_SLEEP" ]; then
    MOVE_ELSEWHERE=$(move_start agent "$MOVE/elsewhere-inst" "CONFIG_DIR=$PRE_UC")
    check "--from-user refuses while another installation's agent uses the same config directory" \
      "$(from_user_preflight_real | grep -c "Another agent of $(id -un) uses $PRE_UC")" "1"
    # The same agent, as one started under another group would read: its
    # binary hidden (it is found by its command line), then its environment
    # too (its installation's start.sh tells its config directory). One whose
    # start.sh names another config directory goes on; one with no start.sh
    # counts.
    # Value: protects=--from-user sees another agent of the user's started under another group, and tells its config directory from its start.sh when the kernel hides its environment;
    #   fails_when=the scan drops agent_exe's command-line fallback, counts every agent whose environment it cannot read, or stops counting one it cannot place;
    #   why_new=the check above reads every exe link and environment; seam=a readlink that cannot read /proc/*/exe, and a tr that cannot read /proc/*/environ;
    #   no_claim=a real newgrp (the stub box has no second group to start a process under)
    # The stubs, for these runs only.
    # shellcheck disable=SC2030,SC2031
    check "--from-user refuses while another agent whose binary cannot be read uses the same config directory" \
      "$( (PATH="$MOVE/noexebin:$PATH"; from_user_preflight_real) | grep -c "Another agent of $(id -un) uses $PRE_UC")" "1"
    printf 'export CONFIG_DIR="%s"\n' "$PRE_UC" > "$MOVE/elsewhere-inst/start.sh"
    # shellcheck disable=SC2030,SC2031
    check "--from-user refuses while an agent it can read neither the binary nor the environment of names the same config in its start.sh" \
      "$( (PATH="$MOVE/noenvbin:$MOVE/noexebin:$PATH"; from_user_preflight_real) | grep -c "Another agent of $(id -un) uses $PRE_UC")" "1"
    printf 'export CONFIG_DIR="%s"\n' "$MOVE/elsewhere-cfg" > "$MOVE/elsewhere-inst/start.sh"
    mkdir -p "$MOVE/elsewhere-cfg"
    # shellcheck disable=SC2030,SC2031
    check "--from-user goes on beside such an agent whose start.sh names another config directory" \
      "$( (PATH="$MOVE/noenvbin:$MOVE/noexebin:$PATH"; from_user_preflight_real) | grep -c 'Moving the user-level installation')" "1"
    rm -f "$MOVE/elsewhere-inst/start.sh"
    # shellcheck disable=SC2030,SC2031
    check "--from-user refuses while such an agent has no start.sh to tell its config directory" \
      "$( (PATH="$MOVE/noenvbin:$MOVE/noexebin:$PATH"; from_user_preflight_real) | grep -c "Another agent of $(id -un) uses $PRE_UC")" "1"
    kill "$MOVE_ELSEWHERE" 2> /dev/null
    move_gone "$MOVE_ELSEWHERE"
    # An agent whose installation was deleted under it: its exe link ends in
    # " (deleted)", which readlink -f fails on.
    # Value: protects=--from-user still sees another agent of the user's whose installation was deleted under it;
    #   fails_when=the scan goes back to readlink -f; why_new=every agent above runs from a directory that exists; seam=none;
    #   no_claim=BusyBox's readlink, which fails on it even with the directory there
    MOVE_ELSEWHERE=$(move_start agent "$MOVE/deleted-inst" "CONFIG_DIR=$PRE_UC")
    rm -rf "$MOVE/deleted-inst"
    check "--from-user refuses while an agent whose installation was deleted uses the same config directory" \
      "$(from_user_preflight_real | grep -c "Another agent of $(id -un) uses $PRE_UC")" "1"
    kill "$MOVE_ELSEWHERE" 2> /dev/null
    move_gone "$MOVE_ELSEWHERE"
    MOVE_ELSEWHERE=$(move_start agent "$MOVE/elsewhere-inst" "CONFIG_DIR=$MOVE/elsewhere-cfg")
    check "--from-user goes on beside another installation's agent with its own config directory" \
      "$(from_user_preflight_real | grep -c 'Moving the user-level installation')" "1"
    kill "$MOVE_ELSEWHERE" 2> /dev/null
    # This installation's own agent, under its own path: stopped by the move,
    # not another installation.
    MOVE_ELSEWHERE=$(move_start agent "$PRE_UI" "CONFIG_DIR=$PRE_UC")
    check "--from-user takes its own installation's running agent for itself" \
      "$(from_user_preflight_real | grep -c 'Moving the user-level installation')" "1"
    kill "$MOVE_ELSEWHERE" 2> /dev/null
  fi
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
# Before that stop (a failed download or ping, an interrupt), it takes back
# what the move created instead, with no restart, and a second signal cannot
# cut it short (#311).
# Value: protects=a --from-user failure before the user-level agent stopped undoes the system pieces the move created, once, ignoring a second signal, and says nothing was moved;
#   fails_when=the undo branch is dropped, runs beside the rollback, or keeps the interrupt trap armed;
#   why_new=the check above never arms the undo; seam=rollback_user_takeover and undo_system_install are stubs; no_claim=what the undo removes (checked through the rollback)
ewc_undo() {
  (
    # shellcheck source=/dev/null
    . "$MOVE/ewc.sh"
    # Called through exit_with_contact.
    # shellcheck disable=SC2317,SC2329
    rollback_user_takeover() { echo "rolled back"; }
    # The undo is signalled while it runs: ignored, it completes.
    # shellcheck disable=SC2317,SC2329
    undo_system_install() { kill -INT "$(sh -c 'echo "$PPID"')"; echo "undone"; }
    trap 'echo "interrupted again"' INT
    TAKEOVER_ROLLBACK=$1
    UNDO_SYSTEM_INSTALL=$2
    FROM_USER_NAME=alice
    exit_with_contact "failed"
  ) 2>&1 | grep -e '^rolled back$' -e '^undone$' -e '^interrupted again$' -e 'Nothing was moved' | tr '\n' '|'
}
check "a --from-user failure before the stop undoes what the move created, through a second signal, and restarts nothing" \
  "$(ewc_undo 0 1)#$(ewc_undo 1 1)#$(ewc_undo 0 0)" \
  "undone|[!] Nothing was moved: the user-level agent of alice was not stopped.|#rolled back|#"

# --from-user: import_user_state outside test mode, through the su stub (it
# prints a PAM line first), with /etc/fivenines_agent rewritten to a scratch
# directory and chown stubbed: a test that is not root cannot give a file away.
# Value: protects=--from-user writes the user's state with the directory root's alone, gives it back, records each file before writing it so a rollback takes back a TOKEN whose chown failed, and refuses a symlinked or empty state file;
#   fails_when=IMPORTED_STATE_FILES is appended after the writes again, the directory is not made root-only around them or not given back, or a symlink or an empty TOKEN is carried;
#   why_new=the harness and test-distro import only plain files through a real chown; seam=/etc/fivenines_agent rewritten, chown stubbed;
#   no_claim=that the files end up owned by fivenines, or the ownership semantics a real chown enforces
sed -n '/^STATE_FILES=/p;/^STATE_FILE_MAX=/p;/^AS_USER_TIMEOUT=/p;/^as_user()/,/^}/p
        /^OWN_AGENTS_FN=/,/^'"'"'$/p;/^decode_state()/,/^}/p
        /^import_user_state()/,/^}/p;/^undo_system_install()/,/^}/p;/^rollback_user_takeover()/,/^}/p' \
  "$ROOT/fivenines_setup.sh" | sed "s|/etc/fivenines_agent|$MOVE/etc2|g" > "$MOVE/import.sh"
mkdir -p "$MOVE/chownbin" "$MOVE/iuc" "$MOVE/b64bin"
cat > "$MOVE/chownbin/chown" << EOF
#!/bin/sh
echo "chown \$*" >> "$MOVE/chown.log"
[ "\$2" != "\${MOVE_CHOWN_FAILS:-}" ]
EOF
# A base64 whose read fails part-way: it prints the start of the encoding, then
# fails, as head | base64 hid (#323). Decoding is the real one's.
cat > "$MOVE/b64bin/base64" << EOF
#!/bin/sh
[ "\$1" = "-d" ] && exec $(command -v base64) "\$@"
$(command -v base64) "\$@" | head -c 8
echo "base64: read error: Input/output error" >&2
exit 1
EOF
chmod 755 "$MOVE/chownbin/chown" "$MOVE/b64bin/base64"
# Runs import_user_state from $MOVE/iuc into an empty $MOVE/etc2, and the
# rollback when it fails; a chown of $1 fails, STATE_FILE_MAX is $2 when
# given, with $3 failread every read fails part-way, and with $3 grown
# MACHINE_ID grows once its size was read. Prints its status.
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
    SERVICE_SET_UP=0
    UNDO_SYSTEM_INSTALL=0
    MOVE_CHOWN_FAILS="${1:-}"
    export MOVE_CHOWN_FAILS
    if [ -n "${2:-}" ]; then STATE_FILE_MAX=$2; fi
    # The chown stub, and the failing base64, for this run only.
    # shellcheck disable=SC2030,SC2031
    PATH="$MOVE/chownbin:$PATH"
    if [ "${3:-}" = failread ]; then PATH="$MOVE/b64bin:$PATH"; fi
    if [ "${3:-}" = grown ]; then PATH="$MOVE/growbin:$PATH"; fi
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
# Value: protects=a state file read only part-way is never installed as a whole one, and an oversized one is refused before it is read (#323);
#   fails_when=the read goes back through a pipe whose status is base64's, or the end marker is printed after a failed read;
#   why_new=the checks above read every file whole; seam=a base64 on the user's PATH that fails part-way;
#   no_claim=a real EIO
check "--from-user stops at a state file whose read fails part-way, and carries nothing" \
  "$(from_user_import "" "" failread)|$(move_names "$MOVE/etc2")|$(grep -c 'Could not read' "$MOVE/out")" \
  "0||1"
check "--from-user stops at a state file larger than STATE_FILE_MAX, and carries nothing" \
  "$(from_user_import "" 30)|$(move_names "$MOVE/etc2")|$(grep -c 'MACHINE_ID is larger than any agent state file' "$MOVE/out")" \
  "0||1"
# Value: protects=a state file that grew past STATE_FILE_MAX after its size was read is neither read past the limit nor carried;
#   fails_when=the user's side encodes the file itself again rather than a copy bounded by head -c (root then receives it whole, and refuses it only once decoded);
#   why_new=the check above refuses a file at its size check; seam=a wc on the user's PATH that reads MACHINE_ID as 1 byte;
#   no_claim=a real concurrent writer
check "--from-user stops at a state file grown past STATE_FILE_MAX since its size was read, and none of it reaches root" \
  "$(from_user_import "" 30 grown)|$(move_names "$MOVE/etc2")|$(grep -c 'MACHINE_ID is larger than any agent state file' "$MOVE/out")|$([ -e "$MOVE/istage/user_state/MACHINE_ID" ] && echo received)" \
  "0||1|"
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
# Value: protects=--from-user removes only what fivenines_setup_user.sh and the agent created (its temporary files included), keeps .env, .env.system and other files, drops only the crontab lines starting it, and stops an agent a crontab entry started again meanwhile (#310);
#   fails_when=the removal goes back to rm -rf of a directory, removes .env, the crontab filter misses a spelling of start.sh or drops a line naming fivenines, or the second stop is dropped;
#   why_new=test-distro Test 12 removes an installation that holds nothing else, on an image with no crontab, in test mode; seam=none;
#   no_claim=that it runs as the user (su is a stub here), or that the service started first
sed -n '/^STATE_FILES=/p;/^USER_INSTALL_FILES=/p;/^USER_CONFIG_FILES=/p;/^AS_USER_TIMEOUT=/p;/^AS_USER_REMOVAL_TIMEOUT=/p
        /^as_user()/,/^}/p;/^OWN_AGENTS_FN=/,/^'"'"'$/p;/^start_spellings()/,/^}/p
        /^stop_user_agent()/,/^}/p;/^remove_user_installation()/,/^}/p' "$ROOT/fivenines_setup.sh" > "$MOVE/from_user.sh"
MOVE_HOME="$MOVE/home/alice"
MOVE_UI="$MOVE_HOME/.local/fivenines"
MOVE_UC="$MOVE_HOME/.config/fivenines_agent"
mkdir -p "$MOVE_UI/fivenines-agent-linux-amd64" "$MOVE_UC"
for _f in start.sh stop.sh status.sh logs.sh refresh.sh agent.pid agent.log \
  fivenines-agent-linux-amd64/fivenines-agent-linux-amd64; do
  : > "$MOVE_UI/$_f"
done
printf 'the operator keeps notes here\n' > "$MOVE_UI/notes.txt"
for _f in TOKEN MACHINE_ID last_capture_id journal_units.allow image_inventory_done \
  image_inventory_done.tmp sudo_refusals sudo_refusals.Xy12Zw .env .env.system; do
  printf '%s\n' "$_f" > "$MOVE_UC/$_f"
done
# The user-level agent, started again since the move stopped it.
MOVE_RESTARTED=""
if [ -n "$MOVE_SLEEP" ]; then
  MOVE_RESTARTED=$(move_start agent "$MOVE_UI")
fi
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
check "--from-user removes the installer's and the agent's files only, and keeps .env and .env.system" \
  "$(move_names "$MOVE_UI")|$(move_names "$MOVE_UC")|$(grep -c '^Kept ' "$MOVE/out")" \
  "notes.txt |.env .env.system |2"
if [ -n "$MOVE_RESTARTED" ]; then
  check "--from-user stops the user-level agent a crontab entry started again, before its files go" \
    "$(grep -c 'was started again since the move stopped it' "$MOVE/out")|$(move_gone "$MOVE_RESTARTED" || echo alive)" "1|"
fi
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
_removed=$(sed -n 's/^USER_INSTALL_FILES="\(.*\)"$/\1/p' "$ROOT/fivenines_setup.sh" \
  | tr ' ' '\n' | grep . | LC_ALL=C sort -u | tr '\n' ' ')
check "--from-user removes every file the user-level scripts write in their install directory" "$_removed" "$_written"

# --from-system: add_reboot_entry, the @reboot line that starts the moved
# agent at boot, as the system service did.
# Value: protects=--from-system adds one @reboot line for its start.sh after the user's own lines, and none when one (any spelling) is already there;
#   fails_when=the already-there check is dropped (two agents with one identity at boot), or the user's lines are lost or a blank line is added;
#   why_new=no test-distro image has a crontab command, so Test 13 takes the no-crontab branch; seam=none;
#   no_claim=what cron does with the line at boot
sed -n '/^ensure_work_dir()/,/^}/p;/^start_spellings()/,/^}/p;/^shell_quote()/,/^}/p
        /^reboot_line()/,/^}/p;/^add_reboot_entry()/,/^}/p' \
  "$ROOT/fivenines_setup_user.sh" > "$MOVE/reboot.sh"
mkdir -p "$MOVE/rstage"
# Runs add_reboot_entry for an installation in $2 (default ~/.local/fivenines)
# over the crontab $1 (- for none, keep to keep the one there), crontab -l
# failing for another reason with $3 fail, and prints its status and the
# crontab after it.
reboot_entry() {
  if [ "$1" != "keep" ]; then
    rm -f "$MOVE/crontab"
    if [ "$1" != "-" ]; then printf '%s\n' "$1" > "$MOVE/crontab"; fi
  fi
  (
    # shellcheck source=/dev/null
    . "$MOVE/reboot.sh"
    HOME="$MOVE_HOME"
    INSTALL_DIR="${2:-$MOVE_HOME/.local/fivenines}"
    WORK_DIR="$MOVE/rstage"
    if [ "${3:-}" = fail ]; then MOVE_CRONTAB_FAIL=1 && export MOVE_CRONTAB_FAIL; fi
    if [ "${3:-}" = vixie ]; then MOVE_CRONTAB_VIXIE=1 && export MOVE_CRONTAB_VIXIE; fi
    add_reboot_entry > /dev/null 2>&1
  )
  printf '%s|%s' "$?" "$(tr '\n' '|' < "$MOVE/crontab" 2>/dev/null)"
}
check "--from-system starts the agent at boot for a user with no crontab" \
  "$(reboot_entry -)" "0|@reboot $MOVE_HOME/.local/fivenines/start.sh|"
check "--from-system starts the agent at boot for a user with no crontab, in cronie's and Vixie cron's words" \
  "$(reboot_entry - "" vixie)" "0|@reboot $MOVE_HOME/.local/fivenines/start.sh|"
check "--from-system adds its @reboot line after the user's own" \
  "$(reboot_entry '0 * * * * echo other')" "0|0 * * * * echo other|@reboot $MOVE_HOME/.local/fivenines/start.sh|"
# The ${HOME} is the literal text of the crontab line.
# shellcheck disable=SC2016
check "--from-system adds no second line for a start.sh the crontab already runs" \
  "$(reboot_entry '@reboot ${HOME}/.local/fivenines/start.sh')" '0|@reboot ${HOME}/.local/fivenines/start.sh|'
check "--from-system adds its line when the crontab has it only commented out" \
  "$(reboot_entry '#@reboot ~/.local/fivenines/start.sh')" "0|#@reboot ~/.local/fivenines/start.sh|@reboot $MOVE_HOME/.local/fivenines/start.sh|"
# Value: protects=only an @reboot line that runs start.sh, as a word of its own, counts as one that starts the agent at boot (#320);
#   fails_when=any line naming the path counts again (a backup cp, a start.sh.bak);
#   why_new=the checks above use whole @reboot lines; seam=none; no_claim=a line that runs start.sh through a wrapper of its own
check "--from-system adds its line beside a crontab line that only copies start.sh" \
  "$(reboot_entry '0 3 * * * cp ~/.local/fivenines/start.sh /backups/')" "0|0 3 * * * cp ~/.local/fivenines/start.sh /backups/|@reboot $MOVE_HOME/.local/fivenines/start.sh|"
check "--from-system adds its line beside an @reboot line that runs another file" \
  "$(reboot_entry '@reboot ~/.local/fivenines/start.sh.bak')" "0|@reboot ~/.local/fivenines/start.sh.bak|@reboot $MOVE_HOME/.local/fivenines/start.sh|"
check "--from-system adds no line beside an @reboot line that runs start.sh after another command" \
  "$(reboot_entry '@reboot sleep 60 && ~/.local/fivenines/start.sh > /dev/null 2>&1')" "0|@reboot sleep 60 && ~/.local/fivenines/start.sh > /dev/null 2>&1|"
# Value: protects=an install path with a space or a quote gets an @reboot line cron runs whole, found again on the next run; one with a %, which cron reads as a new line, gets none (#319);
#   fails_when=the path goes back unquoted, its quoted spelling is not looked for, or a % path is written;
#   why_new=every path above is plain; seam=none; no_claim=what each cron does with the line (cronie, Vixie cron, BusyBox crond)
_spaced="$MOVE_HOME/mon agent's"
check "--from-system quotes an install path that holds a space and a quote" \
  "$(reboot_entry - "$_spaced")" "0|@reboot '$MOVE_HOME/mon agent'\\''s/start.sh'|"
check "--from-system finds its quoted line again" \
  "$(reboot_entry keep "$_spaced")" "0|@reboot '$MOVE_HOME/mon agent'\\''s/start.sh'|"
check "--from-system adds no @reboot line for an install path with a %, and leaves the crontab" \
  "$(reboot_entry '0 * * * * echo other' "$MOVE_HOME/100%")" "1|0 * * * * echo other|"
# Value: protects=a crontab that cannot be read is never replaced (#321);
#   fails_when=any crontab -l failure reads as an empty crontab again;
#   why_new=the stub used to fail only for "no crontab"; seam=crontab stub refusing as cron.deny does; no_claim=other cron implementations' messages
check "--from-system leaves a crontab it cannot read as it is" \
  "$(reboot_entry '0 * * * * echo other' "" fail)" "1|0 * * * * echo other|"

# fivenines_uninstall_user.sh, run whole from a scratch copy (it deletes
# itself) and confirmed with y, on an installation under a scratch HOME.
# Value: protects=the user uninstaller drops only this installation's crontab lines and signals only an agent run from its own directory;
#   fails_when=it goes back to grep -v fivenines on the crontab, or to pkill -f on the binary name or another unanchored pattern;
#   why_new=test-distro Test 11 runs it in test mode, which skips the stop, on an image with no crontab; seam=none;
#   no_claim=which files it removes (checked below)
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
check "fivenines_uninstall_user.sh removes both directories when they hold only the installation" \
  "$([ -e "$MOVE_CAROL/.local/fivenines" ] && echo install)$([ -e "$MOVE_CAROL/.config/fivenines_agent" ] && echo config)" ""
# The @reboot line --from-system writes for a path that needs quoting
# (#319): the quoted spelling is the one start_spellings gives fifth.
# Value: protects=the user uninstaller drops the quoted @reboot line --from-system wrote for a path with a quote;
#   fails_when=START_SPELLING_5 is no longer looked for, or its escaping changes on one side only;
#   why_new=every other crontab here names a plain path; seam=none; no_claim=remove_user_installation, which looks for the same five spellings
MOVE_ERIN="$MOVE/home/erin"
MOVE_ERIN_INST="$MOVE_ERIN/mon agent's"
mkdir -p "$MOVE_ERIN_INST" "$MOVE_ERIN/cfg"
printf '#!/bin/bash\nexport CONFIG_DIR="%s"\n' "$MOVE_ERIN/cfg" > "$MOVE_ERIN_INST/start.sh"
chmod 755 "$MOVE_ERIN_INST/start.sh"
printf '%s\n' '0 * * * * echo other' "@reboot '$MOVE_ERIN/mon agent'\\''s/start.sh'" > "$MOVE/crontab"
cp "$ROOT/fivenines_uninstall_user.sh" "$MOVE/run/fivenines_uninstall_user.sh"
(
  cd "$MOVE/run" || exit 99
  printf 'y\n' | HOME="$MOVE_ERIN" FIVENINES_TEST_MODE=1 \
    FIVENINES_INSTALL_DIR="$MOVE_ERIN_INST" FIVENINES_CONFIG_DIR="$MOVE_ERIN/cfg" \
    sh ./fivenines_uninstall_user.sh > "$MOVE/out" 2>&1
)
check "fivenines_uninstall_user.sh drops the quoted @reboot line of a path with a quote" \
  "$?|$(tr '\n' '|' < "$MOVE/crontab")" "0|0 * * * * echo other|"
# Directories FIVENINES_INSTALL_DIR and FIVENINES_CONFIG_DIR named, which
# hold the user's own files too ($HOME/bin, $HOME/.config).
# Value: protects=the user uninstaller removes only the files the installers and the agent write (.env and .env.system included), and keeps a directory that holds anything else (#313);
#   fails_when=it goes back to rm -rf of either directory, or its lists lose a file the agent writes;
#   why_new=the run above uninstalls directories that hold nothing else; seam=none;
#   no_claim=a file the agent may write in a later release (ci/build-scripts.sh holds the two lists equal, not complete)
MOVE_DAVE="$MOVE/home/dave"
mkdir -p "$MOVE_DAVE/bin/fivenines-agent-linux-amd64" "$MOVE_DAVE/bin/fivenines-agent-linux-amd64.old" "$MOVE_DAVE/.config"
for _f in start.sh stop.sh status.sh logs.sh refresh.sh agent.pid agent.log \
  fivenines-agent-linux-amd64/fivenines-agent-linux-amd64 fivenines-agent-linux-amd64.old/fivenines-agent-linux-amd64; do
  : > "$MOVE_DAVE/bin/$_f"
done
printf '#!/bin/bash\nexport CONFIG_DIR="%s"\n' "$MOVE_DAVE/.config" > "$MOVE_DAVE/bin/start.sh"
printf '#!/bin/sh\n' > "$MOVE_DAVE/bin/stop.sh"
chmod 755 "$MOVE_DAVE/bin/start.sh" "$MOVE_DAVE/bin/stop.sh"
printf 'mine\n' > "$MOVE_DAVE/bin/my-tool"
for _f in TOKEN MACHINE_ID last_capture_id journal_units.allow image_inventory_done \
  image_inventory_done.tmp sudo_refusals sudo_refusals.Ab12Cd .env .env.system; do
  printf '%s\n' "$_f" > "$MOVE_DAVE/.config/$_f"
done
mkdir -p "$MOVE_DAVE/.config/some-app"
rm -f "$MOVE/crontab"
cp "$ROOT/fivenines_uninstall_user.sh" "$MOVE/run/fivenines_uninstall_user.sh"
(
  cd "$MOVE/run" || exit 99
  printf 'y\n' | HOME="$MOVE_DAVE" FIVENINES_TEST_MODE="" \
    FIVENINES_INSTALL_DIR="$MOVE_DAVE/bin" FIVENINES_CONFIG_DIR="$MOVE_DAVE/.config" \
    sh ./fivenines_uninstall_user.sh > "$MOVE/out" 2>&1
)
check "fivenines_uninstall_user.sh removes only its own files from shared directories, and keeps them" \
  "$?|$(move_names "$MOVE_DAVE/bin")|$(move_names "$MOVE_DAVE/.config")|$(grep -c 'Kept ' "$MOVE/out")" \
  "0|my-tool |some-app |2"

# fivenines_uninstall.sh, run whole from a scratch copy in test mode (no
# service management), with id answering root and an existing fivenines
# account, su and userdel stubbed, and a sudo that records any call.
# Value: protects=the system uninstaller removes the account as root without sudo, and exits 1 saying what it left when a removal fails (#302);
#   fails_when=the sudo prefixes come back, step_failed stops setting the exit status, or the final check of the account is dropped;
#   why_new=test-distro Test 8 runs only the successful removal; seam=id, su, userdel and sudo stubbed on PATH;
#   no_claim=the systemd and OpenRC branches (test mode skips them), or a real userdel
mkdir -p "$MOVE/uninstbin"
# shellcheck disable=SC2016
printf '#!/bin/sh\n[ "$*" = "-u" ] && { echo 0; exit 0; }\n[ "$*" = "-u fivenines" ] && { [ -e "%s" ] && exit 1; echo 999; exit 0; }\nexit 1\n' \
  "$MOVE/fivenines-gone" > "$MOVE/uninstbin/id"
printf '#!/bin/sh\nexit 1\n' > "$MOVE/uninstbin/su"
printf '#!/bin/sh\necho sudo >> "%s"\necho "sudo: not found" >&2\nexit 127\n' "$MOVE/uninst-sudo" > "$MOVE/uninstbin/sudo"
# userdel removes the account (a marker file) unless MOVE_USERDEL_FAILS is
# set. With /etc/init.d and /etc/systemd/system rewritten below, the
# uninstaller detects neither OpenRC nor systemd and removes the account with
# userdel: deluser and delgroup (its OpenRC branch, not covered here) are
# stubbed alike only so that no rewrite gap reaches a real account.
for _tool in userdel deluser delgroup; do
  # shellcheck disable=SC2016
  printf '#!/bin/sh\n[ -n "${MOVE_USERDEL_FAILS:-}" ] && exit 8\n: > "%s"\n' "$MOVE/fivenines-gone" > "$MOVE/uninstbin/$_tool"
done
chmod 755 "$MOVE/uninstbin/"*
# SELinux reads as disabled, so no policy module is touched.
printf '#!/bin/sh\necho Disabled\n' > "$MOVE/uninstbin/getenforce"
chmod 755 "$MOVE/uninstbin/getenforce"
# Runs the uninstaller ($1 fail: userdel fails), every path it removes
# rewritten into the scratch directory (it believes it is root: on a host with
# an installation it must never reach the real one), and prints its status,
# the sudo calls it made, and its last line.
system_uninstall() {
  rm -f "$MOVE/fivenines-gone" "$MOVE/uninst-sudo"
  sed "s|/etc/fivenines_agent|$MOVE/u-etc|g;s|/etc/sudoers.d/fivenines|$MOVE/u-sudoers|g;s|/opt/fivenines|$MOVE/u-opt|g
       s|/etc/systemd/system|$MOVE/u-units|g;s|/etc/init.d|$MOVE/u-init|g
       s|/boot/config/custom/fivenines_agent|$MOVE/u-boot|g;s|/var/log/fivenines-agent.log|$MOVE/u-log|g" \
    "$ROOT/fivenines_uninstall.sh" > "$MOVE/run/fivenines_uninstall.sh"
  # A path the list above misses would be removed for real: refused instead.
  if grep -nE '/etc/fivenines|/opt/fivenines|/etc/sudoers|/etc/systemd|/etc/init\.d|/boot/config|/var/log/fivenines' \
    "$MOVE/run/fivenines_uninstall.sh" > "$MOVE/u-system-paths"; then
    printf 'system path left: %s|' "$(head -n 1 "$MOVE/u-system-paths")"
    return
  fi
  mkdir -p "$MOVE/u-etc"
  printf 'per-host-token-0001' > "$MOVE/u-etc/TOKEN"
  (
    cd "$MOVE/run" || exit 99
    if [ "${1:-}" = fail ]; then MOVE_USERDEL_FAILS=1 && export MOVE_USERDEL_FAILS; fi
    # The stubs, for this run only.
    # shellcheck disable=SC2031
    FIVENINES_TEST_MODE=1 PATH="$MOVE/uninstbin:$PATH" sh ./fivenines_uninstall.sh > "$MOVE/out" 2>&1
  )
  printf '%s|%s|%s' "$?" "$(cat "$MOVE/uninst-sudo" 2>/dev/null)" "$(tail -n 1 "$MOVE/out")"
}
# Never as root: the uninstaller would then act on whatever its stubs and
# rewritten paths do not cover.
if [ "$(id -u)" != "0" ]; then
  check "fivenines_uninstall.sh removes the configuration and the account as root, with no sudo" \
    "$(system_uninstall)|$([ -e "$MOVE/u-etc" ] && echo kept)" "0||fivenines agent uninstallation complete.|"
  check "fivenines_uninstall.sh exits 1, and says so, when the account cannot be removed" \
    "$(system_uninstall fail)|$(grep -c 'ERROR: could not remove the system user fivenines' "$MOVE/out")" \
    "1||fivenines agent uninstallation finished with errors (see above).|1"
else
  echo "  (the system uninstaller is not run as root here)"
fi
# userdel, deluser and the service tools live in the sbin directories, which
# a root shell reached through su without -, or a sudo that keeps the
# caller's PATH, may not search: the uninstaller adds them before any of its
# steps. Read, not run: on the test host they are the real tools.
# Value: protects=the system uninstaller finds userdel, deluser, rc-update and systemctl from a PATH with no sbin directory;
#   fails_when=the PATH line is dropped or moved below the first step;
#   why_new=every run above puts its stubs first on PATH; seam=none; no_claim=a host's real sbin tools
# The $ are the uninstaller's own text.
# shellcheck disable=SC2016
check "fivenines_uninstall.sh searches the sbin directories before its first step" \
  "$(in_order "$ROOT/fivenines_uninstall.sh" 'PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"' 'export PATH' 'detect_system() {')" "yes"

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
if [ -z "$MOVE_SLEEP" ] || ! command -v bash > /dev/null 2>&1; then
  echo "  (the control scripts are not run: no pgrep, bash, ps, /proc or runnable copy of sleep here)"
else
  sed -n '/^agent_pattern()/,/^}/p;/^write_control_scripts()/,/^}/p' \
    "$ROOT/fivenines_setup_user.sh" > "$MOVE/control.sh"
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
  _ctl_pids="$MOVE_AGENT $MOVE_TWIN $MOVE_ODD $MOVE_DECOY"
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
  for _pid in $_ctl_pids; do
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
  # agent; MOVE_SLEEP is set only where /proc/self/exe reads).
  MOVE_SPELLED=$(move_start agent "$CTL_DIR/")
  printf '%s\n' "$MOVE_SPELLED" > "$CTL_DIR/agent.pid"
  check "stop.sh stops the agent start.sh recorded under another spelling of its directory" \
    "$(bash "$CTL_DIR/stop.sh" 2>&1)" "Agent stopped (PID: $MOVE_SPELLED)"
  check "that agent is gone" "$(move_gone "$MOVE_SPELLED" || echo alive)" ""
  # A recorded PID the system has reused: a tail -f whose last argument reads
  # like an agent binary's path, which only a check of the binary it runs
  # tells apart.
  # Value: protects=stop.sh never signals a recorded PID that does not run an agent binary;
  #   fails_when=the /proc check is dropped or widened to the whole command line;
  #   why_new=the fallback above is new, and a PID file outlives its process; seam=none;
  #   no_claim=a binary copied into the install dir under an agent's name
  mkdir -p "$CTL_DIR/fivenines-agent-decoy"
  MOVE_REUSED=$(move_start tail "$CTL_DIR/fivenines-agent-decoy/fivenines-agent-decoy")
  printf '%s\n' "$MOVE_REUSED" > "$CTL_DIR/agent.pid"
  check "stop.sh spares a reused PID that does not run an agent binary" \
    "$(bash "$CTL_DIR/stop.sh" 2>&1)|$(move_alive "$MOVE_REUSED" && echo alive)" "Agent not running|alive"
  # A recorded PID that is ANOTHER installation's agent under the same
  # account: its argv[0] has an agent binary's shape, which the old check
  # took for this installation's (#324).
  # Value: protects=stop.sh, status.sh and refresh.sh never take another installation's agent for theirs through a stale agent.pid;
  #   fails_when=the agent.pid check goes back to the argv[0] shape, or stops resolving the install dir;
  #   why_new=the checks above record this installation's agent or no agent at all; seam=none;
  #   no_claim=a symlinked install dir (pwd -P resolves it the same way)
  _other_inst="$MOVE/other-installation"
  MOVE_OTHER=$(move_start agent "$_other_inst")
  printf '%s\n' "$MOVE_OTHER" > "$CTL_DIR/agent.pid"
  check "status.sh does not report another installation's agent its agent.pid names" \
    "$(bash "$CTL_DIR/status.sh" 2>&1)" "Agent is not running"
  printf '%s\n' "$MOVE_OTHER" > "$CTL_DIR/agent.pid"
  check "stop.sh spares another installation's agent its agent.pid names" \
    "$(bash "$CTL_DIR/stop.sh" 2>&1)|$(move_alive "$MOVE_OTHER" && echo alive)" "Agent not running|alive"

  # --from-user: stop_user_agent, which must stop every agent run from the
  # installation before its state is read, including one start.sh did not
  # record (there is no stop.sh here at all).
  # Value: protects=--from-user stops every agent run from the user's install dir, spares a tail -f of it, and acts on no installation path that is not absolute;
  #   fails_when=the own_agents/kill loop or its absolute-path guard is dropped;
  #   why_new=test-distro Test 12 runs the move in test mode, which skips this stop; seam=none;
  #   no_claim=the refusal when an agent survives SIGKILL, or that it runs as the user (su is a stub here)
  sed -n '/^AS_USER_TIMEOUT=/p;/^as_user()/,/^}/p;/^OWN_AGENTS_FN=/,/^'"'"'$/p
          /^stop_user_agent()/,/^}/p' \
    "$ROOT/fivenines_setup.sh" > "$MOVE/stop_user.sh"
  STOP_DIR="$MOVE/home/bob/.local/fivenines"
  : > "$MOVE/refused"
  MOVE_STRAY=$(move_start agent "$STOP_DIR")
  MOVE_STRAY_DECOY=$(move_start tail "$STOP_DIR/fivenines-agent-linux-amd64/agent.log")
  # Runs stop_user_agent on the installation $1 and prints its status.
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
  # The stop goes by the binary a process runs, never by its command line
  # (#306): any local user can start a process whose command line is the
  # agent's path (exec -a), which the stop then waited for, could not signal,
  # and gave up on after stop.sh had stopped the real agent. A test cannot
  # start another user's process, so the decoy here is one of the test's own
  # with that command line and another binary: the stop must spare it. And an
  # agent started under another spelling of the installation's path (here a
  # symlink to it) is found all the same.
  # Value: protects=--from-user waits for and signals only processes running the installation's agent binary, whatever their command line or the spelling of the path they were started by;
  #   fails_when=own_agents goes back to matching command lines (pgrep -f), or stops resolving the installation directory;
  #   why_new=the stub box has no second user, and every agent above is started by the plain path; seam=none;
  #   no_claim=a real second user, whose /proc/PID/exe this account cannot read at all
  _spoof_cmd="$STOP_DIR/fivenines-agent-linux-amd64/fivenines-agent-linux-amd64"
  MOVE_SPOOF=$(bash -c 'exec -a "$0" sleep 300 > /dev/null 2>&1 & echo $!' "$_spoof_cmd")
  MOVE_PIDS="$MOVE_PIDS $MOVE_SPOOF"
  ln -sfn "$STOP_DIR" "$MOVE/home/bob/agent-link"
  MOVE_LINKED=$(move_start agent "$MOVE/home/bob/agent-link")
  _tries=0
  while [ "$(ps -ww -o args= -p "$MOVE_SPOOF" 2>/dev/null)" != "$_spoof_cmd 300" ] && [ "$_tries" -lt 10 ]; do
    sleep 1
    _tries=$((_tries + 1))
  done
  check "--from-user spares a process with the agent's command line but another binary, and stops an agent started through a symlink" \
    "$(stop_user "$STOP_DIR")|$(move_alive "$MOVE_SPOOF" && echo alive)|$(move_alive "$MOVE_LINKED" && echo alive)" "0|alive|"
  kill "$MOVE_SPOOF" "$MOVE_LINKED" 2> /dev/null
  # An agent of the user's started under another group (newgrp docker, then
  # start.sh): the kernel hides its exe link from a reader of the user's
  # primary group, so the stop goes by its command line, the user's own --
  # only for a process named like the agent (comm): another process of the
  # user's whose exe link is hidden too, with the agent's path as its
  # command line, is left alone, its command line not even read.
  # Value: protects=--from-user waits for and stops an agent of the user's whose exe link it cannot read, and takes no other such process for one;
  #   fails_when=agent_exe loses its command-line fallback (the stop then reads no agent, waits for nothing, and the rollback's check reads it stopped), or the fallback stops requiring the agent's comm;
  #   why_new=every agent above has a readable exe link; seam=a readlink on PATH that cannot read /proc/*/exe;
  #   no_claim=a real newgrp, or a process exiting mid-scan
  MOVE_OTHERGID=$(move_start agent "$STOP_DIR")
  MOVE_NOTAGENT=$(bash -c 'exec -a "$0" sleep 300 > /dev/null 2>&1 & echo $!' "$_spoof_cmd")
  MOVE_PIDS="$MOVE_PIDS $MOVE_NOTAGENT"
  _tries=0
  while [ "$(ps -ww -o args= -p "$MOVE_NOTAGENT" 2>/dev/null)" != "$_spoof_cmd 300" ] && [ "$_tries" -lt 10 ]; do
    sleep 1
    _tries=$((_tries + 1))
  done
  _rc=$( (
    # shellcheck source=/dev/null
    . "$MOVE/stop_user.sh"
    FROM_USER_NAME=bob
    USER_INSTALL_DIR="$STOP_DIR"
    # The stub, for this run only.
    # shellcheck disable=SC2030,SC2031
    PATH="$MOVE/noexebin:$PATH"
    stop_user_agent > /dev/null 2>&1
    echo "$?"
  ) )
  check "--from-user stops an agent of the user's whose binary it cannot read, by its command line, and spares another process with that command line" \
    "$_rc|$(move_alive "$MOVE_OTHERGID" && echo alive)|$(move_alive "$MOVE_NOTAGENT" && echo alive)" "0||alive"
  kill "$MOVE_OTHERGID" "$MOVE_NOTAGENT" 2> /dev/null
  # Started through another spelling of the directory (a symlink) as well:
  # its command line names that spelling, resolved before it is compared.
  # Value: protects=the command-line fallback finds an agent started under another spelling of the installation's directory;
  #   fails_when=agent_exe stops resolving the command line's directory;
  #   why_new=the agent above was started by the directory's own spelling; seam=as above;
  #   no_claim=a real newgrp
  MOVE_OTHERGID=$(move_start agent "$MOVE/home/bob/agent-link")
  _rc=$( (
    # shellcheck source=/dev/null
    . "$MOVE/stop_user.sh"
    FROM_USER_NAME=bob
    USER_INSTALL_DIR="$STOP_DIR"
    # The stub, for this run only.
    # shellcheck disable=SC2030,SC2031
    PATH="$MOVE/noexebin:$PATH"
    stop_user_agent > /dev/null 2>&1
    echo "$?"
  ) )
  check "--from-user stops an agent whose binary it cannot read, started through a symlink to its directory" \
    "$_rc|$(move_alive "$MOVE_OTHERGID" && echo alive)" "0|"
  kill "$MOVE_OTHERGID" 2> /dev/null

  # as_user ends what it runs after AS_USER_TIMEOUT, its whole process group,
  # and fails with 124 (#307): the stop runs with INT, TERM and HUP ignored,
  # and the user controls stop.sh.
  # Value: protects=a user's command that never ends cannot hold the root installer, and what runs in su's process group goes with it;
  #   fails_when=as_user goes back to waiting with no bound, or kills only su where su keeps the shell in its group (BusyBox, this stub);
  #   why_new=new bound; seam=AS_USER_TIMEOUT lowered to 2s; no_claim=util-linux su, which moves the command to a session of its own: there su ends the shell, and what the shell started may survive
  _t0=$(date +%s)
  _rc=$( (
    # shellcheck source=/dev/null
    . "$MOVE/stop_user.sh"
    FROM_USER_NAME=bob
    AS_USER_TIMEOUT=2
    trap '' INT TERM HUP
    # shellcheck disable=SC2016
    as_user 'trap "" TERM; sleep "$1" & sleep "$1"' 3017 > /dev/null 2>&1
    echo "$?"
  ) )
  _took=$(( $(date +%s) - _t0 ))
  sleep 1
  # Its exact command line: pgrep is a stub here, which refuses a pattern
  # that is not anchored in the scratch directory.
  # shellcheck disable=SC2009
  check "as_user stops what it runs after AS_USER_TIMEOUT, and all su's process group holds" \
    "rc=$_rc|fast=$([ "$_took" -lt 15 ] && echo yes)|left=$(ps -eo args | grep -cx 'sleep 3017')" "rc=124|fast=yes|left=0"
  # A Ctrl-C or a hangup at the terminal reaches every process of the
  # installer's group, its watcher included, while the installer ignores it
  # (the stop): a watcher that died of it would leave the call with no bound.
  # Run in a group of its own (setsid), signalled whole, as a terminal would;
  # the user's command is in another session and is not. HUP, not INT: an
  # asynchronous command starts with INT ignored, which no trap can undo, so
  # INT would pass whatever the watcher does.
  # Value: protects=the as_user bound survives the terminal's hangup or Ctrl-C;
  #   fails_when=the watcher stops ignoring HUP, INT and TERM (it then dies, and the call waits for the command: rc 0 after 9s);
  #   why_new=the check above sends no signal; seam=AS_USER_TIMEOUT lowered; no_claim=a real terminal
  rm -f "$MOVE/int.rc"
  # The $ are for the child shell. gstack-timing-ok: the assertion is the exit status, the 9s command only has to outlast the 3s bound.
  # shellcheck disable=SC2016
  setsid sh -c '. "$1"; FROM_USER_NAME=bob; AS_USER_TIMEOUT=3; trap "" INT TERM HUP
    as_user "sleep \"\$1\"" 9 > /dev/null 2>&1; echo "$?" > "$2"' sh "$MOVE/stop_user.sh" "$MOVE/int.rc" &
  _grp=$!
  sleep 1
  kill -HUP "-$_grp" 2> /dev/null
  wait "$_grp"
  check "as_user keeps its bound through a hangup the installer ignores" "$(cat "$MOVE/int.rc" 2>/dev/null)" "124"
  # A run that is gone (killed, or ended through a trap) while a call waits:
  # its watcher signals nothing afterwards, since the group may by then belong
  # to someone else.
  # Value: protects=as_user's watcher never kills a process group once its run is gone;
  #   fails_when=the watcher stops checking that the main shell still runs;
  #   why_new=new; seam=AS_USER_TIMEOUT lowered; no_claim=PID reuse itself (the command is left running instead)
  # The $ are for the child shell. gstack-timing-ok: the check at 5s needs only to come after the 2s bound.
  mkdir -p "$MOVE/gone-work"
  # shellcheck disable=SC2016
  setsid sh -c '. "$1"; FROM_USER_NAME=bob; AS_USER_TIMEOUT=2; WORK_DIR=$2
    as_user "sleep \"\$1\"" 3021 > /dev/null 2>&1' sh "$MOVE/stop_user.sh" "$MOVE/gone-work" &
  _gone=$!
  sleep 1
  kill -KILL "$_gone" 2> /dev/null
  wait "$_gone" 2> /dev/null
  sleep 4
  # shellcheck disable=SC2009
  _left=$(ps -eo pid,args | awk '$2 == "sleep" && $3 == "3021" { print $1 }')
  check "as_user's watcher signals nothing once its run is gone" "$([ -n "$_left" ] && echo running)" "running"
  # shellcheck disable=SC2086
  [ -n "$_left" ] && kill $_left 2> /dev/null
  # A signal while a call waits: its trap's exit ends that call (its group)
  # before the rollback runs its own, so an interrupted stop.sh, or the
  # stop's loop, never goes on beside the rollback (it could kill the agent
  # the rollback's start.sh started again).
  # Value: protects=an as_user call a signal interrupted is ended before exit_with_contact's rollback runs;
  #   fails_when=exit_with_contact stops ending the pending call, or as_user stops recording it;
  #   why_new=new; seam=the rollback is a stub that reports whether the interrupted command still runs; no_claim=util-linux su
  sed -n '/^AS_USER_TIMEOUT=/p;/^exit_with_contact()/,/^}/p;/^as_user()/,/^}/p;/^end_pending_as_user()/,/^}/p' \
    "$ROOT/fivenines_setup.sh" > "$MOVE/pending.sh"
  rm -f "$MOVE/pending.out"
  # The $ are for the child shell. gstack-timing-ok: the signal at 1s only has to come while the 30s command runs.
  # shellcheck disable=SC2016
  setsid sh -c '. "$1"; FROM_USER_NAME=bob; AS_USER_TIMEOUT=30; WORK_DIR=$3; TAKEOVER_ROLLBACK=1; PENDING_OUT=$2
    print_error() { :; }
    rollback_user_takeover() {
      if ps -eo args | grep -qx "sleep 3041"; then echo "still running" > "$PENDING_OUT"; else echo "ended" > "$PENDING_OUT"; fi
    }
    trap "exit_with_contact interrupted" HUP
    as_user "sleep \"\$1\"" 3041 > /dev/null 2>&1' sh "$MOVE/pending.sh" "$MOVE/pending.out" "$MOVE/gone-work" &
  _pend=$!
  sleep 1
  kill -HUP "$_pend" 2> /dev/null
  wait "$_pend" 2> /dev/null
  check "a signal during an as_user call ends that call before the rollback runs" "$(cat "$MOVE/pending.out" 2> /dev/null)" "ended"
  # shellcheck disable=SC2009
  _left=$(ps -eo pid,args | awk '$2 == "sleep" && $3 == "3041" { print $1 }')
  # shellcheck disable=SC2086
  [ -n "$_left" ] && kill $_left 2> /dev/null
  # What the user's side prints reaches root's terminal with its control
  # characters (a file name made of escape sequences) and every byte past
  # ASCII (a C1 control, CSI here in UTF-8) as ?: tabs and new lines stay.
  # Value: protects=no escape sequence of the user's, C0 or C1, is played on root's terminal through as_user;
  #   fails_when=as_user prints its captured output or error output unfiltered again;
  #   why_new=every other as_user output here is plain text; seam=none; no_claim=what a given terminal does with a sequence
  _ctl=$(printf 'a\033[2Jb\tc\007de\302\233f')
  # The $ are for the child shell.
  # shellcheck disable=SC2016
  _shown=$( (
    # shellcheck source=/dev/null
    . "$MOVE/stop_user.sh"
    FROM_USER_NAME=bob
    as_user 'printf "%s\n" "$1"; printf "%s\n" "$1" >&2' "$_ctl" 2>&1
  ) | grep '^a' | od -An -c | tr -s ' \n' ' ')
  check "as_user prints what the user's side wrote with its control characters and non-ASCII bytes as ?" \
    "$_shown" " a ? [ 2 J b \t c ? d e ? ? f \n a ? [ 2 J b \t c ? d e ? ? f \n "
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
mkdir -p "$SUD/sudoers.d" "$SUD/work" "$SUD/nvme-class/nvme0" "$SUD/nvme-class/nvme12" "$SUD/nvme-class/nvme100"
printf '%s\n' 'Personalities : [raid1]' 'md0 : active raid1 sdb1[1] sda1[0]' \
  'md_data-1 : active raid1 sdd1[1] sdc1[0]' 'md_home.0 : active raid1 sdf1[1] sde1[0]' \
  'md_a,b : active raid1 sdh1[1] sdg1[0]' 'unused devices: <none>' > "$SUD/mdstat"
: > "$SUD/sudoers"
sed -n '/^write_sudoers_rules()/,/^}/p' "$ROOT/fivenines_common.sh" \
  | sed "s|/proc/mdstat|$SUD/mdstat|g; s|/sys/class/nvme|$SUD/nvme-class|g; s|/etc/sudoers.d|$SUD/sudoers.d|g; s|/etc/sudoers|$SUD/sudoers|g" \
  > "$SUD/write.sh"
# Runs the rewritten write_sudoers_rules, mdadm and nvme the only tools found,
# or no tool at all with $1 none.
md_rules_run() {
  _md_tools=${1:-}
  (
    # shellcheck source=/dev/null
    . "$SUD/write.sh"
    # Called by write_sudoers_rules.
    # shellcheck disable=SC2317,SC2329
    sudoers_tool_path() {
      [ "$_md_tools" != none ] || return 1
      case "$1" in
        mdadm) echo /sbin/mdadm ;;
        nvme) echo /usr/sbin/nvme ;;
        *) return 1 ;;
      esac
    }
    # shellcheck disable=SC2317,SC2329
    visudo() { return 0; }
    # shellcheck disable=SC2317,SC2329
    chown() { return 0; }
    # Not the host's own sudo -V.
    # shellcheck disable=SC2317,SC2329
    sudo_secure_path() { echo /usr/sbin:/usr/bin:/sbin:/bin; }
    WORK_DIR="$SUD/work"
    write_sudoers_rules > "$SUD/out" 2>&1
  )
}
md_rules_run
check "--with-sudoers gives every command of the account root's HOME, before its rules" \
  "$(grep -v '^#' "$SUD/sudoers.d/fivenines" 2>/dev/null | head -n 1)" "Defaults:fivenines always_set_home"
# Value: protects=the account's sudo commands run with no terminal even where sudoers sets requiretty (early RHEL 7), as the agent's do (#309);
#   fails_when=the !requiretty line is dropped, or written after the rules; seam=as below;
#   why_new=no test image sets requiretty; no_claim=that sudo honours it (ci/test-sudo-mail.sh checks it on real sudo)
check "--with-sudoers lets the account's commands run with no terminal, before its rules" \
  "$(grep -v '^#' "$SUD/sudoers.d/fivenines" 2>/dev/null | sed -n 2p)" "Defaults:fivenines !requiretty"
# Value: protects=every listed array gets its exact --detail entry, md0 included, which is all sudo-rs can match (no [0-9] class);
#   fails_when=md0-md999 names are skipped again because the [0-9] patterns cover them on classic sudo;
#   why_new=sudo-rs ignores the patterns; seam=as above; no_claim=what sudo-rs matches (ci/test-sudo-mail.sh)
# Value: protects=nvme gets only the agent's two commands (version, smart-log as JSON on a controller), never format, sanitize or firmware, plus an exact entry per controller the kernel lists, for sudo-rs;
#   fails_when=the nvme rule goes bare or takes a "*", or the exact entries stop following /sys/class/nvme;
#   why_new=no test image has an NVMe controller; seam=as above; no_claim=that sudo-rs accepts the rule (ci/test-sudo-mail.sh)
check "--with-sudoers holds nvme to version and smart-log, with an exact entry per controller listed" \
  "$(grep '/usr/sbin/nvme' "$SUD/sudoers.d/fivenines" 2>/dev/null | tr '\n' '|')" \
  "fivenines ALL=(ALL) NOPASSWD: /usr/sbin/nvme version, /usr/sbin/nvme smart-log /dev/nvme0 -o json, /usr/sbin/nvme smart-log /dev/nvme12 -o json|fivenines ALL=(ALL) NOPASSWD: /usr/sbin/nvme smart-log /dev/nvme[0-9] -o json, /usr/sbin/nvme smart-log /dev/nvme[1-9][0-9] -o json|"
# Value: protects=the exact entries never share a line with a pattern, so a sudo-rs that refuses patterns in arguments (ad74f0a) rejects only the pattern line;
#   fails_when=the [0-9] or * entries go back on the line with --version / version;
#   why_new=sudo-rs refusing a bracket is not released yet, so no image can show it; seam=as above; no_claim=which sudo-rs release refuses it
check "--with-sudoers puts every pattern on a line of its own, apart from the exact entries" \
  "$(grep '^fivenines' "$SUD/sudoers.d/fivenines" | grep -e ' --version' -e ' version' | grep -c '\[\|\*')|$(grep -c '^fivenines ALL=(ALL) NOPASSWD: /sbin/mdadm --detail /dev/md\[0-9\], ' "$SUD/sudoers.d/fivenines")" "0|1"
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
# What the fivenines settings page used to give: a lone "*" is any argument.
printf '%s\n' '    (root) NOPASSWD: /usr/sbin/nvme *' '    (root) NOPASSWD: /usr/sbin/smartctl *' \
  '    (root) NOPASSWD: /usr/sbin/mdadm *' '    (root) NOPASSWD: /usr/bin/fail2ban-client *' > "$SUD/starred"
printf '%s\n' '    (ALL) NOPASSWD: /usr/sbin/smartctl' \
  '    (ALL) NOPASSWD: /sbin/mdadm --version, /sbin/mdadm --detail /dev/md[0-9], /sbin/mdadm --detail /dev/md_data-1' \
  '    (ALL) NOPASSWD: /usr/sbin/nvme version, /usr/sbin/nvme smart-log /dev/nvme[0-9] -o json, /usr/sbin/nvme smart-log /dev/nvme0 -o json' \
  '    (ALL) NOPASSWD: /usr/bin/fail2ban-client version, /usr/bin/fail2ban-client status, /usr/bin/fail2ban-client status *' \
  '    (root) NOPASSWD: NOLOG_OUTPUT: /usr/bin/wg show all dump' > "$SUD/pinned"
check "the bare mdadm and fail2ban-client rules sudo lists are named, the pinned ones are not" \
  "$(unpinned_run "$SUD/bare" | grep -c 'run /sbin/mdadm /usr/bin/fail2ban-client with any arguments')|$(unpinned_run "$SUD/adjacent" | grep -c 'run /sbin/mdadm /usr/bin/fail2ban-client with any arguments')|$(unpinned_run "$SUD/pinned")" "1|1|"
# Value: protects=the "mdadm *", "fail2ban-client *" and "nvme *" rules the fivenines settings page gave are named too, "smartctl *" (what --with-sudoers grants anyway) is not;
#   fails_when=only a bare path counts as unpinned again, or a pinned "status *" item is named;
#   why_new=those rules carry a trailing "*" the bare-path match missed; seam=as above; no_claim=real sudo's listing (ci/test-sudo-mail.sh)
check "the settings page's starred mdadm, fail2ban-client and nvme rules are named, smartctl's is not" \
  "$(unpinned_run "$SUD/starred" | grep -c 'run /usr/bin/fail2ban-client /usr/sbin/mdadm /usr/sbin/nvme with any arguments')" "1"

# --with-sudoers: the paths a rule may name (fivenines_common.sh, held to its
# copies in fivenines_setup.sh and fivenines_update.sh by ci/build-scripts.sh).
# Value: protects=a sudoers rule never names a tool whose link chain or directories a user other than root can change, nor one found through the caller's PATH;
#   fails_when=root_only_chain resolves links first (readlink -f), root_only_path drops its write-bit tests, or sudoers_tool_path searches the caller's PATH;
#   why_new=test-sudo-mail and test-distro only ever offer it root-owned tools in root-only directories; seam=none;
#   no_claim=either write bit on its own, or a non-root link or file inside root-only directories (each needs root to set up)
sed -n '/^root_only_path()/,/^}/p;/^root_only_chain()/,/^}/p;/^sudo_secure_path()/,/^}/p
        /^sudoers_tool_path()/,/^}/p' \
  "$COMMON" > "$MOVE/sudoers_paths.sh"
# A sudo whose -V reports a secure_path of two scratch directories, the second
# listed first, with an empty and a relative entry between them (sudo -V
# reports secure_path to root only, so a test that is not root needs one).
mkdir -p "$MOVE/spbin" "$MOVE/sp-a" "$MOVE/sp-b"
# The $PATH is the literal text sudo prints.
# shellcheck disable=SC2016
printf '#!/bin/sh\n[ "$1" = "-V" ] || exit 1\necho "Sudo version 1.9.15p5"\necho "Value to override user'"'"'s \\$PATH with: %s::relative:%s"\n' \
  "$MOVE/sp-b" "$MOVE/sp-a" > "$MOVE/spbin/sudo"
for _d in "$MOVE/sp-a" "$MOVE/sp-b"; do
  printf '#!/bin/sh\n' > "$_d/fivenines-sp-tool"
done
chmod 755 "$MOVE/spbin/sudo" "$MOVE/sp-a/fivenines-sp-tool" "$MOVE/sp-b/fivenines-sp-tool"
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
  # Value: protects=a rule names the copy sudo itself would run: the first in this host's secure_path, as sudo -V reports it, not in Debian's order (#308);
  #   fails_when=sudoers_tool_path goes back to its fixed list, or stops skipping an entry that is not an absolute directory;
  #   why_new=every other check runs with sudo reporting no secure_path; seam=a sudo stub on PATH (the scratch tools are not root's, so the refusal names the path that was chosen);
  #   no_claim=a real sudo's -V output (ci/test-sudo-mail.sh)
  _out=$(PATH="$MOVE/spbin:$PATH" sudoers_tool_path fivenines-sp-tool 2>&1)
  check "sudoers_tool_path searches the secure_path sudo reports, in its order" \
    "$?|$(printf '%s' "$_out" | grep -c "No sudoers rule for $MOVE/sp-b/fivenines-sp-tool:")" "1|1"
  check "sudo_secure_path falls back to systemd's default PATH when sudo reports none" \
    "$(PATH=/nonexistent sudo_secure_path 2> /dev/null)" "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
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

# fivenines_setup_user.sh --from-system runs the release's
# fivenines_uninstall.sh as root: fetch_system_uninstaller must refuse one the
# signed manifest does not cover (#314).
# Value: protects=--from-system never runs an unverified uninstaller as root;
#   fails_when=fetch_system_uninstaller stops calling verify_from_manifest, or ignores its verdict;
#   why_new=test-distro takes a pre-placed copy in test mode; seam=the mirror double above;
#   no_claim=the test-mode pre-placed copy
sed -n '/^fetch_system_uninstaller()/,/^}/p' "$ROOT/fivenines_setup_user.sh" > "$WORK/fetch_uninstaller.sh"
printf '#!/bin/sh\necho genuine uninstaller\n' > "$MIRROR/fivenines_uninstall.sh"
publish_mirror
# shellcheck source=/dev/null
. "$WORK/fetch_uninstaller.sh"
# The last checks of this file, in the work directory the checks above used
# (emptied here): what they set is not restored.
unset FIVENINES_TEST_MODE FIVENINES_SKIP_VERIFY
# Prints fetch_system_uninstaller's status and what it left to run.
fetch_uninstaller() {
  rm -rf "$WORK_DIR"
  mkdir -p "$WORK_DIR"
  fetch_system_uninstaller > /dev/null 2>&1
  printf '%s|%s' "$?" "$(tail -n 1 "$WORK_DIR/fivenines_uninstall.sh" 2>/dev/null)"
}
check "--from-system takes a release uninstaller the signed manifest covers" "$(fetch_uninstaller)" "0|echo genuine uninstaller"
printf '#!/bin/sh\necho tampered uninstaller\n' > "$MIRROR/fivenines_uninstall.sh"
check "--from-system refuses a release uninstaller the signed manifest does not cover" \
  "$(fetch_uninstaller | cut -d'|' -f1)" "1"
printf '#!/bin/sh\necho genuine uninstaller\n' > "$MIRROR/fivenines_uninstall.sh"
publish_mirror

echo ""
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
