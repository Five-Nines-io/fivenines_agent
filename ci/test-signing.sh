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
# once it verified.
sed -n '/^release_signing_pubkey()/,/^}/p
        /^verify_sums_signature()/,/^}/p
        /^verification_preflight()/,/^}/p
        /^compute_sha256()/,/^}/p
        /^sha256_from_sums()/,/^}/p
        /^verify_sha256()/,/^}/p
        /^verify_from_manifest()/,/^}/p
        /^verify_agent_tarball()/,/^}/p
        /^install_verified_release_file()/,/^}/p' "$COMMON" > "$WORK/funcs.sh"
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
# SHA256SUMS".
WORKFLOW="$ROOT/.github/workflows/build-release.yml"
for asset in fivenines-agent.service fivenines-agent.openrc fivenines_script.sh; do
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
