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
# Usage: sh ci/test-signing.sh

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMMON="$ROOT/fivenines_common.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

print_success() { printf '%s\n' "[+] $1"; }
print_warning() { printf '%s\n' "[!] $1"; }
print_error()   { printf '%s\n' "[-] $1"; }

# Source only the function under test and its dependency.
sed -n '/^release_signing_pubkey()/,/^}/p;/^verify_sums_signature()/,/^}/p' "$COMMON" > "$WORK/funcs.sh"
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
# shellcheck disable=SC2329  # called indirectly, from verify_sums_signature
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

echo ""
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
