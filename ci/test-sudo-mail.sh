#!/bin/sh
# Real-sudo check that the capability probes do not make sudo mail root.
#
# Debian and Ubuntu ship `Defaults mail_badpass`: every `sudo -n` that sudo
# refuses for a user it knows mails root a "SECURITY information" message. The
# probes repeated each refused call every one to five minutes, up to ~1150
# mails a day per command. The fix (fivenines_agent/sudo_refusals.py) asks
# `sudo -n -l` (no command: may this account use sudo without a password at
# all?) and then `sudo -n -l <command>` before running a command, and keeps
# every refusal, across restarts, until the sudo policy changes. What each
# question costs in mail is sudo behaviour, so this checks it against the real
# sudo of each image.
#
# Each case runs the agent's own sudo_refusals.run_checked (it imports only the
# standard library, so the image's python3 runs it) as an unprivileged user,
# with a sendmail stub that keeps every mail, and checks:
#   - the premise, where the stock sudoers sets mail_badpass: a refused bare
#     `sudo -n` does mail root, for the README's user (a NOPASSWD rule for
#     smartctl only) and for a member of the admin group;
#   - the README's user: five probes each of smartctl (allowed), fail2ban-client
#     and nvme (no rule) mail nothing, and smartctl still runs every time;
#   - an account sudoers does not know (the default install): every probe is
#     refused and nothing mails;
#   - the admin-group member, whose rules all need a password: two agent runs
#     (a restart) of five probes each of three commands are refused and mail
#     nothing on sudo >= 1.9.16p1 and sudo-rs, at most once on an older sudo
#     (its refused `sudo -n -l` mails, and nothing else asks).
#
# Needs docker. Usage: sh ci/test-sudo-mail.sh

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/probe.py" <<'EOF'
"""Five run_checked calls per command, as five probes would make them."""
import sys

sys.path.insert(0, "/src")
from fivenines_agent import sudo_refusals  # noqa: E402

ARGVS = {
    "smartctl": ["smartctl", "--version"],
    "fail2ban-client": ["fail2ban-client", "status"],
    "nvme": ["nvme", "version"],
}
failed = False
for spec in sys.argv[1:]:
    name, want = spec.split("=", 1)
    got = []
    reason = None
    for _ in range(5):
        result, refusal = sudo_refusals.run_checked(ARGVS[name], timeout=20)
        if refusal is not None:
            got.append("refused")
            reason = refusal
        else:
            got.append("ran" if result.returncode == 0 else "failed")
    ok = got == [want] * 5
    failed = failed or not ok
    print("    %s %s: %s (want %s) %s" % ("ok  " if ok else "FAIL", name, got, want, reason or ""))
sys.exit(1 if failed else 0)
EOF

cat > "$WORK/case.sh" <<'EOF'
set -u
flavor=$1
fail=0

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  pkg=sudo
  [ "$flavor" = sudo-rs ] && pkg=sudo-rs
  apt-get install -y -qq "$pkg" python3 >/dev/null || exit 2
else
  dnf install -y -q sudo python3 >/dev/null || exit 2
fi
if [ "$flavor" = sudo-rs ] && ! sudo --version 2>&1 | grep -qi 'sudo-rs'; then
  for candidate in /usr/bin/sudo-rs /usr/lib/cargo/bin/sudo; do
    if [ -x "$candidate" ]; then
      ln -sf "$candidate" /usr/local/bin/sudo
      break
    fi
  done
fi
mkdir -p /etc/sudoers.d
if [ ! -f /etc/sudoers ]; then
  printf 'root ALL=(ALL:ALL) ALL\n%%sudo ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n' > /etc/sudoers
  chmod 440 /etc/sudoers
fi
echo "  $(sudo --version 2>&1 | head -1)"

# Every mail sudo sends lands in /var/tmp/mails.
mkdir -p /var/tmp/mails
chmod 1777 /var/tmp/mails
# The $(...) is the stub's own, run for each mail.
# shellcheck disable=SC2016
printf '#!/bin/sh\ncat > "$(mktemp /var/tmp/mails/mail.XXXXXX)"\n' > /usr/sbin/sendmail
chmod 755 /usr/sbin/sendmail
mails() { sleep 2; find /var/tmp/mails -type f | wc -l | tr -d ' '; }
clear_mails() { find /var/tmp/mails -type f -exec rm -f {} +; }

for tool in /usr/sbin/smartctl /usr/bin/fail2ban-client /usr/sbin/nvme; do
  printf '#!/bin/sh\necho "%s 1.0"\n' "${tool##*/}" > "$tool"
  chmod 755 "$tool"
done

# The README's user: one NOPASSWD rule, none for the other tools.
useradd -m fivenines
echo 'fivenines ALL=(ALL) NOPASSWD: /usr/sbin/smartctl' > /etc/sudoers.d/fivenines
chmod 440 /etc/sudoers.d/fivenines
# A member of the admin group, whose rules all need a password.
admin_group=sudo
getent group sudo >/dev/null 2>&1 || admin_group=wheel
useradd -m -G "$admin_group" admin
echo 'admin:Fivenines-ci-1' | chpasswd
# An account sudoers does not know: the default system install.
useradd -m norule
# Each one's config dir, where the agent keeps the refusals across restarts.
for user in fivenines admin norule; do
  mkdir -m 700 "/var/tmp/cfg-$user"
  chown "$user" "/var/tmp/cfg-$user"
done

badpass=0
if [ "$flavor" = sudo ] && grep -Eq '^[[:space:]]*Defaults[[:space:]]+mail_badpass' /etc/sudoers; then
  badpass=1
fi
echo "  stock mail_badpass: $badpass"

# Mails a refused bare `sudo -n -l` may cost: none since 1.9.16p1, nor ever
# under sudo-rs; one (the refusal is then kept) on an older sudo.
gate_mails=0
if [ "$badpass" = 1 ]; then
  version=$(sudo -V 2>/dev/null | sed -n 's/^Sudo version //p' | head -1)
  [ "$(printf '%s\n%s\n' 1.9.16p1 "$version" | sort -V | head -1)" = 1.9.16p1 ] || gate_mails=1
fi

as() {
  user=$1; shift
  runuser -u "$user" -- env PYTHONDONTWRITEBYTECODE=1 CONFIG_DIR="/var/tmp/cfg-$user" "$@"
}

# What each question to sudo costs in mail, per account, each asked once on
# its own (informational: the probes' design rests on this table).
for user in fivenines norule admin; do
  costs=""
  for question in "run" "list" "check" "validate"; do
    case $question in
      run) set -- /usr/bin/fail2ban-client status ;;
      list) set -- -l ;;
      check) set -- -l /usr/bin/fail2ban-client status ;;
      validate) set -- -v ;;
    esac
    as "$user" sudo -n "$@" >/dev/null 2>&1
    costs="$costs $question=$(mails)"
    clear_mails
  done
  echo "    info mails per question, $user:$costs"
done

if [ "$badpass" = 1 ]; then
  as fivenines sudo -n /usr/bin/fail2ban-client status >/dev/null 2>&1
  n=$(mails); clear_mails
  if [ "$n" -ge 1 ]; then echo "    ok   premise: a refused sudo -n mails root ($n)"
  else echo "    FAIL premise: a refused sudo -n mailed nothing"; fail=1; fi
  as admin sudo -n /usr/sbin/smartctl --version >/dev/null 2>&1
  n=$(mails); clear_mails
  if [ "$n" -ge 1 ]; then echo "    ok   premise: an admin-group sudo -n mails root ($n)"
  else echo "    FAIL premise: an admin-group sudo -n mailed nothing"; fail=1; fi
fi

as fivenines python3 /work/probe.py smartctl=ran fail2ban-client=refused nvme=refused || fail=1
n=$(mails); clear_mails
if [ "$n" -eq 0 ]; then echo "    ok   README user: 15 probes, no mail"
else echo "    FAIL README user: 15 probes, $n mails"; fail=1; fi

as norule python3 /work/probe.py smartctl=refused fail2ban-client=refused nvme=refused || fail=1
n=$(mails); clear_mails
if [ "$n" -eq 0 ]; then echo "    ok   no-rule user: 15 probes, no mail"
else echo "    FAIL no-rule user: 15 probes, $n mails"; fail=1; fi

as admin python3 /work/probe.py smartctl=refused fail2ban-client=refused nvme=refused || fail=1
as admin python3 /work/probe.py smartctl=refused fail2ban-client=refused nvme=refused || fail=1
n=$(mails); clear_mails
if [ "$n" -le "$gate_mails" ]; then echo "    ok   admin-group user: 2 runs of 15 probes, $n mail(s) (at most $gate_mails)"
else echo "    FAIL admin-group user: 2 runs of 15 probes, $n mails (at most $gate_mails)"; fail=1; fi

exit "$fail"
EOF

# mktemp -d makes it 0700: the container's users read it under their own uids.
chmod 755 "$WORK"
chmod 644 "$WORK/probe.py" "$WORK/case.sh"

FAIL=0

# $1 image, $2 sudo flavor (sudo or sudo-rs)
run_case() {
  echo "== $1 ($2)"
  if docker run --rm -v "$ROOT:/src:ro" -v "$WORK:/work:ro" "$1" sh /work/case.sh "$2"; then
    echo "  ok   $1"
  else
    echo "  FAIL $1"
    FAIL=$((FAIL + 1))
  fi
  echo ""
}

run_case ubuntu:20.04 sudo      # sudo 1.8.31
run_case ubuntu:22.04 sudo      # 1.9.9: -n tried PAM authentication
run_case ubuntu:24.04 sudo      # 1.9.15
run_case debian:bookworm sudo   # 1.9.13
run_case debian:trixie sudo     # 1.9.16p2: a bare -nl no longer mails
run_case rockylinux:9 sudo      # 1.9.5, no mail_badpass by default
run_case ubuntu:26.04 sudo-rs   # Ubuntu's default sudo since 25.10

echo "FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
