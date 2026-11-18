#!/bin/sh
# Real-sudo check that the capability probes do not make sudo mail root.
#
# Debian and Ubuntu ship `Defaults mail_badpass`: every `sudo -n` that sudo
# refuses for a user it knows mails root a "SECURITY information" message. The
# probes repeated each refused call every one to five minutes, up to ~1150
# mails a day per command. The fix (fivenines_agent/sudo_refusals.py) asks
# whether the account may use sudo without a password at all (`sudo -n -v`,
# or `sudo -n -l` for an admin-group member), then `sudo -n -l <command>`
# before running a command, and keeps every refusal, across restarts, until
# the sudo policy changes. What each question costs in mail is sudo
# behaviour, so this checks it against the real sudo of each image (and
# prints the per-question table the choice of question rests on).
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
#   - a member of the admin group with a NOPASSWD rule for smartctl (the
#     README's user installation): smartctl runs, the others are refused, and
#     nothing mails;
#   - root: every tool runs (sudo never authenticates it) and nothing mails;
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
# The mode sudo installs it with (ubuntu:26.04's sudo-rs image has 0644,
# which visudo -c refuses).
chmod 440 /etc/sudoers
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
# The README's user installation: an admin-group member with a NOPASSWD rule.
useradd -m -G "$admin_group" alice
echo 'alice:Fivenines-ci-2' | chpasswd
echo 'alice ALL=(ALL) NOPASSWD: /usr/sbin/smartctl' > /etc/sudoers.d/alice
chmod 440 /etc/sudoers.d/alice
# Each one's config dir, where the agent keeps the refusals across restarts.
for user in fivenines admin norule alice root; do
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
for user in fivenines norule alice admin; do
  costs=""
  for question in "run" "list" "check" "validate"; do
    case $question in
      run) set -- /usr/bin/fail2ban-client status ;;
      list) set -- -l ;;
      check) set -- -l /usr/bin/fail2ban-client status ;;
      validate) set -- -v ;;
    esac
    as "$user" sudo -n "$@" >/dev/null 2>&1
    rc=$?
    costs="$costs $question=$(mails)/rc$rc"
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

as root python3 /work/probe.py smartctl=ran fail2ban-client=ran nvme=ran || fail=1
n=$(mails); clear_mails
if [ "$n" -eq 0 ]; then echo "    ok   root: 15 probes, no mail"
else echo "    FAIL root: 15 probes, $n mails"; fail=1; fi

as alice python3 /work/probe.py smartctl=ran fail2ban-client=refused nvme=refused || fail=1
n=$(mails); clear_mails
if [ "$n" -eq 0 ]; then echo "    ok   admin-group user with a NOPASSWD rule: 15 probes, no mail"
else echo "    FAIL admin-group user with a NOPASSWD rule: 15 probes, $n mails"; fail=1; fi

as admin python3 /work/probe.py smartctl=refused fail2ban-client=refused nvme=refused || fail=1
as admin python3 /work/probe.py smartctl=refused fail2ban-client=refused nvme=refused || fail=1
n=$(mails); clear_mails
if [ "$n" -le "$gate_mails" ]; then echo "    ok   admin-group user: 2 runs of 15 probes, $n mail(s) (at most $gate_mails)"
else echo "    FAIL admin-group user: 2 runs of 15 probes, $n mails (at most $gate_mails)"; fail=1; fi

# --with-sudoers: write_sudoers_rules (fivenines_common.sh) against this
# image's real visudo and sudo. What it writes must parse, run exactly the
# commands it names for the fivenines account, and nothing else; a file it
# did not write must be left alone.
for tool in /usr/sbin/smartctl /usr/sbin/nvme /usr/bin/fail2ban-client /usr/sbin/mdadm /usr/bin/wg; do
  printf '#!/bin/sh\necho "%s $*"\n' "${tool##*/}" > "$tool"
  chmod 755 "$tool"
done
# as fivenines, sudo -n ARGV: prints what the tool printed (its name and
# arguments), or nothing when sudo refused. stderr is kept for the message:
# sudo can warn there and still run the command.
sudo_as_fivenines() {
  # The argv is deliberately word-split into the command and its arguments.
  # shellcheck disable=SC2086
  as fivenines sudo -n $1 2>/tmp/sudo.err
}
if [ "$flavor" = sudo-rs ] && ! command -v visudo >/dev/null 2>&1; then
  for candidate in /usr/bin/visudo-rs /usr/lib/cargo/bin/visudo; do
    if [ -x "$candidate" ]; then
      ln -sf "$candidate" /usr/local/bin/visudo
      break
    fi
  done
fi
# write_sudoers_rules reads the md arrays and NVMe controllers from a fake
# /proc/mdstat and /sys/class/nvme: the container has none, and their exact
# entries are what sudo-rs (no [0-9] class) runs.
mkdir -p /tmp/fake-nvme/nvme0 /tmp/fake-nvme/nvme12
printf '%s\n' 'Personalities : [raid1]' 'md0 : active raid1 sdb1[1] sda1[0]' \
  'md127 : active raid1 sdd1[1] sdc1[0]' 'unused devices: <none>' > /tmp/fake-mdstat
sed 's|/proc/mdstat|/tmp/fake-mdstat|g; s|/sys/class/nvme|/tmp/fake-nvme|g' \
  /src/fivenines_common.sh > /tmp/fivenines_common.sh
with_sudoers() {
  (
    . /tmp/fivenines_common.sh
    WORK_DIR=$(mktemp -d)
    write_sudoers_rules
  ) > /tmp/with-sudoers.out 2>&1
}
operator_rule=$(cat /etc/sudoers.d/fivenines)
with_sudoers
rc=$?
if [ "$rc" -ne 0 ] && [ "$(cat /etc/sudoers.d/fivenines)" = "$operator_rule" ] \
  && grep -q 'was not written by this installer' /tmp/with-sudoers.out; then
  echo "    ok   --with-sudoers leaves an operator's /etc/sudoers.d/fivenines alone"
elif [ "$rc" -ne 0 ] && [ "$flavor" = sudo-rs ] && grep -q 'no visudo' /tmp/with-sudoers.out \
  && [ "$(cat /etc/sudoers.d/fivenines)" = "$operator_rule" ]; then
  echo "    info --with-sudoers: sudo-rs here has no visudo, so the operator's file is not even looked at"
else
  echo "    FAIL --with-sudoers and an operator's /etc/sudoers.d/fivenines (rc $rc)"; cat /tmp/with-sudoers.out; fail=1
fi
rm -f /etc/sudoers.d/fivenines
with_sudoers
rc=$?
sed 's/^/      | /' /tmp/with-sudoers.out
if [ "$rc" -ne 0 ] && [ "$flavor" = sudo-rs ] && grep -q 'no visudo' /tmp/with-sudoers.out; then
  echo "    info --with-sudoers: sudo-rs here has no visudo, so it writes nothing"
elif [ "$rc" -ne 0 ]; then
  echo "    FAIL --with-sudoers wrote nothing (rc $rc)"; fail=1
else
  if visudo -c >/dev/null 2>&1; then echo "    ok   --with-sudoers: visudo -c is clean"
  else echo "    FAIL --with-sudoers: visudo -c"; visudo -c; fail=1; fi
  if grep -qx 'Defaults:fivenines always_set_home' /etc/sudoers.d/fivenines; then
    echo "    ok   --with-sudoers: the account's commands get root's HOME"
  elif [ "$flavor" = sudo-rs ]; then
    echo "    info --with-sudoers: this sudo's visudo rejects always_set_home (sudo-rs sets the target's HOME anyway)"
  else
    echo "    FAIL --with-sudoers: no always_set_home line"; fail=1
  fi
  # requiretty (early RHEL 7's sudoers) refuses every sudo run with no
  # terminal, the agent's included (#309). This container gives none: with a
  # global "Defaults requiretty", alice (a NOPASSWD rule, no !requiretty) is
  # refused, and fivenines still runs its commands. Set where that sudoers
  # sets it, near the top, before its #includedir: sudo applies Defaults in
  # the order it reads them (measured: one appended after the include wins
  # over the account's !requiretty, on every sudo of the matrix).
  if grep -qx 'Defaults:fivenines !requiretty' /etc/sudoers.d/fivenines; then
    echo "    ok   --with-sudoers: the account's commands run with no terminal"
    if [ "$flavor" = sudo ]; then
      cp /etc/sudoers /tmp/sudoers.saved
      { echo 'Defaults requiretty'; cat /tmp/sudoers.saved; } > /etc/sudoers
      if ! visudo -c > /dev/null 2>&1; then
        echo "    info this sudo does not know requiretty: not checked"
      else
        if [ -n "$(as alice sudo -n /usr/sbin/smartctl --version 2>/dev/null)" ]; then
          echo "    info premise: requiretty did not refuse alice here (a terminal?)"
        else
          echo "    ok   premise: requiretty refuses an account without !requiretty"
        fi
        out=$(sudo_as_fivenines "/usr/sbin/smartctl --version")
        if [ "$out" = "smartctl --version" ]; then echo "    ok   --with-sudoers: fivenines runs smartctl under requiretty"
        else echo "    FAIL --with-sudoers: fivenines cannot run smartctl under requiretty: '$out' $(cat /tmp/sudo.err)"; fail=1; fi
      fi
      cp /tmp/sudoers.saved /etc/sudoers
      chmod 440 /etc/sudoers
      clear_mails
    fi
  elif [ "$flavor" = sudo-rs ]; then
    echo "    info --with-sudoers: this sudo's visudo rejects !requiretty (sudo-rs has no requiretty)"
  else
    echo "    FAIL --with-sudoers: no !requiretty line"; fail=1
  fi
  # Per tool, what the agent runs. A tool gets an exact line and, for mdadm,
  # nvme and fail2ban-client, a line of patterns, each written whole or not at
  # all: real sudo must take all five tools; sudo-rs may reject the wg rule
  # (no NOLOG_OUTPUT tag) and, after 0.2.15, every pattern line.
  allowed=""
  for tool in smartctl nvme mdadm fail2ban-client wg; do
    case $tool in
      smartctl) argvs="/usr/sbin/smartctl -i -A -H -l ssd /dev/sda|/usr/sbin/smartctl --version" ;;
      nvme) argvs="/usr/sbin/nvme version|/usr/sbin/nvme smart-log /dev/nvme0 -o json|/usr/sbin/nvme smart-log /dev/nvme12 -o json" ;;
      mdadm) argvs="/usr/sbin/mdadm --version|/usr/sbin/mdadm --detail /dev/md0|/usr/sbin/mdadm --detail /dev/md127" ;;
      fail2ban-client) argvs="/usr/bin/fail2ban-client version|/usr/bin/fail2ban-client status|/usr/bin/fail2ban-client status sshd" ;;
      wg) argvs="/usr/bin/wg show all dump" ;;
    esac
    if grep -qE "NOPASSWD:.* [^ ]*/$tool( |\$)" /etc/sudoers.d/fivenines; then
      allowed="$allowed|$argvs"
    elif [ "$flavor" = sudo-rs ] && [ "$tool" = wg ]; then
      # sudo-rs has no NOLOG_OUTPUT tag. Every other tool keeps at least its
      # exact line, the patterns being on a line of their own.
      echo "    info --with-sudoers: this sudo's visudo rejects the $tool rule, so it is not written"
    else
      echo "    FAIL --with-sudoers: no $tool rule written"; fail=1
    fi
  done
  old_ifs=$IFS
  IFS='|'
  for argv in ${allowed#|}; do
    IFS=$old_ifs
    want=$(printf '%s' "$argv" | sed 's|^/[^ ]*/||')
    out=$(sudo_as_fivenines "$argv")
    if [ "$out" = "$want" ]; then echo "    ok   --with-sudoers: fivenines runs $argv"
    elif [ "$flavor" = sudo-rs ] && [ "$argv" = "/usr/bin/fail2ban-client status sshd" ] \
      && ! grep -qF '/usr/bin/fail2ban-client status *' /etc/sudoers.d/fivenines; then
      # Only the pattern line allows a jail, and a sudo-rs that refuses
      # patterns rejected it: the agent then reads the summary but no jail.
      echo "    info --with-sudoers: this sudo-rs rejects the status * line, so no jail is read"
    else echo "    FAIL --with-sudoers: fivenines cannot run $argv: '$out' $(cat /tmp/sudo.err)"; fail=1; fi
  done
  IFS=$old_ifs
  # What the rules must never allow: each of these runs a command as root or
  # changes the host. "--detail /dev/md0 --stop /dev/md0" is what a wildcard
  # after --detail would have let through.
  denied="/usr/bin/wg set wg0 private-key /dev/null|/bin/sh -c id"
  denied="$denied|/usr/sbin/mdadm --monitor --scan --program /bin/sh"
  denied="$denied|/usr/sbin/mdadm --detail /dev/md0 --stop /dev/md0"
  denied="$denied|/usr/bin/fail2ban-client set sshd banip 192.0.2.1"
  denied="$denied|/usr/sbin/nvme format /dev/nvme0|/usr/sbin/nvme smart-log /dev/nvme0 -o json /dev/nvme1"
  IFS='|'
  for argv in $denied; do
    IFS=$old_ifs
    out=$(sudo_as_fivenines "$argv")
    if [ -n "$out" ]; then echo "    FAIL --with-sudoers: fivenines may run $argv: '$out'"; fail=1
    else echo "    ok   --with-sudoers: fivenines may not run $argv"; fi
  done
  IFS=$old_ifs
fi
# sudoers_tool_path (fivenines_common.sh) names the copy sudo itself runs: the
# first in this host's secure_path, read from sudo -V (#308). Rocky's
# /sbin:/bin:/usr/sbin:/usr/bin has no /usr/local, so a copy there must not get
# the rule. Expected: the first directory of the secure_path /etc/sudoers sets
# (systemd's default PATH where it sets none) that holds the tool.
for dir in /usr/local/sbin /usr/sbin; do
  printf '#!/bin/sh\n' > "$dir/fivenines-sp-probe"
  chmod 755 "$dir/fivenines-sp-probe"
done
sp=$(sed -n 's/^[[:space:]]*Defaults[[:space:]][[:space:]]*secure_path[[:space:]]*=[[:space:]]*//p' /etc/sudoers | tr -d '"' | head -n 1)
[ -n "$sp" ] || sp=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
want=""
old_ifs=$IFS
IFS=:
for dir in $sp; do
  if [ -z "$want" ] && [ -x "$dir/fivenines-sp-probe" ]; then want="$dir/fivenines-sp-probe"; fi
done
IFS=$old_ifs
got=$( . /src/fivenines_common.sh; sudoers_tool_path fivenines-sp-probe 2>/dev/null )
if [ "$got" = "$want" ]; then echo "    ok   --with-sudoers: a rule names $got, secure_path's first ($sp)"
else echo "    FAIL --with-sudoers: a rule names '$got', secure_path ($sp) runs '$want'"; fail=1; fi
rm -f /usr/local/sbin/fivenines-sp-probe /usr/sbin/fivenines-sp-probe

# warn_unpinned_sudoers_rules (fivenines_common.sh), over this sudo's own
# sudo -l -U listing: the pinned rules above are never named, the bare rules
# an earlier README gave are.
unpinned() {
  ( . /src/fivenines_common.sh; warn_unpinned_sudoers_rules ) 2>&1
}
out=$(unpinned)
if [ -z "$out" ]; then echo "    ok   no bare-rule warning for the pinned rules"
else echo "    FAIL a bare-rule warning for the pinned rules: $out"; fail=1; fi
printf '%s\n' 'fivenines ALL=(ALL) NOPASSWD: /usr/sbin/mdadm' \
  'fivenines ALL=(ALL) NOPASSWD: /usr/sbin/smartctl, /usr/bin/fail2ban-client' \
  'fivenines ALL=(root) NOPASSWD: /usr/sbin/nvme *' > /etc/sudoers.d/fivenines-bare
chmod 440 /etc/sudoers.d/fivenines-bare
out=$(unpinned)
case "$out" in
  *"run /usr/bin/fail2ban-client /usr/sbin/mdadm /usr/sbin/nvme with any arguments"*)
    echo "    ok   the bare mdadm and fail2ban-client rules, and nvme *, are named" ;;
  *)
    if [ "$flavor" = sudo-rs ] && [ -z "$out" ]; then
      echo "    info this sudo lists no other user's rules (sudo -l -U): no bare-rule warning"
    else
      echo "    FAIL the bare rules are not named: '$out'"; fail=1
    fi
    ;;
esac
rm -f /etc/sudoers.d/fivenines-bare
clear_mails

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
