"""Static checks on the Windows installer's PowerShell and WiX sources.

The scripts only run on Windows: .github/workflows/windows.yml exercises them
on a member server, and its smoke-msi-domain-controller job (on a push that
changes the installer, or on request) on real Windows Server 2019 domain
controllers (ci/windows-dc/). Each check here pins
a rule one of those runs taught, so a regression fails on any machine before
a Windows run is ever dispatched:

- a domain controller's directory-backed SAM makes the LocalAccounts cmdlets
  find nothing (the trial's 1603), so the account goes through ADSI WinNT;
- group and built-in principal names are translated with the install
  language, so nothing is looked up by its English name;
- GetSecurityDescriptor fails once an ACE names a deleted account, so the WMI
  namespace ACL is read in binary, and Windows PowerShell 5.1's -band on the
  byte enum AceFlags raises "Specified cast is not valid";
- helpers that cannot share a file (separate MSI custom actions, bootstrap
  scripts downloaded one by one) must not drift apart.
"""

import fnmatch
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

CREATE_ACCOUNT = "windows/installer/CreateServiceAccount.ps1"
TOKEN_ACL = "windows/installer/SetTokenFileAcl.ps1"
DELEGATE_WMI = "windows/installer/DelegateWmiStorageNamespace.ps1"
PRODUCT_WXS = "windows/installer/Product.wxs"
WINSW_XML = "windows/winsw/fivenines-agent.xml"
SETUP = "fivenines_setup.ps1"
UPDATE = "fivenines_update.ps1"
UNINSTALL = "fivenines_uninstall.ps1"
WINDOWS_WORKFLOW = ".github/workflows/windows.yml"
RELEASE_WORKFLOW = ".github/workflows/build-release.yml"
DC_UNATTEND = "ci/windows-dc/autounattend.xml.in"
DC_RUNNER = "ci/windows-dc/run-vm.sh"
DC_STAGE_SCRIPTS = (
    "ci/windows-dc/common.ps1",
    "ci/windows-dc/stage1.ps1",
    "ci/windows-dc/stage2.ps1",
)


def _read(path):
    # Text mode: a CRLF checkout (Windows CI) reads as LF, so the multiline
    # regexes' ^ and $ hold there too.
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def _strip_comments(text):
    """Text without its comments: full-line ones and ' # ' trailers."""
    lines = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        lines.append(re.sub(r"\s#\s.*$", "", line))
    return "\n".join(lines)


def _code(path):
    """The script without its comments."""
    return _strip_comments(_read(path))


def _code_without(path, name):
    """The script without function `name`, then without its comments."""
    raw = _read(path)
    function = _function(path, name)
    assert function in raw
    return _strip_comments(raw.replace(function, ""))


def _function(path, name):
    match = re.search(
        r"(?ms)^function %s \{.*?^\}" % re.escape(name),
        _read(path),
    )
    assert match, f"function {name} not found in {path}"
    return match.group(0)


def _constant(path, name):
    match = re.search(r'(?m)^\$%s = "([^"]*)"' % re.escape(name), _read(path))
    assert match, f"${name} not found in {path}"
    return match.group(1)


# Value: protects=the account/WMI helpers each custom action and bootstrap script carries its own copy of; fails_when=one copy is fixed and the other is not (an uninstall that reads the WMI ACL the old way, a TOKEN ACL resolving the account differently from the WMI grant); why_new=the same identity check runs in windows.yml, but only on a Windows runner after a push to a CI branch; seam=none; no_claim=that the helpers work, which the Windows runs prove
@pytest.mark.parametrize(
    "name, first, second",
    [
        ("Resolve-ServiceAccountSid", TOKEN_ACL, DELEGATE_WMI),
        ("Resolve-ServiceAccountSid", TOKEN_ACL, SETUP),
        ("Resolve-ServiceAccountSid", TOKEN_ACL, UPDATE),
        ("ConvertTo-MsiPasswordArgument", SETUP, UPDATE),
        ("Get-MsiProductCode", SETUP, UPDATE),
        ("Get-PreflightVerdict", SETUP, UPDATE),
        ("Invoke-AccountPreflight", SETUP, UPDATE),
        ("New-PrivateWorkDirectory", SETUP, UPDATE),
        ("Invoke-Msiexec", SETUP, UPDATE),
        ("Invoke-Msiexec", SETUP, UNINSTALL),
        ("New-PrivateWorkDirectory", SETUP, UNINSTALL),
        ("Remove-EarlierWorkDirectories", SETUP, UPDATE),
        ("Remove-EarlierWorkDirectories", SETUP, UNINSTALL),
        ("Get-WorkDirectoryKey", SETUP, UPDATE),
        ("Get-WorkDirectoryKey", SETUP, UNINSTALL),
        ("Remove-WorkDirectory", SETUP, UPDATE),
        ("Remove-WorkDirectory", SETUP, UNINSTALL),
        ("Get-WinNTUser", CREATE_ACCOUNT, UNINSTALL),
        ("Get-WmiNamespaceSD", DELEGATE_WMI, UNINSTALL),
        ("Set-WmiNamespaceSD", DELEGATE_WMI, UNINSTALL),
    ],
)
def test_duplicated_helpers_are_identical(name, first, second):
    assert _function(first, name) == _function(second, name)


# Value: protects=the install and uninstall on a domain controller; fails_when=a LocalAccounts cmdlet comes back into the account scripts: on a DC it finds no user or group (v1.22.0 failed there with 1603, reproduced on a Server 2019 DC); why_new=the member-server E2E cannot see it, LocalAccounts works there; seam=none; no_claim=that the WinNT calls replacing them work, which the DC runs prove
@pytest.mark.parametrize("path", [CREATE_ACCOUNT, UNINSTALL])
def test_account_scripts_avoid_the_local_accounts_cmdlets(path):
    code = _code(path)
    for cmdlet in (
        "Get-LocalUser",
        "New-LocalUser",
        "Set-LocalUser",
        "Remove-LocalUser",
        "Get-LocalGroup",
        "Add-LocalGroupMember",
    ):
        assert (
            cmdlet not in code
        ), f"{path} calls {cmdlet}, which sees nothing on a domain controller"


# Value: protects=installs on a non-English Windows; fails_when=a group or built-in principal is looked up by its English name again (the German "Leistungsueberwachungsbenutzer" is not "Performance Monitor Users"); why_new=the English runner finds English names; the E2E only catches the three groups it renames; seam=none; no_claim=that every SID is the right one
@pytest.mark.parametrize("path", [CREATE_ACCOUNT, TOKEN_ACL, DELEGATE_WMI, UNINSTALL])
def test_no_group_or_builtin_principal_by_english_name(path):
    code = _code(path)
    for name in (
        "Performance Monitor Users",
        '"Users"',
        "BUILTIN\\Administrators",
        "NT AUTHORITY\\SYSTEM",
    ):
        assert name not in code, f"{path} names {name!r} instead of its SID"


# Value: protects=the MSI's config/log dir ACL on a localized Windows; fails_when=util:PermissionEx names SYSTEM (or another principal) WiX does not map to a SID itself and LookupAccountName only knows translated ("Systeme" on French); why_new=WiX's mapping list lives in its C++ source, nothing in this repo pins it; seam=none; no_claim=that the ACL is applied
def test_permission_ex_uses_only_names_wix_maps_to_a_sid():
    users = re.findall(r'<util:PermissionEx User="([^"]+)"', _read(PRODUCT_WXS))
    assert users, "no util:PermissionEx found"
    mapped_by_wix = {
        "Everyone",
        "Administrators",
        "LocalSystem",
        "LocalService",
        "NetworkService",
        "AuthenticatedUser",
        "Guests",
        "CREATOR OWNER",
        "INTERACTIVE",
        "Users",
    }
    assert set(users) <= mapped_by_wix


# Value: protects=a reinstall after the account was deleted, and the inherit-only test of an existing WMI grant; fails_when=the WMI namespace ACL is read through GetSecurityDescriptor again (it fails with "unexpected error" once an ACE names a deleted account, failing the install with 1603, found on a DC) or AceFlags is combined with -band without an [int] cast first (Windows PowerShell 5.1 raises "Specified cast is not valid" on the byte enum, parenthesized or not); why_new=both only fail on Windows, after the build; seam=none; no_claim=that GetSD/SetSD are called correctly
@pytest.mark.parametrize("path", [DELEGATE_WMI, UNINSTALL])
def test_wmi_namespace_acl_is_read_in_binary(path):
    code = _code(path)
    assert "GetSecurityDescriptor" not in code
    assert "SetSecurityDescriptor" not in code
    assert not re.search(
        r"(?<!\[int\])\$[\w.]*AceFlags\)?\s*-band|-band\s*\$?inherited",
        code,
        re.IGNORECASE,
    )


# Value: protects=account creation and the uninstall's delete-or-keep decision on a DC; fails_when=a Description tag outgrows the 48-character SAM comment limit (creation fails) or the uninstall spells DC_MANAGED_PREFIX differently (it then keeps, or worse deletes, the wrong account); why_new=windows.yml checks the prefix only on a Windows runner; seam=none; no_claim=that the tags drive the right plan, which Get-AccountPlan's cases cover
def test_description_tags_fit_and_agree():
    prefix = _constant(CREATE_ACCOUNT, "DC_MANAGED_PREFIX")
    for tag in (
        _constant(CREATE_ACCOUNT, "MSI_MANAGED_DESCRIPTION"),
        _constant(CREATE_ACCOUNT, "DC_OPERATOR_DESCRIPTION"),
        prefix + "X" * 15,  # a NetBIOS computer name is at most 15 characters
    ):
        assert len(tag) <= 48, tag
    assert _constant(UNINSTALL, "DC_MANAGED_PREFIX") == prefix
    assert _constant(UNINSTALL, "MSI_MANAGED_DESCRIPTION") == _constant(
        CREATE_ACCOUNT, "MSI_MANAGED_DESCRIPTION"
    )


# Value: protects=the domain-controller E2E harness; fails_when=the autounattend template gains a field run-vm.sh does not fill (Setup then stops on a literal @FIELD@) or the runner copies a stage script or bootstrap script that no longer exists; why_new=a broken harness only shows after an hour-long VM run; seam=none; no_claim=that Windows Setup accepts the answer file
def test_dc_harness_fills_every_template_field_and_ships_its_scripts():
    fields = set(re.findall(r"@([A-Z_]+)@", _read(DC_UNATTEND)))
    runner = _read(DC_RUNNER)
    filled = set(re.findall(r'-e "s/@([A-Z_]+)@/', runner))
    assert fields and fields == filled
    copied = set(re.findall(r'"\$here/([A-Za-z0-9_.]+\.ps1)"', runner))
    copied |= set(re.findall(r'"\$repo/([A-Za-z0-9_.]+\.ps1)"', runner))
    assert {Path(p).name for p in DC_STAGE_SCRIPTS} <= copied
    assert {SETUP, UPDATE, UNINSTALL} <= copied
    for name in copied:
        candidates = [REPO_ROOT / name, REPO_ROOT / "ci/windows-dc" / name]
        assert any(c.is_file() for c in candidates), name


# Value: protects=what the DC job downloads, and when its hour runs; fails_when=an evaluation ISO or the v1.22.0 MSI loses its pinned SHA-256, the job runs on a push that changed no installer file or on a tag (where a release would then depend on Microsoft's ISOs), or it stops running on a push that changed one; why_new=nothing else reads these pins or the trigger; seam=none; no_claim=that Microsoft still serves the same ISO, or that the path list names every file the DC scenarios exercise
def test_dc_job_pins_its_downloads_and_runs_when_the_installer_changes():
    workflow = _read(WINDOWS_WORKFLOW)
    start = workflow.index("  smoke-msi-domain-controller:")
    job = workflow[start:]
    assert "needs: [build-msi, installer-changed]" in job
    assert (
        "(github.event_name == 'workflow_dispatch' && inputs.domain_controller)" in job
    )
    assert "needs.installer-changed.outputs.changed == 'true'" in job
    assert len(re.findall(r"iso_sha256: [0-9a-f]{64}\n", job)) == 2
    assert re.search(r"OLD_MSI_SHA256: [0-9a-f]{64}\n", job)
    assert "sha256sum -c -" in job

    gate_start = workflow.index("  installer-changed:")
    gate = workflow[gate_start:start]
    assert (
        "if: github.event_name == 'push' && !startsWith(github.ref, 'refs/tags/')"
        in gate
    )
    paths = re.search(r"grep -E '\^\((.*)\)'", gate)
    assert paths, "installer-changed lost its path list"
    for watched in (
        "windows/installer/",
        "ci/windows-dc/",
        "fivenines_(setup|update|uninstall)\\.ps1$",
        "\\.github/workflows/windows\\.yml$",
    ):
        assert watched in paths.group(1), watched
    assert "grep -v '\\.md$'" in gate


# Value: protects=every release's MSI; fails_when=the release job stops waiting for windows.yml's member-server E2E, windows.yml triggers on tags again (a second, unwaited run), or one of its artifacts matches the release's fivenines-agent-* download pattern (the E2E's MSI published as a release asset, or an upload clash with any build-release.yml artifact in the same run); why_new=before this a release published whatever windows.yml said, and nothing reads the cross-workflow wiring; seam=none; no_claim=that the E2E itself is sufficient, which the E2E steps decide
def test_release_waits_for_the_windows_e2e():
    release = _read(RELEASE_WORKFLOW)
    call_start = release.index("  windows-e2e:")
    call = release[call_start:].split("\n  release:\n", 1)[0]
    assert "if: startsWith(github.ref, 'refs/tags/v')" in call
    assert "uses: ./.github/workflows/windows.yml" in call
    needs = re.search(r"\n  release:\n(?:    #.*\n)*    needs: \[([^\]]*)\]", release)
    assert needs, "release job lost its needs list"
    assert "windows-e2e" in [n.strip() for n in needs.group(1).split(",")]

    workflow = _read(WINDOWS_WORKFLOW)
    on_start = workflow.index("\non:\n")
    triggers = workflow[on_start:].split("\nconcurrency:", 1)[0]
    assert "workflow_call:" in triggers
    assert "tags:" not in triggers
    assert "group: ${{ github.workflow }}" not in workflow
    for name in re.findall(r"^\s+name: (\S+)$", workflow, re.MULTILINE):
        assert not name.startswith("fivenines-agent-"), name
    # Called on a tag, windows.yml's jobs run in build-release.yml's run, where
    # a second upload of one name fails and every download sees both
    # workflows' artifacts: no windows.yml upload may share a name with an
    # artifact build-release.yml uploads or downloads.
    uploads = _artifact_names(workflow, "upload")
    assert {"windows-ci-agent", "windows-ci-msi"} <= set(uploads), uploads
    theirs = _artifact_names(release, "upload") + _artifact_names(release, "download")
    assert {"fivenines-agent-windows-amd64", "fivenines-agent-*"} <= set(theirs), theirs
    for name in uploads:
        for other in theirs:
            assert not _may_name_one_artifact(name, other), (name, other)


def _artifact_names(workflow, action):
    """The name or pattern of every actions/<action>-artifact step, each
    ${{ }} expression read as *, and * for a step naming none (a download
    of every artifact)."""
    names = []
    lines = workflow.splitlines()
    for i, line in enumerate(lines):
        match = re.match(r"( +)(- +)?uses: actions/%s-artifact@" % action, line)
        if not match:
            continue
        indent = len(match.group(1)) + len(match.group(2) or "")
        next_line = i + 1
        found = []
        for following in lines[next_line:]:
            if following.strip() and len(following) - len(following.lstrip()) < indent:
                break
            key = re.match(r" {%d,}(?:name|pattern): (.+)$" % (indent + 1), following)
            if key:
                found.append(re.sub(r"\$\{\{[^}]*\}\}", "*", key.group(1).strip()))
        assert len(found) <= 1, found
        names.extend(found or ["*"])
    return names


def _may_name_one_artifact(first, second):
    """Whether two artifact names or patterns (* any text) can name the same
    artifact; two that differ before either's first * cannot."""
    first, second = first.lower(), second.lower()
    if "*" not in first and "*" not in second:
        return first == second
    if "*" not in first:
        return fnmatch.fnmatchcase(first, second)
    if "*" not in second:
        return fnmatch.fnmatchcase(second, first)
    a, b = first.split("*", 1)[0], second.split("*", 1)[0]
    return a.startswith(b) or b.startswith(a)


def _job(workflow, name):
    """Job `name` of a workflow, up to the next job's key."""
    lines = workflow.splitlines(keepends=True)
    start = lines.index("  %s:\n" % name)
    end = next(
        (i for i in range(start + 1, len(lines)) if re.match(r"  [\w-]+:\n", lines[i])),
        len(lines),
    )
    return "".join(lines[start:end])


def _job_needs(job):
    match = re.search(r"(?m)^    needs: (.*)$", job)
    if not match:
        return []
    value = match.group(1).strip()
    if value.startswith("["):
        return [name.strip() for name in value[1:-1].split(",")]
    return [value]


def _job_condition(job):
    """A job's if:, its folding and its ${{ }} wrapper undone."""
    match = re.search(r"(?m)^    if: (.*)$", job)
    assert match, "the job has no if:"
    value = match.group(1).strip()
    if value in (">", ">-"):
        folded = []
        end = match.end()
        for line in job[end:].splitlines()[1:]:
            if not line.startswith("      "):
                break
            folded.append(line.strip())
        value = " ".join(folded)
    if value.startswith("${{") and value.endswith("}}"):
        value = value[3:-2]
    return value.strip()


def _truthy(value):
    return value not in (None, False, 0, "")


_EXPRESSION_TOKEN = re.compile(
    r"\s*(?:(?P<op>\|\||&&|==|!=|!|\(|\)|,)|'(?P<str>[^']*)'|(?P<name>[A-Za-z_][\w.-]*))"
)


def _expression(text):
    """A GitHub Actions expression as a function of its contexts, for the
    subset these workflows use: ! (binding tightest), == and != (strings
    compared ignoring case), && and || (returning an operand), parentheses,
    strings, true/false/null, calls, and dotted names, each of which the
    contexts must name (KeyError otherwise)."""
    tokens = []
    pos = 0
    text = text.strip()
    while pos < len(text):
        match = _EXPRESSION_TOKEN.match(text, pos)
        assert match and match.end() > pos, f"cannot read {text[pos:]!r}"
        pos = match.end()
        tokens.append((match.lastgroup, match.group(match.lastgroup)))
    at = [0]

    def peek():
        return tokens[at[0]] if at[0] < len(tokens) else (None, None)

    def take(op=None):
        token = peek()
        assert op is None or token == ("op", op), (op, token)
        at[0] += 1
        return token

    def primary():
        kind, value = take()
        if (kind, value) == ("op", "("):
            inner = disjunction()
            take(")")
            return inner
        if kind == "str":
            return lambda ctx: value
        assert kind == "name", (kind, value)
        if peek() == ("op", "("):
            take("(")
            args = []
            while peek() != ("op", ")"):
                args.append(disjunction())
                if peek() == ("op", ","):
                    take(",")
            take(")")
            return lambda ctx: ctx[value + "()"](*(arg(ctx) for arg in args))
        if value in ("true", "false", "null"):
            literal = {"true": True, "false": False, "null": None}[value]
            return lambda ctx: literal
        return lambda ctx: ctx[value]

    def unary():
        if peek() == ("op", "!"):
            take("!")
            operand = unary()
            return lambda ctx: not _truthy(operand(ctx))
        return primary()

    def comparison():
        left = unary()
        if peek() not in (("op", "=="), ("op", "!=")):
            return left
        equal = take()[1] == "=="
        right = unary()

        def compare(ctx):
            a, b = left(ctx), right(ctx)
            if isinstance(a, str) and isinstance(b, str):
                a, b = a.lower(), b.lower()
            return (a == b) == equal

        return compare

    def chain(operand, op, stop_when):
        parts = [operand()]
        while peek() == ("op", op):
            take(op)
            parts.append(operand())

        def run(ctx):
            value = None
            for part in parts:
                value = part(ctx)
                if stop_when(value):
                    break
            return value

        return run

    def conjunction():
        return chain(comparison, "&&", lambda value: not _truthy(value))

    def disjunction():
        return chain(conjunction, "||", _truthy)

    expression = disjunction()
    assert at[0] == len(tokens), f"unread: {tokens[at[0]:]}"
    return expression


def _job_starts(job, contexts, needs, cancelled=False):
    """Whether GitHub starts a job: an if: with no status function is read
    as success() && (if:), and success() is false once a job it needs did
    not succeed, a skipped one included."""
    condition = _job_condition(job)
    needed = {name: needs[name] for name in _job_needs(job)}
    succeeded = not cancelled and all(n["result"] == "success" for n in needed.values())
    ctx = dict(contexts)
    ctx.update(
        {
            "success()": lambda: succeeded,
            "failure()": lambda: any(n["result"] == "failure" for n in needed.values()),
            "cancelled()": lambda: cancelled,
            "always()": lambda: True,
            "startsWith()": lambda text, prefix: str(text or "")
            .lower()
            .startswith(str(prefix).lower()),
        }
    )
    for name, need in needed.items():
        ctx["needs.%s.result" % name] = need["result"]
        for key, value in need["outputs"].items():
            ctx["needs.%s.outputs.%s" % (name, key)] = value
    explicit = re.search(r"\b(?:success|failure|always|cancelled)\(", condition)
    return bool(explicit or succeeded) and _truthy(_expression(condition)(ctx))


DISPATCH = "workflow_dispatch"


# Value: protects=when the DC job and its gate start, evaluated as GitHub does: an if: with no status function needs every job it needs to succeed; fails_when=!cancelled() goes (a dispatch never runs the DC job), the build-msi check goes, || and && swap, or the gate runs on a tag or a dispatch; why_new=the existing test finds the clauses as substrings and evaluates none; seam=none; no_claim=GitHub's whole expression language, only the operators these two conditions use
@pytest.mark.parametrize(
    "event, ref, asked, msi, cancelled, diff, gate_runs, dc_runs",
    [
        ("push", "refs/heads/fix/x", None, "success", False, "true", True, True),
        ("push", "refs/heads/fix/x", None, "success", False, "false", True, False),
        ("push", "refs/heads/main", None, "success", False, "true", True, True),
        # build-release.yml's call on a tag: the caller's event and ref.
        ("push", "refs/tags/v1.23.0", None, "success", False, "true", False, False),
        # build-release.yml dispatched on a tag: windows.yml declares no
        # workflow_call input, so inputs.domain_controller is null.
        (DISPATCH, "refs/tags/v1.23.0", None, "success", False, "true", False, False),
        (DISPATCH, "refs/heads/fix/x", True, "success", False, "true", False, True),
        (DISPATCH, "refs/heads/fix/x", False, "success", False, "true", False, False),
        ("push", "refs/heads/fix/x", None, "failure", False, "true", True, False),
        (DISPATCH, "refs/heads/fix/x", True, "failure", False, "true", False, False),
        ("push", "refs/heads/fix/x", None, "cancelled", True, "true", True, False),
        # The run cancelled while build-msi had succeeded: only !cancelled()
        # keeps the hour-long job from starting (always() would not).
        ("push", "refs/heads/fix/x", None, "success", True, "true", True, False),
    ],
    ids=[
        "push-changing-the-installer",
        "push-changing-nothing-it-tests",
        "push-to-main-changing-the-installer",
        "release-call-on-a-tag",
        "release-dispatch-on-a-tag",
        "dispatch-asking-for-it",
        "dispatch-not-asking",
        "push-msi-build-failed",
        "dispatch-msi-build-failed",
        "push-run-cancelled",
        "push-run-cancelled-after-the-msi",
    ],
)
def test_dc_job_starts_on_an_installer_push_or_a_request_only(
    event, ref, asked, msi, cancelled, diff, gate_runs, dc_runs
):
    workflow = _read(WINDOWS_WORKFLOW)
    contexts = {
        "github.event_name": event,
        "github.ref": ref,
        "github.ref_type": "tag" if ref.startswith("refs/tags/") else "branch",
        "github.ref_name": ref.split("/", 2)[2],
        "inputs.domain_controller": asked,
    }
    gate = _job(workflow, "installer-changed")
    assert _job_starts(gate, contexts, needs={}) == gate_runs
    needs = {
        "build-msi": {"result": msi, "outputs": {}},
        "installer-changed": {
            "result": "success" if gate_runs else "skipped",
            "outputs": {"changed": diff if gate_runs else None},
        },
    }
    dc = _job(workflow, "smoke-msi-domain-controller")
    assert _job_starts(dc, contexts, needs, cancelled=cancelled) == dc_runs


def _step(job, step_id):
    for block in re.split(r"(?m)^      - ", job)[1:]:
        if re.search(r"(?m)^        id: %s$" % re.escape(step_id), block):
            return block
    raise AssertionError(f"no step with id {step_id}")


def _step_script(step):
    """A step's run: | block, as the runner writes it to its script file."""
    match = re.search(r"(?m)^        run: \|\n", step)
    assert match, "the step has no run block"
    lines = []
    for line in step.split(match.group(0), 1)[1].splitlines():
        if line.strip() and not line.startswith(" " * 10):
            break
        lines.append(line[10:])
    return "\n".join(lines).rstrip() + "\n"


# The DC job's path filter, file by file: what a push changing it decides.
DC_WATCHED = (
    "windows/installer/Product.wxs",
    "windows/winsw/fivenines-agent.xml",
    "ci/windows-dc/run-vm.sh",
    SETUP,
    UPDATE,
    UNINSTALL,
    WINDOWS_WORKFLOW,
)
DC_NOT_WATCHED = (
    "windows/installer/README.md",
    "ci/windows-dc/README.md",
    "fivenines_agent/agent.py",
    RELEASE_WORKFLOW,
    "docs/windows/installer/notes.ps1",
)


# Value: protects=a release published only after the Windows E2E succeeded on the tagged commit; fails_when=the release job's if: gains always() or !cancelled(), or windows-e2e leaves its needs; why_new=the existing test checks needs membership only, and an explicit status function overrides it; seam=none; no_claim=GitHub's own evaluation (the test's evaluator stands in for it)
@pytest.mark.parametrize(
    "e2e, publishes",
    [("success", True), ("failure", False), ("cancelled", False), ("skipped", False)],
)
def test_release_publishes_only_after_the_windows_e2e(e2e, publishes):
    release = _job(_read(RELEASE_WORKFLOW), "release")
    needs = {name: {"result": "success", "outputs": {}} for name in _job_needs(release)}
    assert "windows-e2e" in needs
    needs["windows-e2e"]["result"] = e2e
    contexts = {"github.event_name": "push", "github.ref": "refs/tags/v1.23.0"}
    assert (
        _job_starts(release, contexts, needs, cancelled=e2e == "cancelled") == publishes
    )


# Value: protects=which pushes run the hour-long DC job: the gate's own bash step, run on real git history as a push would; fails_when=the base is not cumulative (a run a newer push cancelled is never made up), main is not compared with its latest v* tag, or the path, Markdown or rename filter misreads a file; why_new=the existing test matches the step's text and never runs it; seam=none; no_claim=GitHub's runner git or its checkout's tags; skipped on Windows (no known bash there)
@pytest.mark.skipif(
    sys.platform == "win32" or not (shutil.which("git") and shutil.which("bash")),
    reason="runs the step's bash script against git",
)
def test_installer_changed_compares_cumulatively(tmp_path):
    gate = _job(_read(WINDOWS_WORKFLOW), "installer-changed")
    output = re.search(
        r"(?m)^      changed: \$\{\{ steps\.([\w-]+)\.outputs\.changed \}\}$", gate
    )
    assert output, "installer-changed does not publish its step's answer"
    step = _step(gate, output.group(1))
    script_file = tmp_path / "step.sh"
    script = _step_script(step)
    assert "${{" not in script  # what runs here is what the runner runs
    script_file.write_text(script)

    repo = tmp_path / "repo"
    repo.mkdir()
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path),
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "ci",
        "GIT_AUTHOR_EMAIL": "ci@example.invalid",
        "GIT_COMMITTER_NAME": "ci",
        "GIT_COMMITTER_EMAIL": "ci@example.invalid",
    }

    def git(*args):
        return subprocess.run(
            ["git", *args],
            cwd=repo,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def commit(*paths, delete=(), move=None):
        for path in paths:
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            with open(repo / path, "a") as f:
                f.write("x\n")
        for path in delete:
            (repo / path).unlink()
        if move:
            (repo / move[1]).parent.mkdir(parents=True, exist_ok=True)
            git("mv", *move)
        git("add", "-A")
        git("commit", "-q", "-m", "change")
        return git("rev-parse", "HEAD")

    def push(ref):
        """The step's answer and the base it compared HEAD with."""
        github_output = tmp_path / "github_output"
        github_output.write_text("")
        run = subprocess.run(
            ["bash", "-e", str(script_file)],
            cwd=repo,
            env=dict(env, GITHUB_REF=ref, GITHUB_OUTPUT=str(github_output)),
            capture_output=True,
            text=True,
        )
        assert run.returncode == 0, run.stderr
        answers = re.findall(r"(?m)^changed=(.*)$", github_output.read_text())
        assert len(answers) == 1, answers
        compared = re.search(r"(?m)^Comparing (\w+) with (\w+)$", run.stdout)
        assert compared and compared.group(2) == git("rev-parse", "HEAD"), run.stdout
        return answers[0], compared.group(1)

    branch = "refs/heads/fix/x"
    git("init", "-q")
    root = commit(*DC_WATCHED, *DC_NOT_WATCHED, "windows/installer/Old.ps1")
    git("update-ref", "refs/remotes/origin/main", root)

    # A branch is compared with where it left main, file by file.
    for path, changed in [(p, "true") for p in DC_WATCHED] + [
        (p, "false") for p in DC_NOT_WATCHED
    ]:
        git("checkout", "-q", "-B", "topic", root)
        commit(path)
        assert push(branch) == (changed, root), path
    # Cumulatively: the push that replaced an installer push (whose run it
    # cancelled) still runs the job, and so does every later one.
    git("checkout", "-q", "-B", "topic", root)
    commit("windows/installer/Product.wxs")
    commit("fivenines_agent/agent.py")
    assert push(branch) == ("true", root)
    commit("README.md")
    assert push(branch) == ("true", root)
    # Markdown under a watched directory is not tested; a deletion and a file
    # moved out of a watched directory are.
    git("checkout", "-q", "-B", "topic", root)
    commit("windows/installer/README.md")
    assert push(branch) == ("false", root)
    commit(move=("windows/installer/Old.ps1", "attic/Old.ps1"))
    assert push(branch) == ("true", root)
    git("checkout", "-q", "-B", "topic", root)
    commit(delete=["windows/installer/Old.ps1"])
    assert push(branch) == ("true", root)
    # Where it left main moves with main: an installer change main made
    # since is not this branch's.
    git("checkout", "-q", "-B", "main", root)
    main = commit("windows/installer/Product.wxs")
    git("update-ref", "refs/remotes/origin/main", main)
    git("checkout", "-q", "-B", "topic", main)
    commit("fivenines_agent/agent.py")
    assert push(branch) == ("false", main)
    # A branch at main's tip is its own base: compared with the commit before.
    git("checkout", "-q", "-B", "topic", main)
    assert push(branch) == ("true", root)

    # main is compared with its latest v* tag: every push until the next
    # release runs the job for an installer change since the last one.
    git("checkout", "-q", "main")
    git("tag", "v1.0.0", root)
    git("tag", "nightly", main)  # not a release tag
    assert push("refs/heads/main") == ("true", root)
    after = commit("fivenines_agent/agent.py")
    assert push("refs/heads/main") == ("true", root)
    git("tag", "v1.1.0", after)
    commit("fivenines_agent/agent.py")
    assert push("refs/heads/main") == ("false", after)
    # A main commit that is the tag itself: compared with the commit before.
    git("checkout", "-q", "main")
    git("reset", "-q", "--hard", after)
    assert push("refs/heads/main") == ("false", main)


# Value: protects=the DC VM's install finishing on a runner slow to fsync, and its logs read from a complete disk; fails_when=cache=unsafe leaves the system disk, QEMU is stopped by a signal it cannot handle, or the disk is read before QEMU exits; why_new=a slow runner fails the DC job only sometimes, an hour in, and logs lost to a SIGKILL show only on a timeout; seam=none; no_claim=that QEMU writes its cache out on SIGTERM (run-vm.sh's comment says it does), or that cache=unsafe is enough on every runner
def test_dc_vm_disk_ignores_flushes_and_is_complete_once_read():
    code = _code(DC_RUNNER)
    system = re.search(r'(?m)-drive file="\$work/disk\.qcow2",(\S+) \\$', code)
    assert system, "run-vm.sh lost the VM's system disk"
    assert "cache=unsafe" in system.group(1).split(",")
    # Its unsafe cache is complete on disk only once QEMU has exited, by
    # itself or on SIGTERM: a SIGKILL would leave the qcow2 the logs are read
    # from without what QEMU still held.
    kills = [k.strip() for k in re.findall(r'\bkill((?: +-\S+)*) +"\$qemu"', code)]
    assert "" in kills, "the timeout no longer stops the VM"
    assert set(kills) <= {"", "-0", "-TERM", "-15", "-s TERM"}, kills
    assert code.index('wait "$qemu"') < code.index("qemu-nbd --connect")


# Value: protects=the agent directories' ACLs; fails_when=an icacls call comes back (it resolves the path again, and /T walks what the account planted), one of the two directories stops going through Grant-AgentDirectory, or -PlanOnly stops refusing before its exit; why_new=only the Windows unit step exercises the function, and it cannot see a call site that bypasses it; seam=none; no_claim=that the function behaves, which windows.yml's "Verify the agent directory grant" step runs for real
def test_agent_directories_are_granted_without_a_recursive_walk():
    script = _read(CREATE_ACCOUNT)
    assert "icacls" not in _code(CREATE_ACCOUNT).lower()
    assert "function Grant-AgentDirectory {" in script
    assert "Grant-AgentDirectory -Path $d -Sid $sid -Root $programData" in script
    assert '(Join-Path $programData "fivenines_agent"),' in script
    assert '(Join-Path $programData "fivenines_agent\\logs")' in script
    # -PlanOnly refuses what the account step would refuse, before its exit.
    assert script.index("[FiveninesAgentDirectory]::Refusal(") < script.index(
        '"FIVENINES_PLAN "'
    )


# Value: protects=the upgrade of every account an earlier release created, and what the DC harness expects of the tags; fails_when=MSI_MANAGED_DESCRIPTION is reworded (a member-server upgrade then finds the account v1.22.0 or older created "not MSI-managed" and fails with 1603, and a DC no longer adopts it) or stage2.ps1's $Legacy/$Own/$OtherDc/$Operator drift from the installer's tags (S2/S4/S5 fail an hour into the DC run); why_new=windows.yml's Get-AccountPlan cases read the constants from the script, so they follow a reword, and only the member smoke's literal and the DC run's S2 catch it, on Windows; seam=none; no_claim=that the tags drive the right plan, which the Get-AccountPlan cases cover
def test_tags_match_earlier_releases_and_the_dc_harness():
    legacy = _constant(CREATE_ACCOUNT, "MSI_MANAGED_DESCRIPTION")
    # Written by every release since Windows support (#57), v1.22.0 included.
    assert legacy == "Fivenines monitoring agent service account"
    stage2 = "ci/windows-dc/stage2.ps1"
    assert _constant(stage2, "Legacy") == legacy
    prefix = _constant(CREATE_ACCOUNT, "DC_MANAGED_PREFIX")
    own = r'(?m)^\$Own = "%s" \+ \$env:COMPUTERNAME$' % re.escape(prefix)
    assert re.search(own, _read(stage2))
    other_dc = _constant(stage2, "OtherDc")
    assert other_dc.startswith(prefix) and len(other_dc) > len(prefix)
    operator = _constant(CREATE_ACCOUNT, "DC_OPERATOR_DESCRIPTION")
    assert _constant(stage2, "Operator") == operator


# Value: protects=-ServiceAccountPassword on fivenines_setup.ps1 and fivenines_update.ps1: refused before the MSI is downloaded, and once accepted handed to msiexec; fails_when=the converted argument stops reaching the array msiexec gets (PowerShell reads a renamed or misspelled variable as $null, so the install silently runs without the password and fails with 1603 on a DC whose account is shared) or the check moves after the download; why_new=the E2Es run the scripts only on Windows after the MSI build, and windows.yml checks ConvertTo-MsiPasswordArgument's body, not how the scripts use it; seam=none; no_claim=that msiexec and the custom action parse the argument, which S5 proves for the setup script
@pytest.mark.parametrize("path", [SETUP, UPDATE])
def test_bootstrap_checks_the_password_first_and_hands_it_to_msiexec(path):
    code = _code(path)
    convert = re.search(
        r"\$(\w+) = ConvertTo-MsiPasswordArgument \$ServiceAccountPassword\b", code
    )
    assert convert, f"{path} does not convert -ServiceAccountPassword"
    assert convert.start() < code.index(
        "Invoke-WebRequest"
    ), f"{path} downloads the MSI before checking -ServiceAccountPassword"
    msiexec = re.search(r"Invoke-Msiexec -Arguments \$(\w+)", code)
    assert msiexec, f"{path} does not run msiexec"
    before_msiexec = code[: msiexec.start()]
    built = list(re.finditer(r"\$%s = @\(" % msiexec.group(1), before_msiexec))
    assert built, f"{path} never builds the msiexec arguments"
    appended = r"\$%s \+= \$%s\b" % (msiexec.group(1), convert.group(1))
    built_end = built[-1].end()
    after_built = before_msiexec[built_end:]
    assert re.search(
        appended, after_built
    ), f"{path} does not pass the converted password to msiexec"


# Value: protects=-ServiceAccountPassword with a relative -MsiPath on the version already installed; fails_when=the bootstrap stops resolving -MsiPath, or resolves it after the download (the ProductCode read goes through COM, which resolves a relative path against the process's working directory, usually System32, instead of PowerShell's location: it found no MSI, msiexec ran a maintenance pass and the script reported success without applying the password); why_new=the smoke-msi E2E runs it from another location, but only on Windows after the MSI build; seam=none; no_claim=that the resolved path is the one Invoke-WebRequest writes, which the E2E proves
@pytest.mark.parametrize("path", [SETUP, UPDATE])
def test_bootstrap_resolves_a_relative_msi_path_first(path):
    code = _code(path)
    resolve = re.search(
        r"(?m)^\$MsiPath = \$ExecutionContext\.SessionState\.Path"
        r"\.GetUnresolvedProviderPathFromPSPath\(\$MsiPath\)$",
        code,
    )
    assert resolve, f"{path} does not resolve -MsiPath"
    assert resolve.start() < code.index(
        "Invoke-WebRequest"
    ), f"{path} uses -MsiPath before resolving it"


# Value: protects=the downloaded MSI, its extracted copy and the install log; fails_when=a default path, the extraction or the log goes back to a bare $env:TEMP (C:\\Windows\\Temp under an RMM tool running as SYSTEM, where a file any local user created stays theirs to rewrite before msiexec runs it), or the account step run in this process compiles its C# in the operator's own %TEMP%; why_new=the E2E and the DC runs pass explicit -MsiPath/-LogFile, so the defaults run nowhere in CI; seam=none; no_claim=that the directory's ACL is private, which windows.yml's "Verify the bootstrap's private work directory" steps check on Windows, under PowerShell 5.1 and 7
@pytest.mark.parametrize("path", [SETUP, UPDATE])
def test_bootstrap_downloads_into_a_private_directory(path):
    code = _code(path)
    assert re.search(r'(?m)^    \[string\]\$MsiPath = "",$', code)
    assert re.search(r'(?m)^    \[string\]\$LogFile = "",$', code)
    assert re.search(r"(?m)^\$WorkDir = New-PrivateWorkDirectory ", code)
    assert re.search(
        r"(?m)^if \(-not \$MsiPath\) \{ \$MsiPath = Join-Path \$WorkDir ", code
    )
    assert re.search(
        r"(?m)^if \(-not \$LogFile\) \{ \$LogFile = Join-Path \$WorkDir ", code
    )
    assert '$image = Join-Path $WorkDir "plan"' in code
    assert "-WorkDir $WorkDir" in code
    # %TEMP% is only ever pointed at the work directory, around the MSI's
    # account step run in this process (its Add-Type compiles in %TEMP%).
    redirect = (
        "$savedTemp = $env:TEMP",
        "$env:TEMP = $WorkDir",
        "$env:TEMP = $savedTemp",
    )
    rest = code
    for line in redirect:
        assert line in code
        rest = rest.replace(line, "")
    assert "$env:TEMP" not in rest
    # Earlier runs' directories go right after this run's is created (a run
    # that keeps failing does not pile them up) and again as the last
    # statement of a run that succeeds; this one stays, as the recorded
    # install source a repair reads, or for a failed run's log. The
    # extraction goes in the preflight's finally either way.
    prune = "Remove-EarlierWorkDirectories -Keep $WorkDir"
    assert code.count(prune) == 2
    assert re.search(
        r'(?m)^\$WorkDir = New-PrivateWorkDirectory "[a-z-]+"\n(#[^\n]*\n)*'
        + re.escape(prune)
        + "$",
        code,
    )
    after = code.rsplit(prune, 1)[1].strip().splitlines()
    assert all(
        line.startswith("Write-Host ") or line == "if ($restartPending) { exit 3010 }"
        for line in after
        if line.strip()
    ), after
    assert "Remove-Item -LiteralPath $WorkDir" not in code
    assert "Get-ChildItem -LiteralPath $WorkDir" not in code
    assert re.search(
        r"\} finally \{\s*Remove-Item -LiteralPath \$image ",
        _function(path, "Invoke-AccountPreflight"),
    )
    # Under %SystemRoot%\Temp (no user can rename another's directory
    # there), owned by Administrators, its ACL checked after creation;
    # PowerShell 7's .NET has no Directory.CreateDirectory(path, ACL).
    helper = _function(path, "New-PrivateWorkDirectory")
    assert 'Join-Path (Join-Path $env:SystemRoot "Temp")' in helper
    assert "$security.SetOwner($admins)" in helper
    assert "did not keep its access control list" in helper
    assert "FileSystemAclExtensions]::CreateDirectory($security, $path)" in helper
    # Recorded with a marker before the directory exists (a run stopped in
    # between leaves no directory unrecorded), and the marker written in a
    # file whose own ACL, set while it is still empty, shuts out the user.
    # The record also names the process running this script (ID and start
    # time), so no other run touches the directory while it is alive.
    assert (
        '$run = "{0}|{1}|{2}" -f $marker, $PID, (Get-Process -Id $PID).StartTime'
        in helper
    )
    record = helper.index("-Name (Split-Path -Leaf $path) -Value $run")
    assert record < helper.index("CreateDirectory(")
    acl = helper.index("Set-Acl -LiteralPath $markerFile -AclObject $markerSecurity")
    assert acl < helper.index("Set-Content -LiteralPath $markerFile -Value $marker")
    assert "$markerSecurity.SetAccessRuleProtection($true, $false)" in helper
    # Windows PowerShell 5.1's Get-Acl and Set-Acl find no registry key by
    # -LiteralPath (the CI step failed on it).
    key_helper = _function(path, "Get-WorkDirectoryKey")
    assert "Get-Acl -Path $key" in key_helper
    assert "Set-Acl -Path $key" in key_helper
    assert "Acl -LiteralPath" not in key_helper
    # The pruning removes only recorded directories, never one found by its
    # name: any local user can create one of any name under %SystemRoot%\Temp
    # and turn it into a link at any moment. A recorded path must first be a
    # plain directory owned by Administrators before its marker is read, and
    # the removal goes through Remove-WorkDirectory, the marker last.
    prune_helper = _function(path, "Remove-EarlierWorkDirectories")
    assert "Get-ChildItem" not in prune_helper
    assert "Remove-Item " not in prune_helper
    assert ".GetValueNames()" in prune_helper
    # A record whose process is still running (same ID and start time,
    # another process than this one) is skipped before anything is read or
    # removed: that run still reads its directory back.
    alive = prune_helper.index("Get-Process -Id ([int]$ownerId)")
    assert "[int]$ownerId -ne $PID" in prune_helper
    assert alive < prune_helper.index("Get-Item -LiteralPath $path")
    owner = prune_helper.index('.Value -eq "S-1-5-32-544"')
    assert owner < prune_helper.index("$found = Get-Content")
    guard = prune_helper.index("if ($marker -and $found -eq $marker) {")
    assert prune_helper.index("Remove-WorkDirectory $path") > guard
    remover = _function(path, "Remove-WorkDirectory")
    assert remover.index('$_.Name -ne ".fivenines-work-directory"') < remover.index(
        "Remove-Item -LiteralPath $Path -Recurse"
    )


# Value: protects=the uninstall log; fails_when=fivenines_uninstall.ps1's -LogFile default goes back to a bare $env:TEMP name (C:\\Windows\\Temp under an RMM tool running as SYSTEM) or a successful uninstall stops removing its work directory; why_new=the Windows runs pass an explicit -LogFile; seam=none; no_claim=that the ACL is private, which windows.yml's work directory steps check
def test_uninstall_logs_into_a_private_directory():
    code = _code(UNINSTALL)
    assert re.search(r'(?m)^    \[string\]\$LogFile = ""$', code)
    assert re.search(r"(?m)^\$WorkDir = New-PrivateWorkDirectory ", code)
    assert re.search(
        r"(?m)^if \(-not \$LogFile\) \{ \$LogFile = Join-Path \$WorkDir ", code
    )
    # Earlier runs' directories go at the start, as in setup and update.
    assert re.search(
        r'(?m)^\$WorkDir = New-PrivateWorkDirectory "fivenines-uninstall"\n(#[^\n]*\n)*'
        + re.escape("Remove-EarlierWorkDirectories -Keep $WorkDir")
        + "$",
        code,
    )
    # After it succeeds no repair is left to protect: every recorded
    # directory goes whatever its age, its own too, the marker last.
    helper = _function(UNINSTALL, "Remove-AllWorkDirectories")
    assert "Remove-EarlierWorkDirectories -Keep $WorkDir -MinAgeMinutes 0" in helper
    assert "Remove-WorkDirectory $WorkDir" in helper
    # Before -KeepAccount's exit 0, and at the end, each after the msiexec /x
    # failure exit.
    calls = re.findall(r"(?m)^\s*Remove-AllWorkDirectories$", code)
    assert len(calls) == 2
    first = re.search(r"(?m)^\s*Remove-AllWorkDirectories$", code)
    assert first.start() > code.index("exit $exitCode")
    rest = code.split(first.group(0), 1)[1].split("\n")
    assert [line.strip() for line in rest[1:3]] == [
        "if ($restartPending) { exit 3010 }",
        "exit 0",
    ], rest[:3]
    after = code.rsplit("Remove-AllWorkDirectories", 1)[1].strip().splitlines()
    assert all(
        line.startswith("Write-Host ") or line == "if ($restartPending) { exit 3010 }"
        for line in after
        if line.strip()
    ), after


# Value: protects=every install, update and uninstall the bootstraps run; fails_when=an msiexec call bypasses Invoke-Msiexec (no retry of the Windows Installer service's 1601/1618, an automatic restart under /qn) or a UI switch comes back at a call site, or the wrapper uses one that shows modal boxes (/qb, /qr, /qf), which hang an RMM or scheduled-task run forever; why_new=windows.yml tests Invoke-Msiexec's body, not that the scripts call it; seam=none; no_claim=that the retry and the window choice work, which windows.yml's "Verify msiexec retries" step runs
@pytest.mark.parametrize("path", [SETUP, UPDATE, UNINSTALL])
def test_bootstraps_run_msiexec_only_through_invoke_msiexec(path):
    outside = _code_without(path, "Invoke-Msiexec")
    assert "Invoke-Msiexec -Arguments" in outside
    # No other way to start msiexec, and no UI switch outside the wrapper.
    assert "Start-Process" not in outside
    assert not re.search(r"(?im)^\s*&\s*[\"']?msiexec", outside)
    assert not re.search(r"(?i)[\"']/(q[nbrf][+!-]*|quiet|passive)[\"']", outside)
    helper = _function(path, "Invoke-Msiexec")
    assert '"/norestart"' in helper
    assert "1601" in helper and "1618" in helper
    # Never a UI level that shows modal boxes (/qb, /qr, /qf).
    assert not re.search(r"(?i)[\"']/q[brf]", helper)


# Value: protects=the plan contract between CreateServiceAccount.ps1 -PlanOnly and the bootstraps' preflight; fails_when=one side renames a key (a verdict reading $Plan.verified finds nothing, so every password reads unchecked and every upgrade given one is refused; one reading $Plan.account finds no SID, so every in-place password step is refused); why_new=windows.yml checks each side alone (the real plan line's keys, the verdict on hand-built plans), so a rename on one side passes both; seam=none; no_claim=that the values are right, which those two steps check
def test_preflight_reads_only_what_the_plan_line_prints():
    line = re.search(
        r'"FIVENINES_PLAN " \+ \(ConvertTo-Json -Compress @\{(.*?)\}\)',
        _read(CREATE_ACCOUNT),
        re.S,
    )
    assert line, "no FIVENINES_PLAN line in CreateServiceAccount.ps1"
    printed = set(re.findall(r"(\w+) = ", line.group(1)))
    assert printed == {"action", "message", "sid", "checked"}
    for path in (SETUP, UPDATE):
        read = set()
        for name in ("Get-PreflightVerdict", "Invoke-AccountPreflight"):
            body = _function(path, name)
            read |= {key.lower() for key in re.findall(r"\$plan\.(\w+)", body, re.I)}
        assert read == printed, f"{path} reads plan keys {sorted(read)}"


def _declared_parameters(path):
    match = re.search(r"(?ms)^param\($(.*?)^\)", _read(path))
    assert match, f"no param block in {path}"
    return {name.lower() for name in re.findall(r"\]\s*\$(\w+)", match.group(1))}


# Value: protects=the remedy operators are given: the DC refusals in the MSI log, the bootstraps' own refusals, the README and the scripts' usage lines name bootstrap parameters that exist; fails_when=-ServiceAccountPassword (or -Token, -KeepAccount, ...) is renamed in a bootstrap script while the 1603 message, the README or the DC harness still name the old spelling (PowerShell then refuses the command the operator was told to run); why_new=the Get-AccountPlan cases only check that a refusal mentions SERVICEACCOUNTPASSWORD, nothing reads the README, and the DC run's S5 would catch the harness call an hour in, for the setup script only; seam=none; no_claim=that the parameters do what the docs say
def test_documented_bootstrap_parameters_exist():
    scripts = {"setup": SETUP, "update": UPDATE, "uninstall": UNINSTALL}
    references = []
    # The refusals' remedy, as an operator reads it in the MSI log.
    remedy = (
        r"\(fivenines_(setup|update)\.ps1"
        r"(?: or fivenines_(setup|update)\.ps1)? -(\w+)\)"
    )
    for match in re.finditer(remedy, _read(CREATE_ACCOUNT)):
        for script in filter(None, match.group(1, 2)):
            references.append((CREATE_ACCOUNT, script, match.group(3)))
    # Every command line the docs, the usage lines and the DC harness give.
    invocation = (
        r'(?:\.\\|& "C:\\fn\\)(?:fivenines_)?'
        r'(setup|update|uninstall)\.ps1"?([^\n(#]*)'
    )
    for path in ("README.md", SETUP, UPDATE, UNINSTALL, "ci/windows-dc/stage2.ps1"):
        text = re.sub(r"`\n\s*", " ", _read(path))
        for match in re.finditer(invocation, text):
            for name in re.findall(r"(?<=\s)-(\w+)", match.group(2)):
                references.append((path, match.group(1), name))
    # The reinstall the bootstraps' own refusals and warnings advise.
    advised = r"fivenines_(setup|update|uninstall)\.ps1((?: -\w+(?: <\w+>)?)*)"
    for path in (SETUP, UPDATE):
        for literal in re.findall(r'"([^"\n]*fivenines_[^"\n]*)"', _code(path)):
            for match in re.finditer(advised, literal):
                for name in re.findall(r"-(\w+)", match.group(2)):
                    references.append((path, match.group(1), name))
    named = {name for _, _, name in references}
    assert {"Token", "ServiceAccountPassword", "LogFile", "KeepAccount"} <= named, named
    for path, script, name in references:
        assert name.lower() in _declared_parameters(
            scripts[script]
        ), f"{path} passes -{name}, which fivenines_{script}.ps1 does not declare"


# Source suffixes only: a local WiX build leaves fivenines-agent.msi (and
# .wixpdb) in windows/installer, which is not gitignored.
WINDOWS_SOURCE_SUFFIXES = {".ps1", ".wxs", ".xml", ".in", ".sh"}


def _windows_sources():
    paths = set(REPO_ROOT.glob("*.ps1"))
    paths |= set(REPO_ROOT.glob("windows/**/*"))
    paths |= set(REPO_ROOT.glob("ci/windows-dc/*"))
    return sorted(
        p for p in paths if p.is_file() and p.suffix in WINDOWS_SOURCE_SUFFIXES
    )


# Value: protects=the Windows scripts parsing alike whatever the install language: Windows PowerShell 5.1, the custom actions' and bootstraps' runtime, reads a .ps1 without a BOM in the machine's ANSI code page; fails_when=a non-ASCII character lands in a .ps1, the WiX source or the DC answer file (a German group name typed with its umlaut matches nothing once read as cp1252, and an en dash's UTF-8 bytes end in 0x93, a curly quote PowerShell takes for a string delimiter); why_new=the lint job's ASCII check (build-release.yml) covers .py/.toml/.yml/.yaml/.json/.sh only; seam=none; no_claim=that a file saved with a BOM would be read right
def test_windows_sources_are_ascii():
    sources = _windows_sources()
    names = {p.relative_to(REPO_ROOT).as_posix() for p in sources}
    assert {CREATE_ACCOUNT, PRODUCT_WXS, SETUP, UNINSTALL, DC_UNATTEND} <= names
    for path in sources:
        data = path.read_bytes()
        bad = next((i for i, b in enumerate(data) if b > 0x7F), None)
        assert bad is None, f"{path}: non-ASCII byte at offset {bad}"


# Value: protects=TOKEN and SERVICEACCOUNTPASSWORD staying out of the /l*v MSI log the bootstrap scripts always write; fails_when=a custom action whose SetProperty data carries [TOKEN] or [SERVICEACCOUNTPASSWORD] loses HideTarget or its hidden property (the log then prints the data in cleartext: PROPERTY CHANGE, CustomActionData, the property dump, observed on a DC run); why_new=only the Windows E2E reads the logs, after a build; seam=none; no_claim=that Windows Installer masks every line, which the E2E and DC runs check
def test_custom_actions_carrying_secrets_hide_their_data():
    wxs = _read(PRODUCT_WXS)
    hidden = set(re.findall(r'<Property Id="([^"]+)"[^>]*Hidden="yes"', wxs))
    carriers = set()
    for match in re.finditer(r'<SetProperty Id="([^"]+)"\s+Value="([^"]*)"', wxs):
        if "[TOKEN]" in match.group(2) or "[SERVICEACCOUNTPASSWORD]" in match.group(2):
            carriers.add(match.group(1))
    assert carriers >= {"CreateServiceAccount", "WriteTokenAcl"}
    for name in carriers:
        assert name in hidden, f"the {name} property is not hidden"
        action = re.search(r'<CustomAction Id="%s"[^>]*/>' % re.escape(name), wxs)
        assert action, f"no CustomAction {name}"
        assert 'HideTarget="yes"' in action.group(0), f"{name} logs its data"


# Value: protects=an unelevated run refused before it touches %SystemRoot%\Temp or HKLM; fails_when=#Requires -RunAsAdministrator is dropped from a bootstrap; why_new=no test checks #Requires, and New-PrivateWorkDirectory runs before Test-IsAdmin; seam=none; no_claim=a script fed to iex, where #Requires is not applied
@pytest.mark.parametrize("path", [SETUP, UPDATE, UNINSTALL])
def test_bootstraps_require_elevation(path):
    assert re.search(r"(?m)^#Requires -RunAsAdministrator$", _read(path))


# Value: protects=what an install, update or uninstall run reports: a 3010 is a warning, the script finishes its work and exits 3010, a failed msiexec exits with its own code; fails_when=3010 falls into the failure branch (the agent is left unstarted), the final exit 3010 goes (a deployment tool never schedules the restart), or a bare Write-Error under "Stop" turns every failure into exit 1; why_new=windows.yml's stand-in msiexec tests only Invoke-Msiexec, never a call site; seam=none; no_claim=that msiexec returns 3010 when a restart is needed, or how a given RMM reads 3010
@pytest.mark.parametrize("path", [SETUP, UPDATE, UNINSTALL])
def test_bootstraps_report_3010_as_a_warning_not_a_failure(path):
    outside = _code_without(path, "Invoke-Msiexec")
    site = re.search(
        r"\$exitCode = Invoke-Msiexec -Arguments [^\n]+\n"
        r"\s*if \(\$exitCode -eq 3010\) \{\n\s*\$restartPending = \$true\n"
        r"\s*Write-Warning [^\n]+\n"
        r"\s*\} elseif \(\$exitCode -ne 0\) \{\n"
        r"\s*Write-Error [^\n]+ -ErrorAction Continue\n"
        r"\s*exit \$exitCode\n",
        outside,
    )
    assert (
        site
    ), f"{path}: 3010 is not a warning, or a failure does not exit with its code"
    # Under "Stop" a bare Write-Error ends the script with 1; the 3010 is
    # the script's own exit code once its work is done.
    assert outside.rstrip().endswith("if ($restartPending) { exit 3010 }")


# Value: protects=a setup or update that finds the Windows Installer service still busy during the preflight's msiexec /a: it stops before anything changes, with msiexec's code; fails_when=the busy check goes (the run falls through to msiexec /i without the account preflight, after a second retry budget), the preflight's catch swallows the busy error as a warning, or the caller exits 1 instead of the code; why_new=windows.yml tests Invoke-Msiexec alone, never the preflight around it; seam=none; no_claim=that msiexec returns 1601/1618 while another installation runs
@pytest.mark.parametrize("path", [SETUP, UPDATE])
def test_preflight_stops_on_a_busy_windows_installer(path):
    preflight = _strip_comments(_function(path, "Invoke-AccountPreflight"))
    busy = preflight.index("if ($extract -eq 1601 -or $extract -eq 1618) {")
    assert preflight.index('$busy.Data["MsiexecExitCode"] = $extract') > busy
    assert preflight.index("throw $busy") > busy
    assert busy < preflight.index("if ($extract -ne 0) {")
    rethrow = 'if ($_.Exception.Data.Contains("MsiexecExitCode")) { throw }'
    assert rethrow in preflight
    code = _code_without(path, "Invoke-AccountPreflight")
    assert re.search(
        r"\$applied = Invoke-AccountPreflight [^\n]+\n\} catch \{\n"
        r"\s*Write-Error \$_ -ErrorAction Continue\n"
        r'\s*if \(\$_\.Exception\.Data\.Contains\("MsiexecExitCode"\)\) '
        r'\{ exit \$_\.Exception\.Data\["MsiexecExitCode"\] \}\n'
        r"\s*exit 1\n",
        code,
    )


# Value: protects=the agent starting after the network on every boot of an MSI install; fails_when=the MSI stops making the service Automatic (Delayed Start) with its deferred sc.exe custom action, runs it without checking its result, after StartAgentService or only on a repair, goes back to WiX's ServiceConfig (MsiConfigureServices: WIX1149, documented as not working), or the WinSW definition stops asking for the delay (WinSW applies its <delayedAutoStart> only to a service it installs itself, so every MSI install up to 1.23.0 started with the plain automatic services, and one ran its first DNS lookup before DHCP had given the machine a DNS server); why_new=only the Windows E2E reads the service's start type, after a build; seam=none; no_claim=that sc.exe applies it, which the E2E checks on install and on an upgrade from v1.22.1
def test_msi_registers_the_service_with_a_delayed_start():
    wxs = _xml_without_comments(PRODUCT_WXS)
    assert not re.search(
        r"<ServiceConfig(FailureActions)?\s", wxs
    ), "WiX's ServiceConfig elements go through MsiConfigureServices (WIX1149)"
    assert re.search(r'<ServiceInstall Id="FivninesAgentService"[^>]*Start="auto"', wxs)
    assert (
        _set_property(wxs, "ConfigureServiceStart")
        == "&quot;sc.exe&quot; config fivenines-agent start= delayed-auto"
    )
    _assert_checked_deferred_before_start(wxs, "ConfigureServiceStart")
    assert "<delayedAutoStart>true</delayedAutoStart>" in _xml_without_comments(
        WINSW_XML
    )


# Value: protects=a crashed agent restarted on every MSI install, on the schedule the WinSW definition and the README describe; fails_when=the MSI loses its deferred sc.exe failure custom action, runs it unchecked, after StartAgentService or only on a repair, or its delays or reset period drift from fivenines-agent.xml's (WinSW applies <onfailure> only to a service it installs itself, so no MSI install up to 1.23.0 had failure actions and a crashed agent stayed stopped until the next boot); why_new=only the Windows E2E reads the service's failure actions, after a build; seam=none; no_claim=that sc.exe applies them or that the SCM restarts the agent, which the E2E checks (registry, and a killed agent restarted)
def test_msi_restarts_the_service_on_failure_as_winsw_describes():
    wxs = _xml_without_comments(PRODUCT_WXS)
    command = re.fullmatch(
        r"&quot;sc\.exe&quot; failure fivenines-agent reset= (\d+) actions= (\S+)",
        _set_property(wxs, "ConfigureServiceRecovery"),
    )
    assert command, "ConfigureServiceRecovery is not an sc.exe failure command"
    _assert_checked_deferred_before_start(wxs, "ConfigureServiceRecovery")
    fields = command.group(2).split("/")
    assert len(fields) % 2 == 0
    assert set(fields[0::2]) == {"restart"}, "every failure action restarts"
    msi_delays = [int(delay) for delay in fields[1::2]]

    winsw = _xml_without_comments(WINSW_XML)
    seconds = {"sec": 1, "min": 60, "hour": 3600}
    winsw_delays = [
        int(value) * seconds[unit] * 1000
        for value, unit in re.findall(
            r'<onfailure action="restart" delay="(\d+) (sec|min|hour)"/>', winsw
        )
    ]
    assert len(winsw_delays) == winsw.count("<onfailure ")
    winsw_reset = re.search(r"<resetfailure>(\d+) (sec|min|hour)</resetfailure>", winsw)
    assert winsw_reset, "fivenines-agent.xml has no resetfailure"
    assert msi_delays == winsw_delays == [10000, 30000, 60000]
    assert (
        int(command.group(1))
        == int(winsw_reset.group(1)) * seconds[winsw_reset.group(2)]
    )


# Value: protects=the agent's first start after an MSI upgrade; fails_when=the MSI drops MSIRESTARTMANAGERCONTROL or sets it to anything but Disable (DisableShutdown still ends a Restart Manager session after StartAgentService: a reader opening base_library.zip as Python does was refused in 2 upgrades of 9, against 6 of 9 with the default and none with Disable), or the upgrade E2E stops reading the property's effect from the upgrade's log; why_new=only the Windows E2E upgrades, and the new agent lost the race on about one upgrade in four, so one E2E run proves nothing; seam=none; no_claim=that Windows Installer honours the property, which the E2E reads in the upgrade's log
def test_msi_runs_without_the_restart_manager():
    wxs = _xml_without_comments(PRODUCT_WXS)
    assert re.findall(r"<Property Id=\"MSIRESTARTMANAGERCONTROL\"[^>]*>", wxs) == [
        '<Property Id="MSIRESTARTMANAGERCONTROL" Value="Disable" />'
    ]
    assert re.search(
        r"if \(-not \(Get-Content upgrade\.log \| Select-String -SimpleMatch -Quiet "
        r'"RESTART MANAGER: Disabled by MSIRESTARTMANAGERCONTROL property"\)\) \{\n'
        r"\s*throw ",
        _upgrade_e2e_step(),
    )


# Value: protects=the release gate's upgrade check; fails_when=its tolerance for #293's residual widens: more than one stop, a death other than PyInstaller's bootstrap refused base_library.zip (another file, a second traceback, agent code), or no longer requiring the restarted service to keep one process for 20s; why_new=the tolerance lives in a workflow step only a Windows runner executes, and a wider one would hide an upgraded agent that crashes; seam=none; no_claim=that the patterns match a real trace, checked against the three traces CI runs captured
def test_upgrade_e2e_tolerates_only_the_old_packages_restart_manager_race():
    step = _upgrade_e2e_step()
    assert "$bootstrapDeath = $false\n" in step
    assert "if ($stops.Count -eq 1 -and (Test-Path -LiteralPath $errLog))" in step
    # All three marks, each exactly once: joined by -and, never -or.
    marks = re.search(
        r"\$bootstrapDeath = \((.*)\) -and\n\s*\((.*)\) -and\n\s*\((.*)\)\n", step
    )
    assert marks, "the tolerance is not a conjunction of three counts"
    assert [mark.split(", ", 1)[1] for mark in marks.groups()] == [
        r""""Traceback \(most recent call last\)").Count -eq 1""",
        r""""(?m)^PermissionError: \[Errno 13\] Permission denied: '[^'\r\n]*\\\\_internal\\\\base_library\.zip'\r?$").Count -eq 1""",
        r""""\[PYI-\d+:ERROR\] Failed to execute script 'pyi[^']*' due to unhandled exception").Count -eq 1""",
    ]
    # The restarted service must still keep one process for 20s.
    assert re.search(
        r"\$first = \(Get-CimInstance [^\n]*\n\s*Start-Sleep -Seconds 20\n\s*\$stops = ",
        step,
    )
    assert (
        "if ($svc.ProcessId -ne $first -or ($stops.Count -ne 0 -and -not $bootstrapDeath))"
        in step
    )


# Value: protects=the agent running again after a repair (Programs and Features > Repair, msiexec /f); fails_when=StartAgentService goes back to NOT Installed (ServiceControl stops the service on a repair and, the Restart Manager disabled, nothing starts it until the next boot), runs on an uninstall, or the E2E stops repairing and checking the account, start type and a running agent; why_new=no run repaired the MSI before; seam=none; no_claim=that a repair keeps the account and start type, which only the Windows E2E step measures
def test_msi_starts_the_agent_again_after_a_repair():
    wxs = _xml_without_comments(PRODUCT_WXS)
    # Only StartAgentService runs on a repair or a maintenance run: the
    # account step would rotate the password, WriteTokenAcl would get an empty
    # TOKEN under Return="check", and the start configuration is already set.
    conditions = dict(
        re.findall(
            r'<Custom Action="([^"]+)" After="[^"]+" Condition="([^"]*)" />', wxs
        )
    )
    assert conditions == {
        "CreateServiceAccount": "NOT Installed",
        "WriteTokenAcl": "NOT Installed",
        "DelegateWmi": "NOT Installed",
        "ConfigureServiceStart": "NOT Installed",
        "ConfigureServiceRecovery": "NOT Installed",
        "StartAgentService": "NOT REMOVE~=&quot;ALL&quot;",
    }
    # On a maintenance run that stopped nothing, sc start fails (1056) on the
    # running agent: only Return="ignore" keeps that run successful.
    start = re.search(r'<CustomAction Id="StartAgentService"([^>]*)/>', wxs)
    assert start and 'Return="ignore"' in start.group(1)
    step = _workflow_step(
        "Repair restarts the agent with its account and start configuration"
    )
    assert '"/i fivenines-agent.msi /qn /l*v maintenance.log"' in step
    assert '"/fa fivenines-agent.msi /qn /l*v repair.log"' in step
    for check in (
        '-ne $running) { throw "the maintenance run restarted the agent" }',
        'if ("$(Get-ServiceState)" -ne "$before") { throw "the maintenance run changed',
        'if ($first -eq $running) { throw "the repair did not stop the agent',
        '-ne "Running") { throw "the repair left the agent stopped" }',
        "if ($after.Account -ne $before.Account) {",
        "if ($after.Start -ne $before.Start -or $after.Delayed -ne $before.Delayed) {",
        "if ($after.Failure -ne $before.Failure) {",
        "-ne $first -or $stops.Count -ne 0) {",
    ):
        assert check in step, check


# Value: protects=the upgrade every install takes from this release on; fails_when=the next-version MSI stops being built one patch version above, or the E2E step that upgrades to it starts tolerating a Restart Manager session or a stop; why_new=the v1.22.1 upgrade step tolerates the old package's residual, so nothing else checks the steady state with no tolerance; seam=none; no_claim=that Windows Installer opens no session there, which the E2E reads in steady.log
def test_upgrade_from_this_release_is_checked_with_no_tolerance():
    workflow = _strip_comments(_read(WINDOWS_WORKFLOW))
    assert (
        '-d ("Version={0}.{1}.{2}" -f $v.Major, $v.Minor, ($v.Build + 1))' in workflow
    )
    assert "-o fivenines-agent-next.msi" in workflow
    assert "windows/installer/fivenines-agent-next.msi" in workflow
    step = _workflow_step("Upgrade from this release opens no Restart Manager session")
    assert "Install-Msi fivenines-agent-next.msi steady.log" in step
    assert "if ($disabled -lt 2 -or $sessions -ne 0) { throw " in step
    assert re.search(
        r"\$first = \(Get-CimInstance [^\n]*\n\s*Start-Sleep -Seconds 20\n\s*\$stops = ",
        step,
    )
    assert "-ne $first -or $stops.Count -ne 0) {" in step
    assert "bootstrapDeath" not in step


def _workflow_step(name):
    """windows.yml's step `name`, up to the next step, without its comments."""
    workflow = _read(WINDOWS_WORKFLOW)
    start = workflow.index("- name: " + name + "\n")
    end = workflow.index("\n      - name: ", start)
    return _strip_comments(workflow[start:end])


def _upgrade_e2e_step():
    """windows.yml's upgrade-from-v1.22.1 step, without its comments."""
    return _workflow_step(
        "Upgrade from v1.22.1 sets the delayed start and the restart on failure"
    )


def _xml_without_comments(path):
    # A commented-out element is not one.
    return re.sub(r"<!--.*?-->", "", _read(path), flags=re.S)


def _set_property(wxs, action):
    found = re.findall(r'<SetProperty Id="%s"\s+Value="([^"]*)"' % action, wxs)
    assert len(found) == 1, f"expected one SetProperty for {action}"
    return found[0]


def _assert_checked_deferred_before_start(wxs, action):
    """A deferred, elevated, checked WixQuietExec custom action, run on a fresh
    install or major upgrade (NOT Installed) before StartAgentService."""
    custom = re.search(r'<CustomAction Id="%s"([^>]*)/>' % action, wxs)
    assert custom, f"no CustomAction {action}"
    for attribute in (
        'DllEntry="WixQuietExec"',
        'Execute="deferred"',
        'Impersonate="no"',
        'Return="check"',
    ):
        assert attribute in custom.group(1), f"{action} lacks {attribute}"
    scheduled = {
        name: (previous, condition)
        for name, previous, condition in re.findall(
            r'<Custom Action="([^"]+)" After="([^"]+)" Condition="([^"]*)" />', wxs
        )
    }
    assert action in scheduled, f"{action} is not scheduled"
    assert scheduled[action][1] == "NOT Installed", f"{action} is not on NOT Installed"
    after = {name: previous for name, (previous, _) in scheduled.items()}
    step, chain = "StartAgentService", []
    while step in after and step not in chain:
        chain.append(step)
        step = after[step]
    assert action in chain[1:], f"{action} does not run before StartAgentService"
    assert step == "InstallServices", "the chain does not start after InstallServices"
