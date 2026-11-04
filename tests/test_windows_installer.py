"""Static checks on the Windows installer's PowerShell and WiX sources.

The scripts only run on Windows: .github/workflows/windows.yml exercises them
on a member server, and its on-request smoke-msi-domain-controller job on real
Windows Server 2019 domain controllers (ci/windows-dc/). Each check here pins
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

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

CREATE_ACCOUNT = "windows/installer/CreateServiceAccount.ps1"
TOKEN_ACL = "windows/installer/SetTokenFileAcl.ps1"
DELEGATE_WMI = "windows/installer/DelegateWmiStorageNamespace.ps1"
PRODUCT_WXS = "windows/installer/Product.wxs"
SETUP = "fivenines_setup.ps1"
UPDATE = "fivenines_update.ps1"
UNINSTALL = "fivenines_uninstall.ps1"
WINDOWS_WORKFLOW = ".github/workflows/windows.yml"
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


def _code(path):
    """The script without its comments: full-line ones and ' # ' trailers."""
    lines = []
    for line in _read(path).splitlines():
        if line.lstrip().startswith("#"):
            continue
        lines.append(re.sub(r"\s#\s.*$", "", line))
    return "\n".join(lines)


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
        ("New-PrivateWorkDirectory", SETUP, UNINSTALL),
        ("Remove-EarlierWorkDirectories", SETUP, UPDATE),
        ("Remove-EarlierWorkDirectories", SETUP, UNINSTALL),
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


# Value: protects=what the DC job downloads; fails_when=an evaluation ISO or the v1.22.0 MSI loses its pinned SHA-256, or the hour-long job starts running on every push; why_new=nothing else reads these pins; seam=none; no_claim=that Microsoft still serves the same ISO
def test_dc_job_pins_its_downloads_and_runs_on_request_only():
    workflow = _read(WINDOWS_WORKFLOW)
    start = workflow.index("  smoke-msi-domain-controller:")
    job = workflow[start:]
    assert (
        "if: github.event_name == 'workflow_dispatch' && inputs.domain_controller"
        in job
    )
    assert len(re.findall(r"iso_sha256: [0-9a-f]{64}\n", job)) == 2
    assert re.search(r"OLD_MSI_SHA256: [0-9a-f]{64}\n", job)
    assert "sha256sum -c -" in job


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


# Value: protects=-ServiceAccountPassword on fivenines_setup.ps1 and fivenines_update.ps1: refused before the MSI is downloaded, and once accepted handed to msiexec; fails_when=the converted argument stops reaching the array msiexec gets (PowerShell reads a renamed or misspelled variable as $null, so the install silently runs without the password and fails with 1603 on a DC whose account is shared) or the check moves after the download; why_new=no Windows run executes fivenines_update.ps1 (the DC run's S5 runs only fivenines_setup.ps1) and windows.yml checks ConvertTo-MsiPasswordArgument's body, not how the scripts use it; seam=none; no_claim=that msiexec and the custom action parse the argument, which S5 proves for the setup script
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
    msiexec = re.search(r"Start-Process msiexec\.exe -ArgumentList \$(\w+)", code)
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


# Value: protects=the downloaded MSI, its extracted copy and the install log; fails_when=a default path, the extraction or the log goes back to a bare $env:TEMP (C:\\Windows\\Temp under an RMM tool running as SYSTEM, where a file any local user created stays theirs to rewrite before msiexec runs it); why_new=the E2E and the DC runs pass explicit -MsiPath/-LogFile, so the defaults run nowhere in CI; seam=none; no_claim=that the directory's ACL is private, which windows.yml's "Verify the bootstrap's private work directory" steps check on Windows, under PowerShell 5.1 and 7
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
    assert "$env:TEMP" not in code
    # After a run that succeeds (the script's last statement) only earlier
    # runs' directories go: this one holds the recorded install source a
    # repair reads, and a failed run keeps it for its log. The extraction
    # goes in the preflight's finally either way.
    prune = "Remove-EarlierWorkDirectories -Keep $WorkDir"
    assert code.count(prune) == 1
    after = code.split(prune, 1)[1].strip().splitlines()
    assert all(line.startswith("Write-Host ") for line in after if line.strip()), after
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


# Value: protects=the uninstall log; fails_when=fivenines_uninstall.ps1's -LogFile default goes back to a bare $env:TEMP name (C:\\Windows\\Temp under an RMM tool running as SYSTEM) or a successful uninstall stops removing its work directory; why_new=the Windows runs pass an explicit -LogFile; seam=none; no_claim=that the ACL is private, which windows.yml's work directory steps check
def test_uninstall_logs_into_a_private_directory():
    code = _code(UNINSTALL)
    assert re.search(r'(?m)^    \[string\]\$LogFile = ""$', code)
    assert re.search(r"(?m)^\$WorkDir = New-PrivateWorkDirectory ", code)
    assert re.search(
        r"(?m)^if \(-not \$LogFile\) \{ \$LogFile = Join-Path \$WorkDir ", code
    )
    removal = "Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue"
    prune = "Remove-EarlierWorkDirectories -Keep $WorkDir"
    # after -KeepAccount's exit 0, and at the end, each after the msiexec /x
    # failure exit
    assert code.count(removal) == 2 and code.count(prune) == 2
    assert code.index(prune) > code.index("exit $proc.ExitCode")
    after = code.rsplit(removal, 1)[1].strip().splitlines()
    assert all(line.startswith("Write-Host ") for line in after if line.strip()), after


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
