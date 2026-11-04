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
        r"(?ms)^function %s \{.*?^\}" % re.escape(name), _read(path).replace("\r\n", "\n")
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
        ("ConvertTo-MsiPasswordArgument", SETUP, UPDATE),
        ("Test-HResult", CREATE_ACCOUNT, UNINSTALL),
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
        assert cmdlet not in code, f"{path} calls {cmdlet}, which sees nothing on a domain controller"


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


# Value: protects=a reinstall after the account was deleted; fails_when=the WMI namespace ACL is read through GetSecurityDescriptor again (it fails with "unexpected error" once an ACE names a deleted account, failing the install with 1603, found on a DC) or AceFlags is combined with -band (Windows PowerShell 5.1 raises "Specified cast is not valid"); why_new=both only fail on Windows, after the build; seam=none; no_claim=that GetSD/SetSD are called correctly
@pytest.mark.parametrize("path", [DELEGATE_WMI, UNINSTALL])
def test_wmi_namespace_acl_is_read_in_binary(path):
    code = _code(path)
    assert "GetSecurityDescriptor" not in code
    assert "SetSecurityDescriptor" not in code
    assert not re.search(r"AceFlags\s*-band|-band\s*\$?inherited", code, re.IGNORECASE)


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
    job = workflow[workflow.index("  smoke-msi-domain-controller:") :]
    assert "if: github.event_name == 'workflow_dispatch' && inputs.domain_controller" in job
    assert len(re.findall(r"iso_sha256: [0-9a-f]{64}\n", job)) == 2
    assert re.search(r"OLD_MSI_SHA256: [0-9a-f]{64}\n", job)
    assert "sha256sum -c -" in job
