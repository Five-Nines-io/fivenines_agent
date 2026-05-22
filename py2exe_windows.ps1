# Build the Windows agent binary.
#
# Usage:   .\py2exe_windows.ps1
# Env:     TARGET_ARCH = amd64 (default) or arm64
#
# Output:  .\dist\windows\fivenines-agent-windows-<arch>\
#
# Uses the runner's Python directly (no extra venv layer - GitHub's
# windows-latest python from actions/setup-python is already isolated).
# The virtualization Poetry group (libvirt, systemd-watchdog, proxmoxer,
# pynvml) is excluded - libvirt does not build on Windows and the rest are
# Linux-only. The windows group (pywin32, wmi) is included so the
# disk-health and software-inventory collectors have what they need at
# runtime. The dev group (pyinstaller) is included by default since
# Poetry includes non-optional groups unless --without is passed.

$ErrorActionPreference = "Stop"

$TARGET_ARCH = if ($env:TARGET_ARCH) { $env:TARGET_ARCH } else { "amd64" }
$BINARY_NAME = "fivenines-agent-windows-$TARGET_ARCH"

Write-Host "=== Python Environment Check ==="
python --version
python -m pip --version

Write-Host "=== Installing build prerequisites ==="
python -m pip install --upgrade pip setuptools wheel

# Poetry is installed by the CI workflow's separate "Install Poetry" step
# (.github/workflows/windows.yml + build-release.yml). Re-installing it here
# breaks on Windows when the existing poetry.exe is locked by the running
# Python process (pip's uninstall step fails with WinError 32 "process
# cannot access the file"). Anyone running this script outside CI must
# pre-install poetry (any 2.x is fine).
poetry --version
if ($LASTEXITCODE -ne 0) {
    Write-Error "poetry is not on PATH. Install it before running this script (e.g. 'pip install poetry==2.2.1')."
    exit 1
}

Write-Host "=== Installing project dependencies (windows + dev, virtualization excluded) ==="
# Scoped to this command so we don't mutate the runner's global poetry config.
$env:POETRY_VIRTUALENVS_CREATE = "false"
poetry install --no-interaction --without virtualization --with windows
if ($LASTEXITCODE -ne 0) { Write-Error "poetry install failed"; exit 1 }

# Defensive: confirm the excluded groups are not importable.
$forbidden = @("libvirt", "systemd_watchdog", "proxmoxer")
foreach ($mod in $forbidden) {
    $check = python -c "import $mod" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Warning "Unexpected: $mod is importable. It should not be on Windows."
    } else {
        Write-Host "Confirmed: $mod not importable (expected)."
    }
}

Write-Host "=== Verifying PyInstaller is importable ==="
python -c "import PyInstaller; print('PyInstaller', PyInstaller.__version__)"
if ($LASTEXITCODE -ne 0) { Write-Error "PyInstaller not importable"; exit 1 }

Write-Host "=== Building Executable ==="
$buildDir = ".\build"
$distDir  = ".\dist\windows"
New-Item -ItemType Directory -Force -Path $buildDir, $distDir | Out-Null

$pyInstallerArgs = @(
    # NB: --strip is intentionally omitted on Windows. PyInstaller's --strip
    # invokes GNU strip on every bundled binary; that corrupts the embedded
    # Python DLL on Windows and the resulting exe fails with
    # "LoadLibrary: Invalid access to memory location" at first run.
    "--optimize=2",
    "--exclude-module", "tkinter",
    "--exclude-module", "unittest",
    "--exclude-module", "pdb",
    "--exclude-module", "doctest",
    "--exclude-module", "test",
    "--exclude-module", "distutils",
    "--exclude-module", "libvirt",
    "--exclude-module", "libvirtmod",
    "--exclude-module", "systemd_watchdog",
    "--exclude-module", "proxmoxer",
    "--hidden-import", "win32timezone",
    "--hidden-import", "wmi",
    "--noconfirm",
    "--onedir",
    "--name", $BINARY_NAME,
    "--workpath", "$buildDir\tmp",
    "--distpath", $buildDir,
    "--clean",
    ".\py2exe_entrypoint.py"
)

python -m PyInstaller @pyInstallerArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "PyInstaller failed with exit code $LASTEXITCODE"
    exit 1
}

# Quick sanity check on the built binary.
Write-Host "=== Binary Verification ==="
$exePath = Join-Path $buildDir "$BINARY_NAME\$BINARY_NAME.exe"
if (-not (Test-Path $exePath)) {
    Write-Error "Binary not found: $exePath"
    exit 1
}
$size = (Get-Item $exePath).Length
Write-Host "Executable size: $size bytes"

# --version must succeed: catches missing hidden imports (win32timezone is
# the classic pywin32-PyInstaller gotcha) before they bite at install time.
& $exePath --version
if ($LASTEXITCODE -ne 0) {
    Write-Error "Smoke check failed: $exePath --version returned $LASTEXITCODE"
    exit 1
}

# Move to the final dist directory.
$finalDir = Join-Path $distDir $BINARY_NAME
if (Test-Path $finalDir) { Remove-Item -Recurse -Force $finalDir }
Move-Item -Path (Join-Path $buildDir $BINARY_NAME) -Destination $finalDir

# Cleanup.
Remove-Item -Recurse -Force "$buildDir\tmp" -ErrorAction SilentlyContinue
Get-ChildItem "$buildDir\*.spec" | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[OK] Build completed successfully!"
Write-Host "Output directory: $finalDir"
Write-Host "Executable: $finalDir\$BINARY_NAME.exe"
