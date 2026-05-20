# Build the Windows agent binary.
#
# Usage:   .\py2exe_windows.ps1
# Env:     TARGET_ARCH = amd64 (default) or arm64
#
# Output:  .\dist\windows\fivenines-agent-windows-<arch>\
#
# The Windows build is far simpler than py2exe.sh (the Linux manylinux
# build). PyInstaller runs natively on Windows: no libpython rebuild, no
# libcrypt or libtirpc bundling. The virtualization Poetry group (libvirt,
# systemd-watchdog, proxmoxer, pynvml) is explicitly excluded - libvirt does
# not build on Windows, and the other three are Linux-only. The windows
# group (pywin32, wmi) is included so the disk-health and software-inventory
# collectors have what they need at runtime.

$ErrorActionPreference = "Stop"

$TARGET_ARCH = $env:TARGET_ARCH
if (-not $TARGET_ARCH) { $TARGET_ARCH = "amd64" }

$BINARY_NAME = "fivenines-agent-windows-$TARGET_ARCH"

Write-Host "=== Python Environment Check ==="
python --version
python -m pip --version

# Create a fresh venv for the build (kept separate from the dev venv).
Write-Host "Creating build virtual environment"
python -m venv .venv-build --clear

$pythonExe = ".\.venv-build\Scripts\python.exe"
$poetryExe = ".\.venv-build\Scripts\poetry.exe"
$pyinstallerExe = ".\.venv-build\Scripts\pyinstaller.exe"

& $pythonExe -m pip install --upgrade pip setuptools wheel
& $pythonExe -m pip install "poetry==2.2.1"

Write-Host "=== Installing Windows dependency group (virtualization excluded) ==="
& $poetryExe config virtualenvs.create false
& $poetryExe cache clear --all . 2>$null
& $poetryExe config installer.max-workers 1
& $poetryExe install --no-interaction --without virtualization --with windows

# Defensive: confirm the excluded groups are not importable.
$forbidden = @("libvirt", "systemd_watchdog", "proxmoxer")
foreach ($mod in $forbidden) {
    $check = & $pythonExe -c "import $mod" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Warning "Unexpected: $mod is importable. It should not be on Windows."
    } else {
        Write-Host "Confirmed: $mod not importable (expected)."
    }
}

Write-Host "=== Building Executable ==="
$buildDir = ".\build"
$distDir  = ".\dist\windows"
New-Item -ItemType Directory -Force -Path $buildDir, $distDir | Out-Null

$pyInstallerArgs = @(
    "--strip",
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

& $pyinstallerExe @pyInstallerArgs
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
