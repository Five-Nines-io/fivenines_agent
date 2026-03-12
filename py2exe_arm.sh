#!/usr/bin/env bash

set -e  # Exit immediately on error

echo "Detected architecture: $TARGET_ARCH"

BINARY_NAME="fivenines-agent-linux-arm"

# Activate the pre-installed virtual environment (deps already in Docker image)
echo "=== Activating pre-installed venv ==="
. /opt/venv/bin/activate

# Verify Python environment
echo "=== Python Environment Check ==="
echo "Python executable path: $(which python)"
echo "Python version: $(python --version)"

#
# Find Python shared library for PyInstaller
#
echo "=== Locating Python shared library ==="
PYTHON_LIB=$(find /usr/local/lib -name "libpython3*.so*" -type f 2>/dev/null | head -1)
if [ -z "$PYTHON_LIB" ]; then
    # Fallback: use sysconfig to locate
    PYTHON_LIB=$(python -c "import sysconfig; import os; lib_dir = sysconfig.get_config_var('LIBDIR'); name = sysconfig.get_config_var('LDLIBRARY'); print(os.path.join(lib_dir, name))" 2>/dev/null)
fi

echo "Python shared library: $PYTHON_LIB"

#
# Build the executable
#
echo "=== Building Executable ==="
echo "Building the executable for 32-bit ARM (Debian/glibc)"
mkdir -p build dist/linux

# Build with PyInstaller - no libvirt, no libcrypt/libtirpc bundling needed
PYINSTALLER_ARGS="--strip \
    --optimize=2 \
    --exclude-module tkinter \
    --exclude-module unittest \
    --exclude-module pdb \
    --exclude-module doctest \
    --exclude-module test \
    --exclude-module distutils \
    --exclude-module libvirt \
    --exclude-module libvirtmod \
    --exclude-module proxmoxer \
    --exclude-module systemd_watchdog \
    --noconfirm \
    --onedir \
    --name $BINARY_NAME \
    --workpath ./build/tmp \
    --distpath ./build \
    --clean \
    --hidden-import=pynvml"

LIBZ=$(find /usr/lib /lib -name "libz.so.1" -type f 2>/dev/null | head -1)
echo "libz.so.1 location: $LIBZ"

EXTRA_BINARIES=""
if [ -n "$PYTHON_LIB" ] && [ -f "$PYTHON_LIB" ]; then
    echo "Adding Python shared library: $PYTHON_LIB"
    EXTRA_BINARIES="--add-binary $PYTHON_LIB:."
fi
if [ -n "$LIBZ" ] && [ -f "$LIBZ" ]; then
    EXTRA_BINARIES="$EXTRA_BINARIES --add-binary $LIBZ:."
fi

pyinstaller $PYINSTALLER_ARGS $EXTRA_BINARIES ./py2exe_entrypoint.py

# Verify built binary
echo "=== Binary Verification ==="
echo "Directory contents:"
ls -lh ./build/$BINARY_NAME/
echo "Executable size: $(ls -lh ./build/$BINARY_NAME/$BINARY_NAME | awk '{print $5}')"
echo "Total directory size: $(du -sh ./build/$BINARY_NAME | awk '{print $1}')"
echo "Binary dependencies:"
ldd ./build/$BINARY_NAME/$BINARY_NAME | head -10 || echo "ldd check failed"

# Quick test
echo "=== Testing Built Binary ==="
./build/$BINARY_NAME/$BINARY_NAME --version || echo "Version check failed, but binary was built"

# Move to final location
mv ./build/$BINARY_NAME ./dist/linux/

#
# Clean up
#
echo "=== Cleanup ==="
rm -rf ./build/tmp ./build/*.spec

echo "[OK] ARM 32-bit build completed successfully!"
echo "Output directory: ./dist/linux/$BINARY_NAME/"
echo "Executable: ./dist/linux/$BINARY_NAME/$BINARY_NAME"
echo ""
echo "The distribution is built with glibc 2.31 for Raspberry Pi OS Bullseye+ compatibility."
