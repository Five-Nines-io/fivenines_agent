#!/usr/bin/env sh

set -e  # Exit immediately on error

echo "Detected architecture: $TARGET_ARCH"

if [ "$TARGET_ARCH" = "arm64" ]; then
    BINARY_NAME="fivenines-agent-alpine-arm64"
else
    BINARY_NAME="fivenines-agent-alpine-amd64"
fi

# Verify Python environment
echo "=== Python Environment Check ==="
echo "Python executable path: $(which python)"
echo "Python version: $(python --version)"
echo "Pip version: $(python -m pip --version)"

# Verify libvirt
echo "=== Libvirt Environment Check ==="
echo "libvirt version: $(pkg-config --modversion libvirt 2>/dev/null || echo 'not found')"

#
# Create virtual environment and install dependencies
#
echo "=== Setting up virtual environment ==="
python -m venv /workspace/venv --clear
. /workspace/venv/bin/activate

# Install build dependencies
python -m pip install --upgrade pip setuptools wheel

# Install libvirt-python matching system version
echo "=== Installing libvirt-python ==="
LIBVIRT_VERSION=$(pkg-config --modversion libvirt)
python -m pip install libvirt-python==$LIBVIRT_VERSION

# Test libvirt-python
python -c "import libvirt; print('libvirt-python imported successfully, version:', libvirt.getVersion())"

#
# Install Poetry and project dependencies
#
echo "=== Installing Poetry and Dependencies ==="
python -m pip install poetry==2.2.1

# Configure Poetry for current venv
poetry config virtualenvs.create false
poetry cache clear --all . || true
poetry config installer.max-workers 1

poetry install --no-interaction

# Remove systemd-watchdog (not needed on Alpine, may fail to import)
pip uninstall -y systemd-watchdog 2>/dev/null || true

# Final verification
echo "=== Final Verification ==="
python -c "import libvirt; print('libvirt version:', libvirt.getVersion())"

# Export dependencies
echo "Exporting dependencies to requirements.txt"
poetry export --without-hashes -o requirements.txt

#
# Find Python shared library for PyInstaller
#
echo "=== Locating Python shared library ==="
PYTHON_LIB=$(find /usr/local/lib -name "libpython3*.so*" -type f 2>/dev/null | head -1)
if [ -z "$PYTHON_LIB" ]; then
    # Alpine Python may have it elsewhere
    PYTHON_LIB=$(python -c "import sysconfig; import os; lib_dir = sysconfig.get_config_var('LIBDIR'); name = sysconfig.get_config_var('LDLIBRARY'); print(os.path.join(lib_dir, name))" 2>/dev/null)
fi

echo "Python shared library: $PYTHON_LIB"

#
# Build the executable
#
echo "=== Building Executable ==="
echo "Building the executable for $TARGET_ARCH (Alpine/musl)"
mkdir -p build dist/linux

# Verify libvirt module
python -c "import libvirt; print('libvirt module path:', libvirt.__file__); print('libvirt version:', libvirt.getVersion())"

# Build with PyInstaller - no need for libcrypt/libtirpc on musl
PYINSTALLER_ARGS="--strip \
    --optimize=2 \
    --exclude-module tkinter \
    --exclude-module unittest \
    --exclude-module pdb \
    --exclude-module doctest \
    --exclude-module test \
    --exclude-module distutils \
    --exclude-module systemd_watchdog \
    --noconfirm \
    --onedir \
    --name $BINARY_NAME \
    --workpath ./build/tmp \
    --distpath ./build \
    --clean \
    --hidden-import=libvirt \
    --hidden-import=libvirtmod \
    --hidden-import=proxmoxer.backends \
    --hidden-import=proxmoxer.backends.https"

if [ -n "$PYTHON_LIB" ] && [ -f "$PYTHON_LIB" ]; then
    echo "Adding Python shared library: $PYTHON_LIB"
    pyinstaller $PYINSTALLER_ARGS \
        --add-binary "$PYTHON_LIB:." \
        ./py2exe_entrypoint.py
else
    echo "No Python shared library found, building without it"
    pyinstaller $PYINSTALLER_ARGS \
        ./py2exe_entrypoint.py
fi

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

# Reset Poetry
echo "Resetting environment"
poetry config virtualenvs.create true
deactivate

echo "[OK] Alpine build completed successfully!"
echo "Output directory: ./dist/linux/$BINARY_NAME/"
echo "Executable: ./dist/linux/$BINARY_NAME/$BINARY_NAME"
echo ""
echo "The distribution is built with musl libc for Alpine Linux compatibility."
