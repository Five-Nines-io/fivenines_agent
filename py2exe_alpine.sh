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

# Install the build tools (pip, setuptools, wheel, poetry and its dependencies)
# from the hash-pinned file: nothing is installed unverified.
echo "=== Installing build tools (hash-pinned) ==="
python -m pip install --require-hashes --no-deps --only-binary :all: -r ci/requirements/build-tools.txt

# Install the libvirt-python matching Alpine's libvirt, also hash-pinned. The
# pin names one version, so fail loudly if the base image's libvirt has moved.
echo "=== Installing libvirt-python ==="
LIBVIRT_VERSION=$(pkg-config --modversion libvirt)
if ! grep -q "^libvirt-python==${LIBVIRT_VERSION} " ci/requirements/libvirt-python-alpine.txt; then
    echo "Alpine's libvirt is ${LIBVIRT_VERSION}, but ci/requirements/libvirt-python-alpine.txt pins another libvirt-python."
    echo "Update ci/requirements/libvirt-python-alpine.in and run ci/requirements/compile.sh."
    exit 1
fi
# Built from sdist without isolation, so it uses the pinned setuptools above.
python -m pip install --require-hashes --no-deps --no-build-isolation -r ci/requirements/libvirt-python-alpine.txt

# Test libvirt-python
python -c "import libvirt; print('libvirt-python imported successfully, version:', libvirt.getVersion())"

#
# Configure Poetry (installed above) and install project dependencies
#
echo "=== Installing project dependencies ==="

# Configure Poetry for current venv
poetry config virtualenvs.create false
poetry cache clear --all . || true
poetry config installer.max-workers 1

# Wheels only (hash-checked against poetry.lock): an sdist poetry would have to
# build fetches its build backend unpinned, so that fails instead.
POETRY_INSTALLER_ONLY_BINARY=":all:" poetry install --no-interaction

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
    --hidden-import=proxmoxer.backends.https \
    --hidden-import=scramp \
    --hidden-import=dateutil.parser \
    --hidden-import=paho.mqtt.client \
    --copy-metadata pg8000 \
    --copy-metadata scramp"

if [ -n "$PYTHON_LIB" ] && [ -f "$PYTHON_LIB" ]; then
    echo "Adding Python shared library: $PYTHON_LIB"
    pyinstaller $PYINSTALLER_ARGS \
        --add-binary "$PYTHON_LIB:." \
        --add-binary "/usr/lib/libz.so.1:." \
        ./py2exe_entrypoint.py
else
    echo "No Python shared library found, building without it"
    pyinstaller $PYINSTALLER_ARGS \
        --add-binary "/usr/lib/libz.so.1:." \
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

# Quick test. --version imports the full collector graph (incl. pg8000, which
# reads its package metadata at import), so a failure here means a missing
# hidden import or un-copied metadata -- fail the build rather than ship it.
echo "=== Testing Built Binary ==="
if ! ./build/$BINARY_NAME/$BINARY_NAME --version; then
    echo "Smoke check FAILED: built binary cannot run --version. Aborting."
    exit 1
fi

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
