#!/usr/bin/env bash

# Build script for Synology DSM compatible binary.
# Based on py2exe.sh but excludes libvirt-python and systemd-watchdog.
# Run inside the same manylinux2014 Docker container used by py2exe.sh.
#
# Usage: TARGET_ARCH=amd64 ./py2exe_synology.sh
#        TARGET_ARCH=arm64 ./py2exe_synology.sh

set -e  # Exit immediately on error

# Source the profile to get the correct Python in PATH (manylinux setup)
source /etc/profile

# Detect OS for path separator
if [ "$RUNNER_OS" == 'Windows' ]; then
    PATH_SEPARATOR=";"
else
    PATH_SEPARATOR=":"
fi

echo "Detected architecture: $TARGET_ARCH"

if [[ "$TARGET_ARCH" == "arm64" ]]; then
    export CC=aarch64-redhat-linux-gcc
    export CXX=aarch64-redhat-linux-g++
    BINARY_NAME="fivenines-agent-synology-arm64"
elif [[ "$TARGET_ARCH" == "arm" ]]; then
    export CC=arm-linux-gnueabi-gcc
    export CXX=arm-linux-gnueabi-g++
    BINARY_NAME="fivenines-agent-synology-arm"
else
    export CC=gcc
    export CXX=g++
    BINARY_NAME="fivenines-agent-synology-amd64"
fi

# Verify we're using the correct Python from manylinux
echo "=== Python Environment Check ==="
echo "Python executable path: $(which python)"
echo "Python version: $(python --version)"
echo "Pip version: $(python -m pip --version)"

#
# Install and enable virtualenv
#
echo "Installing and enabling virtualenv"
python -m pip install virtualenv || {
    echo "Failed to install virtualenv. Exiting."
    exit 1
}

# Create the virtual environment
echo "Creating virtual environment"
if ! python -m venv /workspace/venv --clear; then
    echo "Failed to create virtual environment. Reinstalling dependencies and retrying..."
    python -m ensurepip --default-pip || {
        echo "Failed to ensure pip. Exiting."
        exit 1
    }
    python -m pip install --upgrade pip setuptools wheel
    python -m venv /workspace/venv --clear || {
        echo "Retry failed. Exiting."
        exit 1
    }
fi

# Verify virtual environment creation
if [ ! -f "/workspace/venv/bin/python" ]; then
    echo "Virtual environment creation failed. Exiting."
    ls -al /workspace/venv
    exit 1
fi

# Activate the virtual environment
echo "Activating virtual environment"
source /workspace/venv/bin/activate || {
    echo "Failed to activate virtual environment. Exiting."
    exit 1
}

# Verify activation
if [ -z "$VIRTUAL_ENV" ]; then
    echo "Virtual environment activation failed. Exiting."
    exit 1
fi

# Install build dependencies
echo "=== Installing Build Dependencies ==="
python -m pip install --upgrade pip setuptools wheel

# Install Poetry
echo "=== Installing Poetry and Dependencies ==="
python -m pip install poetry==2.2.1 || {
    echo "Failed to install Poetry. Exiting."
    exit 1
}

# Configure Poetry to use the current virtual environment
poetry config virtualenvs.create false
poetry cache clear --all . || true
poetry config installer.max-workers 1

poetry install --no-interaction || {
    echo "Poetry installation failed. Exiting."
    exit 1
}

# Remove libraries not needed for Synology (no libvirt, no systemd watchdog, no proxmoxer)
echo "=== Removing Synology-incompatible dependencies ==="
pip uninstall -y libvirt-python systemd-watchdog proxmoxer || true
echo "Removed libvirt-python, systemd-watchdog, and proxmoxer"

# Verify libvirt is gone (should fail)
if python -c "import libvirt" 2>/dev/null; then
    echo "WARNING: libvirt is still importable after uninstall"
else
    echo "Confirmed: libvirt not available (expected)"
fi

# Export dependencies to requirements.txt
echo "Exporting dependencies to requirements.txt"
poetry export --without-hashes -o requirements.txt || {
    echo "Failed to export dependencies. Exiting."
    exit 1
}

#
# Build libpython3.9.so from source for PyInstaller
#
echo "=== Building libpython3.9.so from source ==="

PYTHON_LIB_DIR="/opt/python/cp39-cp39/lib"
LIBPYTHON_PATH="$PYTHON_LIB_DIR/libpython3.9.so"

if [ ! -f "$LIBPYTHON_PATH" ]; then
    echo "Building Python 3.9.23 shared library from source..."

    cd /tmp

    if ! wget -q --timeout=30 "https://www.python.org/ftp/python/3.9.23/Python-3.9.23.tgz"; then
        echo "Failed to download Python source"
        exit 1
    fi

    tar xzf Python-3.9.23.tgz
    cd Python-3.9.23

    echo "Configuring Python build for shared library..."
    ./configure \
        --enable-shared \
        --disable-test-modules \
        --prefix=/tmp/python-shared \
        --quiet \
        --without-ensurepip \
        --without-static-libpython \
        --with-system-ffi \
        --enable-loadable-sqlite-extensions \
        ac_cv_working_openssl_hashlib_md5=yes \
        ac_cv_working_openssl_ssl=yes || {
        echo "Python configure failed"
        exit 1
    }

    echo "Building shared library (this may take a few minutes)..."
    make libpython3.9.so -j$(nproc) || {
        echo "Failed to build shared library"
        exit 1
    }

    if [ -f "libpython3.9.so" ]; then
        echo "Successfully built libpython3.9.so"
        ldd libpython3.9.so || echo "ldd check failed"

        if ldd libpython3.9.so | grep -q "libcrypt.so.2"; then
            echo "WARNING: libpython3.9.so depends on libcrypt.so.2"
            if [ -f "/lib64/libcrypt.so.1" ]; then
                echo "Creating libcrypt.so.2 compatibility link"
                ln -sf /lib64/libcrypt.so.1 /lib64/libcrypt.so.2
            fi
        fi

        cp libpython3.9.so "$LIBPYTHON_PATH"
        ln -sf libpython3.9.so "$PYTHON_LIB_DIR/libpython3.9.so.1.0"

        echo "Installed shared library:"
        ls -la "$PYTHON_LIB_DIR"/libpython3.9.so*
        file "$LIBPYTHON_PATH"
    else
        echo "Shared library build failed - file not found"
        exit 1
    fi

    cd /workspace
    rm -rf /tmp/Python-3.9.23*

    echo "$PYTHON_LIB_DIR" > /etc/ld.so.conf.d/python-shared.conf
    ldconfig

    echo "libpython3.9.so ready for PyInstaller"
else
    echo "libpython3.9.so already exists"
fi

#
# Build the executable
#
echo "=== Building Synology Executable ==="
echo "Building the executable for $TARGET_ARCH (Synology variant)"
mkdir -p build dist/linux

PYTHON_LIB=$(find /opt/python/cp39-cp39/lib -name "libpython3.9.so*" -type f | head -1)
if [ -n "$PYTHON_LIB" ]; then
    echo "Found Python library: $PYTHON_LIB"
    LD_LIBRARY_PATH="/opt/python/cp39-cp39/lib:$LD_LIBRARY_PATH" poetry run pyinstaller \
        --strip \
        --optimize=2 \
        --exclude-module tkinter \
        --exclude-module unittest \
        --exclude-module pdb \
        --exclude-module doctest \
        --exclude-module test \
        --exclude-module distutils \
        --exclude-module libvirt \
        --exclude-module libvirtmod \
        --exclude-module systemd_watchdog \
        --exclude-module proxmoxer \
        --noconfirm \
        --onedir \
        --name "$BINARY_NAME" \
        --workpath ./build/tmp \
        --distpath ./build \
        --clean \
        --add-binary "$PYTHON_LIB:." \
        --add-binary "/usr/local/lib/libcrypt.so.2:." \
        --add-binary "/usr/local/lib/libcrypt.so.1:." \
        --add-binary "/usr/lib64/libz.so.1:." \
        ./py2exe_entrypoint.py || {
        echo "PyInstaller failed. Exiting."
        exit 1
    }
else
    echo "Python shared library not found after build attempt"
    exit 1
fi

# Check built binary
echo "=== Binary Verification ==="
echo "Directory contents:"
ls -lh ./build/$BINARY_NAME/
echo "Executable size: $(ls -lh ./build/$BINARY_NAME/$BINARY_NAME | awk '{print $5}')"
echo "Total directory size: $(du -sh ./build/$BINARY_NAME | awk '{print $1}')"
echo "Binary dependencies:"
ldd ./build/$BINARY_NAME/$BINARY_NAME | head -10 || echo "ldd check failed (might be expected)"

# Quick test of the binary
echo "=== Testing Built Binary ==="
./build/$BINARY_NAME/$BINARY_NAME --version || echo "Version check failed, but binary was built"

# Move to final location
mv ./build/$BINARY_NAME ./dist/linux/

#
# Clean up
#
echo "=== Cleanup ==="
rm -rf ./build/tmp ./build/*.spec

# Reset Poetry's configuration
echo "Resetting environment"
poetry config virtualenvs.create true
deactivate

echo "[OK] Synology build completed successfully!"
echo "Output directory: ./dist/linux/$BINARY_NAME/"
echo "Executable: ./dist/linux/$BINARY_NAME/$BINARY_NAME"
echo ""
echo "Next step: run synology/build_spk.sh to assemble the SPK package."
