#!/usr/bin/env bash

# Build Linux agent binary (glibc, manylinux). Set SYNOLOGY=1 for Synology DSM variant
# (excludes libvirt, systemd-watchdog, proxmoxer). Run inside manylinux Docker.
#
# Usage: TARGET_ARCH=amd64 ./py2exe.sh
#        TARGET_ARCH=arm64 ./py2exe.sh
#        SYNOLOGY=1 TARGET_ARCH=amd64 ./py2exe.sh

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
[ -n "${SYNOLOGY:-}" ] && echo "Build variant: Synology DSM"

if [[ "$TARGET_ARCH" == "arm64" ]]; then
    export CC=aarch64-redhat-linux-gcc
    export CXX=aarch64-redhat-linux-g++
    ARCH_SUFFIX="arm64"
elif [[ "$TARGET_ARCH" == "arm" ]]; then
    export CC=arm-linux-gnueabi-gcc
    export CXX=arm-linux-gnueabi-g++
    ARCH_SUFFIX="arm"
else
    export CC=gcc
    export CXX=g++
    ARCH_SUFFIX="amd64"
fi

if [ -n "${SYNOLOGY:-}" ]; then
    BINARY_NAME="fivenines-agent"
    DIR_NAME="fivenines-agent-synology-${ARCH_SUFFIX}"
else
    BINARY_NAME="fivenines-agent-linux-${ARCH_SUFFIX}"
fi

# Verify we're using the correct Python from manylinux
echo "=== Python Environment Check ==="
echo "Python executable path: $(which python)"
echo "Python version: $(python --version)"
echo "Pip version: $(python -m pip --version)"

if [ -z "${SYNOLOGY:-}" ]; then
    # Verify libvirt library (should be our custom built libvirt 6.10.0)
    echo "=== Libvirt Environment Check ==="
    echo "Checking for libvirt libraries:"
    ls -la /usr/lib64/libvirt.so* 2>/dev/null || echo "Custom libvirt not found"
    ls -la /usr/lib64/libvirt.so* 2>/dev/null || echo "System libvirt not found"
    echo "PKG_CONFIG_PATH: $PKG_CONFIG_PATH"
    echo "libvirt version: $(pkg-config --modversion libvirt 2>/dev/null || echo 'not found')"
fi

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
    ls -al /workspace/venv  # List directory contents for debugging
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

# Install build dependencies explicitly
echo "=== Installing Build Dependencies ==="
python -m pip install --upgrade pip setuptools wheel

#
# Install Poetry and dependencies
#
echo "=== Installing Poetry and Dependencies ==="
python -m pip install poetry==2.2.1 || {
    echo "Failed to install Poetry. Exiting."
    exit 1
}
poetry config virtualenvs.create false
poetry cache clear --all . || true
poetry config installer.max-workers 1

if [ -n "${SYNOLOGY:-}" ]; then
    # Synology: remove libvirt/systemd-watchdog/proxmoxer so Poetry does not build them
    echo "=== Removing Synology-incompatible dependencies from pyproject ==="
    poetry remove libvirt-python systemd-watchdog proxmoxer || true
    poetry install --no-interaction || {
        echo "Poetry installation failed. Exiting."
        exit 1
    }
    echo "=== Removing Synology-incompatible dependencies ==="
    pip uninstall -y libvirt-python systemd-watchdog proxmoxer || true
    echo "Removed libvirt-python, systemd-watchdog, and proxmoxer"
    if python -c "import libvirt" 2>/dev/null; then
        echo "WARNING: libvirt is still importable after uninstall"
    else
        echo "Confirmed: libvirt not available (expected)"
    fi
else
    # Full build: install libvirt-python then Poetry
    echo "=== Installing libvirt-python ==="
    pkg-config --exists libvirt || {
        echo "libvirt development headers not found."
        echo "PKG_CONFIG_PATH: $PKG_CONFIG_PATH"
        exit 1
    }
    if ! python -m pip install libvirt-python==11.6.0; then
        export CFLAGS="$(pkg-config --cflags libvirt)"
        export LDFLAGS="$(pkg-config --libs libvirt)"
        python -m pip install -v libvirt-python==11.6.0 || {
            echo "libvirt-python installation failed completely. Exiting."
            exit 1
        }
    fi
    python -c "import libvirt; print('libvirt-python imported successfully')"
    poetry install --no-interaction || {
        echo "Poetry installation failed. Exiting."
        exit 1
    }
    echo "=== Final Verification ==="
    python -c "import libvirt; print('Final libvirt version check:', libvirt.getVersion())"
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

    # Download Python 3.9.23 source
    if ! wget -q --timeout=30 "https://www.python.org/ftp/python/3.9.23/Python-3.9.23.tgz"; then
        echo "Failed to download Python source"
        exit 1
    fi

    tar xzf Python-3.9.23.tgz
    cd Python-3.9.23

    # Configure for shared library build - minimal configuration
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

    # Build only the shared library target
    echo "Building shared library (this may take a few minutes)..."
    make libpython3.9.so -j$(nproc) || {
        echo "Failed to build shared library"
        exit 1
    }

    # Verify the shared library was created and check its dependencies
    if [ -f "libpython3.9.so" ]; then
        echo "Successfully built libpython3.9.so"
        echo "Checking shared library dependencies:"
        ldd libpython3.9.so || echo "ldd check failed"

        # Check if it depends on libcrypt.so.2
        if ldd libpython3.9.so | grep -q "libcrypt.so.2"; then
            echo "WARNING: libpython3.9.so depends on libcrypt.so.2"
            echo "Available libcrypt libraries:"
            find /lib64 /usr/lib64 -name "libcrypt*" 2>/dev/null || echo "No libcrypt found"

            # Try to create a compatibility link if libcrypt.so.1 exists
            if [ -f "/lib64/libcrypt.so.1" ]; then
                echo "Creating libcrypt.so.2 compatibility link"
                ln -sf /lib64/libcrypt.so.1 /lib64/libcrypt.so.2
            fi
        fi

        # Copy to the expected location
        cp libpython3.9.so "$LIBPYTHON_PATH"

        # Create versioned symlink
        ln -sf libpython3.9.so "$PYTHON_LIB_DIR/libpython3.9.so.1.0"

        echo "Installed shared library:"
        ls -la "$PYTHON_LIB_DIR"/libpython3.9.so*
        file "$LIBPYTHON_PATH"

    else
        echo "Shared library build failed - file not found"
        exit 1
    fi

    # Clean up
    cd /workspace
    rm -rf /tmp/Python-3.9.23*

    # Update library cache
    echo "$PYTHON_LIB_DIR" > /etc/ld.so.conf.d/python-shared.conf
    ldconfig

    echo "libpython3.9.so ready for PyInstaller"

else
    echo "libpython3.9.so already exists"
fi

#
# Build the executable
#
echo "=== Building Executable ==="
echo "Building the executable for $TARGET_ARCH${SYNOLOGY:+ (Synology variant)}"
mkdir -p build dist/linux

if [ -z "${SYNOLOGY:-}" ]; then
    echo "Checking libvirt module path:"
    python -c "import libvirt; print('libvirt module path:', libvirt.__file__); print('libvirt version:', libvirt.getVersion())"
fi

PYTHON_LIB=$(find /opt/python/cp39-cp39/lib -name "libpython3.9.so*" -type f | head -1)
if [ -z "$PYTHON_LIB" ]; then
    echo "Python shared library not found after build attempt"
    exit 1
fi
echo "Found Python library: $PYTHON_LIB"

# Common PyInstaller args for both main and Synology builds
PYI_BASE=(
    --strip --optimize=2
    --exclude-module tkinter --exclude-module unittest --exclude-module pdb
    --exclude-module doctest --exclude-module test --exclude-module distutils
    --noconfirm --onedir --name "$BINARY_NAME"
    --workpath ./build/tmp --distpath ./build --clean
    --add-binary "$PYTHON_LIB:."
    --add-binary "/usr/local/lib/libcrypt.so.2:." --add-binary "/usr/local/lib/libcrypt.so.1:."
    --add-binary "/usr/lib64/libz.so.1:."
)
if [ -n "${SYNOLOGY:-}" ]; then
    PYI_EXTRA=(--exclude-module libvirt --exclude-module libvirtmod --exclude-module systemd_watchdog --exclude-module proxmoxer)
else
    PYI_EXTRA=(--hidden-import=libvirt --hidden-import=libvirtmod --hidden-import=proxmoxer.backends --hidden-import=proxmoxer.backends.https --add-binary "/usr/lib64/libtirpc.so.3:.")
fi

LD_LIBRARY_PATH="/opt/python/cp39-cp39/lib:$LD_LIBRARY_PATH" poetry run pyinstaller \
    "${PYI_BASE[@]}" "${PYI_EXTRA[@]}" ./py2exe_entrypoint.py || {
    echo "PyInstaller failed. Exiting."
    exit 1
}

# Check built binary (onedir creates a directory with the executable inside)
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
if [ -n "${SYNOLOGY:-}" ]; then
    mv ./build/$BINARY_NAME ./dist/linux/$DIR_NAME
else
    mv ./build/$BINARY_NAME ./dist/linux/
fi

#
# Clean up
#
echo "=== Cleanup ==="
rm -rf ./build/tmp ./build/*.spec

# Reset Poetry's configuration
echo "Resetting environment"
poetry config virtualenvs.create true
deactivate

echo "[OK] Build completed successfully!"
if [ -n "${SYNOLOGY:-}" ]; then
    echo "Output directory: ./dist/linux/$DIR_NAME/"
    echo "Executable: ./dist/linux/$DIR_NAME/$BINARY_NAME"
    echo ""
    echo "Next step: run synology/build_spk.sh to assemble the SPK package."
else
    echo "Output directory: ./dist/linux/$BINARY_NAME/"
    echo "Executable: ./dist/linux/$BINARY_NAME/$BINARY_NAME"
    echo ""
    echo "The distribution should be compatible with CentOS 7 and include libvirt 6.10.0 with cgroup V2 and RSS support."
fi
