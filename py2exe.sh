#!/usr/bin/env bash

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
    export CC=aarch64-linux-gnu-gcc
    export CXX=aarch64-linux-gnu-g++
    BINARY_NAME="fivenines-agent-linux-arm64"
elif [[ "$TARGET_ARCH" == "arm" ]]; then
    export CC=arm-linux-gnueabi-gcc
    export CXX=arm-linux-gnueabi-g++
    BINARY_NAME="fivenines-agent-linux-arm"
else
    export CC=gcc
    export CXX=g++
    BINARY_NAME="fivenines-agent-linux-amd64"
fi

# Verify we're using the correct Python from manylinux
echo "=== Python Environment Check ==="
echo "Python executable path: $(which python)"
echo "Python version: $(python --version)"
echo "Pip version: $(python -m pip --version)"

# Verify libvirt library (should be our custom built one)
echo "=== Libvirt Environment Check ==="
echo "Checking for libvirt libraries:"
ls -la /usr/local/lib64/libvirt.so* 2>/dev/null || echo "Custom libvirt not found"
ls -la /usr/lib64/libvirt.so* 2>/dev/null || echo "System libvirt not found"
echo "PKG_CONFIG_PATH: $PKG_CONFIG_PATH"
echo "libvirt version: $(pkg-config --modversion libvirt 2>/dev/null || echo 'not found')"

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

# Try to install libvirt-python separately with better error handling
echo "=== Installing libvirt-python ==="
echo "Attempting to install libvirt-python..."

# First, verify we can compile against libvirt
echo "Testing libvirt compilation environment..."
pkg-config --exists libvirt || {
    echo "libvirt development headers not found."
    echo "PKG_CONFIG_PATH: $PKG_CONFIG_PATH"
    echo "Available .pc files:"
    find /usr/local /usr -name "*.pc" 2>/dev/null | grep -i libvirt || echo "No libvirt.pc files found"
    exit 1
}

echo "libvirt compile flags: $(pkg-config --cflags libvirt)"
echo "libvirt link flags: $(pkg-config --libs libvirt)"

# Install libvirt-python with explicit flags
if ! python -m pip install libvirt-python==11.6.0; then
    echo "Direct pip install failed. Trying with explicit flags..."
    
    # Try with explicit flags
    export CFLAGS="$(pkg-config --cflags libvirt)"
    export LDFLAGS="$(pkg-config --libs libvirt)"
    
    python -m pip install -v libvirt-python==11.6.0 || {
        echo "libvirt-python installation failed completely. Exiting."
        exit 1
    }
fi

# Test libvirt-python installation
echo "=== Testing libvirt-python Installation ==="
python -c "import libvirt; print('libvirt-python imported successfully')"
python -c "import libvirt; print('libvirt version:', libvirt.getVersion())"

#
# Install Poetry and dependencies
#
echo "=== Installing Poetry and Dependencies ==="
python -m pip install poetry==2.1.3 || {
    echo "Failed to install Poetry. Exiting."
    exit 1
}

# Configure Poetry to use the current virtual environment
echo "Configuring Poetry to avoid creating separate environments"
poetry config virtualenvs.create false
# Clear any existing Poetry cache to avoid conflicts
poetry cache clear --all . || true
poetry config installer.max-workers 1

poetry install --no-interaction || {
    echo "Poetry installation failed. Exiting."
    exit 1
}

# Final verification
echo "=== Final Verification ==="
python -c "import libvirt; print('Final libvirt version check:', libvirt.getVersion())"

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
        --disable-ipv6 \
        --without-ensurepip \
        --without-static-libpython || {
        echo "Python configure failed"
        exit 1
    }
    
    # Build only the shared library target
    echo "Building shared library (this may take a few minutes)..."
    make libpython3.9.so -j$(nproc) || {
        echo "Failed to build shared library"
        exit 1
    }
    
    # Verify the shared library was created
    if [ -f "libpython3.9.so" ]; then
        echo "Successfully built libpython3.9.so"
        
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
echo "Building the executable for $TARGET_ARCH"
mkdir -p build dist/linux

# Verify which libvirt module PyInstaller will find
echo "Checking libvirt module path:"
python -c "import libvirt; print('libvirt module path:', libvirt.__file__); print('libvirt version:', libvirt.getVersion())"

# Build with PyInstaller
export LD_LIBRARY_PATH="/opt/python/cp39-cp39/lib:$LD_LIBRARY_PATH"

# Try to find the actual Python shared library
PYTHON_LIB=$(find /opt/python/cp39-cp39/lib -name "libpython3.9.so*" -type f | head -1)
if [ -n "$PYTHON_LIB" ]; then
    echo "Found Python library: $PYTHON_LIB"
    poetry run pyinstaller \
        --noconfirm \
        --onefile \
        --name $BINARY_NAME \
        --workpath ./build/tmp \
        --distpath ./build \
        --clean \
        --hidden-import=libvirt \
        --hidden-import=libvirtmod \
        --add-binary "$PYTHON_LIB:." \
	--add-binary "/usr/local/lib/libcrypt.so.2:." \
	--add-binary "/usr/local/lib/libcrypt.so.1:." \
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
echo "Binary size: $(ls -lh ./build/$BINARY_NAME | awk '{print $5}')"
echo "Binary dependencies:"
ldd ./build/$BINARY_NAME | head -10 || echo "ldd check failed (might be expected)"

# Quick test of the binary
echo "=== Testing Built Binary ==="
./build/$BINARY_NAME --version || echo "Version check failed, but binary was built"

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

echo "✅ Build completed successfully!"
echo "Binary location: ./dist/linux/$BINARY_NAME"
echo ""
echo "The binary should be compatible with CentOS 7 and include RSS support."
