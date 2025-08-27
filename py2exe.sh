#!/usr/bin/env bash

set -e  # Exit immediately on error

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


# Verify libvirt library
ls -la /usr/lib64/libvirt.so*

#
# Install and enable virtualenv
#
echo "Installing and enabling virtualenv"
python3 -m pip install virtualenv || {
    echo "Failed to install virtualenv. Exiting."
    exit 1
}

# Debug Python paths
echo "Python executable path: $(which python3)"
echo "Python version: $(python3 --version)"
echo "Pip version: $(python3 -m pip --version)"

# Create the virtual environment
echo "Creating virtual environment"
if ! python3 -m venv /workspace/venv --clear; then
    echo "Failed to create virtual environment. Reinstalling dependencies and retrying..."
    python3 -m ensurepip --default-pip || {
        echo "Failed to ensure pip. Exiting."
        exit 1
    }
    python3 -m pip install --upgrade pip setuptools wheel
    python3 -m venv /workspace/venv --clear || {
        echo "Retry failed. Exiting."
        exit 1
    }
fi

# Debug Python paths
echo "Python executable path: $(which python3)"
echo "Python version: $(python3 --version)"
echo "Pip version: $(python3 -m pip --version)"



# Verify virtual environment creation
if [ ! -f "/workspace/venv/bin/python3" ]; then
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

#python3 -m pip install setuptools_rust

#
# Install Poetry and dependencies
#
echo "Installing Poetry and dependencies"
python3 -m pip install poetry==2.1.3 || {
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

echo "Verifying libvirt-python version:"
python3 -c "import libvirt; print('libvirt version:', libvirt.getVersion())"
echo "Checking system libvirt library:"


# Export dependencies to requirements.txt
echo "Exporting dependencies to requirements.txt"
poetry export --without-hashes -o requirements.txt || {
    echo "Failed to export dependencies. Exiting."
    exit 1
}

#
# Build the executable
#
echo "Building the executable for $TARGET_ARCH"
mkdir -p build dist/linux

# Verify which libvirt module PyInstaller will find
 echo "Checking libvirt module path:"
 python3 -c "import libvirt; print('libvirt module path:', libvirt.__file__); print('libvirt version:', libvirt.getVersion())"

# # Set runtime library path environment for the binary to find bundled libraries
# export LDFLAGS="-Wl,-rpath,./lib -Wl,-rpath,\$ORIGIN/lib"

 poetry run pyinstaller \
     --noconfirm \
     --onefile \
     --name $BINARY_NAME \
     --workpath ./build/tmp \
     --distpath ./build \
     --dist dist/linux \
     --clean \
     ./py2exe_entrypoint.py || {
     echo "PyInstaller failed. Exiting."
     exit 1
}

#
# Clean up
#
echo "Cleaning up build files"
rm -rf ./build/tmp ./build/*.spec

# Reset Poetry's configuration
echo "Resetting environment"
poetry config virtualenvs.create true
deactivate
