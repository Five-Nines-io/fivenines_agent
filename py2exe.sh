#!/usr/bin/env bash

# IMPORTANT: PyInstaller need to be installed in the virtual environment (venv), so it can find the dependencies within the venv.

if [ "$RUNNER_OS" == 'Windows' ]; then
        PATH_SEPARATOR=";"
else
        PATH_SEPARATOR=":"
fi

#
# Install and enable virtualenv
#

echo "Installing and enabling virtualenv"

#sudo apt install python3-virtualenv
python3 -m pip install --user virtualenv
# virtualenv venv
python3 -m venv venv

# search for the `activate` script in the venv directory due to the `posix_local` and `posix_prefix` prefixes changes
ACTIVATE_SCRIPT=$(find venv -name activate)
source $ACTIVATE_SCRIPT

#
# Install dependencies with poetry inside the virtual environment
#

echo "Installing poetry and dependencies"
python3 -m pip install poetry==1.8.4

# It's important to disable virtualenvs.create, so pyinstaller can find the dependencies within the same virtual environment.
poetry config virtualenvs.create false
#poetry lock;
poetry install --no-interaction
# poetry add -G dev poetry-plugin-export
# poetry add -G dev pyinstaller

#
# Export dependencies to requirements.txt for backward compatibility with the old build process
#

echo "Exporting dependencies to requirements.txt for backward compatibility with the old build process"
poetry export --without-hashes -o requirements.txt

#
# Build the executable
#

echo "Building the executable"

mkdir -p build
poetry run pyinstaller \
        --noconfirm \
        --onefile \
        --name fivenines-agent-linux-amd64 \
        --workpath ./build/tmp \
        --distpath ./build \
        --dist dist/linux \
        --clean \
	--add-binary "/usr/lib/x86_64-linux-gnu/libssl.so.3:." \
	--add-binary "/usr/lib/x86_64-linux-gnu/libcrypto.so.3:." \
	./py2exe_entrypoint.py

#
# Clean up
#

echo "Cleaning up"
rm -rf ./build/tmp ./build/*.spec;

echo "Resetting environment"
poetry config virtualenvs.create true
deactivate
