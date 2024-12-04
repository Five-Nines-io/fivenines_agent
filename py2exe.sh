#!bash

# IMPORTANT: PyInstaller need to be installed in the virtual environment (venv), so it can find the dependencies within the venv.

if [ "$RUNNER_OS" == 'Windows' ]; then
        PATH_SEPARATOR=";"
else
        PATH_SEPARATOR=":"
fi

#
# Install virtualenv
#

#sudo apt install python3-virtualenv
virtualenv venv
source venv/bin/activate

#
# Install dependencies with poetry inside the virtual environment
#

# It's important to disable virtualenvs.create, so pyinstaller can find the dependencies within the same virtual environment.
poetry config virtualenvs.create false
#poetry lock;
poetry install --no-interaction
# poetry add -G dev poetry-plugin-export
# poetry add -G dev pyinstaller

# Just for backward compatibility with the old build process
poetry export --without-hashes -o requirements.txt

#
# Build the executable
#

mkdir -p build
poetry run pyinstaller \
        --noconfirm \
        --onefile \
        --name fivenines-agent-linux-amd64 \
        --workpath ./build/tmp \
        --distpath ./build \
        --dist dist/linux \
        --clean \
        ./py2exe_entrypoint.py

# poetry config virtualenvs.create true

# clean up
rm -rf ./build/tmp ./build/*.spec;

