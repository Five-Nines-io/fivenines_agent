#!/usr/bin/env bash
# Assemble a Synology SPK package from a built binary.
#
# Usage: ./synology/build_spk.sh <version> <arch>
#   version: agent version string, e.g. 1.5.4
#   arch:    x86_64 or aarch64
#
# Prerequisites: run py2exe_synology.sh first to produce the binary.

set -e

VERSION=${1:?"Usage: $0 <version> <arch>"}
ARCH=${2:?"Usage: $0 <version> <arch>"}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

if [ "$ARCH" = "x86_64" ]; then
    BINARY_ARCH="amd64"
elif [ "$ARCH" = "aarch64" ]; then
    BINARY_ARCH="arm64"
else
    echo "Unsupported arch: $ARCH (use x86_64 or aarch64)"
    exit 1
fi

BINARY_DIR="${REPO_ROOT}/dist/linux/fivenines-agent-synology-${BINARY_ARCH}"
BINARY="${BINARY_DIR}/fivenines-agent"
SPK_NAME="fivenines-agent-${VERSION}-${ARCH}.spk"
BUILD_DIR="/tmp/spkbuild-$$"

if [ ! -f "${BINARY}" ]; then
    echo "Binary not found: ${BINARY}"
    echo "Run py2exe_synology.sh first."
    exit 1
fi

echo "=== Building SPK: ${SPK_NAME} ==="
echo "Version: ${VERSION}  Arch: ${ARCH}  Binary: ${BINARY}"

# Create build workspace
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/package/bin"
mkdir -p "${BUILD_DIR}/scripts"
mkdir -p "${BUILD_DIR}/conf"
mkdir -p "${BUILD_DIR}/WIZARD_UIFILES"

# Copy binary payload
cp "${BINARY}" "${BUILD_DIR}/package/bin/fivenines-agent"
chmod +x "${BUILD_DIR}/package/bin/fivenines-agent"

# Copy all files from the binary dist dir (shared libs, etc.)
rsync -a --exclude "fivenines-agent" \
    "${BINARY_DIR}/" "${BUILD_DIR}/package/bin/"

# Create package.tgz
echo "Creating package.tgz..."
tar czf "${BUILD_DIR}/package.tgz" -C "${BUILD_DIR}/package" .

# INFO arch: Synology uses armv8 for 64-bit ARM (see Appendix A: Platform and Arch Value Mapping)
INFO_ARCH="${ARCH}"
[ "$ARCH" = "aarch64" ] && INFO_ARCH="armv8"

# Fill in INFO template
sed \
    -e "s/{{VERSION}}/${VERSION}/g" \
    -e "s/{{ARCH}}/${INFO_ARCH}/g" \
    "${SCRIPT_DIR}/INFO.template" > "${BUILD_DIR}/INFO"

# Generate required Package Center icons if missing (64x64 and 256x256)
if [ ! -f "${SCRIPT_DIR}/PACKAGE_ICON.PNG" ] || [ ! -f "${SCRIPT_DIR}/PACKAGE_ICON_256.PNG" ]; then
    echo "Generating required PACKAGE_ICON.PNG and PACKAGE_ICON_256.PNG..."
    python3 "${SCRIPT_DIR}/gen_icons.py"
fi
cp "${SCRIPT_DIR}/PACKAGE_ICON.PNG" "${SCRIPT_DIR}/PACKAGE_ICON_256.PNG" "${BUILD_DIR}/"

# Copy all required lifecycle scripts (Synology developer guide: scripts.html)
for script in start-stop-status postinst preinst preuninst postuninst preupgrade postupgrade; do
    cp "${SCRIPT_DIR}/scripts/${script}" "${BUILD_DIR}/scripts/"
    chmod +x "${BUILD_DIR}/scripts/${script}"
done
cp "${SCRIPT_DIR}/conf/privilege" "${BUILD_DIR}/conf/"
cp "${SCRIPT_DIR}/WIZARD_UIFILES/install_uifile" "${BUILD_DIR}/WIZARD_UIFILES/"

# Assemble SPK (tar archive; INFO and icons first per Synology package layout)
echo "Assembling SPK..."
OUTPUT_DIR="${REPO_ROOT}/dist/synology"
mkdir -p "${OUTPUT_DIR}"
tar cf "${OUTPUT_DIR}/${SPK_NAME}" \
    -C "${BUILD_DIR}" \
    INFO \
    PACKAGE_ICON.PNG \
    PACKAGE_ICON_256.PNG \
    package.tgz \
    scripts \
    conf \
    WIZARD_UIFILES

# Clean up
rm -rf "${BUILD_DIR}"

echo ""
echo "[OK] SPK created: ${OUTPUT_DIR}/${SPK_NAME}"
echo "Install via Synology Package Center > Manual Install."
