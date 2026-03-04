#!/bin/sh
# zkguard installer — downloads the latest release binary from GitHub.
# Usage: curl -sSf https://raw.githubusercontent.com/farm32df1/LLMguardZKP/main/zkguard/install.sh | sh
set -e

REPO="farm32df1/LLMguardZKP"
INSTALL_DIR="${ZKGUARD_INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="zkguard"

# Detect OS
OS="$(uname -s)"
case "$OS" in
    Linux)  OS_TAG="linux" ;;
    Darwin) OS_TAG="darwin" ;;
    *)      echo "Error: unsupported OS: $OS"; exit 1 ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)  ARCH_TAG="x86_64" ;;
    aarch64|arm64)  ARCH_TAG="aarch64" ;;
    *)              echo "Error: unsupported architecture: $ARCH"; exit 1 ;;
esac

ASSET_NAME="zkguard-${OS_TAG}-${ARCH_TAG}"

echo "Detecting system: ${OS_TAG}/${ARCH_TAG}"

# Get latest release tag
LATEST_TAG=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [ -z "$LATEST_TAG" ]; then
    echo "Error: could not determine latest release"
    exit 1
fi

echo "Latest release: ${LATEST_TAG}"

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${ASSET_NAME}.tar.gz"

echo "Downloading ${DOWNLOAD_URL}..."

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

curl -sSfL "$DOWNLOAD_URL" -o "${TMPDIR}/${ASSET_NAME}.tar.gz"
tar xzf "${TMPDIR}/${ASSET_NAME}.tar.gz" -C "$TMPDIR"

# Install
if [ -w "$INSTALL_DIR" ]; then
    mv "${TMPDIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
else
    echo "Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo mv "${TMPDIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
fi

chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

echo ""
echo "zkguard ${LATEST_TAG} installed to ${INSTALL_DIR}/${BINARY_NAME}"
echo ""
echo "Usage:"
echo "  zkguard scan --text \"your text here\""
echo "  zkguard sanitize --text \"text with API keys\""
echo "  zkguard proxy --port 8080 --provider anthropic"
echo "  zkguard demo"
