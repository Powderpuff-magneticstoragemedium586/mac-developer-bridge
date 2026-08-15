#!/bin/bash
set -euo pipefail
INSTALL_DIR="${MAC_DEV_BRIDGE_INSTALL_DIR:-$HOME/.local/share/mac-developer-bridge}"
NODE_BIN="${NODE_BIN:-$(command -v node)}"
exec "$NODE_BIN" "$INSTALL_DIR/bridge.mjs"
