#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p reports/slither
find reports/slither -maxdepth 1 -name "*.json" -delete

export HOME="${HOME:-$(pwd)}"
export SOLC_SELECT_HOME="${SOLC_SELECT_HOME:-$(pwd)/.solc-select}"
mkdir -p "$SOLC_SELECT_HOME"
mkdir -p "$SOLC_SELECT_HOME/artifacts"

if [ -f "sec-tools-env/bin/activate" ]; then
  . sec-tools-env/bin/activate
fi

echo "Using HOME=$HOME"
echo "Using SOLC_SELECT_HOME=$SOLC_SELECT_HOME"

slither ./contracts/VulnerableBank.sol \
  --json reports/slither/vulnerable_bank.json || true

slither ./contracts/OpenZep-SecureBank.sol \
  --solc-remaps "@openzeppelin=node_modules/@openzeppelin" \
  --json reports/slither/secure_bank.json || true

if command -v deactivate >/dev/null 2>&1; then
  deactivate
fi