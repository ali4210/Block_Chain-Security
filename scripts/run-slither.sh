#!/usr/bin/env bash
set -e

cd "$(dirname "$0")/.."

mkdir -p reports/slither
find reports/slither -maxdepth 1 -name "*.json" -delete

source sec-tools-env/bin/activate

slither ./contracts/VulnerableBank.sol \
  --json reports/slither/vulnerable_bank.json || true

slither ./contracts/OpenZep-SecureBank.sol \
  --solc-remaps "@openzeppelin=node_modules/@openzeppelin" \
  --json reports/slither/secure_bank.json || true

deactivate