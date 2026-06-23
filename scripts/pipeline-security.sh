#!/usr/bin/env bash
set -uo pipefail

echo "=== Normal Production Security Pipeline Started ==="

npm run scan:slither
npm run scan:mythril
npm run detect:defi

npm run monitor:consensus || true
npm run screen:wallets || true

gate_exit_code=0
npm run security:gate || gate_exit_code=$?

npm run incident:orchestrate || true
npm run normalize:reports || true
npm run enrich:findings || true
npm run report:html || true

echo "=== Normal Production Security Pipeline Finished ==="
exit "$gate_exit_code"