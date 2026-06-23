#!/usr/bin/env bash
set -euo pipefail

echo "=== Fail-Fast Security Pipeline Started ==="

npm run scan:slither
npm run scan:mythril
npm run detect:defi
npm run monitor:consensus
npm run screen:wallets
npm run security:gate
npm run incident:orchestrate
npm run normalize:reports
npm run enrich:findings
npm run report:html

echo "=== Fail-Fast Security Pipeline Finished ==="