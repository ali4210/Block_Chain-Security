#!/usr/bin/env bash
set -euo pipefail

echo "=== Strict Security Pipeline Started ==="

npm run scan:slither
npm run scan:mythril
npm run detect:defi
npm run monitor:consensus
npm run screen:wallets

gate_exit_code=0
npm run security:gate || gate_exit_code=$?

npm run incident:orchestrate
npm run normalize:reports
npm run enrich:findings
REPORT_HTML_NAME="security-report-strict.html" npm run report:html

echo "=== Strict Security Pipeline Finished ==="
exit "$gate_exit_code"