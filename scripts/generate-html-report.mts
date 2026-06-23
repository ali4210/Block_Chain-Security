import fs from "node:fs";
import path from "node:path";

type Severity = "HIGH" | "MEDIUM" | "LOW" | "INFO";

type UnifiedFinding = {
  tool: "slither" | "mythril" | "defi-detector" | "consensus-monitor" | "wallet-screening";
  report: string;
  contract: string;
  rule: string;
  severity: Severity;
  confidence?: string;
  title: string;
  description: string;
  location?: string;
};

type IncidentAction = {
  id: string;
  severity: Severity;
  tool: string;
  title: string;
  rule: string;
  affected_component: string;
  action: string;
  owner: string;
  status: string;
  rationale: string;
  remediation: string;
  evidence: {
    report: string;
    location?: string;
    description: string;
  };
  created_at: string;
};

const ROOT = process.cwd();
const OUTPUT_DIR = path.join(ROOT, "reports", "html");
const REPORT_HTML_NAME = process.env.REPORT_HTML_NAME?.trim() || "security-report.html";
const OUTPUT_FILE = path.join(OUTPUT_DIR, REPORT_HTML_NAME);

const REPORTS = {
  slither: [
    { file: "reports/slither/vulnerable_bank.json", label: "slither-vulnerable" },
    { file: "reports/slither/secure_bank.json", label: "slither-secure" }
  ],
  mythril: [
    { file: "reports/mythril/vulnerable_bank.json", label: "mythril-vulnerable" }
  ],
  defi: [
    { file: "reports/defi/defi_alerts.json", label: "defi-runtime-monitor" }
  ],
  consensus: [
    { file: "reports/consensus/consensus_status.json", label: "consensus-health" }
  ],
  wallets: [
    { file: "reports/wallet-screening/wallet_screening.json", label: "wallet-screening" }
  ],
  incident: {
    file: "reports/incident/incident_response.json"
  }
};

const SLITHER_RULE_MAP: Record<string, Severity> = {
  "reentrancy-eth": "HIGH",
  "reentrancy-no-eth": "HIGH",
  "reentrancy-benign": "MEDIUM",
  "arbitrary-send-eth": "HIGH",
  "controlled-delegatecall": "HIGH",
  "unchecked-lowlevel": "MEDIUM",
  "unchecked-send": "MEDIUM",
  "tx-origin": "HIGH",
  "suicidal": "HIGH",
  "shadowing-state": "MEDIUM",
  "timestamp": "MEDIUM",
  "weak-prng": "MEDIUM",
  "assembly": "LOW",
  "low-level-calls": "MEDIUM",
  "pragma": "INFO",
  "solc-version": "INFO",
  "naming-convention": "INFO",
  "dead-code": "LOW",
  "external-function": "INFO",
  "immutable-states": "LOW"
};

function fileExists(filePath: string): boolean {
  return fs.existsSync(path.join(ROOT, filePath));
}

function readJsonSafe(filePath: string): any | null {
  const abs = path.join(ROOT, filePath);
  if (!fs.existsSync(abs)) return null;
  const raw = fs.readFileSync(abs, "utf8").trim();
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function normalizeMythrilSeverity(value: unknown): Severity {
  const v = String(value ?? "").toLowerCase().trim();
  if (v === "high" || v === "error" || v === "fatal") return "HIGH";
  if (v === "medium" || v === "warning") return "MEDIUM";
  if (v === "low") return "LOW";
  return "INFO";
}

function normalizeSlitherSeverity(check: string, impact?: string): Severity {
  const mapped = SLITHER_RULE_MAP[check];
  if (mapped) return mapped;

  const v = String(impact ?? "").toLowerCase().trim();
  if (v === "high") return "HIGH";
  if (v === "medium") return "MEDIUM";
  if (v === "low") return "LOW";
  return "INFO";
}

function normalizeDefiSeverity(value: unknown): Severity {
  const v = String(value ?? "").toUpperCase().trim();
  if (v === "HIGH" || v === "MEDIUM" || v === "LOW" || v === "INFO") return v as Severity;
  return "INFO";
}

function normalizeWalletSeverity(value: unknown): Severity {
  const v = String(value ?? "").toUpperCase().trim();
  if (v === "HIGH" || v === "MEDIUM" || v === "LOW" || v === "INFO") return v as Severity;
  return "INFO";
}

function parseSlitherReport(file: string, label: string): UnifiedFinding[] {
  const data = readJsonSafe(file);
  const detectors = Array.isArray(data?.results?.detectors) ? data.results.detectors : [];

  return detectors.map((item: any): UnifiedFinding => {
    const elements = Array.isArray(item?.elements) ? item.elements : [];
    const first = elements[0] ?? {};
    const source = first?.source_mapping ?? {};
    const lines = Array.isArray(source?.lines) ? source.lines.join(",") : "";
    const contract =
      first?.type_specific_fields?.parent?.name ??
      first?.type_specific_fields?.parent?.type ??
      "UnknownContract";

    return {
      tool: "slither",
      report: label,
      contract,
      rule: String(item?.check ?? "unknown"),
      severity: normalizeSlitherSeverity(item?.check, item?.impact),
      confidence: String(item?.confidence ?? ""),
      title: String(item?.check ?? "Slither finding"),
      description: String(item?.description ?? "").replace(/\s+/g, " ").trim(),
      location: source?.filename_relative
        ? `${source.filename_relative}${lines ? `:${lines}` : ""}`
        : undefined
    };
  });
}

function parseMythrilReport(file: string, label: string): UnifiedFinding[] {
  const data = readJsonSafe(file);
  const issues = Array.isArray(data?.issues) ? data.issues : [];

  return issues.map((item: any): UnifiedFinding => ({
    tool: "mythril",
    report: label,
    contract: String(item?.contract ?? "UnknownContract"),
    rule: String(item?.["swc-id"] ?? item?.title ?? "unknown"),
    severity: normalizeMythrilSeverity(item?.severity),
    title: String(item?.title ?? "Mythril issue"),
    description: String(item?.description ?? "").replace(/\s+/g, " ").trim(),
    location:
      item?.filename && item?.lineno
        ? `${item.filename}:${item.lineno}`
        : item?.filename
        ? String(item.filename)
        : undefined
  }));
}

function parseDefiReport(file: string, label: string): UnifiedFinding[] {
  const data = readJsonSafe(file);
  const alerts = Array.isArray(data?.alerts) ? data.alerts : [];

  return alerts.map((item: any): UnifiedFinding => ({
    tool: "defi-detector",
    report: label,
    contract: String(item?.protocols?.join(", ") ?? "RuntimeProtocol"),
    rule: String(item?.rule_id ?? "unknown"),
    severity: normalizeDefiSeverity(item?.severity),
    title: String(item?.title ?? "DeFi detector alert"),
    description: String(item?.description ?? "").replace(/\s+/g, " ").trim(),
    location: item?.tx_hashes?.length ? `tx=${item.tx_hashes.join(",")}` : undefined
  }));
}

function parseConsensusReport(file: string, label: string): UnifiedFinding[] {
  const data = readJsonSafe(file);
  if (!data) return [];

  const health = String(data?.health ?? "INFO").toUpperCase().trim();
  const severity: Severity =
    health === "HIGH" || health === "MEDIUM" || health === "LOW" || health === "INFO"
      ? (health as Severity)
      : "INFO";

  const network = String(data?.network ?? "unknown-network");
  const latestBlock = Number(data?.latest_block_number ?? 0);
  const seconds = Number(data?.seconds_since_last_block ?? 0);

  return [
    {
      tool: "consensus-monitor",
      report: label,
      contract: network,
      rule: "consensus-health",
      severity,
      title: "Consensus / chain health status",
      description: [
        data?.details ? String(data.details) : "",
        `Network: ${network}`,
        `Latest block: ${latestBlock}`,
        `Seconds since last block: ${seconds}`
      ]
        .filter(Boolean)
        .join(". "),
      location: undefined
    }
  ];
}

function parseWalletReport(file: string, label: string): UnifiedFinding[] {
  const data = readJsonSafe(file);
  if (!data) return [];

  const items = Array.isArray(data?.results)
    ? data.results
    : Array.isArray(data?.wallets)
    ? data.wallets
    : Array.isArray(data)
    ? data
    : [];

  return items.map((item: any): UnifiedFinding => ({
    tool: "wallet-screening",
    report: label,
    contract: String(item?.wallet ?? item?.address ?? item?.entity ?? "WalletEntity"),
    rule: String(item?.rule_id ?? item?.status ?? item?.risk ?? "wallet-screening"),
    severity: normalizeWalletSeverity(item?.severity ?? item?.risk_level ?? item?.risk),
    title: String(item?.title ?? item?.label ?? "Wallet screening result"),
    description: String(
      item?.description ??
        item?.details ??
        `Wallet screening result for ${item?.wallet ?? item?.address ?? "unknown wallet"}`
    ).replace(/\s+/g, " ").trim(),
    location: item?.wallet || item?.address ? `wallet=${item?.wallet ?? item?.address}` : undefined
  }));
}

function readIncidentActions(): IncidentAction[] {
  const data = readJsonSafe(REPORTS.incident.file);
  return Array.isArray(data?.incidents) ? data.incidents : [];
}

function collectFindings(): UnifiedFinding[] {
  const findings: UnifiedFinding[] = [];

  for (const report of REPORTS.slither) findings.push(...parseSlitherReport(report.file, report.label));
  for (const report of REPORTS.mythril) findings.push(...parseMythrilReport(report.file, report.label));
  for (const report of REPORTS.defi) findings.push(...parseDefiReport(report.file, report.label));
  for (const report of REPORTS.consensus) findings.push(...parseConsensusReport(report.file, report.label));
  for (const report of REPORTS.wallets) findings.push(...parseWalletReport(report.file, report.label));

  return findings;
}

function severityRank(severity: Severity): number {
  if (severity === "HIGH") return 0;
  if (severity === "MEDIUM") return 1;
  if (severity === "LOW") return 2;
  return 3;
}

function groupCounts(findings: UnifiedFinding[]) {
  return {
    HIGH: findings.filter((f) => f.severity === "HIGH").length,
    MEDIUM: findings.filter((f) => f.severity === "MEDIUM").length,
    LOW: findings.filter((f) => f.severity === "LOW").length,
    INFO: findings.filter((f) => f.severity === "INFO").length
  };
}

function toolCounts(findings: UnifiedFinding[]) {
  const counts: Record<string, number> = {};
  for (const finding of findings) {
    counts[finding.tool] = (counts[finding.tool] ?? 0) + 1;
  }
  return counts;
}

function determineGateStatus(findings: UnifiedFinding[]): "PASS" | "FAIL" {
  return findings.some((f) => f.severity === "HIGH") ? "FAIL" : "PASS";
}

function renderBadge(severity: string): string {
  const cls = severity.toLowerCase();
  return `<span class="badge ${cls}">${escapeHtml(severity)}</span>`;
}

function renderToolRows(counts: Record<string, number>): string {
  return Object.entries(counts)
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(
      ([tool, count]) => `
        <tr>
          <td>${escapeHtml(tool)}</td>
          <td>${escapeHtml(count)}</td>
        </tr>
      `
    )
    .join("");
}

function renderFindingRows(findings: UnifiedFinding[]): string {
  return findings
    .sort((a, b) => {
      const sev = severityRank(a.severity) - severityRank(b.severity);
      if (sev !== 0) return sev;
      return a.tool.localeCompare(b.tool);
    })
    .map(
      (f) => `
        <tr>
          <td>${renderBadge(f.severity)}</td>
          <td>${escapeHtml(f.tool)}</td>
          <td>${escapeHtml(f.contract)}</td>
          <td>${escapeHtml(f.rule)}</td>
          <td>${escapeHtml(f.title)}</td>
          <td>${escapeHtml(f.location ?? "-")}</td>
          <td>${escapeHtml(f.description)}</td>
        </tr>
      `
    )
    .join("");
}

function renderIncidentRows(incidents: IncidentAction[]): string {
  return incidents
    .sort((a, b) => {
      const sev = severityRank(a.severity as Severity) - severityRank(b.severity as Severity);
      if (sev !== 0) return sev;
      return a.id.localeCompare(b.id);
    })
    .map(
      (i) => `
        <tr>
          <td>${escapeHtml(i.id)}</td>
          <td>${renderBadge(i.severity)}</td>
          <td>${escapeHtml(i.tool)}</td>
          <td>${escapeHtml(i.affected_component)}</td>
          <td>${escapeHtml(i.action)}</td>
          <td>${escapeHtml(i.owner)}</td>
          <td>${escapeHtml(i.status)}</td>
          <td>${escapeHtml(i.remediation)}</td>
        </tr>
      `
    )
    .join("");
}

function renderSourceList(): string {
  const allSources = [
    ...REPORTS.slither.map((x) => x.file),
    ...REPORTS.mythril.map((x) => x.file),
    ...REPORTS.defi.map((x) => x.file),
    ...REPORTS.consensus.map((x) => x.file),
    ...REPORTS.wallets.map((x) => x.file),
    REPORTS.incident.file
  ];

  return allSources
    .map((file) => {
      const present = fileExists(file);
      return `
        <li>
          <span>${escapeHtml(file)}</span>
          <span class="source-status ${present ? "present" : "missing"}">${present ? "present" : "missing"}</span>
        </li>
      `;
    })
    .join("");
}

function buildHtml(findings: UnifiedFinding[], incidents: IncidentAction[]): string {
  const counts = groupCounts(findings);
  const byTool = toolCounts(findings);
  const totalFindings = findings.length;
  const totalIncidents = incidents.length;
  const gateStatus = determineGateStatus(findings);
  const generatedAt = new Date().toISOString();

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Security Pipeline HTML Report</title>
  <style>
    :root {
      --bg: #0b1020;
      --panel: #121a2b;
      --panel-2: #0f1726;
      --text: #e8eefc;
      --muted: #9fb0d0;
      --border: #233252;
      --high: #ef4444;
      --medium: #f59e0b;
      --low: #22c55e;
      --info: #38bdf8;
      --accent: #8b5cf6;
      --shadow: 0 10px 30px rgba(0,0,0,0.28);
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, Arial, sans-serif;
      background: linear-gradient(180deg, #0a0f1d 0%, #12192b 100%);
      color: var(--text);
      line-height: 1.5;
    }

    .container {
      max-width: 1280px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }

    .hero, .panel {
      background: rgba(18, 26, 43, 0.95);
      border: 1px solid var(--border);
      border-radius: 18px;
      box-shadow: var(--shadow);
    }

    .hero {
      padding: 28px;
      margin-bottom: 22px;
    }

    .hero h1 {
      margin: 0 0 8px;
      font-size: 32px;
    }

    .hero p {
      margin: 6px 0;
      color: var(--muted);
    }

    .gate {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      margin-top: 14px;
      padding: 10px 14px;
      border-radius: 999px;
      font-weight: 700;
      background: ${gateStatus === "FAIL" ? "rgba(239,68,68,0.12)" : "rgba(34,197,94,0.12)"};
      color: ${gateStatus === "FAIL" ? "#fecaca" : "#bbf7d0"};
      border: 1px solid ${gateStatus === "FAIL" ? "rgba(239,68,68,0.35)" : "rgba(34,197,94,0.35)"};
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 16px;
      margin-bottom: 22px;
    }

    .stat {
      padding: 20px;
      background: rgba(15, 23, 38, 0.95);
      border: 1px solid var(--border);
      border-radius: 16px;
      box-shadow: var(--shadow);
    }

    .stat .label {
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      margin-bottom: 10px;
    }

    .stat .value {
      font-size: 30px;
      font-weight: 800;
    }

    .stat.high .value { color: var(--high); }
    .stat.medium .value { color: var(--medium); }
    .stat.low .value { color: var(--low); }
    .stat.info .value { color: var(--info); }

    .panel {
      padding: 22px;
      margin-bottom: 22px;
    }

    .panel h2 {
      margin: 0 0 14px;
      font-size: 22px;
    }

    .muted {
      color: var(--muted);
    }

    .badge {
      display: inline-block;
      padding: 5px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }

    .badge.high { background: rgba(239,68,68,0.16); color: #fecaca; border: 1px solid rgba(239,68,68,0.35); }
    .badge.medium { background: rgba(245,158,11,0.16); color: #fde68a; border: 1px solid rgba(245,158,11,0.35); }
    .badge.low { background: rgba(34,197,94,0.16); color: #bbf7d0; border: 1px solid rgba(34,197,94,0.35); }
    .badge.info { background: rgba(56,189,248,0.16); color: #bae6fd; border: 1px solid rgba(56,189,248,0.35); }

    table {
      width: 100%;
      border-collapse: collapse;
      overflow: hidden;
      border-radius: 12px;
    }

    thead th {
      text-align: left;
      font-size: 13px;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: var(--muted);
      background: rgba(255,255,255,0.03);
      padding: 14px 12px;
      border-bottom: 1px solid var(--border);
    }

    tbody td {
      padding: 14px 12px;
      border-bottom: 1px solid rgba(35,50,82,0.7);
      vertical-align: top;
      font-size: 14px;
    }

    tbody tr:hover {
      background: rgba(255,255,255,0.025);
    }

    .sources {
      list-style: none;
      margin: 0;
      padding: 0;
      display: grid;
      gap: 10px;
    }

    .sources li {
      display: flex;
      justify-content: space-between;
      gap: 14px;
      padding: 12px 14px;
      border: 1px solid var(--border);
      border-radius: 12px;
      background: rgba(255,255,255,0.02);
      word-break: break-word;
    }

    .source-status {
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .source-status.present { color: #86efac; }
    .source-status.missing { color: #fca5a5; }

    .footer {
      color: var(--muted);
      font-size: 13px;
      margin-top: 14px;
    }

    @media (max-width: 960px) {
      .grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
    }

    @media (max-width: 640px) {
      .grid {
        grid-template-columns: 1fr;
      }

      .hero h1 {
        font-size: 26px;
      }

      .container {
        padding: 20px 14px 36px;
      }

      table, thead, tbody, th, td, tr {
        font-size: 13px;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <section class="hero">
      <h1>Security Pipeline HTML Report</h1>
      <p>Human-readable output for smart contract security, DeFi runtime alerts, consensus monitoring, wallet screening, and incident orchestration.</p>
      <p>Generated at: ${escapeHtml(generatedAt)}</p>
      <div class="gate">Security Gate Status: ${escapeHtml(gateStatus)}</div>
    </section>

    <section class="grid">
      <div class="stat high">
        <div class="label">High</div>
        <div class="value">${counts.HIGH}</div>
      </div>
      <div class="stat medium">
        <div class="label">Medium</div>
        <div class="value">${counts.MEDIUM}</div>
      </div>
      <div class="stat low">
        <div class="label">Low</div>
        <div class="value">${counts.LOW}</div>
      </div>
      <div class="stat info">
        <div class="label">Info</div>
        <div class="value">${counts.INFO}</div>
      </div>
    </section>

    <section class="grid">
      <div class="stat">
        <div class="label">Total Findings</div>
        <div class="value">${totalFindings}</div>
      </div>
      <div class="stat">
        <div class="label">Total Incidents</div>
        <div class="value">${totalIncidents}</div>
      </div>
      <div class="stat">
        <div class="label">Unique Tools</div>
        <div class="value">${Object.keys(byTool).length}</div>
      </div>
      <div class="stat">
        <div class="label">HTML Output</div>
        <div class="value" style="font-size:18px;">${escapeHtml(`reports/html/${REPORT_HTML_NAME}`)}</div>
      </div>
    </section>

    <section class="panel">
      <h2>Executive Summary</h2>
      <p class="muted">
        This report aggregates raw JSON outputs into a browser-readable format so stakeholders can review the overall risk picture, severity distribution, source tools, and response actions without opening machine-oriented files.
      </p>
      <p class="muted">
        A FAIL status means at least one HIGH severity finding was detected by the pipeline input set. A PASS status means no HIGH severity findings were present in the collected findings.
      </p>
    </section>

    <section class="panel">
      <h2>Findings by Tool</h2>
      <table>
        <thead>
          <tr>
            <th>Tool</th>
            <th>Finding Count</th>
          </tr>
        </thead>
        <tbody>
          ${renderToolRows(byTool)}
        </tbody>
      </table>
    </section>

    <section class="panel">
      <h2>Detailed Findings</h2>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Tool</th>
            <th>Affected Component</th>
            <th>Rule</th>
            <th>Title</th>
            <th>Location</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          ${renderFindingRows(findings)}
        </tbody>
      </table>
    </section>

    <section class="panel">
      <h2>Incident Actions</h2>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Severity</th>
            <th>Tool</th>
            <th>Affected Component</th>
            <th>Action</th>
            <th>Owner</th>
            <th>Status</th>
            <th>Remediation</th>
          </tr>
        </thead>
        <tbody>
          ${renderIncidentRows(incidents)}
        </tbody>
      </table>
    </section>

    <section class="panel">
      <h2>Source Files</h2>
      <ul class="sources">
        ${renderSourceList()}
      </ul>
      <div class="footer">
        Open this file directly in your browser after pipeline execution.
      </div>
    </section>
  </div>
</body>
</html>`;
}

function main() {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });

  const findings = collectFindings();
  const incidents = readIncidentActions();

  const html = buildHtml(findings, incidents);
  fs.writeFileSync(OUTPUT_FILE, html, "utf8");

  console.log("=== HTML Security Report Generated ===");
  console.log(`Findings          : ${findings.length}`);
  console.log(`Incidents         : ${incidents.length}`);
  console.log(`Output            : reports/html/${REPORT_HTML_NAME}`);
}

main();