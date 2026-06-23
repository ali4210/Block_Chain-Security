import fs from "node:fs";
import path from "node:path";

type Severity = "HIGH" | "MEDIUM" | "LOW" | "INFO";

type EnrichedMetadata = {
  swc_id?: string;
  swc_title?: string;
  owasp_sc_top10?: string;
  weakness_class?: string;
  impact_summary?: string;
  remediation_summary?: string;
  remediation_steps?: string[];
  references?: string[];
  confidence_note?: string;
};

type UnifiedFinding = {
  id?: string;
  record_type?: string;
  source?: string;
  source_report?: string;
  tool: string;
  report?: string;
  contract?: string;
  affected_component?: string;
  rule: string;
  severity: Severity;
  confidence?: string;
  title: string;
  description: string;
  location?: string;
  enrichment?: EnrichedMetadata;
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

type FindingsBundle = {
  generated_at?: string;
  findings: UnifiedFinding[];
  enrichment_summary?: Record<string, number>;
};

const ROOT = process.cwd();
const OUTPUT_DIR = path.join(ROOT, "reports", "html");
const REPORT_HTML_NAME = process.env.REPORT_HTML_NAME?.trim() || "security-report.html";
const OUTPUT_FILE = path.join(OUTPUT_DIR, REPORT_HTML_NAME);

const ENRICHED_FINDINGS_FILE = path.join(ROOT, "dashboard", "data", "enriched-findings.json");
const RAW_FINDINGS_FILE = path.join(ROOT, "dashboard", "data", "findings.json");
const INCIDENT_FILE = path.join(ROOT, "reports", "incident", "incident_response.json");

const SOURCE_FILES = [
  "reports/slither/vulnerable_bank.json",
  "reports/slither/secure_bank.json",
  "reports/mythril/vulnerable_bank.json",
  "reports/defi/defi_alerts.json",
  "reports/consensus/consensus_status.json",
  "reports/wallet-screening/wallet_screening.json",
  "reports/incident/incident_response.json",
  "dashboard/data/findings.json",
  "dashboard/data/enriched-findings.json"
];

function fileExists(filePath: string): boolean {
  return fs.existsSync(path.join(ROOT, filePath));
}

function readJsonSafeAbsolute(filePath: string): any | null {
  if (!fs.existsSync(filePath)) return null;
  const raw = fs.readFileSync(filePath, "utf8").trim();
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function readJsonSafeRelative(filePath: string): any | null {
  return readJsonSafeAbsolute(path.join(ROOT, filePath));
}

function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function normalizeSeverity(value: unknown): Severity {
  const v = String(value ?? "").toUpperCase().trim();
  if (v === "HIGH" || v === "MEDIUM" || v === "LOW" || v === "INFO") return v as Severity;
  return "INFO";
}

function severityRank(severity: Severity): number {
  if (severity === "HIGH") return 0;
  if (severity === "MEDIUM") return 1;
  if (severity === "LOW") return 2;
  return 3;
}

function loadFindingsBundle(): FindingsBundle {
  const enriched = readJsonSafeAbsolute(ENRICHED_FINDINGS_FILE);
  if (Array.isArray(enriched?.findings)) {
    return {
      generated_at: enriched.generated_at,
      findings: enriched.findings.map((f: any) => ({
        ...f,
        severity: normalizeSeverity(f?.severity)
      })),
      enrichment_summary: enriched.enrichment_summary ?? {}
    };
  }

  const raw = readJsonSafeAbsolute(RAW_FINDINGS_FILE);
  if (Array.isArray(raw)) {
    return {
      findings: raw.map((f: any) => ({
        ...f,
        severity: normalizeSeverity(f?.severity)
      }))
    };
  }

  if (Array.isArray(raw?.findings)) {
    return {
      generated_at: raw.generated_at,
      findings: raw.findings.map((f: any) => ({
        ...f,
        severity: normalizeSeverity(f?.severity)
      }))
    };
  }

  return {
    findings: []
  };
}

function readIncidentActions(): IncidentAction[] {
  const data = readJsonSafeAbsolute(INCIDENT_FILE);
  return Array.isArray(data?.incidents) ? data.incidents : [];
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
    .map((f) => {
      const component = f.affected_component ?? f.contract ?? "-";
      const swc = f.enrichment?.swc_id
        ? `${escapeHtml(f.enrichment.swc_id)}${f.enrichment?.swc_title ? ` — ${escapeHtml(f.enrichment.swc_title)}` : ""}`
        : "-";
      const owasp = f.enrichment?.owasp_sc_top10 ? escapeHtml(f.enrichment.owasp_sc_top10) : "-";
      const weakness = f.enrichment?.weakness_class ? escapeHtml(f.enrichment.weakness_class) : "-";
      const impact = f.enrichment?.impact_summary ? escapeHtml(f.enrichment.impact_summary) : "-";
      const remedy = f.enrichment?.remediation_summary ? escapeHtml(f.enrichment.remediation_summary) : "-";
      const steps = Array.isArray(f.enrichment?.remediation_steps) && f.enrichment!.remediation_steps!.length
        ? `<ul class="compact-list">${f.enrichment!.remediation_steps!.map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ul>`
        : "-";

      return `
        <tr>
          <td>${renderBadge(f.severity)}</td>
          <td>${escapeHtml(f.tool)}</td>
          <td>${escapeHtml(component)}</td>
          <td>${escapeHtml(f.rule)}</td>
          <td>${escapeHtml(f.title)}</td>
          <td>${escapeHtml(f.location ?? "-")}</td>
          <td>${escapeHtml(f.description)}</td>
          <td>${swc}</td>
          <td>${owasp}</td>
          <td>${weakness}</td>
          <td>${impact}</td>
          <td>${remedy}</td>
          <td>${steps}</td>
        </tr>
      `;
    })
    .join("");
}

function renderIncidentRows(incidents: IncidentAction[]): string {
  return incidents
    .sort((a, b) => {
      const sev = severityRank(a.severity) - severityRank(b.severity);
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
  return SOURCE_FILES
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

function buildHtml(bundle: FindingsBundle, incidents: IncidentAction[]): string {
  const findings = bundle.findings;
  const counts = groupCounts(findings);
  const byTool = toolCounts(findings);
  const totalFindings = findings.length;
  const totalIncidents = incidents.length;
  const gateStatus = determineGateStatus(findings);
  const generatedAt = new Date().toISOString();
  const mappedSwc = findings.filter((f) => f.enrichment?.swc_id).length;
  const mappedOwasp = findings.filter((f) => f.enrichment?.owasp_sc_top10).length;

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
      max-width: 1500px;
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
      word-break: break-word;
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
      white-space: nowrap;
    }

    .badge.high { background: rgba(239,68,68,0.16); color: #fecaca; border: 1px solid rgba(239,68,68,0.35); }
    .badge.medium { background: rgba(245,158,11,0.16); color: #fde68a; border: 1px solid rgba(245,158,11,0.35); }
    .badge.low { background: rgba(34,197,94,0.16); color: #bbf7d0; border: 1px solid rgba(34,197,94,0.35); }
    .badge.info { background: rgba(56,189,248,0.16); color: #bae6fd; border: 1px solid rgba(56,189,248,0.35); }

    .table-wrap {
      overflow-x: auto;
    }

    table {
      width: 100%;
      min-width: 1400px;
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
      vertical-align: top;
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

    .compact-list {
      margin: 0;
      padding-left: 18px;
    }

    .compact-list li {
      margin: 0 0 6px;
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
      white-space: nowrap;
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
    }
  </style>
</head>
<body>
  <div class="container">
    <section class="hero">
      <h1>Security Pipeline HTML Report</h1>
      <p>Human-readable output for smart contract security, DeFi runtime alerts, consensus monitoring, wallet screening, incident orchestration, and enrichment with SWC/OWASP context.</p>
      <p>Generated at: ${escapeHtml(generatedAt)}</p>
      <p>Input dataset timestamp: ${escapeHtml(bundle.generated_at ?? "not provided")}</p>
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
        <div class="label">Mapped SWC</div>
        <div class="value">${mappedSwc}</div>
      </div>
      <div class="stat">
        <div class="label">Mapped OWASP</div>
        <div class="value">${mappedOwasp}</div>
      </div>
    </section>

    <section class="grid">
      <div class="stat">
        <div class="label">Unique Tools</div>
        <div class="value">${Object.keys(byTool).length}</div>
      </div>
      <div class="stat">
        <div class="label">HTML Output</div>
        <div class="value" style="font-size:18px;">${escapeHtml(`reports/html/${REPORT_HTML_NAME}`)}</div>
      </div>
      <div class="stat">
        <div class="label">Findings Source</div>
        <div class="value" style="font-size:18px;">${escapeHtml(fs.existsSync(ENRICHED_FINDINGS_FILE) ? "enriched-findings.json" : "findings.json")}</div>
      </div>
      <div class="stat">
        <div class="label">Gate Basis</div>
        <div class="value" style="font-size:18px;">High severity count</div>
      </div>
    </section>

    <section class="panel">
      <h2>Executive Summary</h2>
      <p class="muted">
        This report aggregates pipeline outputs into a browser-readable format so stakeholders can review severity distribution, source tools, incident response actions, and enrichment context without opening machine-oriented JSON files.
      </p>
      <p class="muted">
        A FAIL status means at least one HIGH severity finding was detected in the selected findings dataset. A PASS status means no HIGH severity findings were present in the collected findings.
      </p>
    </section>

    <section class="panel">
      <h2>Findings by Tool</h2>
      <div class="table-wrap">
        <table style="min-width: 500px;">
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
      </div>
    </section>

    <section class="panel">
      <h2>Detailed Findings</h2>
      <div class="table-wrap">
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
              <th>SWC</th>
              <th>OWASP</th>
              <th>Weakness Class</th>
              <th>Impact</th>
              <th>Remedy</th>
              <th>Recommended Steps</th>
            </tr>
          </thead>
          <tbody>
            ${renderFindingRows(findings)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="panel">
      <h2>Incident Actions</h2>
      <div class="table-wrap">
        <table style="min-width: 1000px;">
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
      </div>
    </section>

    <section class="panel">
      <h2>Source Files</h2>
      <ul class="sources">
        ${renderSourceList()}
      </ul>
      <div class="footer">
        Open this file directly in your browser after pipeline execution or download it from GitHub Actions artifacts.
      </div>
    </section>
  </div>
</body>
</html>`;
}

function main() {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });

  const bundle = loadFindingsBundle();
  const incidents = readIncidentActions();

  const html = buildHtml(bundle, incidents);
  fs.writeFileSync(OUTPUT_FILE, html, "utf8");

  console.log("=== HTML Security Report Generated ===");
  console.log(`Findings          : ${bundle.findings.length}`);
  console.log(`Incidents         : ${incidents.length}`);
  console.log(`Mapped SWC        : ${bundle.findings.filter((f) => f.enrichment?.swc_id).length}`);
  console.log(`Mapped OWASP      : ${bundle.findings.filter((f) => f.enrichment?.owasp_sc_top10).length}`);
  console.log(`Output            : reports/html/${REPORT_HTML_NAME}`);
}
main();