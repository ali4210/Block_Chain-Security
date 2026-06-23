import fs from "node:fs";
import path from "node:path";

type Severity = "HIGH" | "MEDIUM" | "LOW" | "INFO";
type Status = "OPEN" | "REVIEW_REQUIRED" | "MONITORING" | "CLOSED";
type ActionType =
  | "BLOCK_BUILD"
  | "ESCALATE_SECURITY"
  | "MANUAL_REVIEW"
  | "MONITOR"
  | "LOG_ONLY";

type UnifiedFinding = {
  tool: "slither" | "mythril" | "defi-detector" | "consensus-monitor";
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
  tool: UnifiedFinding["tool"];
  title: string;
  rule: string;
  affected_component: string;
  action: ActionType;
  owner: string;
  status: Status;
  rationale: string;
  remediation: string;
  evidence: {
    report: string;
    location?: string;
    description: string;
  };
  created_at: string;
};

type IncidentReport = {
  generated_at: string;
  summary: {
    total_findings: number;
    total_incidents: number;
    by_severity: Record<Severity, number>;
    by_action: Record<ActionType, number>;
  };
  incidents: IncidentAction[];
};

const ROOT = process.cwd();
const OUTPUT_DIR = path.join(ROOT, "reports", "incident");
const OUTPUT_FILE = path.join(OUTPUT_DIR, "incident_response.json");

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
  ]
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

function readJson(filePath: string): any {
  const abs = path.join(ROOT, filePath);
  if (!fs.existsSync(abs)) throw new Error(`Missing required report: ${filePath}`);
  const raw = fs.readFileSync(abs, "utf8").trim();
  if (!raw) throw new Error(`Empty required report: ${filePath}`);
  return JSON.parse(raw);
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

function parseSlitherReport(file: string, label: string): UnifiedFinding[] {
  const data = readJson(file);
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
  const data = readJson(file);
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
  const data = readJson(file);
  const alerts = Array.isArray(data?.alerts) ? data.alerts : [];

  return alerts.map((item: any): UnifiedFinding => ({
    tool: "defi-detector",
    report: label,
    contract: String(item?.protocols?.join(", ") ?? "RuntimeProtocol"),
    rule: String(item?.rule_id ?? "unknown"),
    severity: normalizeDefiSeverity(item?.severity),
    title: String(item?.title ?? "DeFi detector alert"),
    description: String(item?.description ?? "").replace(/\s+/g, " ").trim(),
    location:
      item?.tx_hashes?.length
        ? `tx=${item.tx_hashes.join(",")}`
        : undefined
  }));
}

function parseConsensusReport(file: string, label: string): UnifiedFinding[] {
  const data = readJson(file);

  const health = String(data?.health ?? "INFO").toUpperCase().trim();
  const level: Severity =
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
      severity: level,
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

function getOwner(finding: UnifiedFinding): string {
  if (finding.tool === "slither" || finding.tool === "mythril") return "Application Security Team";
  if (finding.tool === "defi-detector") return "SOC / Blockchain Monitoring Team";
  return "DevOps / Node Operations Team";
}

function getAction(finding: UnifiedFinding): ActionType {
  if (finding.severity === "HIGH" && finding.tool === "defi-detector") return "ESCALATE_SECURITY";
  if (finding.severity === "HIGH") return "BLOCK_BUILD";
  if (finding.severity === "MEDIUM") return "MANUAL_REVIEW";
  if (finding.severity === "LOW") return "MONITOR";
  return "LOG_ONLY";
}

function getStatus(severity: Severity): Status {
  if (severity === "HIGH") return "OPEN";
  if (severity === "MEDIUM") return "REVIEW_REQUIRED";
  if (severity === "LOW") return "MONITORING";
  return "CLOSED";
}

function getRemediation(finding: UnifiedFinding): string {
  if (finding.tool === "slither" || finding.tool === "mythril") {
    return "Review the affected contract logic, patch the vulnerable code path, rerun static analysis, and require secure code review before redeployment.";
  }
  if (finding.tool === "defi-detector") {
    return "Investigate the suspicious transaction pattern, validate counterparties and wallet behavior, and consider pausing sensitive protocol actions if exploit conditions are confirmed.";
  }
  return "Verify node health, inspect RPC connectivity and recent blocks, confirm expected chain activity, and restore normal monitoring thresholds if the slowdown is benign.";
}

function getRationale(finding: UnifiedFinding): string {
  if (finding.severity === "HIGH") return "This finding is severe enough to require immediate containment and should block promotion until reviewed.";
  if (finding.severity === "MEDIUM") return "This finding indicates meaningful risk and requires analyst review before it can be dismissed.";
  if (finding.severity === "LOW") return "This finding should be tracked for operational awareness and future tuning.";
  return "This finding is informational and is being retained for audit visibility.";
}

function buildIncident(finding: UnifiedFinding, index: number): IncidentAction {
  return {
    id: `INC-${String(index + 1).padStart(4, "0")}`,
    severity: finding.severity,
    tool: finding.tool,
    title: finding.title,
    rule: finding.rule,
    affected_component: finding.contract,
    action: getAction(finding),
    owner: getOwner(finding),
    status: getStatus(finding.severity),
    rationale: getRationale(finding),
    remediation: getRemediation(finding),
    evidence: {
      report: finding.report,
      location: finding.location,
      description: finding.description
    },
    created_at: new Date().toISOString()
  };
}

function main() {
  const findings: UnifiedFinding[] = [];

  for (const report of REPORTS.slither) findings.push(...parseSlitherReport(report.file, report.label));
  for (const report of REPORTS.mythril) findings.push(...parseMythrilReport(report.file, report.label));
  for (const report of REPORTS.defi) findings.push(...parseDefiReport(report.file, report.label));
  for (const report of REPORTS.consensus) findings.push(...parseConsensusReport(report.file, report.label));

  const incidents = findings.map(buildIncident);

  const bySeverity: Record<Severity, number> = {
    HIGH: incidents.filter((i) => i.severity === "HIGH").length,
    MEDIUM: incidents.filter((i) => i.severity === "MEDIUM").length,
    LOW: incidents.filter((i) => i.severity === "LOW").length,
    INFO: incidents.filter((i) => i.severity === "INFO").length
  };

  const byAction: Record<ActionType, number> = {
    BLOCK_BUILD: incidents.filter((i) => i.action === "BLOCK_BUILD").length,
    ESCALATE_SECURITY: incidents.filter((i) => i.action === "ESCALATE_SECURITY").length,
    MANUAL_REVIEW: incidents.filter((i) => i.action === "MANUAL_REVIEW").length,
    MONITOR: incidents.filter((i) => i.action === "MONITOR").length,
    LOG_ONLY: incidents.filter((i) => i.action === "LOG_ONLY").length
  };

  const report: IncidentReport = {
    generated_at: new Date().toISOString(),
    summary: {
      total_findings: findings.length,
      total_incidents: incidents.length,
      by_severity: bySeverity,
      by_action: byAction
    },
    incidents
  };

  fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(report, null, 2), "utf8");

  console.log("=== Incident Orchestrator Summary ===");
  console.log(`Total findings   : ${report.summary.total_findings}`);
  console.log(`Total incidents  : ${report.summary.total_incidents}`);
  console.log(`High             : ${report.summary.by_severity.HIGH}`);
  console.log(`Medium           : ${report.summary.by_severity.MEDIUM}`);
  console.log(`Low              : ${report.summary.by_severity.LOW}`);
  console.log(`Info             : ${report.summary.by_severity.INFO}`);
  console.log("Output report    : reports/incident/incident_response.json");
}

try {
  main();
} catch (error) {
  console.error(`\n[FAIL] Incident orchestrator could not complete: ${(error as Error).message}`);
  process.exit(1);
}