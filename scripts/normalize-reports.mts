import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "UNKNOWN";
type FindingSeverity = "HIGH" | "MEDIUM" | "LOW" | "INFO" | "UNKNOWN";
type PipelineStatus = "PASS" | "FAIL" | "PARTIAL" | "UNKNOWN";
type FindingStatus = "OPEN" | "ACKNOWLEDGED" | "RESOLVED" | "BLOCKING" | "INFORMATIONAL";
type IncidentStatus = "OPEN" | "REVIEW_REQUIRED" | "MONITORING" | "CLOSED";
type IncidentAction = "BLOCK_BUILD" | "ESCALATE_SECURITY" | "MANUAL_REVIEW" | "MONITOR" | "LOG_ONLY";
type WalletStatus = "SCREENED" | "REVIEW_REQUIRED" | "ALLOW_LISTED" | "BLOCKED" | "ERROR";
type ComplianceDecision = "BLOCK" | "REVIEW" | "REPORT" | "ALLOW";
type ComplianceStatus = "OPEN" | "UNDER_REVIEW" | "REPORTED" | "APPROVED" | "BLOCKED" | "CLOSED";
type CasePriority = "P1" | "P2" | "P3" | "P4";
type CaseStatus = "QUEUED" | "UNDER_REVIEW" | "ESCALATED" | "CLOSED";
type AlertStatus = "PENDING" | "SENT" | "DELIVERED" | "FAILED" | "ACKNOWLEDGED";
type AlertChannel = "SLACK" | "EMAIL" | "WEBHOOK" | "TEAMS" | "SIEM";
type InputState = "FOUND" | "MISSING" | "EMPTY" | "INVALID";

type UnifiedFinding = {
  tool: "slither" | "mythril" | "defi-detector" | "consensus-monitor";
  report: string;
  contract: string;
  rule: string;
  severity: "HIGH" | "MEDIUM" | "LOW" | "INFO";
  confidence?: string;
  title: string;
  description: string;
  location?: string;
};

type IncidentActionRecord = {
  id: string;
  severity: "HIGH" | "MEDIUM" | "LOW" | "INFO";
  tool: UnifiedFinding["tool"];
  title: string;
  rule: string;
  affected_component: string;
  action: IncidentAction;
  owner: string;
  status: IncidentStatus;
  rationale: string;
  remediation: string;
  evidence: {
    report: string;
    location?: string;
    description: string;
  };
  created_at: string;
};

type DashboardSummary = {
  generated_at: string;
  pipeline_status: PipelineStatus;
  last_pipeline_run: string | null;
  kpis: {
    total_findings: number;
    high_findings: number;
    total_incidents: number;
    high_risk_wallets: number;
    block_cases: number;
    escalated_cases: number;
  };
  breakdowns: {
    findings_by_severity: Record<string, number>;
    incidents_by_severity: Record<string, number>;
    compliance_by_decision: Record<string, number>;
    cases_by_status: Record<string, number>;
  };
  input_presence: {
    total_declared_inputs: number;
    found: number;
    missing: number;
    empty: number;
    invalid: number;
    files: Array<{
      label: string;
      file: string;
      state: InputState;
      size_bytes: number | null;
      sha256: string | null;
      note: string | null;
    }>;
  };
};

type NormalizedFinding = {
  id: string;
  record_type: "finding";
  source: string;
  source_report: string | null;
  tool: "slither" | "mythril" | "defi-detector" | "consensus-monitor" | "security-gate";
  rule: string;
  title: string;
  summary: string;
  severity: FindingSeverity;
  status: FindingStatus;
  asset: {
    type: string;
    name: string;
    network: string | null;
    location: string | null;
  };
  confidence: string | null;
  recommendation: string | null;
  evidence: {
    report: string | null;
    location: string | null;
    raw_ref: string | null;
  };
  timestamps: {
    created_at: string;
    updated_at: string | null;
    observed_at: string | null;
  };
  metadata: Record<string, any>;
};

type NormalizedIncident = {
  id: string;
  record_type: "incident";
  source: string;
  source_report: string | null;
  title: string;
  summary: string;
  severity: "HIGH" | "MEDIUM" | "LOW" | "INFO";
  status: IncidentStatus;
  owner: string;
  action: IncidentAction;
  affected_component: string;
  rationale: string;
  remediation: string;
  evidence: {
    report: string;
    location: string | null;
    description: string;
    raw_ref: string | null;
  };
  timestamps: {
    created_at: string;
    updated_at: string | null;
    closed_at: string | null;
  };
  metadata: Record<string, any>;
};

type NormalizedWallet = {
  id: string;
  record_type: "wallet";
  wallet_address: string;
  network: string | null;
  label: string | null;
  risk_score: number | null;
  risk_level: Severity;
  status: WalletStatus;
  screening_result: string;
  matched_lists: string[];
  source: string;
  timestamps: {
    screened_at: string | null;
    updated_at: string | null;
  };
  metadata: Record<string, any>;
};

type NormalizedCompliance = {
  id: string;
  record_type: "compliance";
  subject_type: "TRANSACTION" | "WALLET" | "CONTRACT" | "CASE" | "UNKNOWN";
  subject_id: string;
  decision: ComplianceDecision;
  status: ComplianceStatus;
  jurisdiction: string | null;
  rule_hits: string[];
  rationale: string;
  source: string;
  timestamps: {
    created_at: string | null;
    updated_at: string | null;
  };
  metadata: Record<string, any>;
};

type NormalizedCase = {
  id: string;
  record_type: "case";
  title: string;
  priority: CasePriority;
  status: CaseStatus;
  linked_subjects: string[];
  assigned_to: string | null;
  source: string;
  timestamps: {
    created_at: string | null;
    updated_at: string | null;
    closed_at: string | null;
  };
  metadata: Record<string, any>;
};

type NormalizedAlert = {
  id: string;
  record_type: "alert";
  title: string;
  severity: Severity;
  status: AlertStatus;
  channel: AlertChannel;
  recipient: string | null;
  related_record_type: string | null;
  related_record_id: string | null;
  source: string;
  timestamps: {
    created_at: string | null;
    sent_at: string | null;
    acknowledged_at: string | null;
  };
  metadata: Record<string, any>;
};

type NormalizedEvidence = {
  id: string;
  record_type: "evidence";
  evidence_type: string;
  title: string;
  description: string;
  source: string;
  source_file: string | null;
  source_report: string | null;
  related_record_type: string | null;
  related_record_id: string | null;
  derivation_stage: string | null;
  collector: string | null;
  collection_notes: string | null;
  integrity: {
    sha256: string | null;
    content_length: number | null;
    hash_scope: "FILE" | "RECORD" | "TEXT" | "UNKNOWN";
  };
  provenance: {
    origin_system: string | null;
    origin_path: string | null;
    observed_at: string | null;
    generated_at: string | null;
  };
  timestamps: {
    created_at: string | null;
    updated_at: string | null;
  };
  metadata: Record<string, any>;
};

type OptionalReportSpec = {
  label: string;
  file: string;
};

type InputPresenceRecord = {
  label: string;
  file: string;
  state: InputState;
  size_bytes: number | null;
  sha256: string | null;
  note: string | null;
};

const ROOT = process.cwd();
const OUT_DIR = path.join(ROOT, "dashboard", "data");
const NOW = new Date().toISOString();

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
  incident: [
    { file: "reports/incident/incident_response.json", label: "incident-orchestrator" }
  ],
  wallets: [
    { file: "reports/wallet-screening/wallet_screening.json", label: "wallet-screening" }
  ],
  compliance: [
    { file: "reports/compliance/compliance_report.json", label: "compliance-engine" }
  ],
  cases: [
    { file: "reports/cases/case_management.json", label: "case-management" }
  ],
  alerts: [
    { file: "reports/alerts/alerts.json", label: "alert-dispatcher" }
  ]
};

const SLITHER_RULE_MAP: Record<string, FindingSeverity> = {
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

const inputPresence: InputPresenceRecord[] = [];

function ensureDir(dirPath: string) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function sha256Text(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sha256File(absPath: string): string {
  const buf = fs.readFileSync(absPath);
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function noteInput(label: string, file: string, state: InputState, sizeBytes: number | null, sha: string | null, note: string | null) {
  inputPresence.push({
    label,
    file,
    state,
    size_bytes: sizeBytes,
    sha256: sha,
    note
  });
}

function readJsonRequired(filePath: string, label: string): any {
  const abs = path.join(ROOT, filePath);

  if (!fs.existsSync(abs)) {
    noteInput(label, filePath, "MISSING", null, null, "Required input missing");
    throw new Error(`Missing required report: ${filePath}`);
  }

  const stat = fs.statSync(abs);
  const raw = fs.readFileSync(abs, "utf8").trim();
  const sha = sha256File(abs);

  if (!raw) {
    noteInput(label, filePath, "EMPTY", stat.size, sha, "Required input empty");
    throw new Error(`Empty required report: ${filePath}`);
  }

  try {
    const parsed = JSON.parse(raw);
    noteInput(label, filePath, "FOUND", stat.size, sha, null);
    return parsed;
  } catch (error) {
    noteInput(label, filePath, "INVALID", stat.size, sha, `Invalid JSON: ${(error as Error).message}`);
    throw new Error(`Invalid JSON in ${filePath}: ${(error as Error).message}`);
  }
}

function readJsonOptional(filePath: string, label: string): any | null {
  const abs = path.join(ROOT, filePath);

  if (!fs.existsSync(abs)) {
    noteInput(label, filePath, "MISSING", null, null, "Optional input missing");
    return null;
  }

  const stat = fs.statSync(abs);
  const raw = fs.readFileSync(abs, "utf8").trim();
  const sha = sha256File(abs);

  if (!raw) {
    noteInput(label, filePath, "EMPTY", stat.size, sha, "Optional input empty");
    return null;
  }

  try {
    const parsed = JSON.parse(raw);
    noteInput(label, filePath, "FOUND", stat.size, sha, null);
    return parsed;
  } catch (error) {
    noteInput(label, filePath, "INVALID", stat.size, sha, `Invalid JSON: ${(error as Error).message}`);
    return null;
  }
}

function writeJson(name: string, data: unknown) {
  ensureDir(OUT_DIR);
  fs.writeFileSync(path.join(OUT_DIR, name), JSON.stringify(data, null, 2), "utf8");
}

function normalizeMythrilSeverity(value: unknown): "HIGH" | "MEDIUM" | "LOW" | "INFO" {
  const v = String(value ?? "").toLowerCase().trim();
  if (v === "high" || v === "error" || v === "fatal") return "HIGH";
  if (v === "medium" || v === "warning") return "MEDIUM";
  if (v === "low") return "LOW";
  return "INFO";
}

function normalizeSlitherSeverity(check: string, impact?: string): FindingSeverity {
  const mapped = SLITHER_RULE_MAP[check];
  if (mapped) return mapped;

  const v = String(impact ?? "").toLowerCase().trim();
  if (v === "high") return "HIGH";
  if (v === "medium") return "MEDIUM";
  if (v === "low") return "LOW";
  return "INFO";
}

function normalizeDefiSeverity(value: unknown): "HIGH" | "MEDIUM" | "LOW" | "INFO" {
  const v = String(value ?? "").toUpperCase().trim();
  if (v === "HIGH" || v === "MEDIUM" || v === "LOW" || v === "INFO") return v as "HIGH" | "MEDIUM" | "LOW" | "INFO";
  return "INFO";
}

function normalizeGeneralSeverity(value: unknown): Severity {
  const v = String(value ?? "").toUpperCase().trim();
  if (v === "CRITICAL" || v === "HIGH" || v === "MEDIUM" || v === "LOW" || v === "INFO") return v as Severity;
  return "UNKNOWN";
}

function inferFindingStatus(severity: FindingSeverity): FindingStatus {
  if (severity === "HIGH") return "BLOCKING";
  if (severity === "MEDIUM") return "OPEN";
  if (severity === "LOW") return "ACKNOWLEDGED";
  return "INFORMATIONAL";
}

function parseSlitherFindings(): NormalizedFinding[] {
  const results: NormalizedFinding[] = [];

  for (const report of REPORTS.slither) {
    const data = readJsonRequired(report.file, report.label);
    const detectors = Array.isArray(data?.results?.detectors) ? data.results.detectors : [];

    for (const item of detectors) {
      const elements = Array.isArray(item?.elements) ? item.elements : [];
      const first = elements[0] ?? {};
      const source = first?.source_mapping ?? {};
      const lines = Array.isArray(source?.lines) ? source.lines.join(",") : "";
      const contract =
        first?.type_specific_fields?.parent?.name ??
        first?.type_specific_fields?.parent?.type ??
        "UnknownContract";

      const severity = normalizeSlitherSeverity(String(item?.check ?? "unknown"), item?.impact);
      const location = source?.filename_relative
        ? `${source.filename_relative}${lines ? `:${lines}` : ""}`
        : null;

      results.push({
        id: `FND-${String(results.length + 1).padStart(4, "0")}`,
        record_type: "finding",
        source: "slither",
        source_report: report.label,
        tool: "slither",
        rule: String(item?.check ?? "unknown"),
        title: String(item?.check ?? "Slither finding"),
        summary: String(item?.description ?? "").replace(/\s+/g, " ").trim(),
        severity,
        status: inferFindingStatus(severity),
        asset: {
          type: "SMART_CONTRACT",
          name: contract,
          network: "local-hardhat",
          location
        },
        confidence: item?.confidence ? String(item.confidence) : null,
        recommendation: "Review the flagged code path, remediate the vulnerability, and rerun the static scan.",
        evidence: {
          report: report.label,
          location,
          raw_ref: report.file
        },
        timestamps: {
          created_at: NOW,
          updated_at: null,
          observed_at: NOW
        },
        metadata: {
          impact: item?.impact ?? null,
          check: item?.check ?? null
        }
      });
    }
  }

  return results;
}

function parseMythrilFindings(startIndex: number): NormalizedFinding[] {
  const results: NormalizedFinding[] = [];
  for (const report of REPORTS.mythril) {
    const data = readJsonRequired(report.file, report.label);
    const issues = Array.isArray(data?.issues) ? data.issues : [];

    for (const item of issues) {
      const severity = normalizeMythrilSeverity(item?.severity);
      const location =
        item?.filename && item?.lineno
          ? `${item.filename}:${item.lineno}`
          : item?.filename
          ? String(item.filename)
          : null;

      results.push({
        id: `FND-${String(startIndex + results.length + 1).padStart(4, "0")}`,
        record_type: "finding",
        source: "mythril",
        source_report: report.label,
        tool: "mythril",
        rule: String(item?.["swc-id"] ?? item?.title ?? "unknown"),
        title: String(item?.title ?? "Mythril issue"),
        summary: String(item?.description ?? "").replace(/\s+/g, " ").trim(),
        severity,
        status: inferFindingStatus(severity),
        asset: {
          type: "SMART_CONTRACT",
          name: String(item?.contract ?? "UnknownContract"),
          network: "local-hardhat",
          location
        },
        confidence: null,
        recommendation: "Review symbolic execution findings, patch the vulnerable logic, and rerun analysis.",
        evidence: {
          report: report.label,
          location,
          raw_ref: report.file
        },
        timestamps: {
          created_at: NOW,
          updated_at: null,
          observed_at: NOW
        },
        metadata: {
          swc_id: item?.["swc-id"] ?? null,
          function: item?.function ?? null
        }
      });
    }
  }
  return results;
}

function parseDefiFindings(startIndex: number): NormalizedFinding[] {
  const results: NormalizedFinding[] = [];
  for (const report of REPORTS.defi) {
    const data = readJsonRequired(report.file, report.label);
    const alerts = Array.isArray(data?.alerts) ? data.alerts : [];

    for (const item of alerts) {
      const severity = normalizeDefiSeverity(item?.severity);
      const contract = Array.isArray(item?.protocols) && item.protocols.length
        ? item.protocols.join(", ")
        : "RuntimeProtocol";
      const location = Array.isArray(item?.tx_hashes) && item.tx_hashes.length
        ? `tx=${item.tx_hashes.join(",")}`
        : null;

      results.push({
        id: `FND-${String(startIndex + results.length + 1).padStart(4, "0")}`,
        record_type: "finding",
        source: "defi-detector",
        source_report: report.label,
        tool: "defi-detector",
        rule: String(item?.rule_id ?? "unknown"),
        title: String(item?.title ?? "DeFi detector alert"),
        summary: String(item?.description ?? "").replace(/\s+/g, " ").trim(),
        severity,
        status: inferFindingStatus(severity),
        asset: {
          type: "PROTOCOL_ACTIVITY",
          name: contract,
          network: String(item?.network ?? "unknown"),
          location
        },
        confidence: null,
        recommendation: "Investigate the suspicious runtime behavior and confirm whether exploit conditions exist.",
        evidence: {
          report: report.label,
          location,
          raw_ref: report.file
        },
        timestamps: {
          created_at: NOW,
          updated_at: null,
          observed_at: NOW
        },
        metadata: {
          tx_hashes: Array.isArray(item?.tx_hashes) ? item.tx_hashes : [],
          protocols: Array.isArray(item?.protocols) ? item.protocols : []
        }
      });
    }
  }
  return results;
}

function parseConsensusFindings(startIndex: number): NormalizedFinding[] {
  const results: NormalizedFinding[] = [];
  for (const report of REPORTS.consensus) {
    const data = readJsonRequired(report.file, report.label);
    const severity = normalizeDefiSeverity(data?.health);
    const network = String(data?.network ?? "unknown-network");
    const latestBlock = Number(data?.latest_block_number ?? 0);
    const seconds = Number(data?.seconds_since_last_block ?? 0);

    results.push({
      id: `FND-${String(startIndex + results.length + 1).padStart(4, "0")}`,
      record_type: "finding",
      source: "consensus-monitor",
      source_report: report.label,
      tool: "consensus-monitor",
      rule: "consensus-health",
      title: "Consensus / chain health status",
      summary: [
        data?.details ? String(data.details) : "",
        `Network: ${network}`,
        `Latest block: ${latestBlock}`,
        `Seconds since last block: ${seconds}`
      ].filter(Boolean).join(". "),
      severity,
      status: inferFindingStatus(severity),
      asset: {
        type: "BLOCKCHAIN_NETWORK",
        name: network,
        network,
        location: null
      },
      confidence: null,
      recommendation: "Verify node health, RPC connectivity, and block production timing before promotion.",
      evidence: {
        report: report.label,
        location: null,
        raw_ref: report.file
      },
      timestamps: {
        created_at: NOW,
        updated_at: null,
        observed_at: NOW
      },
      metadata: {
        latest_block_number: latestBlock,
        seconds_since_last_block: seconds
      }
    });
  }
  return results;
}

function parseIncidents(): NormalizedIncident[] {
  const incidents: NormalizedIncident[] = [];

  for (const report of REPORTS.incident) {
    const data = readJsonOptional(report.file, report.label);
    const rows = Array.isArray(data?.incidents) ? data.incidents : [];

    for (const item of rows) {
      incidents.push({
        id: String(item?.id ?? `INC-${String(incidents.length + 1).padStart(4, "0")}`),
        record_type: "incident",
        source: "incident-orchestrator",
        source_report: report.label,
        title: String(item?.title ?? "Incident"),
        summary: String(item?.rationale ?? item?.title ?? "Incident summary"),
        severity: String(item?.severity ?? "INFO") as "HIGH" | "MEDIUM" | "LOW" | "INFO",
        status: String(item?.status ?? "OPEN") as IncidentStatus,
        owner: String(item?.owner ?? "Unassigned"),
        action: String(item?.action ?? "LOG_ONLY") as IncidentAction,
        affected_component: String(item?.affected_component ?? "unknown"),
        rationale: String(item?.rationale ?? ""),
        remediation: String(item?.remediation ?? ""),
        evidence: {
          report: String(item?.evidence?.report ?? report.label),
          location: item?.evidence?.location ? String(item.evidence.location) : null,
          description: String(item?.evidence?.description ?? ""),
          raw_ref: report.file
        },
        timestamps: {
          created_at: String(item?.created_at ?? NOW),
          updated_at: null,
          closed_at: null
        },
        metadata: {
          tool: item?.tool ?? null,
          rule: item?.rule ?? null
        }
      });
    }
  }

  return incidents;
}

function parseWallets(): NormalizedWallet[] {
  const results: NormalizedWallet[] = [];

  for (const report of REPORTS.wallets) {
    const data = readJsonOptional(report.file, report.label);
    const rows =
      Array.isArray(data?.records) ? data.records :
      Array.isArray(data?.wallets) ? data.wallets :
      Array.isArray(data?.results) ? data.results :
      [];

    for (const item of rows) {
      const riskScore = item?.risk_score != null ? Number(item.risk_score) : null;
      const riskLevel = normalizeGeneralSeverity(item?.risk_level ?? item?.severity);
      const address = String(item?.wallet_address ?? item?.address ?? item?.wallet ?? `wallet-${results.length + 1}`);

      let status: WalletStatus = "SCREENED";
      const statusRaw = String(item?.status ?? "").toUpperCase().trim();
      if (statusRaw === "REVIEW_REQUIRED" || statusRaw === "ALLOW_LISTED" || statusRaw === "BLOCKED" || statusRaw === "ERROR" || statusRaw === "SCREENED") {
        status = statusRaw as WalletStatus;
      } else if (riskLevel === "HIGH" || riskLevel === "CRITICAL") {
        status = "REVIEW_REQUIRED";
      }

      results.push({
        id: `WLT-${String(results.length + 1).padStart(4, "0")}`,
        record_type: "wallet",
        wallet_address: address,
        network: item?.network ? String(item.network) : null,
        label: item?.label ? String(item.label) : null,
        risk_score: Number.isFinite(riskScore as number) ? riskScore : null,
        risk_level: riskLevel,
        status,
        screening_result: String(item?.screening_result ?? item?.result ?? "screened"),
        matched_lists: Array.isArray(item?.matched_lists) ? item.matched_lists.map(String) : [],
        source: report.label,
        timestamps: {
          screened_at: item?.screened_at ? String(item.screened_at) : NOW,
          updated_at: null
        },
        metadata: {
          raw_status: item?.status ?? null
        }
      });
    }
  }

  return results;
}

function parseCompliance(): NormalizedCompliance[] {
  const results: NormalizedCompliance[] = [];

  for (const report of REPORTS.compliance) {
    const data = readJsonOptional(report.file, report.label);
    const rows =
      Array.isArray(data?.cases) ? data.cases :
      Array.isArray(data?.results) ? data.results :
      [];

    for (const item of rows) {
      const decisionRaw = String(item?.decision ?? item?.result ?? "ALLOW").toUpperCase().trim();
      const decision: ComplianceDecision =
        decisionRaw === "BLOCK" || decisionRaw === "REVIEW" || decisionRaw === "REPORT" || decisionRaw === "ALLOW"
          ? decisionRaw as ComplianceDecision
          : "ALLOW";

      let status: ComplianceStatus = "APPROVED";
      if (decision === "BLOCK") status = "BLOCKED";
      else if (decision === "REVIEW") status = "UNDER_REVIEW";
      else if (decision === "REPORT") status = "REPORTED";

      const subjectTypeRaw = String(item?.subject_type ?? "UNKNOWN").toUpperCase().trim();
      const subjectType =
        subjectTypeRaw === "TRANSACTION" || subjectTypeRaw === "WALLET" || subjectTypeRaw === "CONTRACT" || subjectTypeRaw === "CASE"
          ? subjectTypeRaw as "TRANSACTION" | "WALLET" | "CONTRACT" | "CASE"
          : "UNKNOWN";

      results.push({
        id: `CMP-${String(results.length + 1).padStart(4, "0")}`,
        record_type: "compliance",
        subject_type: subjectType,
        subject_id: String(item?.subject_id ?? item?.wallet_address ?? item?.tx_hash ?? item?.contract ?? `subject-${results.length + 1}`),
        decision,
        status,
        jurisdiction: item?.jurisdiction ? String(item.jurisdiction) : null,
        rule_hits: Array.isArray(item?.rule_hits) ? item.rule_hits.map(String) : [],
        rationale: String(item?.rationale ?? item?.reason ?? `${decision} decision`),
        source: report.label,
        timestamps: {
          created_at: item?.created_at ? String(item.created_at) : NOW,
          updated_at: null
        },
        metadata: {
          raw: item
        }
      });
    }
  }

  return results;
}

function parseCases(): NormalizedCase[] {
  const results: NormalizedCase[] = [];

  for (const report of REPORTS.cases) {
    const data = readJsonOptional(report.file, report.label);
    const rows =
      Array.isArray(data?.cases) ? data.cases :
      Array.isArray(data?.results) ? data.results :
      [];

    for (const item of rows) {
      const priorityRaw = String(item?.priority ?? "P3").toUpperCase().trim();
      const statusRaw = String(item?.status ?? "QUEUED").toUpperCase().trim();

      const priority: CasePriority = priorityRaw === "P1" || priorityRaw === "P2" || priorityRaw === "P3" || priorityRaw === "P4"
        ? priorityRaw as CasePriority
        : "P3";

      const status: CaseStatus =
        statusRaw === "QUEUED" || statusRaw === "UNDER_REVIEW" || statusRaw === "ESCALATED" || statusRaw === "CLOSED"
          ? statusRaw as CaseStatus
          : "QUEUED";

      results.push({
        id: String(item?.id ?? `CAS-${String(results.length + 1).padStart(4, "0")}`),
        record_type: "case",
        title: String(item?.title ?? `Case ${results.length + 1}`),
        priority,
        status,
        linked_subjects: Array.isArray(item?.linked_subjects) ? item.linked_subjects.map(String) : [],
        assigned_to: item?.assigned_to ? String(item.assigned_to) : null,
        source: report.label,
        timestamps: {
          created_at: item?.created_at ? String(item.created_at) : NOW,
          updated_at: item?.updated_at ? String(item.updated_at) : null,
          closed_at: item?.closed_at ? String(item.closed_at) : null
        },
        metadata: {
          raw: item
        }
      });
    }
  }

  return results;
}

function parseAlerts(incidents: NormalizedIncident[]): NormalizedAlert[] {
  const results: NormalizedAlert[] = [];

  for (const report of REPORTS.alerts) {
    const data = readJsonOptional(report.file, report.label);
    const rows = Array.isArray(data?.alerts) ? data.alerts : Array.isArray(data) ? data : [];

    for (const item of rows) {
      const severity = normalizeGeneralSeverity(item?.severity);
      const statusRaw = String(item?.status ?? "PENDING").toUpperCase().trim();
      const channelRaw = String(item?.channel ?? "WEBHOOK").toUpperCase().trim();

      const status: AlertStatus =
        statusRaw === "PENDING" || statusRaw === "SENT" || statusRaw === "DELIVERED" || statusRaw === "FAILED" || statusRaw === "ACKNOWLEDGED"
          ? statusRaw as AlertStatus
          : "PENDING";

      const channel: AlertChannel =
        channelRaw === "SLACK" || channelRaw === "EMAIL" || channelRaw === "WEBHOOK" || channelRaw === "TEAMS" || channelRaw === "SIEM"
          ? channelRaw as AlertChannel
          : "WEBHOOK";

      results.push({
        id: String(item?.id ?? `ALT-${String(results.length + 1).padStart(4, "0")}`),
        record_type: "alert",
        title: String(item?.title ?? item?.message ?? `Alert ${results.length + 1}`),
        severity,
        status,
        channel,
        recipient: item?.recipient ? String(item.recipient) : null,
        related_record_type: item?.related_record_type ? String(item.related_record_type) : null,
        related_record_id: item?.related_record_id ? String(item.related_record_id) : null,
        source: report.label,
        timestamps: {
          created_at: item?.created_at ? String(item.created_at) : NOW,
          sent_at: item?.sent_at ? String(item.sent_at) : null,
          acknowledged_at: item?.acknowledged_at ? String(item.acknowledged_at) : null
        },
        metadata: {
          raw: item
        }
      });
    }
  }

  if (results.length === 0) {
    for (const incident of incidents) {
      results.push({
        id: `ALT-${String(results.length + 1).padStart(4, "0")}`,
        record_type: "alert",
        title: `Alert for ${incident.id}`,
        severity: normalizeGeneralSeverity(incident.severity),
        status: "SENT",
        channel: "WEBHOOK",
        recipient: incident.owner,
        related_record_type: "incident",
        related_record_id: incident.id,
        source: "derived-from-incidents",
        timestamps: {
          created_at: incident.timestamps.created_at,
          sent_at: incident.timestamps.created_at,
          acknowledged_at: null
        },
        metadata: {
          derived: true,
          incident_action: incident.action
        }
      });
    }
  }

  return results;
}

function buildEvidence(
  findings: NormalizedFinding[],
  incidents: NormalizedIncident[],
  wallets: NormalizedWallet[],
  compliance: NormalizedCompliance[],
  cases: NormalizedCase[],
  alerts: NormalizedAlert[]
): NormalizedEvidence[] {
  const evidence: NormalizedEvidence[] = [];

  const pushEvidence = (
    evidenceType: string,
    title: string,
    description: string,
    source: string,
    sourceFile: string | null,
    sourceReport: string | null,
    relatedRecordType: string | null,
    relatedRecordId: string | null,
    derivationStage: string | null,
    originPath: string | null,
    metadata: Record<string, any>
  ) => {
    const textForHash = JSON.stringify({ title, description, source, sourceFile, sourceReport, relatedRecordType, relatedRecordId, derivationStage, metadata });
    evidence.push({
      id: `EVD-${String(evidence.length + 1).padStart(4, "0")}`,
      record_type: "evidence",
      evidence_type: evidenceType,
      title,
      description,
      source,
      source_file: sourceFile,
      source_report: sourceReport,
      related_record_type: relatedRecordType,
      related_record_id: relatedRecordId,
      derivation_stage: derivationStage,
      collector: "normalize-reports.mts",
      collection_notes: "Derived during normalization from source security and compliance reports.",
      integrity: {
        sha256: sha256Text(textForHash),
        content_length: textForHash.length,
        hash_scope: "RECORD"
      },
      provenance: {
        origin_system: source,
        origin_path: originPath,
        observed_at: NOW,
        generated_at: NOW
      },
      timestamps: {
        created_at: NOW,
        updated_at: null
      },
      metadata
    });
  };

  for (const item of findings) {
    pushEvidence(
      "FINDING_RECORD",
      item.title,
      item.summary,
      item.source,
      item.evidence.raw_ref,
      item.source_report,
      "finding",
      item.id,
      "NORMALIZATION",
      item.asset.location,
      {
        severity: item.severity,
        rule: item.rule,
        asset: item.asset
      }
    );
  }

  for (const item of incidents) {
    pushEvidence(
      "INCIDENT_RECORD",
      item.title,
      item.evidence.description || item.summary,
      item.source,
      item.evidence.raw_ref,
      item.source_report,
      "incident",
      item.id,
      "INCIDENT_ORCHESTRATION",
      item.evidence.location,
      {
        severity: item.severity,
        action: item.action,
        owner: item.owner
      }
    );
  }

  for (const item of wallets) {
    pushEvidence(
      "WALLET_SCREENING",
      item.wallet_address,
      `Wallet screening result: ${item.screening_result}`,
      item.source,
      "reports/wallet-screening/wallet_screening.json",
      item.source,
      "wallet",
      item.id,
      "WALLET_SCREENING",
      item.wallet_address,
      {
        risk_level: item.risk_level,
        risk_score: item.risk_score,
        matched_lists: item.matched_lists
      }
    );
  }

  for (const item of compliance) {
    pushEvidence(
      "COMPLIANCE_DECISION",
      item.subject_id,
      item.rationale,
      item.source,
      "reports/compliance/compliance_report.json",
      item.source,
      "compliance",
      item.id,
      "COMPLIANCE_ASSESSMENT",
      item.subject_id,
      {
        decision: item.decision,
        subject_type: item.subject_type,
        rule_hits: item.rule_hits
      }
    );
  }

  for (const item of cases) {
    pushEvidence(
      "CASE_RECORD",
      item.title,
      `Case status: ${item.status}`,
      item.source,
      "reports/cases/case_management.json",
      item.source,
      "case",
      item.id,
      "CASE_MANAGEMENT",
      item.id,
      {
        priority: item.priority,
        linked_subjects: item.linked_subjects
      }
    );
  }

  for (const item of alerts) {
    pushEvidence(
      "ALERT_RECORD",
      item.title,
      `Alert channel ${item.channel} status ${item.status}`,
      item.source,
      "reports/alerts/alerts.json",
      item.source,
      "alert",
      item.id,
      "ALERT_DISPATCH",
      item.related_record_id,
      {
        severity: item.severity,
        channel: item.channel,
        recipient: item.recipient
      }
    );
  }

  return evidence;
}

function countBy<T>(rows: T[], selector: (item: T) => string): Record<string, number> {
  return rows.reduce<Record<string, number>>((acc, item) => {
    const key = selector(item) || "UNKNOWN";
    acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {});
}

function buildDashboardSummary(
  findings: NormalizedFinding[],
  incidents: NormalizedIncident[],
  wallets: NormalizedWallet[],
  compliance: NormalizedCompliance[],
  cases: NormalizedCase[]
): DashboardSummary {
  const inputCounts = {
    found: inputPresence.filter((x) => x.state === "FOUND").length,
    missing: inputPresence.filter((x) => x.state === "MISSING").length,
    empty: inputPresence.filter((x) => x.state === "EMPTY").length,
    invalid: inputPresence.filter((x) => x.state === "INVALID").length
  };

  const pipelineStatus: PipelineStatus =
    findings.some((x) => x.severity === "HIGH") || compliance.some((x) => x.decision === "BLOCK")
      ? "FAIL"
      : inputCounts.missing > 0 || inputCounts.invalid > 0 || inputCounts.empty > 0
      ? "PARTIAL"
      : findings.length > 0
      ? "PASS"
      : "UNKNOWN";

  return {
    generated_at: NOW,
    pipeline_status: pipelineStatus,
    last_pipeline_run: NOW,
    kpis: {
      total_findings: findings.length,
      high_findings: findings.filter((x) => x.severity === "HIGH").length,
      total_incidents: incidents.length,
      high_risk_wallets: wallets.filter((x) => x.risk_level === "HIGH" || x.risk_level === "CRITICAL").length,
      block_cases: compliance.filter((x) => x.decision === "BLOCK").length,
      escalated_cases: cases.filter((x) => x.status === "ESCALATED").length
    },
    breakdowns: {
      findings_by_severity: countBy(findings, (x) => x.severity),
      incidents_by_severity: countBy(incidents, (x) => x.severity),
      compliance_by_decision: countBy(compliance, (x) => x.decision),
      cases_by_status: countBy(cases, (x) => x.status)
    },
    input_presence: {
      total_declared_inputs: inputPresence.length,
      found: inputCounts.found,
      missing: inputCounts.missing,
      empty: inputCounts.empty,
      invalid: inputCounts.invalid,
      files: inputPresence
    }
  };
}

function main() {
  try {
    ensureDir(OUT_DIR);

    const slitherFindings = parseSlitherFindings();
    const mythrilFindings = parseMythrilFindings(slitherFindings.length);
    const defiFindings = parseDefiFindings(slitherFindings.length + mythrilFindings.length);
    const consensusFindings = parseConsensusFindings(slitherFindings.length + mythrilFindings.length + defiFindings.length);

    const findings = [
      ...slitherFindings,
      ...mythrilFindings,
      ...defiFindings,
      ...consensusFindings
    ];

    const incidents = parseIncidents();
    const wallets = parseWallets();
    const compliance = parseCompliance();
    const cases = parseCases();
    const alerts = parseAlerts(incidents);
    const evidence = buildEvidence(findings, incidents, wallets, compliance, cases, alerts);
    const summary = buildDashboardSummary(findings, incidents, wallets, compliance, cases);

    writeJson("dashboard-summary.json", summary);
    writeJson("findings.json", findings);
    writeJson("incidents.json", incidents);
    writeJson("wallets.json", wallets);
    writeJson("compliance.json", compliance);
    writeJson("cases.json", cases);
    writeJson("alerts.json", alerts);
    writeJson("evidence.json", evidence);

    console.log("=== Normalize Reports Summary ===");
    console.log(`Findings       : ${findings.length}`);
    console.log(`Incidents      : ${incidents.length}`);
    console.log(`Wallets        : ${wallets.length}`);
    console.log(`Compliance     : ${compliance.length}`);
    console.log(`Cases          : ${cases.length}`);
    console.log(`Alerts         : ${alerts.length}`);
    console.log(`Evidence       : ${evidence.length}`);
    console.log(`Inputs tracked : ${inputPresence.length}`);
    console.log(`Output dir     : dashboard/data`);
  } catch (error) {
    console.error(`\n[FAIL] normalize-reports.mts could not complete: ${(error as Error).message}`);
    process.exit(1);
  }
}

main();