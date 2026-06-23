import fs from "node:fs";
import path from "node:path";

type GateLevel = "HIGH" | "MEDIUM" | "LOW" | "INFO";

type UnifiedFinding = {
  tool: "slither" | "mythril" | "defi-detector" | "consensus-monitor";
  report: string;
  contract: string;
  rule: string;
  severity: GateLevel;
  confidence?: string;
  title: string;
  description: string;
  location?: string;
};

const ROOT = process.cwd();

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

const FAIL_ON: GateLevel[] = ["HIGH"];

const SLITHER_RULE_MAP: Record<string, GateLevel> = {
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

  if (!fs.existsSync(abs)) {
    throw new Error(`Missing required report: ${filePath}`);
  }

  const raw = fs.readFileSync(abs, "utf8").trim();

  if (!raw) {
    throw new Error(`Empty required report: ${filePath}`);
  }

  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error(`Invalid JSON in ${filePath}: ${(error as Error).message}`);
  }
}

function normalizeMythrilSeverity(value: unknown): GateLevel {
  const v = String(value ?? "").toLowerCase().trim();
  if (v === "high" || v === "error" || v === "fatal") return "HIGH";
  if (v === "medium" || v === "warning") return "MEDIUM";
  if (v === "low") return "LOW";
  return "INFO";
}

function normalizeSlitherSeverity(check: string, impact?: string): GateLevel {
  const mapped = SLITHER_RULE_MAP[check];
  if (mapped) return mapped;

  const v = String(impact ?? "").toLowerCase().trim();
  if (v === "high") return "HIGH";
  if (v === "medium") return "MEDIUM";
  if (v === "low") return "LOW";
  return "INFO";
}

function normalizeDefiSeverity(value: unknown): GateLevel {
  const v = String(value ?? "").toUpperCase().trim();
  if (v === "HIGH" || v === "MEDIUM" || v === "LOW" || v === "INFO") return v as GateLevel;
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
  const level: GateLevel =
    health === "HIGH" || health === "MEDIUM" || health === "LOW" || health === "INFO"
      ? (health as GateLevel)
      : "INFO";

  const network = String(data?.network ?? "unknown-network");
  const latestBlock = Number(data?.latest_block_number ?? 0);
  const seconds = Number(data?.seconds_since_last_block ?? 0);

  const descriptionParts = [
    data?.details ? String(data.details) : "",
    `Network: ${network}`,
    `Latest block: ${latestBlock}`,
    `Seconds since last block: ${seconds}`
  ].filter(Boolean);

  return [
    {
      tool: "consensus-monitor",
      report: label,
      contract: network,
      rule: "consensus-health",
      severity: level,
      title: "Consensus / chain health status",
      description: descriptionParts.join(". "),
      location: undefined
    }
  ];
}

function groupBySeverity(findings: UnifiedFinding[]) {
  return {
    HIGH: findings.filter((f) => f.severity === "HIGH"),
    MEDIUM: findings.filter((f) => f.severity === "MEDIUM"),
    LOW: findings.filter((f) => f.severity === "LOW"),
    INFO: findings.filter((f) => f.severity === "INFO")
  };
}

function printFindings(title: string, findings: UnifiedFinding[]) {
  console.log(`\n${title} (${findings.length})`);
  for (const f of findings) {
    const meta = [
      f.tool,
      f.report,
      f.contract,
      f.rule,
      f.location ? `@ ${f.location}` : "",
      f.confidence ? `confidence=${f.confidence}` : ""
    ]
      .filter(Boolean)
      .join(" | ");

    console.log(`- [${f.severity}] ${f.title}`);
    console.log(`  ${meta}`);
    console.log(`  ${f.description}`);
  }
}

function main() {
  try {
    const allFindings: UnifiedFinding[] = [];

    for (const report of REPORTS.slither) {
      allFindings.push(...parseSlitherReport(report.file, report.label));
    }

    for (const report of REPORTS.mythril) {
      allFindings.push(...parseMythrilReport(report.file, report.label));
    }

    for (const report of REPORTS.defi) {
      allFindings.push(...parseDefiReport(report.file, report.label));
    }

    for (const report of REPORTS.consensus) {
      allFindings.push(...parseConsensusReport(report.file, report.label));
    }

    const grouped = groupBySeverity(allFindings);

    console.log("=== Security Gate Summary ===");
    console.log(`Total findings : ${allFindings.length}`);
    console.log(`High           : ${grouped.HIGH.length}`);
    console.log(`Medium         : ${grouped.MEDIUM.length}`);
    console.log(`Low            : ${grouped.LOW.length}`);
    console.log(`Info           : ${grouped.INFO.length}`);

    if (grouped.HIGH.length) printFindings("High severity findings", grouped.HIGH);
    if (grouped.MEDIUM.length) printFindings("Medium severity findings", grouped.MEDIUM);

    const failCount = allFindings.filter((f) => FAIL_ON.includes(f.severity)).length;

    if (failCount > 0) {
      console.error(`\n[FAIL] Security gate blocked the build due to ${failCount} high-severity finding(s).`);
      process.exit(1);
    }

    console.log("\n[PASS] Security gate passed. No blocking findings detected.");
  } catch (error) {
    console.error(`\n[FAIL] Security gate could not complete: ${(error as Error).message}`);
    process.exit(1);
  }
}

main();