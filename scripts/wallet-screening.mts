import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
type WalletStatus = "SCREENED" | "REVIEW_REQUIRED" | "ALLOW_LISTED" | "BLOCKED" | "ERROR";

type WalletScreeningRecord = {
  id: string;
  wallet_address: string;
  network: string;
  label: string | null;
  risk_score: number;
  risk_level: RiskLevel;
  status: WalletStatus;
  screening_result: string;
  matched_lists: string[];
  flags: string[];
  screening_reason: string;
  source_signals: string[];
  evidence_refs: string[];
  screened_at: string;
  metadata: {
    source_reports: string[];
    sha256_fingerprint: string;
    derived_from_rule_ids: string[];
    tx_hashes: string[];
  };
};

type WalletScreeningSummary = {
  total_records: number;
  critical_risk: number;
  high_risk: number;
  medium_risk: number;
  low_risk: number;
  info_risk: number;
  review_required: number;
  allow_listed: number;
  blocked: number;
};

type WalletScreeningOutput = {
  generated_at: string;
  summary: WalletScreeningSummary;
  records: WalletScreeningRecord[];
};

const ROOT = process.cwd();
const OUT_DIR = path.join(ROOT, "reports", "wallet-screening");
const OUT_FILE = path.join(OUT_DIR, "wallet_screening.json");

const INPUTS = {
  defi: { file: "reports/defi/defi_alerts.json", label: "defi-runtime-monitor" },
  incident: { file: "reports/incident/incident_response.json", label: "incident-orchestrator" },
  consensus: { file: "reports/consensus/consensus_status.json", label: "consensus-health" }
};

function ensureDir(dirPath: string) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function readJsonOptional(filePath: string): any | null {
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

function sha256(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function normalizeAddress(value: unknown): string | null {
  const v = String(value ?? "").trim();
  if (!v) return null;

  if (/^0x[a-fA-F0-9]{40}$/.test(v)) return v.toLowerCase();

  if (/^0x[A-Za-z0-9]{4,32}$/.test(v)) return v;

  return null;
}

function extractAddressesFromText(value: unknown): string[] {
  const text = String(value ?? "");
  if (!text) return [];

  const matches = text.match(/0x[a-zA-Z0-9]{4,40}/g) || [];
  return uniq(
    matches
      .map((m) => normalizeAddress(m))
      .filter(Boolean) as string[]
  );
}

function toArray(value: unknown): any[] {
  return Array.isArray(value) ? value : [];
}

function uniq(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

function scoreToLevel(score: number): RiskLevel {
  if (score >= 90) return "CRITICAL";
  if (score >= 75) return "HIGH";
  if (score >= 50) return "MEDIUM";
  if (score >= 20) return "LOW";
  return "INFO";
}

function levelToStatus(level: RiskLevel): WalletStatus {
  if (level === "CRITICAL") return "BLOCKED";
  if (level === "HIGH") return "REVIEW_REQUIRED";
  if (level === "MEDIUM") return "REVIEW_REQUIRED";
  if (level === "LOW") return "SCREENED";
  return "ALLOW_LISTED";
}

function buildReason(level: RiskLevel, flags: string[], matchedLists: string[]): string {
  const parts: string[] = [];
  parts.push(`Risk level assessed as ${level}`);
  if (flags.length) parts.push(`Flags: ${flags.join(", ")}`);
  if (matchedLists.length) parts.push(`Matched lists: ${matchedLists.join(", ")}`);
  return parts.join(". ");
}

function collectWalletCandidates(): Array<{
  wallet_address: string;
  network: string;
  label: string | null;
  source_report: string;
  tx_hashes: string[];
  rule_ids: string[];
  source_signals: string[];
  matched_lists: string[];
  flags: string[];
  base_score: number;
}> {
  const candidates: Array<{
    wallet_address: string;
    network: string;
    label: string | null;
    source_report: string;
    tx_hashes: string[];
    rule_ids: string[];
    source_signals: string[];
    matched_lists: string[];
    flags: string[];
    base_score: number;
  }> = [];

  const defi = readJsonOptional(INPUTS.defi.file);
  const incident = readJsonOptional(INPUTS.incident.file);
  const consensus = readJsonOptional(INPUTS.consensus.file);

  const defiAlerts = toArray(defi?.alerts);
  for (const alert of defiAlerts) {
    const addresses = uniq([
      ...toArray(alert?.wallets).map((x) => normalizeAddress(x)),
      ...toArray(alert?.addresses).map((x) => normalizeAddress(x)),
      normalizeAddress(alert?.wallet_address),
      normalizeAddress(alert?.counterparty),
      normalizeAddress(alert?.from),
      normalizeAddress(alert?.to),
      ...extractAddressesFromText(alert?.description),
      ...extractAddressesFromText(alert?.title),
      ...toArray(alert?.events).flatMap((event) => [
        normalizeAddress(event?.address),
        normalizeAddress(event?.counterparty),
        ...extractAddressesFromText(event?.address),
        ...extractAddressesFromText(event?.counterparty)
      ])
    ].filter(Boolean) as string[]);

    const protocols = toArray(alert?.protocols).map(String);
    const txHashes = toArray(alert?.tx_hashes).map(String);
    const ruleId = String(alert?.rule_id ?? "unknown-rule");
    const severity = String(alert?.severity ?? "INFO").toUpperCase().trim();

    let baseScore = 20;
    if (severity === "HIGH") baseScore = 80;
    else if (severity === "MEDIUM") baseScore = 55;
    else if (severity === "LOW") baseScore = 30;

    const matchedLists: string[] = [];
    const flags: string[] = [];
    const title = String(alert?.title ?? "").toLowerCase();
    const description = String(alert?.description ?? "").toLowerCase();

    if (title.includes("mixer") || description.includes("mixer")) {
      matchedLists.push("MIXER_EXPOSURE");
      flags.push("mixer_interaction");
      baseScore += 10;
    }

    if (title.includes("drain") || description.includes("drain") || title.includes("exploit") || description.includes("exploit")) {
      matchedLists.push("EXPLOIT_ACTIVITY");
      flags.push("exploit_pattern");
      baseScore += 10;
    }

    if (title.includes("sanction") || description.includes("sanction")) {
      matchedLists.push("SANCTIONS");
      flags.push("sanctions_exposure");
      baseScore += 20;
    }

    for (const address of addresses) {
      candidates.push({
        wallet_address: address,
        network: String(alert?.network ?? "ethereum"),
        label: protocols.length ? protocols.join(", ") : null,
        source_report: INPUTS.defi.label,
        tx_hashes: txHashes,
        rule_ids: [ruleId],
        source_signals: [`DeFi alert: ${String(alert?.title ?? "unnamed-alert")}`],
        matched_lists: uniq(matchedLists),
        flags: uniq(flags),
        base_score: Math.min(baseScore, 100)
      });
    }
  }

  const incidents = toArray(incident?.incidents);
  for (const item of incidents) {
    const location = String(item?.evidence?.location ?? "");
    const txMatch = location.match(/tx=([^,\s]+)/);
    const txHashes = txMatch ? [txMatch[1]] : [];
    const component = String(item?.affected_component ?? "");
    const wallet = normalizeAddress(component);

    if (!wallet) continue;

    let baseScore = 35;
    const severity = String(item?.severity ?? "INFO").toUpperCase().trim();
    if (severity === "HIGH") baseScore = 85;
    else if (severity === "MEDIUM") baseScore = 60;
    else if (severity === "LOW") baseScore = 30;

    const action = String(item?.action ?? "");
    const matchedLists: string[] = [];
    const flags: string[] = [];

    if (action === "BLOCK_BUILD") {
      matchedLists.push("BLOCKED_INTERNAL_POLICY");
      flags.push("policy_block");
      baseScore += 10;
    }

    candidates.push({
      wallet_address: wallet,
      network: "ethereum",
      label: "Incident-linked wallet",
      source_report: INPUTS.incident.label,
      tx_hashes,
      rule_ids: [String(item?.rule ?? "unknown-rule")],
      source_signals: [`Incident: ${String(item?.title ?? "unnamed-incident")}`],
      matched_lists: uniq(matchedLists),
      flags: uniq(flags),
      base_score: Math.min(baseScore, 100)
    });
  }

  if (consensus?.health && String(consensus.health).toUpperCase() === "HIGH") {
  }

  return candidates;
}

function mergeCandidates(candidates: ReturnType<typeof collectWalletCandidates>): WalletScreeningRecord[] {
  const grouped = new Map<string, {
    wallet_address: string;
    network: string;
    label: string | null;
    source_reports: string[];
    tx_hashes: string[];
    rule_ids: string[];
    source_signals: string[];
    matched_lists: string[];
    flags: string[];
    score: number;
  }>();

  for (const item of candidates) {
    const existing = grouped.get(item.wallet_address);
    if (!existing) {
      grouped.set(item.wallet_address, {
        wallet_address: item.wallet_address,
        network: item.network,
        label: item.label,
        source_reports: [item.source_report],
        tx_hashes: [...item.tx_hashes],
        rule_ids: [...item.rule_ids],
        source_signals: [...item.source_signals],
        matched_lists: [...item.matched_lists],
        flags: [...item.flags],
        score: item.base_score
      });
      continue;
    }

    existing.source_reports.push(item.source_report);
    existing.tx_hashes.push(...item.tx_hashes);
    existing.rule_ids.push(...item.rule_ids);
    existing.source_signals.push(...item.source_signals);
    existing.matched_lists.push(...item.matched_lists);
    existing.flags.push(...item.flags);
    existing.score = Math.min(100, Math.max(existing.score, item.base_score) + Math.min(item.matched_lists.length * 3, 10));
  }

  const now = new Date().toISOString();

  return [...grouped.values()].map((item, index) => {
    const matchedLists = uniq(item.matched_lists);
    const flags = uniq(item.flags);
    const sourceReports = uniq(item.source_reports);
    const txHashes = uniq(item.tx_hashes);
    const ruleIds = uniq(item.rule_ids);
    const sourceSignals = uniq(item.source_signals);
    const riskLevel = scoreToLevel(item.score);
    const status = levelToStatus(riskLevel);
    const fingerprint = sha256(JSON.stringify({
      wallet_address: item.wallet_address,
      network: item.network,
      sourceReports,
      matchedLists,
      flags,
      txHashes,
      ruleIds
    }));

    return {
      id: `WLT-${String(index + 1).padStart(4, "0")}`,
      wallet_address: item.wallet_address,
      network: item.network,
      label: item.label,
      risk_score: item.score,
      risk_level: riskLevel,
      status,
      screening_result:
        status === "BLOCKED" ? "blocked" :
        status === "REVIEW_REQUIRED" ? "review_required" :
        status === "ALLOW_LISTED" ? "allow_listed" :
        "screened",
      matched_lists: matchedLists,
      flags,
      screening_reason: buildReason(riskLevel, flags, matchedLists),
      source_signals: sourceSignals,
      evidence_refs: txHashes,
      screened_at: now,
      metadata: {
        source_reports: sourceReports,
        sha256_fingerprint: fingerprint,
        derived_from_rule_ids: ruleIds,
        tx_hashes: txHashes
      }
    };
  });
}

function summarize(records: WalletScreeningRecord[]): WalletScreeningSummary {
  return {
    total_records: records.length,
    critical_risk: records.filter((r) => r.risk_level === "CRITICAL").length,
    high_risk: records.filter((r) => r.risk_level === "HIGH").length,
    medium_risk: records.filter((r) => r.risk_level === "MEDIUM").length,
    low_risk: records.filter((r) => r.risk_level === "LOW").length,
    info_risk: records.filter((r) => r.risk_level === "INFO").length,
    review_required: records.filter((r) => r.status === "REVIEW_REQUIRED").length,
    allow_listed: records.filter((r) => r.status === "ALLOW_LISTED").length,
    blocked: records.filter((r) => r.status === "BLOCKED").length
  };
}

function main() {
  try {
    ensureDir(OUT_DIR);

    const candidates = collectWalletCandidates();
    const records = mergeCandidates(candidates);
    const output: WalletScreeningOutput = {
      generated_at: new Date().toISOString(),
      summary: summarize(records),
      records
    };

    fs.writeFileSync(OUT_FILE, JSON.stringify(output, null, 2), "utf8");

    console.log("=== Wallet Screening Summary ===");
    console.log(`Wallets screened : ${output.summary.total_records}`);
    console.log(`Critical risk    : ${output.summary.critical_risk}`);
    console.log(`High risk        : ${output.summary.high_risk}`);
    console.log(`Medium risk      : ${output.summary.medium_risk}`);
    console.log(`Low risk         : ${output.summary.low_risk}`);
    console.log(`Info risk        : ${output.summary.info_risk}`);
    console.log(`Review required  : ${output.summary.review_required}`);
    console.log(`Blocked          : ${output.summary.blocked}`);
    console.log(`Output report    : reports/wallet-screening/wallet_screening.json`);
  } catch (error) {
    console.error(`\n[FAIL] Wallet screening failed: ${(error as Error).message}`);
    process.exit(1);
  }
}

main();