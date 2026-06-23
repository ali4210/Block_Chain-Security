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
  tool: string;
  report: string;
  contract: string;
  rule: string;
  severity: Severity;
  confidence?: string;
  title: string;
  description: string;
  location?: string;
  enrichment?: EnrichedMetadata;
};

type EnrichedReport = {
  generated_at: string;
  findings: UnifiedFinding[];
  enrichment_summary: Record<string, number>;
};

const ROOT = process.cwd();
const INPUT_FILE = path.join(ROOT, "dashboard", "data", "findings.json");
const OUTPUT_FILE = path.join(ROOT, "dashboard", "data", "enriched-findings.json");

const ENRICHMENT_MAP: Record<string, EnrichedMetadata> = {
  "reentrancy-eth": {
    swc_id: "SWC-107",
    swc_title: "Reentrancy",
    owasp_sc_top10: "SC05:2025 - Reentrancy Attacks",
    weakness_class: "Reentrancy",
    impact_summary: "An external call may re-enter the contract before internal state is finalized, enabling repeated withdrawals or inconsistent accounting.",
    remediation_summary: "Apply Checks-Effects-Interactions, add ReentrancyGuard, and prefer pull-payment patterns.",
    remediation_steps: [
      "Update internal balances before external calls.",
      "Add OpenZeppelin ReentrancyGuard to sensitive functions.",
      "Prefer pull-over-push withdrawal logic.",
      "Retest with static and symbolic analysis after patching."
    ],
    references: [
      "https://swcregistry.io/docs/SWC-107/",
      "https://owasp.org/www-project-smart-contract-top-10/"
    ]
  },
  "reentrancy-benign": {
    swc_id: "SWC-107",
    swc_title: "Reentrancy",
    owasp_sc_top10: "SC05:2025 - Reentrancy Attacks",
    weakness_class: "Reentrancy",
    impact_summary: "Execution order may still create inconsistent state even when direct theft is not immediately confirmed.",
    remediation_summary: "Harden function sequencing and apply reentrancy-safe state management.",
    remediation_steps: [
      "Move state updates before external interaction.",
      "Use a reentrancy guard where needed.",
      "Review cross-function state dependencies."
    ],
    references: [
      "https://swcregistry.io/docs/SWC-107/",
      "https://owasp.org/www-project-smart-contract-top-10/"
    ]
  },
  "arbitrary-send-eth": {
    swc_id: "SWC-105",
    swc_title: "Unprotected Ether Withdrawal",
    owasp_sc_top10: "SC01:2025 - Access Control Vulnerabilities",
    weakness_class: "Access Control / Unauthorized Asset Movement",
    impact_summary: "A weakly protected withdrawal path may allow unauthorized Ether transfer to attacker-chosen destinations.",
    remediation_summary: "Restrict privileged withdrawals, validate recipients, and enforce role-based authorization.",
    remediation_steps: [
      "Protect administrative transfer functions with strict access control.",
      "Validate recipient and amount constraints.",
      "Add tests for unauthorized drain scenarios."
    ],
    references: [
      "https://owasp.org/www-project-smart-contract-top-10/"
    ]
  },
  "low-level-calls": {
    swc_id: "SWC-104",
    swc_title: "Unchecked Call Return Value",
    owasp_sc_top10: "SC06:2025 - Unchecked External Calls",
    weakness_class: "Unchecked External Calls",
    impact_summary: "Low-level external calls can fail silently or behave unexpectedly if return values are not validated.",
    remediation_summary: "Check call success explicitly and reduce trust in external contracts.",
    remediation_steps: [
      "Check the boolean success result of low-level calls.",
      "Revert on failed external interactions unless failure is intentionally tolerated.",
      "Review callback and fallback behavior."
    ],
    references: [
      "https://owasp.org/www-project-smart-contract-top-10/"
    ]
  },
  "tx-origin": {
    swc_id: "SWC-115",
    swc_title: "Authorization through tx.origin",
    owasp_sc_top10: "SC01:2025 - Access Control Vulnerabilities",
    weakness_class: "Access Control",
    impact_summary: "Using tx.origin for authorization can allow phishing-style call chains to bypass intended trust boundaries.",
    remediation_summary: "Use msg.sender-based authorization and role modifiers instead of tx.origin.",
    remediation_steps: [
      "Replace tx.origin checks with msg.sender checks.",
      "Use Ownable or AccessControl role patterns.",
      "Retest authorization paths after the change."
    ],
    references: [
      "https://swcregistry.io/docs/SWC-115/",
      "https://owasp.org/www-project-smart-contract-top-10/"
    ]
  },
  "timestamp": {
    swc_id: "SWC-116",
    swc_title: "Block values as a proxy for time",
    owasp_sc_top10: "SC03:2025 - Logic Errors",
    weakness_class: "Time / Logic Dependency",
    impact_summary: "Validator-influenced timing values can create manipulation windows in protocol logic.",
    remediation_summary: "Avoid critical trust decisions based solely on timestamp or block number assumptions.",
    remediation_steps: [
      "Use broader timing tolerances.",
      "Avoid timestamp-sensitive critical logic where possible.",
      "Model adversarial timing behavior in tests."
    ],
    references: [
      "https://owasp.org/www-project-smart-contract-top-10/"
    ]
  },
  "weak-prng": {
    swc_id: "SWC-120",
    swc_title: "Weak Sources of Randomness from Chain Attributes",
    owasp_sc_top10: "SC09:2025 - Insecure Randomness",
    weakness_class: "Insecure Randomness",
    impact_summary: "On-chain pseudo-randomness derived from predictable values can be anticipated or manipulated.",
    remediation_summary: "Use verifiable randomness or commit-reveal designs.",
    remediation_steps: [
      "Do not rely only on block timestamp or blockhash.",
      "Use VRF or secure commit-reveal schemes."
    ],
    references: [
      "https://owasp.org/www-project-smart-contract-top-10/"
    ]
  },
  "flash-loan-pattern": {
    owasp_sc_top10: "SC07:2025 - Flash Loan Attacks",
    weakness_class: "Flash Loan Facilitated Attack",
    impact_summary: "The transaction pattern matches borrow-manipulate-repay behavior consistent with flash-loan-assisted exploitation.",
    remediation_summary: "Add protocol invariants, oracle protections, liquidity checks, and slippage guards.",
    remediation_steps: [
      "Model single-transaction capital amplification scenarios.",
      "Harden oracle and governance logic against temporary liquidity manipulation.",
      "Add circuit breakers for abnormal transaction paths."
    ],
    references: [
      "https://owasp.org/www-project-smart-contract-top-10/"
    ]
  },
  "rapid-withdrawals": {
    owasp_sc_top10: "SC05:2025 - Reentrancy Attacks",
    weakness_class: "Rapid Drain / Suspicious Withdrawal Pattern",
    impact_summary: "Rapid repeated withdrawals may indicate exploit execution or compromised account activity.",
    remediation_summary: "Investigate withdrawal controls, rate limits, and abnormal activity protections.",
    remediation_steps: [
      "Review withdrawal rate thresholds.",
      "Add anomaly detection or temporary account freezing logic.",
      "Validate whether the pattern reflects exploit replay behavior."
    ],
    references: [
      "https://owasp.org/www-project-smart-contract-top-10/"
    ]
  },
  "large-transfer": {
    owasp_sc_top10: "SC03:2025 - Logic Errors",
    weakness_class: "Operational / Abnormal Value Movement",
    impact_summary: "Large value movement may indicate misuse, compromised workflow, or a need for stronger transfer safeguards.",
    remediation_summary: "Investigate thresholds, validate counterparties, and apply transfer controls where necessary.",
    remediation_steps: [
      "Review movement against approved operational baselines.",
      "Add rate limits or additional approvals for large transfers."
    ],
    references: [
      "https://owasp.org/www-project-smart-contract-top-10/"
    ]
  },
  "multi-hop-transfer": {
    owasp_sc_top10: "SC03:2025 - Logic Errors",
    weakness_class: "Suspicious Movement Pattern",
    impact_summary: "Multi-hop value transfer chains can indicate laundering, obfuscation, or exploit cash-out behavior.",
    remediation_summary: "Correlate transfers, counterparties, and protocol rules before approving or ignoring the pattern.",
    remediation_steps: [
      "Track linked addresses and timing clusters.",
      "Review whether the flow bypasses intended treasury or bridge constraints."
    ],
    references: [
      "https://owasp.org/www-project-smart-contract-top-10/"
    ]
  },
  "liquidity-spike": {
    owasp_sc_top10: "SC07:2025 - Flash Loan Attacks",
    weakness_class: "Liquidity Manipulation Signal",
    impact_summary: "Sudden liquidity changes may indicate flash-loan-assisted market distortion or exploit staging.",
    remediation_summary: "Add liquidity monitoring thresholds and strengthen dependent pricing logic.",
    remediation_steps: [
      "Review dependent business logic for liquidity sensitivity.",
      "Introduce circuit breakers for abrupt liquidity jumps."
    ],
    references: [
      "https://owasp.org/www-project-smart-contract-top-10/"
    ]
  },
  "consensus-health": {
    owasp_sc_top10: "SC10:2025 - Denial of Service (DoS) Attacks",
    weakness_class: "Chain Availability / DoS Exposure",
    impact_summary: "A stalled or unhealthy chain can delay or block execution, monitoring, and operational response.",
    remediation_summary: "Validate RPC health, monitor liveness, and route critical operations through resilient infrastructure.",
    remediation_steps: [
      "Monitor block production delay thresholds.",
      "Fail over to secondary RPC infrastructure.",
      "Pause sensitive automations when chain liveness is degraded."
    ],
    references: [
      "https://owasp.org/www-project-smart-contract-top-10/"
    ]
  }
};

function readJsonSafe(filePath: string): any | null {
  if (!fs.existsSync(filePath)) return null;
  const raw = fs.readFileSync(filePath, "utf8").trim();
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function ensureArrayFindings(data: any): UnifiedFinding[] {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.findings)) return data.findings;
  return [];
}

function enrichByMythrilSwc(rule: string): EnrichedMetadata | undefined {
  const normalized = String(rule || "").toUpperCase().trim();

  const mythrilMap: Record<string, EnrichedMetadata> = {
    "SWC-107": ENRICHMENT_MAP["reentrancy-eth"],
    "SWC-104": ENRICHMENT_MAP["low-level-calls"],
    "SWC-105": ENRICHMENT_MAP["arbitrary-send-eth"],
    "SWC-115": ENRICHMENT_MAP["tx-origin"],
    "SWC-116": ENRICHMENT_MAP["timestamp"],
    "SWC-120": ENRICHMENT_MAP["weak-prng"]
  };

  return mythrilMap[normalized];
}

function fallbackEnrichment(finding: UnifiedFinding): EnrichedMetadata {
  return {
    weakness_class: "Unmapped Security Finding",
    impact_summary: `No predefined SWC/OWASP mapping exists yet for rule "${finding.rule}". Manual analyst review is recommended.`,
    remediation_summary: "Review the tool output manually, validate exploitability, and map the finding into your internal taxonomy.",
    remediation_steps: [
      "Review raw finding details and affected code path.",
      "Assess exploitability and business impact.",
      "Create a new local enrichment rule if this finding recurs."
    ],
    references: [
      "https://swcregistry.io",
      "https://owasp.org/www-project-smart-contract-top-10/"
    ],
    confidence_note: "Fallback enrichment applied because no exact mapping rule was found."
  };
}

function enrichFinding(finding: UnifiedFinding): UnifiedFinding {
  let enrichment: EnrichedMetadata | undefined;

  if (finding.tool === "mythril" && /^SWC-\d+$/i.test(finding.rule)) {
    enrichment = enrichByMythrilSwc(finding.rule);
  }

  if (!enrichment) {
    enrichment = ENRICHMENT_MAP[finding.rule];
  }

  if (!enrichment) {
    enrichment = fallbackEnrichment(finding);
  }

  return {
    ...finding,
    enrichment
  };
}

function summarize(findings: UnifiedFinding[]) {
  return {
    total_findings: findings.length,
    enriched_findings: findings.filter((f) => f.enrichment).length,
    mapped_swc: findings.filter((f) => f.enrichment?.swc_id).length,
    mapped_owasp: findings.filter((f) => f.enrichment?.owasp_sc_top10).length
  };
}

function main() {
  const input = readJsonSafe(INPUT_FILE);

  if (!input) {
    console.error(`Input file not found or invalid: ${INPUT_FILE}`);
    process.exit(1);
  }

  const findings = ensureArrayFindings(input);
  const enrichedFindings = findings.map(enrichFinding);

  const output: EnrichedReport = {
    generated_at: new Date().toISOString(),
    findings: enrichedFindings,
    enrichment_summary: summarize(enrichedFindings)
  };

  fs.mkdirSync(path.dirname(OUTPUT_FILE), { recursive: true });
  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(output, null, 2), "utf8");

  console.log("=== Findings Enrichment Summary ===");
  console.log(`Input file         : ${INPUT_FILE}`);
  console.log(`Input findings     : ${findings.length}`);
  console.log(`Output file        : ${OUTPUT_FILE}`);
  console.log(`Mapped SWC         : ${output.enrichment_summary.mapped_swc}`);
  console.log(`Mapped OWASP       : ${output.enrichment_summary.mapped_owasp}`);
  console.log(`Enriched findings  : ${output.enrichment_summary.enriched_findings}`);
}

main();