import fs from "node:fs";
import path from "node:path";

type Decision = "ALLOW" | "REVIEW" | "BLOCK" | "REPORT";
type ComplianceSeverity = "HIGH" | "MEDIUM" | "LOW" | "INFO";

type ComplianceCase = {
  case_id: string;
  incident_id: string;
  compliance_domain: "AML" | "KYC" | "KYT" | "AUDIT" | "OPS";
  policy_reference: string;
  severity: ComplianceSeverity;
  decision: Decision;
  owner: string;
  reason: string;
  evidence_refs: string[];
  generated_at: string;
};

type ComplianceReport = {
  generated_at: string;
  summary: {
    total_cases: number;
    by_decision: Record<Decision, number>;
    by_domain: Record<"AML" | "KYC" | "KYT" | "AUDIT" | "OPS", number>;
  };
  cases: ComplianceCase[];
};

const ROOT = process.cwd();
const INCIDENT_FILE = path.join(ROOT, "reports", "incident", "incident_response.json");
const SCREENING_FILE = path.join(ROOT, "reports", "compliance", "wallet_screening.json");
const OUTPUT_DIR = path.join(ROOT, "reports", "compliance");
const OUTPUT_FILE = path.join(OUTPUT_DIR, "compliance_cases.json");

function readJson(filePath: string): any {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Missing required file: ${filePath}`);
  }
  const raw = fs.readFileSync(filePath, "utf8").trim();
  if (!raw) {
    throw new Error(`Empty required file: ${filePath}`);
  }
  return JSON.parse(raw);
}

function inferDomain(incident: any): "AML" | "KYC" | "KYT" | "AUDIT" | "OPS" {
  const tool = String(incident?.tool ?? "");
  const title = String(incident?.title ?? "").toLowerCase();
  const rule = String(incident?.rule ?? "").toLowerCase();

  if (tool === "consensus-monitor") return "OPS";
  if (tool === "slither" || tool === "mythril") return "AUDIT";
  if (title.includes("flash-loan") || title.includes("withdrawals") || rule.includes("large-transfer") || rule.includes("multi-hop")) return "KYT";
  if (title.includes("emergency") || rule.includes("emergency-function")) return "AML";
  return "KYC";
}

function inferPolicy(domain: string, severity: string): string {
  if (domain === "AML") return severity === "HIGH" ? "AML-SAR-001" : "AML-REVIEW-002";
  if (domain === "KYT") return severity === "HIGH" ? "KYT-BLOCK-003" : "KYT-REVIEW-004";
  if (domain === "AUDIT") return severity === "HIGH" ? "AUDIT-BLOCK-005" : "AUDIT-TRACE-006";
  if (domain === "OPS") return "OPS-RESILIENCE-007";
  return "KYC-CDD-008";
}

function inferDecision(incident: any, screeningRecords: any[]): Decision {
  const severity = String(incident?.severity ?? "INFO");
  const affected = String(incident?.affected_component ?? "");

  const relatedScreening = screeningRecords.filter((r: any) => String(r?.wallet_id ?? "").includes(affected));

  if (severity === "HIGH") {
    if (relatedScreening.some((r: any) => r.decision === "BLOCK")) return "BLOCK";
    return "REPORT";
  }

  if (severity === "MEDIUM") return "REVIEW";
  if (severity === "LOW") return "ALLOW";
  return "ALLOW";
}

function inferOwner(domain: string): string {
  if (domain === "AML" || domain === "KYC" || domain === "KYT") return "Compliance Team";
  if (domain === "AUDIT") return "Application Security Team";
  return "DevOps / Node Operations Team";
}

function buildReason(incident: any, decision: Decision, domain: string): string {
  return `Incident ${incident.id} mapped to ${domain} controls and resulted in ${decision} due to severity ${incident.severity} and supporting screening evidence.`;
}

function main() {
  try {
    const incidents = readJson(INCIDENT_FILE)?.incidents ?? [];
    const screeningRecords = readJson(SCREENING_FILE)?.records ?? [];

    const cases: ComplianceCase[] = incidents.map((incident: any, index: number) => {
      const domain = inferDomain(incident);
      const decision = inferDecision(incident, screeningRecords);

      return {
        case_id: `CASE-${String(index + 1).padStart(4, "0")}`,
        incident_id: String(incident.id),
        compliance_domain: domain,
        policy_reference: inferPolicy(domain, String(incident.severity)),
        severity: String(incident.severity) as ComplianceSeverity,
        decision,
        owner: inferOwner(domain),
        reason: buildReason(incident, decision, domain),
        evidence_refs: [
          String(incident?.evidence?.report ?? "unknown-report"),
          String(incident?.evidence?.location ?? "no-location")
        ],
        generated_at: new Date().toISOString()
      };
    });

    const report: ComplianceReport = {
      generated_at: new Date().toISOString(),
      summary: {
        total_cases: cases.length,
        by_decision: {
          ALLOW: cases.filter((c) => c.decision === "ALLOW").length,
          REVIEW: cases.filter((c) => c.decision === "REVIEW").length,
          BLOCK: cases.filter((c) => c.decision === "BLOCK").length,
          REPORT: cases.filter((c) => c.decision === "REPORT").length
        },
        by_domain: {
          AML: cases.filter((c) => c.compliance_domain === "AML").length,
          KYC: cases.filter((c) => c.compliance_domain === "KYC").length,
          KYT: cases.filter((c) => c.compliance_domain === "KYT").length,
          AUDIT: cases.filter((c) => c.compliance_domain === "AUDIT").length,
          OPS: cases.filter((c) => c.compliance_domain === "OPS").length
        }
      },
      cases
    };

    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
    fs.writeFileSync(OUTPUT_FILE, JSON.stringify(report, null, 2), "utf8");

    console.log("=== Compliance Engine Summary ===");
    console.log(`Total cases      : ${report.summary.total_cases}`);
    console.log(`BLOCK            : ${report.summary.by_decision.BLOCK}`);
    console.log(`REVIEW           : ${report.summary.by_decision.REVIEW}`);
    console.log(`REPORT           : ${report.summary.by_decision.REPORT}`);
    console.log(`ALLOW            : ${report.summary.by_decision.ALLOW}`);
    console.log(`Output report    : reports/compliance/compliance_cases.json`);
  } catch (error) {
    console.error(`\n[FAIL] Compliance engine could not complete: ${(error as Error).message}`);
    process.exit(1);
  }
}

main();