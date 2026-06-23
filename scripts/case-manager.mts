import fs from "node:fs";
import path from "node:path";

type AuditEvent = {
  event_id: string;
  case_id: string;
  incident_id: string;
  actor: string;
  action: string;
  status: string;
  timestamp: string;
  note: string;
};

type ManagedCase = {
  case_id: string;
  incident_id: string;
  domain: string;
  decision: string;
  owner: string;
  workflow_status: "QUEUED" | "UNDER_REVIEW" | "ESCALATED" | "CLOSED";
  retention_class: "AML_5Y" | "SECURITY_3Y" | "OPS_1Y";
  regulator_mapping: string[];
};

type CaseManagementReport = {
  generated_at: string;
  summary: {
    total_cases: number;
    queued: number;
    under_review: number;
    escalated: number;
    closed: number;
  };
  managed_cases: ManagedCase[];
  audit_log: AuditEvent[];
};

const ROOT = process.cwd();
const INPUT_FILE = path.join(ROOT, "reports", "compliance", "compliance_cases.json");
const OUTPUT_DIR = path.join(ROOT, "reports", "compliance");
const OUTPUT_FILE = path.join(OUTPUT_DIR, "case_management.json");

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

function workflowStatus(decision: string): "QUEUED" | "UNDER_REVIEW" | "ESCALATED" | "CLOSED" {
  if (decision === "BLOCK" || decision === "REPORT") return "ESCALATED";
  if (decision === "REVIEW") return "UNDER_REVIEW";
  if (decision === "ALLOW") return "QUEUED";
  return "CLOSED";
}

function retentionClass(domain: string): "AML_5Y" | "SECURITY_3Y" | "OPS_1Y" {
  if (domain === "AML" || domain === "KYC" || domain === "KYT") return "AML_5Y";
  if (domain === "OPS") return "OPS_1Y";
  return "SECURITY_3Y";
}

function regulatorMapping(domain: string): string[] {
  if (domain === "AML" || domain === "KYC" || domain === "KYT") return ["FATF", "MiCA", "FinCEN"];
  if (domain === "OPS") return ["MiCA"];
  return ["Internal Security Audit"];
}

function main() {
  try {
    const compliance = readJson(INPUT_FILE);
    const cases = Array.isArray(compliance?.cases) ? compliance.cases : [];

    const managedCases: ManagedCase[] = cases.map((item: any) => ({
      case_id: String(item.case_id),
      incident_id: String(item.incident_id),
      domain: String(item.compliance_domain),
      decision: String(item.decision),
      owner: String(item.owner),
      workflow_status: workflowStatus(String(item.decision)),
      retention_class: retentionClass(String(item.compliance_domain)),
      regulator_mapping: regulatorMapping(String(item.compliance_domain))
    }));

    const auditLog: AuditEvent[] = managedCases.map((item, index) => ({
      event_id: `AUD-${String(index + 1).padStart(4, "0")}`,
      case_id: item.case_id,
      incident_id: item.incident_id,
      actor: item.owner,
      action: `CASE_${item.workflow_status}`,
      status: item.workflow_status,
      timestamp: new Date().toISOString(),
      note: `Case ${item.case_id} routed to ${item.owner} with ${item.decision} decision and ${item.retention_class} retention policy.`
    }));

    const report: CaseManagementReport = {
      generated_at: new Date().toISOString(),
      summary: {
        total_cases: managedCases.length,
        queued: managedCases.filter((c) => c.workflow_status === "QUEUED").length,
        under_review: managedCases.filter((c) => c.workflow_status === "UNDER_REVIEW").length,
        escalated: managedCases.filter((c) => c.workflow_status === "ESCALATED").length,
        closed: managedCases.filter((c) => c.workflow_status === "CLOSED").length
      },
      managed_cases: managedCases,
      audit_log: auditLog
    };

    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
    fs.writeFileSync(OUTPUT_FILE, JSON.stringify(report, null, 2), "utf8");

    console.log("=== Case Management Summary ===");
    console.log(`Total cases      : ${report.summary.total_cases}`);
    console.log(`Queued           : ${report.summary.queued}`);
    console.log(`Under review     : ${report.summary.under_review}`);
    console.log(`Escalated        : ${report.summary.escalated}`);
    console.log(`Closed           : ${report.summary.closed}`);
    console.log(`Output report    : reports/compliance/case_management.json`);
  } catch (error) {
    console.error(`\n[FAIL] Case manager could not complete: ${(error as Error).message}`);
    process.exit(1);
  }
}

main();