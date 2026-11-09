export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type AssessmentStatus =
  | 'CREATED'
  | 'REPOSITORY_FETCH'
  | 'REPOSITORY_ANALYSIS'
  | 'STATIC_SCANS'
  | 'SBOM_GENERATION'
  | 'DEPENDENCY_ANALYSIS'
  | 'RUNTIME_PROVISIONING'
  | 'DYNAMIC_TESTING'
  | 'FINDING_NORMALIZATION'
  | 'CORRELATION_AND_RISK'
  | 'AI_ANALYSIS'
  | 'REPORT_GENERATION'
  | 'COMPLETED'
  | 'PARTIAL'
  | 'FAILED'
  | 'CANCELLED';

export type CheckStatus =
  | 'PENDING'
  | 'RUNNING'
  | 'PASSED'
  | 'FAILED'
  | 'BLOCKED'
  | 'NOT_ASSESSED'
  | 'SKIPPED'
  | 'INCONCLUSIVE';

export type FindingStatus =
  | 'SUSPECTED'
  | 'CONFIRMED'
  | 'FALSE_POSITIVE'
  | 'ACCEPTED_RISK'
  | 'MITIGATED'
  | 'RESOLVED';

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  is_verified: boolean;
  created_at: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface Project {
  id: string;
  name: string;
  description: string | null;
  owner_id: string;
  created_at: string;
  updated_at: string;
}

export interface Repository {
  id: string;
  project_id: string;
  name: string;
  full_name: string;
  html_url: string;
  clone_url: string;
  default_branch: string;
  is_private: boolean;
  language: string | null;
  created_at: string;
}

export interface ScanJob {
  id: string;
  assessment_id: string;
  tool_name: string;
  job_type: string;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  exit_code: number | null;
  findings_count: number;
  error_message: string | null;
  created_at: string;
}

export interface Assessment {
  id: string;
  project_id: string;
  repository_id: string;
  branch: string;
  commit_sha: string | null;
  target_url: string | null;
  status: AssessmentStatus;
  current_stage: string | null;
  overall_risk_score: number | null;
  max_severity: Severity | null;
  findings_count: number;
  error_message: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface AssessmentProgress {
  assessment_id: string;
  status: AssessmentStatus;
  current_stage: string | null;
  completed_percentage: number;
  stages: Record<string, string>;
  checks: Record<string, string>;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export interface Evidence {
  id: string;
  finding_id: string;
  evidence_type: string;
  data: Record<string, any>;
  redacted: boolean;
  created_at: string;
}

export interface Finding {
  id: string;
  assessment_id: string;
  fingerprint: string;
  tool_name: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: string;
  category: string;
  cwe_ids: string[];
  cve_ids: string[];
  cvss_score: number | null;
  risk_score: number;
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  target_endpoint: string | null;
  status: FindingStatus;
  reachability: string;
  ai_explanation: string | null;
  ai_remediation: string | null;
  created_at: string;
  evidence?: Evidence[];
}

export interface GraphNode {
  id: string;
  name: string;
  version: string;
  purl?: string;
  type?: string;
  is_direct: boolean;
  has_vulnerabilities: boolean;
  vulnerabilities?: Array<{
    cve_id: string;
    severity: string;
    description: string;
  }>;
}

export interface GraphEdge {
  source: string;
  target: string;
  scope?: string;
}

export interface DependencyGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  summary: {
    total_components: number;
    direct_dependencies: number;
    transitive_dependencies: number;
    vulnerable_components: number;
  };
}

export interface RemediationProposal {
  id: string;
  finding_id: string;
  summary: string;
  rationale: string;
  diff: string;
  is_approved: boolean;
  approved_by_id: string | null;
  approved_at: string | null;
  verification_status: string | null;
  created_at: string;
}

export interface Report {
  id: string;
  assessment_id: string;
  format: 'pdf' | 'json' | 'sarif' | 'csv';
  file_path: string;
  file_size: number | null;
  sha256_hash: string | null;
  generated_at: string;
}
