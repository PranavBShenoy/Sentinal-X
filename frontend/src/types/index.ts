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

/** Deterministic risk scores produced by the backend RiskEngine are 0–10. */
export type RiskScore = number;

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
  tool_name: string;
  status: string;
  check_status: string | null;
  tool_version: string | null;
  findings_count: number;
  started_at: string | null;
  completed_at: string | null;
  execution_time_seconds: number | null;
  error_message: string | null;
  /** Legacy UI aliases; ApiClient derives these from ScanJobResponse. */
  job_type: string;
  exit_code: number | null;
}

export type ScanJobResponse = Omit<ScanJob, 'job_type' | 'exit_code'>;

export interface Assessment {
  id: string;
  project_id: string;
  repository_id: string | null;
  branch: string | null;
  commit_sha: string | null;
  target_url: string | null;
  status: AssessmentStatus;
  current_stage: string | null;
  risk_score: RiskScore | null;
  risk_level: string | null;
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
  scan_jobs: ScanJob[];
  runtime_status: string | null;
  completed_percentage: number;
  stages: Record<string, string>;
  checks: Record<string, string>;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export type AssessmentProgressResponse = Omit<AssessmentProgress, 'scan_jobs'> & {
  scan_jobs: ScanJobResponse[];
};

/** Assessment configuration accepted by the Control Plane API. */
export interface AssessmentConfig {
  enable_active_dast?: boolean;
  enable_git_history_scan?: boolean;
  target_url?: string;
  openapi_spec_url?: string;
  artifact_url?: string;
  /** SHA-256 digest, optionally prefixed with `sha256:`. */
  artifact_sha256?: string;
  test_username?: string;
  test_password?: string;
  scan_depth?: 'quick' | 'standard' | 'deep';
  max_concurrent_scanners?: number;
}

export interface AssessmentCreateRequest {
  repository_id: string;
  branch?: string;
  commit_sha?: string;
  config?: AssessmentConfig;
}

/** Control Plane → Runtime Host job request contract. */
export interface JobSubmitRequest {
  job_id: string;
  tenant_id: string;
  assessment_id: string;
  operation: 'build' | 'run' | 'cleanup' | 'cancel';
  resources: string[];
  resource_limits: Record<string, unknown>;
  idempotency_key: string;
  artifact_url?: string;
  artifact_sha256?: string;
  image_tag?: string;
  container_name?: string;
  network_name?: string;
  app_port?: number;
  cpu_limit: '1.0';
  mem_limit: '512m';
  drop_capabilities: ['ALL'];
  no_new_privileges: true;
  read_only_rootfs: true;
}

export interface Evidence {
  id: string;
  finding_id: string;
  evidence_type: string;
  data: Record<string, any>;
  redacted: boolean;
  created_at: string;
}

/** Exact nullable response fields returned by backend FindingResponse. */
export interface FindingResponse {
  id: string;
  assessment_id: string;
  title: string;
  description: string | null;
  category: string;
  subcategory: string | null;
  severity: string;
  status: string;
  confidence: string;
  source_tool: string;
  rule_id: string | null;
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  endpoint: string | null;
  component: string | null;
  cve_ids: string[] | null;
  cvss_score: number | null;
  affected_version: string | null;
  fixed_version: string | null;
  risk_score: RiskScore | null;
  risk_rationale: string | null;
  ai_explanation: string | null;
  ai_impact: string | null;
  ai_remediation_steps: string[] | null;
  code_snippet: string | null;
  first_seen_at: string;
  last_seen_at: string;
}

/** Presentation shape consumed by existing findings UI; normalized by ApiClient. */
export interface Finding extends Omit<FindingResponse, 'risk_score' | 'cve_ids'> {
  fingerprint: string;
  tool_name: string;
  cwe_ids: string[];
  cve_ids: string[];
  risk_score: RiskScore;
  target_endpoint: string | null;
  reachability: string;
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
  assessment_id: string;
  finding_id: string;
  status: string;
  summary: string | null;
  remediation_steps: string[] | null;
  patch_diff: string | null;
  proposed_branch: string | null;
  approved_at: string | null;
  pr_url: string | null;
  created_at: string;
}

export interface Report {
  id: string;
  assessment_id: string;
  format: 'pdf' | 'json' | 'sarif' | 'csv';
  file_size_bytes: number | null;
  generated_at: string;
}
