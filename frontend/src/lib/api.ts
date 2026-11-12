import {
  AuthTokens,
  User,
  Project,
  Repository,
  Assessment,
  AssessmentProgress,
  ScanJob,
  Finding,
  DependencyGraphData,
  RemediationProposal,
  Report,
  AssessmentConfig,
  AssessmentCreateRequest,
  FindingResponse,
  ScanJobResponse,
  AssessmentProgressResponse,
} from '../types';

const API_BASE = '/api/v1';

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly detail?: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

function describeValidationDetail(detail: unknown): string {
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    return detail.map((issue) => {
      if (!issue || typeof issue !== 'object') return String(issue);
      const item = issue as { loc?: unknown[]; msg?: unknown };
      const location = Array.isArray(item.loc)
        ? item.loc.filter((part) => part !== 'body').join('.')
        : '';
      const message = typeof item.msg === 'string' ? item.msg : 'Invalid value';
      return location ? `${location}: ${message}` : message;
    }).join('; ');
  }
  if (detail && typeof detail === 'object') return JSON.stringify(detail);
  return '';
}

function normalizeFinding(finding: FindingResponse): import('../types').Finding {
  return {
    ...finding,
    fingerprint: finding.rule_id || finding.id,
    tool_name: finding.source_tool,
    cwe_ids: [],
    cve_ids: finding.cve_ids || [],
    risk_score: finding.risk_score ?? 0,
    target_endpoint: finding.endpoint,
    reachability: 'UNKNOWN',
    ai_remediation: finding.ai_remediation_steps?.join('\n') || null,
    created_at: finding.first_seen_at,
  };
}

function normalizeScanJob(job: ScanJobResponse): ScanJob {
  return { ...job, job_type: job.tool_name, exit_code: null };
}

class ApiClient {
  private accessToken: string | null = null;
  private refreshToken: string | null = null;

  constructor() {
    this.accessToken = localStorage.getItem('sentinelx_access_token');
    this.refreshToken = localStorage.getItem('sentinelx_refresh_token');
  }

  public setTokens(tokens: AuthTokens) {
    this.accessToken = tokens.access_token;
    this.refreshToken = tokens.refresh_token;
    localStorage.setItem('sentinelx_access_token', tokens.access_token);
    localStorage.setItem('sentinelx_refresh_token', tokens.refresh_token);
  }

  public clearTokens() {
    this.accessToken = null;
    this.refreshToken = null;
    localStorage.removeItem('sentinelx_access_token');
    localStorage.removeItem('sentinelx_refresh_token');
  }

  public isAuthenticated(): boolean {
    return !!this.accessToken;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${API_BASE}${endpoint}`;
    const headers = new Headers(options.headers || {});

    if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
    }

    if (this.accessToken) {
      headers.set('Authorization', `Bearer ${this.accessToken}`);
    }

    const response = await fetch(url, {
      ...options,
      headers,
    });

    if (response.status === 401) {
      this.clearTokens();
      window.dispatchEvent(new CustomEvent('auth:expired'));
      throw new Error('Authentication expired. Please sign in again.');
    }

    if (!response.ok) {
      throw await this.createApiError(response);
    }

    if (response.status === 204) {
      return {} as T;
    }

    return response.json();
  }

  private async createApiError(response: Response): Promise<ApiError> {
    const payload = await response.json().catch(() => ({}));
    const detail = payload?.detail ?? payload?.message;
    const description = describeValidationDetail(detail);
    if (response.status === 403) {
      return new ApiError(
        403,
        description
          ? `Permission or authorization token was rejected: ${description}`
          : 'Permission or authorization token was rejected (403).',
        detail,
      );
    }
    if (response.status === 422) {
      return new ApiError(
        422,
        description
          ? `Request validation failed: ${description}`
          : 'Request validation failed (422). Check the submitted fields.',
        detail,
      );
    }
    return new ApiError(
      response.status,
      description || `HTTP Error ${response.status}`,
      detail,
    );
  }

  // --- Auth API ---
  async login(credentials: { email: string; password: string }): Promise<AuthTokens> {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials),
    });
    if (!res.ok) {
      throw await this.createApiError(res);
    }
    const data: AuthTokens = await res.json();
    this.setTokens(data);
    return data;
  }

  async register(data: { email: string; password: string; full_name?: string; username?: string }): Promise<User> {
    const username = data.username || data.email.split('@')[0].replace(/[^a-zA-Z0-9_-]/g, '_');
    return this.request<User>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        email: data.email,
        password: data.password,
        username: username.length >= 3 ? username : `${username}_user`,
        full_name: data.full_name,
      }),
    });
  }

  async getMe(): Promise<User> {
    return this.request<User>('/auth/me');
  }

  // --- Projects API ---
  async getProjects(): Promise<{ items: Project[]; total: number }> {
    return this.request<{ items: Project[]; total: number }>('/projects');
  }

  async createProject(data: { name: string; description?: string }): Promise<Project> {
    return this.request<Project>('/projects', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async getProject(id: string): Promise<Project> {
    return this.request<Project>(`/projects/${id}`);
  }

  async deleteProject(id: string): Promise<void> {
    return this.request<void>(`/projects/${id}`, { method: 'DELETE' });
  }

  // --- Repositories API ---
  async getRepositories(projectId: string): Promise<Repository[]> {
    return this.request<Repository[]>(`/projects/${projectId}/repositories`);
  }

  async createRepository(projectId: string, data: { name?: string; full_name?: string; clone_url: string; default_branch?: string }): Promise<Repository> {
    return this.request<Repository>(`/projects/${projectId}/repositories`, {
      method: 'POST',
      body: JSON.stringify({
        full_name: data.full_name || data.name || 'repository',
        clone_url: data.clone_url,
        default_branch: data.default_branch || 'main',
        is_private: false,
      }),
    });
  }

  // --- Assessments API ---
  async getAssessments(page: number = 1, pageSize: number = 20): Promise<{ items: Assessment[]; total: number }> {
    return this.request<{ items: Assessment[]; total: number }>(`/assessments?page=${page}&page_size=${pageSize}`);
  }

  async getProjectAssessments(projectId: string): Promise<Assessment[]> {
    return this.request<Assessment[]>(`/projects/${projectId}/assessments`);
  }

  async createAssessment(projectId: string, data: AssessmentCreateRequest & {
    // Existing form controls that are not part of AssessmentConfig are
    // accepted for compatibility, then intentionally omitted from the API body.
    config?: AssessmentConfig & {
      enable_sast?: boolean;
      enable_secrets?: boolean;
      enable_sbom?: boolean;
      enable_deps?: boolean;
      enable_runtime?: boolean;
      enable_dast?: boolean;
    };
  }): Promise<Assessment> {
    const config = data.config;
    const requestBody: AssessmentCreateRequest = {
      repository_id: data.repository_id,
      branch: data.branch,
      commit_sha: data.commit_sha,
      config: config ? {
        target_url: config.target_url,
        enable_active_dast: config.enable_active_dast ?? config.enable_dast,
        enable_git_history_scan: config.enable_git_history_scan,
        openapi_spec_url: config.openapi_spec_url,
        artifact_url: config.artifact_url,
        artifact_sha256: config.artifact_sha256,
        test_username: config.test_username,
        test_password: config.test_password,
        scan_depth: config.scan_depth,
        max_concurrent_scanners: config.max_concurrent_scanners,
      } : undefined,
    };
    return this.request<Assessment>(`/projects/${projectId}/assessments`, {
      method: 'POST',
      body: JSON.stringify(requestBody),
    });
  }

  async startAssessment(assessmentId: string): Promise<Assessment> {
    return this.request<Assessment>(`/assessments/${assessmentId}/start`, {
      method: 'POST',
    });
  }

  async getAssessment(id: string): Promise<Assessment> {
    return this.request<Assessment>(`/assessments/${id}`);
  }

  async getAssessmentProgress(id: string): Promise<AssessmentProgress> {
    const result = await this.request<AssessmentProgressResponse>(`/assessments/${id}/progress`);
    return { ...result, scan_jobs: result.scan_jobs.map(normalizeScanJob) };
  }

  async getAssessmentJobs(id: string): Promise<ScanJob[]> {
    const result = await this.request<ScanJobResponse[]>(`/assessments/${id}/jobs`);
    return result.map(normalizeScanJob);
  }

  // --- Findings API ---
  async getFindings(params: {
    assessment_id?: string;
    severity?: string;
    tool_name?: string;
    status?: string;
    search?: string;
    page?: number;
    page_size?: number;
  }): Promise<{ items: Finding[]; total: number }> {
    const q = new URLSearchParams();
    if (params.assessment_id) q.set('assessment_id', params.assessment_id);
    if (params.severity) q.set('severity', params.severity);
    if (params.tool_name) q.set('tool_name', params.tool_name);
    if (params.status) q.set('status', params.status);
    if (params.search) q.set('search', params.search);
    if (params.page) q.set('page', String(params.page));
    if (params.page_size) q.set('page_size', String(params.page_size));

    const result = await this.request<{ items: FindingResponse[]; total: number }>(`/findings?${q.toString()}`);
    return { ...result, items: result.items.map(normalizeFinding) };
  }

  async getFinding(id: string): Promise<Finding> {
    const result = await this.request<FindingResponse>(`/findings/${id}`);
    return normalizeFinding(result);
  }

  async updateFindingDisposition(id: string, status: string, notes?: string): Promise<Finding> {
    const result = await this.request<FindingResponse>(`/findings/${id}/disposition`, {
      method: 'PATCH',
      body: JSON.stringify({ status, notes }),
    });
    return normalizeFinding(result);
  }

  // --- Dependency Graph API ---
  async getDependencyGraph(assessmentId: string): Promise<DependencyGraphData> {
    return this.request<DependencyGraphData>(`/assessments/${assessmentId}/dependency-graph`);
  }

  // --- Remediation API ---
  async getRemediationProposals(assessmentId: string): Promise<RemediationProposal[]> {
    return this.request<RemediationProposal[]>(`/assessments/${assessmentId}/remediations`);
  }

  async generateRemediation(findingId: string): Promise<RemediationProposal> {
    return this.request<RemediationProposal>(`/findings/${findingId}/remediate`, {
      method: 'POST',
    });
  }

  async approveRemediation(
    remediationId: string,
    approved: boolean = true,
    rejection_reason?: string,
  ): Promise<RemediationProposal> {
    return this.request<RemediationProposal>(`/remediations/${remediationId}/approve`, {
      method: 'POST',
      body: JSON.stringify({ approved, rejection_reason }),
    });
  }

  // --- Reports API ---
  async getReports(assessmentId: string): Promise<Report[]> {
    return this.request<Report[]>(`/assessments/${assessmentId}/reports`);
  }

  async generateReport(assessmentId: string, format: 'pdf' | 'json' | 'sarif' | 'csv'): Promise<Report> {
    return this.request<Report>(`/assessments/${assessmentId}/reports`, {
      method: 'POST',
      body: JSON.stringify({ format }),
    });
  }

  getReportDownloadUrl(reportId: string): string {
    // The API currently authenticates direct browser downloads with its user
    // access JWT in the query parameter; it does not accept Runtime Host read tokens.
    const token = this.accessToken ? `?token=${encodeURIComponent(this.accessToken)}` : '';
    return `${API_BASE}/reports/${reportId}/download${token}`;
  }
}

export const api = new ApiClient();
