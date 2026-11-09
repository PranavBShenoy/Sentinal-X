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
} from '../types';

const API_BASE = '/api/v1';

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
      let errorMsg = `HTTP Error ${response.status}`;
      try {
        const errorJson = await response.json();
        errorMsg = errorJson.detail || errorJson.message || errorMsg;
      } catch {
        // use default errorMsg
      }
      throw new Error(errorMsg);
    }

    if (response.status === 204) {
      return {} as T;
    }

    return response.json();
  }

  // --- Auth API ---
  async login(credentials: { email: string; password: string }): Promise<AuthTokens> {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Login failed' }));
      throw new Error(err.detail || 'Invalid username or password');
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

  async createAssessment(projectId: string, data: {
    repository_id: string;
    branch?: string;
    commit_sha?: string;
    config?: {
      target_url?: string;
      enable_sast?: boolean;
      enable_secrets?: boolean;
      enable_sbom?: boolean;
      enable_deps?: boolean;
      enable_runtime?: boolean;
      enable_dast?: boolean;
    };
  }): Promise<Assessment> {
    return this.request<Assessment>(`/projects/${projectId}/assessments`, {
      method: 'POST',
      body: JSON.stringify(data),
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
    return this.request<AssessmentProgress>(`/assessments/${id}/progress`);
  }

  async getAssessmentJobs(id: string): Promise<ScanJob[]> {
    return this.request<ScanJob[]>(`/assessments/${id}/jobs`);
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

    return this.request<{ items: Finding[]; total: number }>(`/findings?${q.toString()}`);
  }

  async getFinding(id: string): Promise<Finding> {
    return this.request<Finding>(`/findings/${id}`);
  }

  async updateFindingDisposition(id: string, status: string, notes?: string): Promise<Finding> {
    return this.request<Finding>(`/findings/${id}/disposition`, {
      method: 'PATCH',
      body: JSON.stringify({ status, notes }),
    });
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

  async approveRemediation(remediationId: string): Promise<RemediationProposal> {
    return this.request<RemediationProposal>(`/remediations/${remediationId}/approve`, {
      method: 'POST',
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
    return `${API_BASE}/reports/${reportId}/download`;
  }
}

export const api = new ApiClient();
