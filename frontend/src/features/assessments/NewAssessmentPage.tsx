import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../../lib/api';
import { Project, Repository } from '../../types';
import {
  PlayCircle,
  FolderGit2,
  GitBranch,
  ShieldCheck,
  AlertTriangle,
  Globe,
  Cpu,
  Layers,
  ArrowRight,
} from 'lucide-react';

export const NewAssessmentPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const preselectedProjectId = searchParams.get('project_id');

  const [projects, setProjects] = useState<Project[]>([]);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>(preselectedProjectId || '');
  const [selectedRepoId, setSelectedRepoId] = useState<string>('');
  const [branch, setBranch] = useState('main');
  const [commitSha, setCommitSha] = useState('');
  const [targetUrl, setTargetUrl] = useState('');

  // Engine toggles
  const [enableSast, setEnableSast] = useState(true);
  const [enableSecrets, setEnableSecrets] = useState(true);
  const [enableSbom, setEnableSbom] = useState(true);
  const [enableDeps, setEnableDeps] = useState(true);
  const [enableRuntime, setEnableRuntime] = useState(true);
  const [enableDast, setEnableDast] = useState(true);

  const [loading, setLoading] = useState(false);
  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ssrfWarning, setSsrfWarning] = useState<string | null>(null);

  const navigate = useNavigate();

  useEffect(() => {
    const loadProjects = async () => {
      setLoading(true);
      try {
        const res = await api.getProjects();
        setProjects(res.items || []);
        if (preselectedProjectId && res.items?.some((p) => p.id === preselectedProjectId)) {
          setSelectedProjectId(preselectedProjectId);
        } else if (res.items?.length > 0) {
          setSelectedProjectId(res.items[0].id);
        }
      } catch (err: any) {
        setError(err.message || 'Failed to fetch projects');
      } finally {
        setLoading(false);
      }
    };
    loadProjects();
  }, [preselectedProjectId]);

  useEffect(() => {
    if (!selectedProjectId) return;
    const loadRepos = async () => {
      try {
        const repos = await api.getRepositories(selectedProjectId);
        setRepositories(repos);
        if (repos.length > 0) {
          setSelectedRepoId(repos[0].id);
          setBranch(repos[0].default_branch || 'main');
        } else {
          setSelectedRepoId('');
        }
      } catch (err: any) {
        setError(err.message || 'Failed to fetch repositories for project');
      }
    };
    loadRepos();
  }, [selectedProjectId]);

  // SSRF Client-side validation warning
  const handleUrlChange = (val: string) => {
    setTargetUrl(val);
    setSsrfWarning(null);
    if (!val) return;

    if (
      val.includes('localhost') ||
      val.includes('127.0.0.1') ||
      val.includes('169.254.') ||
      val.includes('::1') ||
      val.includes('metadata.google')
    ) {
      setSsrfWarning('SSRF Warning: Loopback and cloud metadata targets will be rejected by backend security policies.');
    }
  };

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProjectId || !selectedRepoId) {
      setError('Please select a project and a repository.');
      return;
    }

    setLaunching(true);
    setError(null);

    try {
      // 1. Create Assessment
      const assessment = await api.createAssessment(selectedProjectId, {
        repository_id: selectedRepoId,
        branch: branch || 'main',
        commit_sha: commitSha || undefined,
        config: {
          target_url: targetUrl || undefined,
          enable_sast: enableSast,
          enable_secrets: enableSecrets,
          enable_sbom: enableSbom,
          enable_deps: enableDeps,
          enable_runtime: enableRuntime,
          enable_dast: enableDast,
        },
      });

      // 2. Start Assessment Pipeline
      await api.startAssessment(assessment.id);

      // 3. Navigate to live progress screen
      navigate(`/assessments/${assessment.id}`);
    } catch (err: any) {
      setError(err.message || 'Failed to launch assessment');
      setLaunching(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2.5">
          Launch Security Assessment
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Configure multi-tool static, supply-chain, runtime, and dynamic security analysis
        </p>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-sm flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
          <span>{error}</span>
        </div>
      )}

      <form onSubmit={handleLaunch} className="space-y-6">
        {/* Step 1: Target Definition */}
        <div className="bg-surface border border-border rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-200 border-b border-border/70 pb-3">
            <FolderGit2 className="w-4 h-4 text-emerald-400" />
            1. Target Repository & Branch
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                Project *
              </label>
              <select
                value={selectedProjectId}
                onChange={(e) => setSelectedProjectId(e.target.value)}
                required
                className="w-full px-3.5 py-2.5 bg-surface-elevated border border-border rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                Repository *
              </label>
              {repositories.length === 0 ? (
                <div className="text-xs text-amber-400 py-2.5">
                  No repositories found in this project. Please add one in the Projects page.
                </div>
              ) : (
                <select
                  value={selectedRepoId}
                  onChange={(e) => setSelectedRepoId(e.target.value)}
                  required
                  className="w-full px-3.5 py-2.5 bg-surface-elevated border border-border rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
                >
                  {repositories.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.full_name || r.name} ({r.clone_url})
                    </option>
                  ))}
                </select>
              )}
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                Branch
              </label>
              <div className="relative">
                <GitBranch className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
                <input
                  type="text"
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                  placeholder="main"
                  className="w-full pl-10 pr-3.5 py-2 bg-surface-elevated border border-border rounded-lg text-sm text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
                Commit SHA (Optional Pin)
              </label>
              <input
                type="text"
                value={commitSha}
                onChange={(e) => setCommitSha(e.target.value)}
                placeholder="e.g. 7f8a3c2..."
                className="w-full px-3.5 py-2 bg-surface-elevated border border-border rounded-lg text-sm text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>
        </div>

        {/* Step 2: Runtime & Staging Configuration */}
        <div className="bg-surface border border-border rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-200 border-b border-border/70 pb-3">
            <Globe className="w-4 h-4 text-cyan-400" />
            2. Runtime & DAST Target
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
              Target Staging URL (Optional)
            </label>
            <input
              type="url"
              value={targetUrl}
              onChange={(e) => handleUrlChange(e.target.value)}
              placeholder="https://staging.internal.example.com"
              className="w-full px-3.5 py-2.5 bg-surface-elevated border border-border rounded-lg text-sm text-slate-100 font-mono text-xs focus:outline-none focus:border-emerald-500"
            />
            <p className="text-[11px] text-slate-400 mt-1">
              If left blank and isolated runtime is enabled, SENTINEL-X will provision an ephemeral
              sandboxed container from repository Dockerfiles or project detectors.
            </p>
            {ssrfWarning && (
              <p className="text-xs text-amber-400 mt-2 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                {ssrfWarning}
              </p>
            )}
          </div>
        </div>

        {/* Step 3: Analysis Modules */}
        <div className="bg-surface border border-border rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-200 border-b border-border/70 pb-3">
            <Cpu className="w-4 h-4 text-emerald-400" />
            3. Engine Selection & Scan Scope
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <label className="flex items-start gap-3 p-3.5 bg-surface-elevated border border-border rounded-xl cursor-pointer hover:border-slate-600 transition-colors">
              <input
                type="checkbox"
                checked={enableSast}
                onChange={(e) => setEnableSast(e.target.checked)}
                className="mt-0.5 rounded text-emerald-600 focus:ring-emerald-500"
              />
              <div>
                <div className="text-sm font-medium text-slate-200">SAST (Semgrep)</div>
                <div className="text-xs text-slate-400 mt-0.5">
                  Static analysis for SQLi, XSS, insecure deserialization, command injection
                </div>
              </div>
            </label>

            <label className="flex items-start gap-3 p-3.5 bg-surface-elevated border border-border rounded-xl cursor-pointer hover:border-slate-600 transition-colors">
              <input
                type="checkbox"
                checked={enableSecrets}
                onChange={(e) => setEnableSecrets(e.target.checked)}
                className="mt-0.5 rounded text-emerald-600 focus:ring-emerald-500"
              />
              <div>
                <div className="text-sm font-medium text-slate-200">Secret Detection (Gitleaks)</div>
                <div className="text-xs text-slate-400 mt-0.5">
                  Identifies API keys, private tokens, passwords with automatic masking
                </div>
              </div>
            </label>

            <label className="flex items-start gap-3 p-3.5 bg-surface-elevated border border-border rounded-xl cursor-pointer hover:border-slate-600 transition-colors">
              <input
                type="checkbox"
                checked={enableSbom}
                onChange={(e) => setEnableSbom(e.target.checked)}
                className="mt-0.5 rounded text-emerald-600 focus:ring-emerald-500"
              />
              <div>
                <div className="text-sm font-medium text-slate-200">SBOM Inventory (Syft)</div>
                <div className="text-xs text-slate-400 mt-0.5">
                  CycloneDX Software Bill of Materials generation and package cataloging
                </div>
              </div>
            </label>

            <label className="flex items-start gap-3 p-3.5 bg-surface-elevated border border-border rounded-xl cursor-pointer hover:border-slate-600 transition-colors">
              <input
                type="checkbox"
                checked={enableDeps}
                onChange={(e) => setEnableDeps(e.target.checked)}
                className="mt-0.5 rounded text-emerald-600 focus:ring-emerald-500"
              />
              <div>
                <div className="text-sm font-medium text-slate-200">Dependency CVEs (Grype & OSV)</div>
                <div className="text-xs text-slate-400 mt-0.5">
                  CVE matching, EPSS score lookup, and transitive reachability analysis
                </div>
              </div>
            </label>

            <label className="flex items-start gap-3 p-3.5 bg-surface-elevated border border-border rounded-xl cursor-pointer hover:border-slate-600 transition-colors">
              <input
                type="checkbox"
                checked={enableRuntime}
                onChange={(e) => setEnableRuntime(e.target.checked)}
                className="mt-0.5 rounded text-emerald-600 focus:ring-emerald-500"
              />
              <div>
                <div className="text-sm font-medium text-slate-200">Isolated Runtime (Docker)</div>
                <div className="text-xs text-slate-400 mt-0.5">
                  Ephemeral container execution with dropped capabilities (cap_drop=ALL)
                </div>
              </div>
            </label>

            <label className="flex items-start gap-3 p-3.5 bg-surface-elevated border border-border rounded-xl cursor-pointer hover:border-slate-600 transition-colors">
              <input
                type="checkbox"
                checked={enableDast}
                onChange={(e) => setEnableDast(e.target.checked)}
                className="mt-0.5 rounded text-emerald-600 focus:ring-emerald-500"
              />
              <div>
                <div className="text-sm font-medium text-slate-200">Dynamic Testing (DAST & ZAP)</div>
                <div className="text-xs text-slate-400 mt-0.5">
                  Active security header audit, CORS check, cookie security, and web probes
                </div>
              </div>
            </label>
          </div>
        </div>

        {/* Launch Button */}
        <div className="flex items-center justify-end gap-4 pt-2">
          <button
            type="submit"
            disabled={launching || !selectedRepoId}
            className="px-6 py-3 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-semibold rounded-xl text-sm flex items-center gap-2 shadow-xl shadow-emerald-900/30 transition-all"
          >
            {launching ? (
              'Initiating Pipeline...'
            ) : (
              <>
                <PlayCircle className="w-5 h-5" />
                Execute Assessment Pipeline
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};
