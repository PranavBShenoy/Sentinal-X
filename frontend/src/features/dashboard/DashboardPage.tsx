import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../../lib/api';
import { Assessment, Project, Finding } from '../../types';
import { StatusBadge } from '../../components/StatusBadge';
import { SeverityBadge } from '../../components/SeverityBadge';
import { RiskScoreMeter } from '../../components/RiskScoreMeter';
import { formatDate } from '../../lib/utils';
import {
  ShieldAlert,
  PlayCircle,
  FolderGit2,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  Server,
  Layers,
} from 'lucide-react';

export const DashboardPage: React.FC = () => {
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [assRes, projRes, findRes] = await Promise.all([
        api.getAssessments(1, 10),
        api.getProjects(),
        api.getFindings({ page_size: 5 }),
      ]);
      setAssessments(assRes.items || []);
      setProjects(projRes.items || []);
      setFindings(findRes.items || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load dashboard telemetry.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  // Compute metrics
  const totalFindings = assessments.reduce((acc, a) => acc + (a.findings_count || 0), 0);
  const criticalFindings = findings.filter((f) => f.severity === 'CRITICAL').length;
  const highFindings = findings.filter((f) => f.severity === 'HIGH').length;

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2.5">
            Security Assessment Dashboard
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time telemetry, vulnerability correlation, and supply-chain risk status
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            disabled={loading}
            className="px-3 py-2 bg-surface border border-border hover:bg-surface-elevated text-slate-300 rounded-lg text-sm flex items-center gap-2 transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <Link
            to="/assessments/new"
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-medium rounded-lg text-sm flex items-center gap-2 shadow-lg shadow-emerald-900/30 transition-colors"
          >
            <PlayCircle className="w-4 h-4" />
            Launch Assessment
          </Link>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-sm flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-surface border border-border">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Total Assessments
            </span>
            <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <Layers className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 text-3xl font-bold font-mono text-slate-100">
            {loading ? '--' : assessments.length}
          </div>
          <div className="text-xs text-slate-400 mt-1">Tracked across all workspaces</div>
        </div>

        <div className="p-5 rounded-xl bg-surface border border-border">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Protected Projects
            </span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <FolderGit2 className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 text-3xl font-bold font-mono text-slate-100">
            {loading ? '--' : projects.length}
          </div>
          <div className="text-xs text-slate-400 mt-1">Active repository targets</div>
        </div>

        <div className="p-5 rounded-xl bg-surface border border-border">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Critical & High
            </span>
            <div className="p-2 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 text-3xl font-bold font-mono text-red-400">
            {loading ? '--' : criticalFindings + highFindings}
          </div>
          <div className="text-xs text-slate-400 mt-1">Priority remediation needed</div>
        </div>

        <div className="p-5 rounded-xl bg-surface border border-border">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Security Engine
            </span>
            <div className="p-2 rounded-lg bg-teal-500/10 text-teal-400 border border-teal-500/20">
              <Server className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
            <span className="font-semibold text-emerald-400 text-sm">ONLINE</span>
          </div>
          <div className="text-xs text-slate-400 mt-1">7 Analysis Engines Ready</div>
        </div>
      </div>

      {/* Recent Assessments Table */}
      <div className="bg-surface border border-border rounded-xl overflow-hidden">
        <div className="p-5 border-b border-border flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-slate-100">Recent Assessments</h2>
            <p className="text-xs text-slate-400 mt-0.5">Execution history, verdicts, and risk scores</p>
          </div>
          <Link
            to="/assessments/new"
            className="text-xs text-emerald-400 hover:text-emerald-300 font-medium flex items-center gap-1"
          >
            New Assessment <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        {assessments.length === 0 && !loading ? (
          <div className="p-12 text-center">
            <div className="w-12 h-12 rounded-full bg-surface-elevated flex items-center justify-center mx-auto text-slate-500 mb-3">
              <Layers className="w-6 h-6" />
            </div>
            <p className="text-sm font-medium text-slate-300">No assessments executed yet</p>
            <p className="text-xs text-slate-500 mt-1">
              Create a project and launch your first comprehensive security scan.
            </p>
            <Link
              to="/assessments/new"
              className="inline-flex items-center gap-2 mt-4 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-medium transition-colors"
            >
              <PlayCircle className="w-4 h-4" />
              Start First Scan
            </Link>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-surface-elevated/50 text-slate-400 uppercase text-[11px] font-semibold tracking-wider border-b border-border">
                <tr>
                  <th className="px-5 py-3">Assessment ID / Branch</th>
                  <th className="px-5 py-3">Status</th>
                  <th className="px-5 py-3">Risk Score</th>
                  <th className="px-5 py-3">Findings</th>
                  <th className="px-5 py-3">Execution Time</th>
                  <th className="px-5 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {assessments.map((a) => (
                  <tr key={a.id} className="hover:bg-surface-elevated/30 transition-colors">
                    <td className="px-5 py-4">
                      <div className="font-mono text-xs text-slate-200 font-semibold">
                        {a.id.substring(0, 8)}...
                      </div>
                      <div className="text-xs text-slate-400 mt-0.5">
                        branch: <span className="font-mono text-emerald-400">{a.branch}</span>
                        {a.commit_sha && (
                          <span className="font-mono ml-2 text-slate-500">
                            ({a.commit_sha.substring(0, 7)})
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-5 py-4">
                      <StatusBadge status={a.status} />
                    </td>
                    <td className="px-5 py-4">
                      <RiskScoreMeter score={a.overall_risk_score} size="sm" />
                    </td>
                    <td className="px-5 py-4">
                      <span className="font-mono text-sm font-semibold text-slate-200">
                        {a.findings_count}
                      </span>
                    </td>
                    <td className="px-5 py-4 text-xs text-slate-400">
                      {formatDate(a.created_at)}
                    </td>
                    <td className="px-5 py-4 text-right">
                      <Link
                        to={`/assessments/${a.id}`}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-elevated hover:bg-slate-700 text-xs font-medium text-slate-200 border border-border transition-colors"
                      >
                        Inspect <ArrowRight className="w-3.5 h-3.5" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
