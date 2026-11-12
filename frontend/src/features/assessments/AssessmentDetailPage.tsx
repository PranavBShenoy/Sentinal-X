import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../../lib/api';
import { Assessment, AssessmentProgress, ScanJob, Finding } from '../../types';
import { StatusBadge } from '../../components/StatusBadge';
import { RiskScoreMeter } from '../../components/RiskScoreMeter';
import { SeverityBadge } from '../../components/SeverityBadge';
import { formatDate } from '../../lib/utils';
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Layers,
  Network,
  Wrench,
  FileText,
  Terminal,
  RefreshCw,
  Cpu,
  ArrowRight,
  XCircle,
} from 'lucide-react';

export const AssessmentDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();

  const [assessment, setAssessment] = useState<Assessment | null>(null);
  const [progress, setProgress] = useState<AssessmentProgress | null>(null);
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAssessmentData = async () => {
    if (!id) return;
    try {
      const [ass, prog, jbs, findRes] = await Promise.all([
        api.getAssessment(id),
        api.getAssessmentProgress(id).catch(() => null),
        api.getAssessmentJobs(id).catch(() => []),
        api.getFindings({ assessment_id: id, page_size: 5 }).catch(() => ({ items: [], total: 0 })),
      ]);
      setAssessment(ass);
      if (prog) setProgress(prog);
      setJobs(jbs);
      setFindings(findRes.items || []);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch assessment');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAssessmentData();

    // Poll while running
    const interval = setInterval(() => {
      if (
        assessment &&
        (assessment.status === 'COMPLETED' ||
          assessment.status === 'PARTIAL' ||
          assessment.status === 'FAILED' ||
          assessment.status === 'CANCELLED')
      ) {
        clearInterval(interval);
        return;
      }
      fetchAssessmentData();
    }, 2500);

    return () => clearInterval(interval);
  }, [id, assessment?.status]);

  if (loading && !assessment) {
    return <div className="p-12 text-center text-slate-400">Loading assessment details...</div>;
  }

  if (error || !assessment) {
    return (
      <div className="p-6 rounded-xl bg-red-950/40 border border-red-800 text-red-300">
        <h3 className="font-semibold text-lg">Failed to load assessment</h3>
        <p className="text-sm mt-1">{error || 'Assessment not found'}</p>
        <Link
          to="/"
          className="inline-flex items-center gap-2 mt-4 px-3 py-1.5 bg-surface-elevated rounded text-xs text-slate-200"
        >
          Return to Dashboard
        </Link>
      </div>
    );
  }

  // Pipeline stages definition
  const PIPELINE_STAGES = [
    { key: 'REPOSITORY_FETCH', label: 'Repository Ingestion' },
    { key: 'STATIC_SCANS', label: 'Static SAST & Secrets' },
    { key: 'SBOM_GENERATION', label: 'SBOM & Vulnerabilities' },
    { key: 'RUNTIME_PROVISIONING', label: 'Runtime Container' },
    { key: 'DYNAMIC_TESTING', label: 'Dynamic DAST' },
    { key: 'CORRELATION_AND_RISK', label: 'Risk Correlation' },
    { key: 'AI_ANALYSIS', label: 'AI Remediation' },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner & Assessment Overview */}
      <div className="bg-surface border border-border rounded-xl p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div>
            <div className="flex items-center gap-3">
              <span className="font-mono text-xs text-slate-400 bg-surface-elevated px-2.5 py-1 rounded border border-border">
                ID: {assessment.id}
              </span>
              <StatusBadge status={assessment.status} />
            </div>
            <h1 className="text-xl font-bold text-slate-100 mt-2">
              Branch: <span className="text-emerald-400 font-mono">{assessment.branch}</span>
              {assessment.commit_sha && (
                <span className="ml-2 text-sm text-slate-400 font-mono">
                  ({assessment.commit_sha.substring(0, 7)})
                </span>
              )}
            </h1>
            <div className="flex items-center gap-4 text-xs text-slate-400 mt-1">
              <span>Initiated: {formatDate(assessment.created_at)}</span>
              {assessment.completed_at && <span>Completed: {formatDate(assessment.completed_at)}</span>}
            </div>
          </div>

          <div className="flex items-center gap-6">
            <div className="text-right">
              <span className="text-xs uppercase tracking-wider font-semibold text-slate-400 block mb-1">
                Detected Findings
              </span>
              <span className="font-mono text-3xl font-extrabold text-slate-100">
                {assessment.findings_count}
              </span>
            </div>
            <div className="h-12 w-px bg-border hidden sm:block" />
            <div>
              <span className="text-xs uppercase tracking-wider font-semibold text-slate-400 block mb-1">
                Overall Risk Score
              </span>
              <RiskScoreMeter score={assessment.risk_score} size="md" />
            </div>
          </div>
        </div>

        {/* Action quick links */}
        <div className="mt-6 pt-4 border-t border-border flex flex-wrap items-center gap-3">
          <Link
            to={`/findings?assessment_id=${assessment.id}`}
            className="px-3.5 py-1.5 rounded-lg bg-surface-elevated hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-2 border border-border transition-colors"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
            View All Findings ({assessment.findings_count})
          </Link>
          <Link
            to={`/assessments/${assessment.id}/graph`}
            className="px-3.5 py-1.5 rounded-lg bg-surface-elevated hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-2 border border-border transition-colors"
          >
            <Network className="w-3.5 h-3.5 text-cyan-400" />
            Dependency Graph
          </Link>
          <Link
            to={`/remediation?assessment_id=${assessment.id}`}
            className="px-3.5 py-1.5 rounded-lg bg-surface-elevated hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-2 border border-border transition-colors"
          >
            <Wrench className="w-3.5 h-3.5 text-emerald-400" />
            AI Remediation Proposals
          </Link>
          <Link
            to={`/reports?assessment_id=${assessment.id}`}
            className="px-3.5 py-1.5 rounded-lg bg-surface-elevated hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-2 border border-border transition-colors ml-auto"
          >
            <FileText className="w-3.5 h-3.5 text-teal-400" />
            Export Security Reports
          </Link>
        </div>
      </div>

      {/* Progress & Live Pipeline Stages */}
      <div className="bg-surface border border-border rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-slate-100 uppercase tracking-wider flex items-center gap-2">
            <Cpu className="w-4 h-4 text-emerald-400" />
            Assessment Pipeline Telemetry
          </h2>
          {progress && (
            <span className="font-mono text-xs text-emerald-400 font-semibold">
              {progress.completed_percentage}% Completed
            </span>
          )}
        </div>

        {progress && (
          <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden mb-6">
            <div
              className="h-full bg-emerald-500 rounded-full transition-all duration-500"
              style={{ width: `${progress.completed_percentage}%` }}
            />
          </div>
        )}

        {/* Pipeline Stage Indicators */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
          {PIPELINE_STAGES.map((st, idx) => {
            const isCompleted =
              assessment.status === 'COMPLETED' ||
              assessment.status === 'PARTIAL' ||
              (progress?.stages && progress.stages[st.key] === 'PASSED');
            const isRunning = assessment.current_stage === st.key;
            const isBlocked = progress?.stages && progress.stages[st.key] === 'BLOCKED';

            return (
              <div
                key={st.key}
                className={`p-3 rounded-lg border text-center flex flex-col items-center justify-center transition-all ${
                  isCompleted
                    ? 'bg-emerald-950/30 border-emerald-800 text-emerald-300'
                    : isRunning
                    ? 'bg-sky-950/40 border-sky-800 text-sky-300 animate-pulse'
                    : isBlocked
                    ? 'bg-amber-950/30 border-amber-800 text-amber-300'
                    : 'bg-surface-elevated/50 border-border text-slate-400'
                }`}
              >
                <div className="w-5 h-5 mb-1.5 flex items-center justify-center">
                  {isCompleted ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  ) : isRunning ? (
                    <RefreshCw className="w-4 h-4 text-sky-400 animate-spin" />
                  ) : isBlocked ? (
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                  ) : (
                    <Clock className="w-4 h-4 text-slate-500" />
                  )}
                </div>
                <span className="text-[11px] font-semibold leading-tight">{st.label}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Security Tools Execution Log Table */}
      <div className="bg-surface border border-border rounded-xl overflow-hidden">
        <div className="p-5 border-b border-border flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              Integrated Scanner Executions
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Isolated tool outputs, exit codes, and coverage verification
            </p>
          </div>
        </div>

        {jobs.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-400">
            No scanner executions recorded yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-surface-elevated/50 text-slate-400 uppercase text-[11px] font-semibold tracking-wider border-b border-border">
                <tr>
                  <th className="px-5 py-3">Tool Name</th>
                  <th className="px-5 py-3">Job Category</th>
                  <th className="px-5 py-3">Execution Status</th>
                  <th className="px-5 py-3">Findings</th>
                  <th className="px-5 py-3">Exit Code</th>
                  <th className="px-5 py-3">Status Note / Error</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {jobs.map((j) => (
                  <tr key={j.id} className="hover:bg-surface-elevated/30 transition-colors">
                    <td className="px-5 py-3 font-semibold text-slate-200 flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-emerald-400" />
                      {j.tool_name}
                    </td>
                    <td className="px-5 py-3 text-xs text-slate-400 font-mono">{j.job_type}</td>
                    <td className="px-5 py-3">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold ${
                          j.status === 'COMPLETED' || j.status === 'PASSED'
                            ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-800'
                            : j.status === 'BLOCKED'
                            ? 'bg-amber-950/60 text-amber-400 border border-amber-800'
                            : j.status === 'FAILED'
                            ? 'bg-rose-950/60 text-rose-400 border border-rose-800'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {j.status}
                      </span>
                    </td>
                    <td className="px-5 py-3 font-mono font-semibold text-slate-200">
                      {j.findings_count}
                    </td>
                    <td className="px-5 py-3 font-mono text-xs text-slate-400">
                      {j.exit_code !== null ? j.exit_code : '--'}
                    </td>
                    <td className="px-5 py-3 text-xs text-slate-400 truncate max-w-xs">
                      {j.error_message || 'Completed successfully.'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Findings Preview */}
      {findings.length > 0 && (
        <div className="bg-surface border border-border rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              Top Priority Findings
            </h2>
            <Link
              to={`/findings?assessment_id=${assessment.id}`}
              className="text-xs text-emerald-400 hover:text-emerald-300 font-medium flex items-center gap-1"
            >
              See all ({assessment.findings_count}) <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <div className="space-y-2">
            {findings.map((f) => (
              <div
                key={f.id}
                className="p-3.5 rounded-lg bg-surface-elevated/60 border border-border flex items-center justify-between gap-4"
              >
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={f.severity} size="sm" />
                  <div>
                    <h4 className="text-sm font-semibold text-slate-200">{f.title}</h4>
                    <div className="text-xs text-slate-400 font-mono mt-0.5">
                      {f.file_path ? `${f.file_path}:${f.line_start || 1}` : f.tool_name}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <RiskScoreMeter score={f.risk_score} size="sm" showLabel={false} />
                  <Link
                    to={`/findings?assessment_id=${assessment.id}&finding_id=${f.id}`}
                    className="p-1.5 rounded bg-surface border border-border text-slate-400 hover:text-slate-200 text-xs"
                  >
                    Details
                  </Link>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
