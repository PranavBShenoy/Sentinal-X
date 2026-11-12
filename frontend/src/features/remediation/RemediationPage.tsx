import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../../lib/api';
import { RemediationProposal, Assessment } from '../../types';
import { formatDate } from '../../lib/utils';
import {
  Wrench,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Bot,
  RefreshCw,
  GitPullRequest,
  Check,
  Clock,
} from 'lucide-react';

export const RemediationPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const assessmentIdParam = searchParams.get('assessment_id');

  const [proposals, setProposals] = useState<RemediationProposal[]>([]);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string>(
    assessmentIdParam || ''
  );
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Load assessments for filter dropdown
  useEffect(() => {
    const loadAss = async () => {
      try {
        const res = await api.getAssessments(1, 50);
        setAssessments(res.items || []);
        if (!selectedAssessmentId && res.items?.length > 0) {
          setSelectedAssessmentId(res.items[0].id);
        }
      } catch {
        // ignore
      }
    };
    loadAss();
  }, []);

  const loadProposals = async () => {
    if (!selectedAssessmentId) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.getRemediationProposals(selectedAssessmentId);
      setProposals(res || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load remediation proposals');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedAssessmentId) {
      loadProposals();
    }
  }, [selectedAssessmentId]);

  const handleApprove = async (proposalId: string) => {
    setActionLoading(proposalId);
    try {
      await api.approveRemediation(proposalId);
      await loadProposals();
    } catch (err: any) {
      alert(err.message || 'Failed to approve remediation proposal');
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2.5">
            <Wrench className="w-6 h-6 text-emerald-400" />
            Remediation & Patch Hub
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            AI-synthesized security patches with human approval and verification re-scans
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={selectedAssessmentId}
            onChange={(e) => setSelectedAssessmentId(e.target.value)}
            className="px-3.5 py-2 bg-surface border border-border rounded-lg text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
          >
            {assessments.map((a) => (
              <option key={a.id} value={a.id}>
                Assessment {a.id.substring(0, 8)} ({a.branch})
              </option>
            ))}
          </select>
          <button
            onClick={loadProposals}
            disabled={loading}
            className="p-2 bg-surface border border-border hover:bg-surface-elevated text-slate-300 rounded-lg text-sm"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-sm flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="p-12 text-center text-slate-400">Loading remediation proposals...</div>
      ) : proposals.length === 0 ? (
        <div className="bg-surface border border-border rounded-xl p-12 text-center">
          <Bot className="w-12 h-12 text-slate-500 mx-auto mb-3" />
          <h3 className="text-base font-semibold text-slate-200">No Proposals for this Assessment</h3>
          <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
            Remediation proposals are generated automatically during assessment or on demand from
            the Findings Explorer.
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {proposals.map((prop) => {
            const isApproved = ['APPROVED', 'APPLIED', 'VERIFIED'].includes(prop.status);
            return (
            <div
              key={prop.id}
              className="bg-surface border border-border rounded-xl p-6 space-y-4 hover:border-slate-600 transition-colors"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border pb-3">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono text-xs text-slate-400 bg-surface-elevated px-2 py-0.5 rounded border border-border">
                      Proposal: {prop.id.substring(0, 8)}
                    </span>
                    {isApproved ? (
                      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/70 text-emerald-400 border border-emerald-800">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Approved
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-950/70 text-amber-400 border border-amber-800">
                        <Clock className="w-3.5 h-3.5" /> Pending Review
                      </span>
                    )}
                  </div>
                  <h3 className="font-semibold text-slate-100">{prop.summary}</h3>
                </div>

                {!isApproved ? (
                  <button
                    onClick={() => handleApprove(prop.id)}
                    disabled={actionLoading === prop.id}
                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-semibold rounded-lg text-xs flex items-center gap-1.5 shadow-lg shadow-emerald-900/30 transition-colors self-start sm:self-auto"
                  >
                    <Check className="w-4 h-4" />
                    {actionLoading === prop.id ? 'Approving...' : 'Approve Fix'}
                  </button>
                ) : (
                  <div className="text-xs text-slate-400 font-mono">
                    Approved at {formatDate(prop.approved_at)}
                  </div>
                )}
              </div>

              {/* Rationale */}
              <div className="bg-surface-elevated/70 p-4 rounded-xl border border-border/80 text-xs text-slate-200 leading-relaxed">
                <span className="font-semibold text-emerald-400 uppercase tracking-wider block mb-1">
                  Security Rationale
                </span>
                {(prop.remediation_steps || []).join(" · ") || prop.summary}
              </div>

              {/* Unified Diff Viewer */}
              {prop.patch_diff && (
                <div>
                  <span className="font-semibold text-slate-400 uppercase tracking-wider text-xs block mb-2">
                    Proposed Code Changes (Unified Diff)
                  </span>
                  <div className="bg-[#090d16] border border-border rounded-xl p-4 font-mono text-xs overflow-x-auto leading-relaxed">
                    {prop.patch_diff.split('\n').map((line, idx) => {
                      let color = 'text-slate-300';
                      let bg = '';
                      if (line.startsWith('+') && !line.startsWith('+++')) {
                        color = 'text-emerald-400 font-medium';
                        bg = 'bg-emerald-950/30';
                      } else if (line.startsWith('-') && !line.startsWith('---')) {
                        color = 'text-rose-400 font-medium';
                        bg = 'bg-rose-950/30';
                      } else if (line.startsWith('@@')) {
                        color = 'text-cyan-400 font-semibold';
                      }
                      return (
                        <div key={idx} className={`${color} ${bg} px-1 rounded`}>
                          {line}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
