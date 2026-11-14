import React, { useState } from 'react';
import { Finding, FindingStatus, RemediationProposal } from '../../types';
import { api } from '../../lib/api';
import { SeverityBadge } from '../../components/SeverityBadge';
import { RiskScoreMeter } from '../../components/RiskScoreMeter';
import {
  X,
  Code,
  ShieldAlert,
  Bot,
  Wrench,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  ExternalLink,
} from 'lucide-react';

function hasReviewableDiff(diff: string | null | undefined): boolean {
  if (!diff || /patch details depend|insecure code pattern flagged|apply recommended parameterization/i.test(diff)) {
    return false;
  }
  return /^---\s/m.test(diff) && /^\+\+\+\s/m.test(diff) && /^@@/m.test(diff);
}

interface FindingDetailModalProps {
  finding: Finding | null;
  onClose: () => void;
  onDispositionUpdated: (updated: Finding) => void;
}

export const FindingDetailModal: React.FC<FindingDetailModalProps> = ({
  finding,
  onClose,
  onDispositionUpdated,
}) => {
  if (!finding) return null;

  const [activeTab, setActiveTab] = useState<'details' | 'evidence' | 'ai'>('details');
  const [selectedStatus, setSelectedStatus] = useState<string>(finding.status);
  const [notes, setNotes] = useState('');
  const [updating, setUpdating] = useState(false);
  const [generatingAi, setGeneratingAi] = useState(false);
  const [aiProposal, setAiProposal] = useState<RemediationProposal | null>(null);
  const [remediationError, setRemediationError] = useState<string | null>(null);
  const reviewableDiff = hasReviewableDiff(aiProposal?.patch_diff);

  const handleUpdateDisposition = async () => {
    setUpdating(true);
    try {
      const updated = await api.updateFindingDisposition(finding.id, selectedStatus, notes);
      onDispositionUpdated(updated);
    } catch (err: any) {
      alert(err.message || 'Failed to update finding disposition');
    } finally {
      setUpdating(false);
    }
  };

  const handleGenerateAiFix = async () => {
    setGeneratingAi(true);
    setRemediationError(null);
    try {
      const proposal = await api.generateRemediation(finding.id);
      setAiProposal(proposal);
      setActiveTab('ai');
    } catch (err: any) {
      setRemediationError(err.message || 'Failed to generate remediation proposal');
    } finally {
      setGeneratingAi(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-surface border border-border rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-6 border-b border-border flex items-start justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2.5">
              <SeverityBadge severity={finding.severity} />
              <span className="font-mono text-xs text-slate-400 bg-surface-elevated px-2 py-0.5 rounded border border-border">
                {finding.tool_name}
              </span>
              <span className="font-mono text-xs text-emerald-400 font-semibold">
                Risk Score: {finding.risk_score.toFixed(1)}/10
              </span>
            </div>
            <h2 className="text-lg font-bold text-slate-100">{finding.title}</h2>
            {finding.file_path && (
              <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
                <FileCode className="w-3.5 h-3.5 text-slate-500" />
                <span>
                  {finding.file_path}
                  {finding.line_start && `:${finding.line_start}`}
                </span>
              </div>

            )}
          </div>

          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-surface-elevated"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="px-6 border-b border-border flex gap-4 text-xs font-semibold">
          <button
            onClick={() => setActiveTab('details')}
            className={`py-3 border-b-2 transition-colors ${
              activeTab === 'details'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Vulnerability Details
          </button>
          <button
            onClick={() => setActiveTab('evidence')}
            className={`py-3 border-b-2 transition-colors ${
              activeTab === 'evidence'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Evidence & Snippets
          </button>
          <button
            onClick={() => setActiveTab('ai')}
            className={`py-3 border-b-2 transition-colors flex items-center gap-1.5 ${
              activeTab === 'ai'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Bot className="w-3.5 h-3.5" />
            AI Explanation & Fix
          </button>
        </div>

        {/* Body Content */}
        <div className="p-6 overflow-y-auto flex-1 space-y-6">
          {activeTab === 'details' && (
            <div className="space-y-6">
              {/* Description */}
              <div>
                <h4 className="text-xs uppercase font-semibold text-slate-400 tracking-wider mb-2">
                  Description
                </h4>
                <div className="bg-surface-elevated/70 p-4 rounded-xl border border-border/80 text-sm text-slate-200 leading-relaxed">
                  {finding.description}
                </div>
              </div>

              {/* Security Classification */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 bg-surface-elevated rounded-lg border border-border">
                  <span className="text-[11px] text-slate-400 block mb-1">CWE References</span>
                  <span className="font-mono text-xs font-semibold text-slate-200">
                    {finding.cwe_ids?.length > 0 ? finding.cwe_ids.join(', ') : 'None'}
                  </span>
                </div>
                <div className="p-3 bg-surface-elevated rounded-lg border border-border">
                  <span className="text-[11px] text-slate-400 block mb-1">CVE Identifiers</span>
                  <span className="font-mono text-xs font-semibold text-slate-200">
                    {finding.cve_ids?.length > 0 ? finding.cve_ids.join(', ') : 'None'}
                  </span>
                </div>
                <div className="p-3 bg-surface-elevated rounded-lg border border-border">
                  <span className="text-[11px] text-slate-400 block mb-1">Base CVSS Score</span>
                  <span className="font-mono text-xs font-semibold text-slate-200">
                    {finding.cvss_score !== null ? finding.cvss_score.toFixed(1) : 'N/A'}
                  </span>
                </div>
                <div className="p-3 bg-surface-elevated rounded-lg border border-border">
                  <span className="text-[11px] text-slate-400 block mb-1">Reachability</span>
                  <span className="font-mono text-xs font-semibold text-slate-200">
                    {finding.reachability || 'UNKNOWN'}
                  </span>
                </div>
              </div>

              {/* Disposition Review Workflow */}
              <div className="p-4 bg-surface-elevated/60 border border-border rounded-xl space-y-3">
                <h4 className="text-xs uppercase font-semibold text-slate-300 tracking-wider">
                  Security Triage & Disposition
                </h4>
                <div className="flex flex-col sm:flex-row gap-3">
                  <select
                    value={selectedStatus}
                    onChange={(e) => setSelectedStatus(e.target.value)}
                    className="px-3 py-2 bg-surface border border-border rounded-lg text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
                  >
                    <option value="SUSPECTED">SUSPECTED (Under Review)</option>
                    <option value="CONFIRMED">CONFIRMED (Valid Vulnerability)</option>
                    <option value="FALSE_POSITIVE">FALSE_POSITIVE (Dismiss)</option>
                    <option value="ACCEPTED_RISK">ACCEPTED_RISK (Risk Exception)</option>
                    <option value="MITIGATED">MITIGATED (Fix Verified)</option>
                  </select>
                  <input
                    type="text"
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    placeholder="Triage rationale / justification notes..."
                    className="flex-1 px-3 py-2 bg-surface border border-border rounded-lg text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
                  />
                  <button
                    onClick={handleUpdateDisposition}
                    disabled={updating}
                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold transition-colors"
                  >
                    {updating ? 'Saving...' : 'Update Disposition'}
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'evidence' && (
            <div className="space-y-4">
              <h4 className="text-xs uppercase font-semibold text-slate-400 tracking-wider">
                Captured Evidence & Context
              </h4>
              {finding.evidence && finding.evidence.length > 0 ? (
                finding.evidence.map((ev, i) => (
                  <div key={i} className="p-4 rounded-xl bg-surface-elevated border border-border font-mono text-xs">
                    <div className="text-[11px] text-emerald-400 mb-2 uppercase">
                      Evidence Type: {ev.evidence_type} {ev.redacted && '(Redacted for Security)'}
                    </div>
                    <pre className="overflow-x-auto text-slate-300">
                      {JSON.stringify(ev.data, null, 2)}
                    </pre>
                  </div>
                ))
              ) : (
                <div className="p-6 bg-surface-elevated/40 rounded-xl border border-border text-center text-xs text-slate-400">
                  {finding.file_path ? (
                    <div>
                      <p className="font-mono text-slate-300">
                        File: {finding.file_path}:{finding.line_start}
                      </p>
                      <p className="mt-1 text-slate-500">
                        Secret patterns and sensitive strings were automatically masked in accordance with zero-trust storage policies.
                      </p>
                    </div>
                  ) : (
                    'No raw snippet payload stored for this finding.'
                  )}
                </div>
              )}
            </div>
          )}

          {activeTab === 'ai' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h4 className="text-xs uppercase font-semibold text-slate-400 tracking-wider flex items-center gap-2">
                  <Bot className="w-4 h-4 text-emerald-400" />
                  AI Security Analysis & Remediation
                </h4>
                <button
                  onClick={handleGenerateAiFix}
                  disabled={generatingAi || !!aiProposal}
                  className="px-3 py-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 border border-emerald-500/30 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors"
                >
                  <Wrench className="w-3.5 h-3.5" />
                  {generatingAi ? 'Analyzing...' : aiProposal ? 'Analysis Complete' : 'Generate AI Analysis'}
                </button>
              </div>

              {remediationError && (
                <div className="p-3 rounded-lg border border-red-800 bg-red-950/30 text-xs text-red-300">
                  {remediationError}
                </div>
              )}

              {aiProposal?.generation_mode === 'deterministic' && (
                <div className="p-3 rounded-lg border border-amber-700/60 bg-amber-950/20 text-xs text-amber-200">
                  AI analysis is unavailable, so these are rule-based remediation steps. Check the
                  server's AI provider configuration and try again later.
                </div>
              )}

              {(aiProposal?.remediation_steps?.length || finding.ai_remediation) && (
                <div className="p-4 rounded-xl bg-surface-elevated border border-border space-y-2">
                  <div className="text-xs font-semibold text-emerald-400">Remediation Guidance</div>
                  <ul className="list-disc pl-5 space-y-1 text-xs text-slate-200">
                    {(aiProposal?.remediation_steps ?? finding.ai_remediation?.split('\n') ?? []).map((step, index) => (
                      <li key={index}>{step}</li>
                    ))}
                  </ul>
                </div>
              )}

              {finding.ai_explanation ? (
                <div className="p-4 rounded-xl bg-surface-elevated border border-border space-y-3">
                  <div className="text-xs font-semibold text-emerald-400">Security Impact Analysis</div>
                  <p className="text-xs text-slate-200 leading-relaxed whitespace-pre-wrap">
                    {finding.ai_explanation}
                  </p>
                </div>
              ) : (
                <div className="p-4 rounded-xl bg-surface-elevated/40 border border-border text-xs text-slate-400">
                  Request AI guidance here. A reviewable code diff appears only when relevant source context is available.
                </div>
              )}

              {reviewableDiff && aiProposal?.patch_diff ? (
                <div className="p-4 rounded-xl bg-[#090d16] border border-border space-y-2 font-mono text-xs">
                  <div className="text-xs font-semibold text-slate-400 font-sans">Proposed Code Changes (Unified Diff)</div>
                  <pre className="overflow-x-auto text-emerald-300">
                    {aiProposal.patch_diff}
                  </pre>
                </div>
              ) : aiProposal && (
                <div className="p-4 rounded-xl bg-surface-elevated/40 border border-border text-xs text-slate-400">
                  {aiProposal.patch_diff
                    ? 'The AI returned a remediation suggestion, not a unified code diff. It cannot be applied or approved as a patch.'
                    : 'No reviewable source diff was produced for this finding. Review the guidance above; a code diff requires relevant source evidence.'}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
