import React, { useState, useEffect } from 'react';
import { Finding, RemediationProposal } from '../../types';
import { api } from '../../lib/api';
import { SeverityBadge } from '../../components/SeverityBadge';
import {
  X,
  Code,
  Bot,
  Wrench,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Globe,
  Layers,
  Terminal,
  ShieldCheck,
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
  const [notes, setNotes] = useState(finding.suppression_reason || '');
  const [updating, setUpdating] = useState(false);
  const [dispositionFeedback, setDispositionFeedback] = useState<{
    type: 'success' | 'error';
    message: string;
  } | null>(null);
  const [generatingAi, setGeneratingAi] = useState(false);
  const [loadingAi, setLoadingAi] = useState(false);
  const [aiProposal, setAiProposal] = useState<RemediationProposal | null>(null);
  const [remediationError, setRemediationError] = useState<string | null>(null);
  const reviewableDiff = hasReviewableDiff(aiProposal?.patch_diff);

  // Synchronize triage status & notes when finding updates
  useEffect(() => {
    setSelectedStatus(finding.status);
    setNotes(finding.suppression_reason || '');
  }, [finding.status, finding.suppression_reason]);

  // CRITICAL FIX: Reset and load proposal specific to this finding ID to avoid state leaks
  useEffect(() => {
    setDispositionFeedback(null);
    setRemediationError(null);
    setAiProposal(null);

    let isMounted = true;
    setLoadingAi(true);

    api.getFindingRemediation(finding.id)
      .then((proposal) => {
        if (isMounted && proposal) {
          setAiProposal(proposal);
        }
      })
      .catch(() => {
        // Ignored; finding may not have a proposal yet
      })
      .finally(() => {
        if (isMounted) setLoadingAi(false);
      });

    return () => {
      isMounted = false;
    };
  }, [finding.id]);

  const handleUpdateDisposition = async () => {
    setUpdating(true);
    setDispositionFeedback(null);
    try {
      const updated = await api.updateFindingDisposition(finding.id, selectedStatus, notes);
      onDispositionUpdated(updated);
      setDispositionFeedback({
        type: 'success',
        message: `Disposition updated to ${updated.status}.`,
      });
    } catch (err: any) {
      console.error('Failed to update finding disposition:', err);
      setDispositionFeedback({
        type: 'error',
        message: err.message || 'Failed to update finding disposition',
      });
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
      // Sync finding in parent state so finding has the newly generated ai explanation and steps
      const updatedFinding: Finding = {
        ...finding,
        ai_explanation: proposal.summary,
        ai_remediation_steps: proposal.remediation_steps || [],
        ai_remediation: proposal.remediation_steps?.join('\n') || null,
      };
      onDispositionUpdated(updatedFinding);
      setActiveTab('ai');
    } catch (err: any) {
      setRemediationError(err.message || 'Failed to generate remediation proposal');
    } finally {
      setGeneratingAi(false);
    }
  };

  const rawEvidence = finding.raw_evidence;
  const rawMessage = rawEvidence?.extra?.message || rawEvidence?.message || null;
  const rawMetadata = rawEvidence?.extra?.metadata || rawEvidence?.metadata || null;
  const hasEvidenceContent = Boolean(
    finding.code_snippet ||
    (rawEvidence && Object.keys(rawEvidence).length > 0) ||
    (finding.evidence && finding.evidence.length > 0)
  );

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-surface border border-border rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-6 border-b border-border flex items-start justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2.5">
              <SeverityBadge severity={finding.severity} />
              <span className="font-mono text-xs text-slate-400 bg-surface-elevated px-2 py-0.5 rounded border border-border">
                {finding.tool_name || finding.source_tool}
              </span>
              <span className="font-mono text-xs text-emerald-400 font-semibold">
                Risk Score: {typeof finding.risk_score === 'number' ? finding.risk_score.toFixed(1) : finding.risk_score}/10
              </span>
              <span
                className={`font-mono text-xs px-2 py-0.5 rounded border font-semibold ${
                  finding.status === 'FALSE_POSITIVE'
                    ? 'bg-slate-800/80 text-slate-400 border-slate-700'
                    : finding.status === 'ACCEPTED_RISK'
                    ? 'bg-amber-950/60 text-amber-300 border-amber-800'
                    : finding.status === 'FIXED' || finding.status === 'MITIGATED'
                    ? 'bg-blue-950/60 text-blue-300 border-blue-800'
                    : finding.status === 'CONFIRMED'
                    ? 'bg-rose-950/60 text-rose-300 border-rose-800'
                    : 'bg-emerald-950/60 text-emerald-300 border-emerald-800'
                }`}
              >
                {finding.status}
              </span>
            </div>
            <h2 className="text-lg font-bold text-slate-100">{finding.title}</h2>
            {finding.file_path ? (
              <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
                <FileCode className="w-3.5 h-3.5 text-slate-500" />
                <span>
                  {finding.file_path}
                  {finding.line_start ? `:${finding.line_start}` : ''}
                </span>
              </div>
            ) : finding.endpoint ? (
              <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
                <Globe className="w-3.5 h-3.5 text-slate-500" />
                <span>{finding.endpoint}</span>
              </div>
            ) : null}
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
            className={`py-3 border-b-2 transition-colors flex items-center gap-1.5 ${
              activeTab === 'evidence'
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
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
                  {finding.description || 'No detailed description provided by the scanner.'}
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
                    {finding.cvss_score !== null && finding.cvss_score !== undefined
                      ? Number(finding.cvss_score).toFixed(1)
                      : 'N/A'}
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
                <div className="flex items-center justify-between">
                  <h4 className="text-xs uppercase font-semibold text-slate-300 tracking-wider">
                    Security Triage & Disposition
                  </h4>
                  {finding.suppressed_at && (
                    <span className="text-[11px] text-slate-400 font-mono">
                      Last updated: {new Date(finding.suppressed_at).toLocaleString()}
                    </span>
                  )}
                </div>

                {dispositionFeedback && (
                  <div
                    className={`p-3 rounded-lg text-xs flex items-center justify-between gap-2 border ${
                      dispositionFeedback.type === 'success'
                        ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                        : 'bg-rose-950/40 border-rose-800 text-rose-300'
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      {dispositionFeedback.type === 'success' ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                      ) : (
                        <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                      )}
                      <span>{dispositionFeedback.message}</span>
                    </div>
                    <button
                      onClick={() => setDispositionFeedback(null)}
                      className="text-slate-400 hover:text-slate-200"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                )}

                <div className="flex flex-col sm:flex-row gap-3">
                  <select
                    value={selectedStatus}
                    onChange={(e) => setSelectedStatus(e.target.value)}
                    className="px-3 py-2 bg-surface border border-border rounded-lg text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
                  >
                    <option value="OPEN">OPEN (Under Review / Suspected)</option>
                    <option value="CONFIRMED">CONFIRMED (Valid Vulnerability)</option>
                    <option value="FALSE_POSITIVE">FALSE_POSITIVE (Dismiss / False Positive)</option>
                    <option value="ACCEPTED_RISK">ACCEPTED_RISK (Risk Exception)</option>
                    <option value="FIXED">FIXED (Mitigated / Verified)</option>
                    <option value="SUPPRESSED">SUPPRESSED (Muted)</option>
                    {selectedStatus === 'SUSPECTED' && <option value="SUSPECTED">SUSPECTED (Under Review)</option>}
                    {selectedStatus === 'MITIGATED' && <option value="MITIGATED">MITIGATED (Fix Verified)</option>}
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
                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold transition-colors flex items-center justify-center min-w-[140px]"
                  >
                    {updating ? 'Saving...' : 'Update Disposition'}
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'evidence' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h4 className="text-xs uppercase font-semibold text-slate-400 tracking-wider flex items-center gap-1.5">
                  <Layers className="w-4 h-4 text-emerald-400" />
                  Captured Evidence & Context
                </h4>
                <span className="text-[11px] font-mono text-slate-400 bg-surface-elevated px-2 py-0.5 rounded border border-border">
                  Tool: {finding.tool_name || finding.source_tool}
                </span>
              </div>

              {/* Code Snippet Evidence (Semgrep / Secrets / Vulnerability) */}
              {finding.code_snippet && (
                <div className="p-4 rounded-xl bg-[#090d16] border border-border space-y-2 font-mono text-xs">
                  <div className="flex items-center justify-between font-sans">
                    <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                      <Code className="w-3.5 h-3.5 text-emerald-400" />
                      Captured Source Code Snippet
                    </span>
                    <span className="text-[11px] text-slate-400 flex items-center gap-1">
                      <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
                      Zero-Trust Sanitized
                    </span>
                  </div>
                  {finding.file_path && (
                    <div className="text-[11px] text-slate-400 font-mono">
                      File: {finding.file_path}:{finding.line_start || 1}
                    </div>
                  )}
                  <pre className="overflow-x-auto text-emerald-300 p-3 rounded-lg bg-surface/50 border border-border/40 whitespace-pre leading-relaxed">
                    {finding.code_snippet}
                  </pre>
                </div>
              )}

              {/* Scanner Diagnostic Observation / Message */}
              {rawMessage && (
                <div className="p-4 rounded-xl bg-surface-elevated border border-border space-y-1.5 text-xs">
                  <span className="font-semibold text-emerald-400 uppercase tracking-wider text-[11px] block">
                    Scanner Observation & Message
                  </span>
                  <p className="text-slate-200 leading-relaxed font-sans">
                    {rawMessage}
                  </p>
                </div>
              )}

              {/* Metadata Tags / Intelligence */}
              {rawMetadata && (
                <div className="p-4 rounded-xl bg-surface-elevated/70 border border-border space-y-3 text-xs">
                  <span className="font-semibold text-slate-400 uppercase tracking-wider text-[11px] block">
                    Scanner Taxonomy & References
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {rawMetadata.cwe && (
                      <span className="bg-surface px-2.5 py-1 rounded border border-border text-[11px] text-amber-300 font-mono">
                        {Array.isArray(rawMetadata.cwe) ? rawMetadata.cwe.join(', ') : rawMetadata.cwe}
                      </span>
                    )}
                    {rawMetadata.owasp && (
                      <span className="bg-surface px-2.5 py-1 rounded border border-border text-[11px] text-blue-300 font-mono">
                        OWASP: {Array.isArray(rawMetadata.owasp) ? rawMetadata.owasp.join(', ') : rawMetadata.owasp}
                      </span>
                    )}
                    {rawMetadata.impact && (
                      <span className="bg-surface px-2.5 py-1 rounded border border-border text-[11px] text-slate-300 font-mono">
                        Impact: {rawMetadata.impact}
                      </span>
                    )}
                    {rawMetadata.confidence && (
                      <span className="bg-surface px-2.5 py-1 rounded border border-border text-[11px] text-slate-300 font-mono">
                        Confidence: {rawMetadata.confidence}
                      </span>
                    )}
                    {rawMetadata.likelihood && (
                      <span className="bg-surface px-2.5 py-1 rounded border border-border text-[11px] text-slate-300 font-mono">
                        Likelihood: {rawMetadata.likelihood}
                      </span>
                    )}
                  </div>
                  {rawMetadata.references && Array.isArray(rawMetadata.references) && rawMetadata.references.length > 0 && (
                    <div className="pt-2 border-t border-border/60">
                      <span className="text-[11px] text-slate-400 block mb-1">References:</span>
                      <ul className="space-y-1">
                        {rawMetadata.references.slice(0, 3).map((ref: string, idx: number) => (
                          <li key={idx} className="truncate">
                            <a
                              href={ref}
                              target="_blank"
                              rel="noreferrer"
                              className="text-emerald-400 hover:underline text-[11px] font-mono"
                            >
                              {ref}
                            </a>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {/* DAST / HTTP Header Context */}
              {rawEvidence && rawEvidence.header && (
                <div className="p-4 rounded-xl bg-surface-elevated border border-border space-y-2 text-xs">
                  <span className="font-semibold text-emerald-400 uppercase tracking-wider text-[11px] block">
                    HTTP Response Header Audit
                  </span>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 font-mono text-xs">
                    <div className="p-2.5 bg-surface rounded border border-border">
                      <span className="text-[10px] text-slate-400 block">Header</span>
                      <span className="text-slate-200">{rawEvidence.header}</span>
                    </div>
                    <div className="p-2.5 bg-surface rounded border border-border">
                      <span className="text-[10px] text-slate-400 block">Status</span>
                      <span className="text-amber-300">{rawEvidence.status || 'detected'}</span>
                    </div>
                    <div className="p-2.5 bg-surface rounded border border-border">
                      <span className="text-[10px] text-slate-400 block">Actual Value</span>
                      <span className="text-slate-300 truncate block">{rawEvidence.actual || '(None / Missing)'}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Raw JSON Payload */}
              {rawEvidence && Object.keys(rawEvidence).length > 0 && (
                <div className="p-4 rounded-xl bg-surface-elevated/40 border border-border space-y-2 text-xs">
                  <span className="font-semibold text-slate-400 font-mono text-[11px] uppercase block">
                    Complete Raw Scanner Payload
                  </span>
                  <pre className="overflow-x-auto text-slate-300 p-3 rounded-lg bg-[#090d16] border border-border/40 font-mono text-xs max-h-52">
                    {JSON.stringify(rawEvidence, null, 2)}
                  </pre>
                </div>
              )}

              {/* Legacy finding.evidence array if present */}
              {finding.evidence && finding.evidence.length > 0 && (
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
              )}

              {/* Fallback if zero evidence was stored */}
              {!hasEvidenceContent && (
                <div className="p-6 bg-surface-elevated/40 rounded-xl border border-border text-center text-xs text-slate-400">
                  <FileCode className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                  <p className="font-mono text-slate-300">
                    {finding.file_path ? `${finding.file_path}:${finding.line_start || 1}` : finding.endpoint || 'Repository scope'}
                  </p>
                  <p className="mt-1 text-slate-500 max-w-md mx-auto">
                    No source code snippet was stored for this finding. Secret tokens and sensitive strings were automatically masked in accordance with zero-trust storage policies.
                  </p>
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
                  disabled={generatingAi}
                  className="px-3.5 py-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 border border-emerald-500/30 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50"
                >
                  <Wrench className={`w-3.5 h-3.5 ${generatingAi ? 'animate-spin' : ''}`} />
                  {generatingAi
                    ? 'Analyzing...'
                    : aiProposal || finding.ai_explanation
                    ? 'Re-analyze with AI'
                    : 'Generate AI Analysis'}
                </button>
              </div>

              {remediationError && (
                <div className="p-3 rounded-lg border border-red-800 bg-red-950/30 text-xs text-red-300">
                  {remediationError}
                </div>
              )}

              {loadingAi && !aiProposal && (
                <div className="p-3 rounded-lg border border-border bg-surface-elevated/40 text-xs text-slate-400 flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                  Checking for existing AI analysis...
                </div>
              )}

              {aiProposal?.generation_mode === 'deterministic' && (
                <div className="p-3 rounded-lg border border-amber-700/60 bg-amber-950/20 text-xs text-amber-200">
                  AI analysis is currently unavailable, so these are rule-based remediation steps. Check the
                  server&apos;s AI provider configuration and try again later.
                </div>
              )}

              {(aiProposal?.remediation_steps?.length || finding.ai_remediation_steps?.length || finding.ai_remediation) ? (
                <div className="p-4 rounded-xl bg-surface-elevated border border-border space-y-2">
                  <div className="text-xs font-semibold text-emerald-400">Remediation Guidance</div>
                  <ul className="list-disc pl-5 space-y-1 text-xs text-slate-200">
                    {(
                      aiProposal?.remediation_steps ??
                      finding.ai_remediation_steps ??
                      finding.ai_remediation?.split('\n') ??
                      []
                    ).map((step, index) => (
                      <li key={index}>{step}</li>
                    ))}
                  </ul>
                </div>
              ) : null}

              {(aiProposal?.summary || finding.ai_explanation) ? (
                <div className="p-4 rounded-xl bg-surface-elevated border border-border space-y-3">
                  <div className="text-xs font-semibold text-emerald-400">Security Impact Analysis</div>
                  <p className="text-xs text-slate-200 leading-relaxed whitespace-pre-wrap">
                    {aiProposal?.summary || finding.ai_explanation}
                  </p>
                </div>
              ) : (
                <div className="p-4 rounded-xl bg-surface-elevated/40 border border-border text-xs text-slate-400">
                  No AI guidance has been generated yet for this finding. Click &quot;Generate AI Analysis&quot; above to request an evidence-grounded security explanation and fix recommendations.
                </div>
              )}

              {reviewableDiff && aiProposal?.patch_diff ? (
                <div className="p-4 rounded-xl bg-[#090d16] border border-border space-y-2 font-mono text-xs">
                  <div className="text-xs font-semibold text-slate-400 font-sans">Proposed Code Changes (Unified Diff)</div>
                  <pre className="overflow-x-auto text-emerald-300">
                    {aiProposal.patch_diff}
                  </pre>
                </div>
              ) : aiProposal ? (
                <div className="p-4 rounded-xl bg-surface-elevated/40 border border-border text-xs text-slate-400">
                  {aiProposal.patch_diff
                    ? 'The AI returned a remediation suggestion, not a unified code diff. It cannot be applied or approved as a patch.'
                    : 'No reviewable source diff was produced for this finding. Review the guidance above; a code diff requires relevant source evidence.'}
                </div>
              ) : null}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
