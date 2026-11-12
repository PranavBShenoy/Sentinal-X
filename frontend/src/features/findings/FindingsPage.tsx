import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../../lib/api';
import { Finding } from '../../types';
import { SeverityBadge } from '../../components/SeverityBadge';
import { RiskScoreMeter } from '../../components/RiskScoreMeter';
import { FindingDetailModal } from './FindingDetailModal';
import {
  ShieldAlert,
  Search,
  Filter,
  RefreshCw,
  AlertTriangle,
  FileCode,
  ArrowUpDown,
  ExternalLink,
} from 'lucide-react';

export const FindingsPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const assessmentIdParam = searchParams.get('assessment_id');
  const findingIdParam = searchParams.get('finding_id');

  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [toolFilter, setToolFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Selected finding for modal
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const loadFindings = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getFindings({
        assessment_id: assessmentIdParam || undefined,
        severity: severityFilter || undefined,
        tool_name: toolFilter || undefined,
        status: statusFilter || undefined,
        search: searchQuery || undefined,
        page_size: 50,
      });
      setFindings(res.items || []);
      setTotal(res.total || 0);

      if (findingIdParam && res.items) {
        const match = res.items.find((f) => f.id === findingIdParam);
        if (match) setSelectedFinding(match);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load findings');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFindings();
  }, [assessmentIdParam, severityFilter, toolFilter, statusFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadFindings();
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2.5">
            Findings Explorer
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Normalized, deduplicated, and contextualized security vulnerabilities
            {assessmentIdParam && (
              <span className="font-mono ml-1 text-emerald-400 text-xs">
                (Filtered by assessment {assessmentIdParam.substring(0, 8)}...)
              </span>
            )}
          </p>
        </div>
        <button
          onClick={loadFindings}
          disabled={loading}
          className="px-3.5 py-2 bg-surface border border-border hover:bg-surface-elevated text-slate-300 rounded-lg text-sm flex items-center gap-2 transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-sm flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Filter Bar */}
      <div className="bg-surface border border-border rounded-xl p-4 flex flex-col md:flex-row gap-3 items-center justify-between">
        <form onSubmit={handleSearchSubmit} className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search CVE, CWE, file, title..."
            className="w-full pl-9 pr-4 py-2 bg-surface-elevated border border-border rounded-lg text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
          />
        </form>

        <div className="flex flex-wrap items-center gap-2.5 w-full md:w-auto">
          {/* Severity */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 bg-surface-elevated border border-border rounded-lg text-xs text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>

          {/* Tool */}
          <select
            value={toolFilter}
            onChange={(e) => setToolFilter(e.target.value)}
            className="px-3 py-2 bg-surface-elevated border border-border rounded-lg text-xs text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="">All Scanners</option>
            <option value="semgrep">Semgrep (SAST)</option>
            <option value="gitleaks">Gitleaks (Secrets)</option>
            <option value="grype">Grype (Dependencies)</option>
            <option value="trivy">Trivy (Containers/IaC)</option>
            <option value="zap">OWASP ZAP (DAST)</option>
          </select>

          {/* Status */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 bg-surface-elevated border border-border rounded-lg text-xs text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="">All Dispositions</option>
            <option value="CONFIRMED">Confirmed</option>
            <option value="SUSPECTED">Suspected</option>
            <option value="FALSE_POSITIVE">False Positive</option>
            <option value="ACCEPTED_RISK">Accepted Risk</option>
            <option value="MITIGATED">Mitigated</option>
          </select>
        </div>
      </div>

      {/* Findings Table */}
      <div className="bg-surface border border-border rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-slate-400">Loading findings catalog...</div>
        ) : findings.length === 0 ? (
          <div className="p-12 text-center">
            <ShieldAlert className="w-12 h-12 text-slate-500 mx-auto mb-3" />
            <h3 className="text-base font-semibold text-slate-200">No Findings Found</h3>
            <p className="text-xs text-slate-400 mt-1">
              Either no matching vulnerabilities were discovered or current filter criteria returned 0 results.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-surface-elevated/50 text-slate-400 uppercase text-[11px] font-semibold tracking-wider border-b border-border">
                <tr>
                  <th className="px-5 py-3">Severity</th>
                  <th className="px-5 py-3">Finding Title & Location</th>
                  <th className="px-5 py-3">Scanner</th>
                  <th className="px-5 py-3">Risk Score</th>
                  <th className="px-5 py-3">Status</th>
                  <th className="px-5 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {findings.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => setSelectedFinding(f)}
                    className="hover:bg-surface-elevated/40 transition-colors cursor-pointer"
                  >
                    <td className="px-5 py-3.5">
                      <SeverityBadge severity={f.severity} size="sm" />
                    </td>
                    <td className="px-5 py-3.5">
                      <div className="font-semibold text-slate-200 hover:text-emerald-400 transition-colors">
                        {f.title}
                      </div>
                      <div className="text-xs text-slate-400 font-mono flex items-center gap-1.5 mt-0.5">
                        {f.file_path ? (
                          <>
                            <FileCode className="w-3.5 h-3.5 text-slate-500" />
                            <span>
                              {f.file_path}:{f.line_start || 1}
                            </span>
                          </>
                        ) : f.target_endpoint ? (
                          <span>{f.target_endpoint}</span>
                        ) : (
                          <span className="text-slate-500">Repository root</span>
                        )}
                        {f.cve_ids?.length > 0 && (
                          <span className="bg-surface-elevated px-1.5 py-0.5 rounded text-[10px] text-amber-400 border border-border">
                            {f.cve_ids[0]}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-5 py-3.5">
                      <span className="font-mono text-xs text-slate-300 bg-surface-elevated px-2 py-0.5 rounded border border-border">
                        {f.tool_name}
                      </span>
                    </td>
                    <td className="px-5 py-3.5">
                      <RiskScoreMeter score={f.risk_score} size="sm" showLabel={false} />
                    </td>
                    <td className="px-5 py-3.5">
                      <span className="text-xs font-mono font-medium text-slate-400">
                        {f.status}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedFinding(f);
                        }}
                        className="px-2.5 py-1 bg-surface-elevated hover:bg-slate-700 text-slate-300 text-xs rounded border border-border transition-colors"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          onDispositionUpdated={(updated) => {
            setSelectedFinding(updated);
            setFindings((prev) => prev.map((item) => (item.id === updated.id ? updated : item)));
          }}
        />
      )}
    </div>
  );
};
