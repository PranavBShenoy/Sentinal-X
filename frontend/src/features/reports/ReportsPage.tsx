import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../../lib/api';
import { Report, Assessment } from '../../types';
import { formatDate } from '../../lib/utils';
import {
  FileText,
  Download,
  Plus,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  FileCode,
  FileSpreadsheet,
} from 'lucide-react';

export const ReportsPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const assessmentIdParam = searchParams.get('assessment_id');

  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string>(
    assessmentIdParam || ''
  );
  const [reports, setReports] = useState<Report[]>([]);
  const [selectedFormat, setSelectedFormat] = useState<'pdf' | 'json' | 'sarif' | 'csv'>('json');
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const loadAssessments = async () => {
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
    loadAssessments();
  }, []);

  const loadReports = async () => {
    if (!selectedAssessmentId) return;
    setLoading(true);
    setError(null);
    try {
      const reps = await api.getReports(selectedAssessmentId);
      setReports(reps || []);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch generated reports');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedAssessmentId) {
      loadReports();
    }
  }, [selectedAssessmentId]);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAssessmentId) return;

    setGenerating(true);
    setError(null);
    try {
      await api.generateReport(selectedAssessmentId, selectedFormat);
      await loadReports();
    } catch (err: any) {
      setError(err.message || 'Failed to generate report');
    } finally {
      setGenerating(false);
    }
  };

  const getFormatIcon = (format: string) => {
    switch (format.toLowerCase()) {
      case 'pdf':
        return <FileText className="w-5 h-5 text-red-400" />;
      case 'sarif':
        return <FileCode className="w-5 h-5 text-purple-400" />;
      case 'json':
        return <FileCode className="w-5 h-5 text-emerald-400" />;
      case 'csv':
        return <FileSpreadsheet className="w-5 h-5 text-blue-400" />;
      default:
        return <FileText className="w-5 h-5 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2.5">
            <FileText className="w-6 h-6 text-teal-400" />
            Security Assessment Reports
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Generate and export compliance-ready JSON, OASIS SARIF 2.1.0, CSV, and executive PDF reports
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
            onClick={loadReports}
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

      {/* Generator Form */}
      <div className="bg-surface border border-border rounded-xl p-6">
        <h2 className="text-base font-semibold text-slate-100 mb-4">Export New Assessment Report</h2>
        <form onSubmit={handleGenerate} className="flex flex-col sm:flex-row gap-4 items-center">
          <div className="w-full sm:w-64">
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
              Select Output Format
            </label>
            <select
              value={selectedFormat}
              onChange={(e) => setSelectedFormat(e.target.value as any)}
              className="w-full px-3 py-2 bg-surface-elevated border border-border rounded-lg text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
            >
              <option value="json">Machine JSON (Structured Telemetry)</option>
              <option value="sarif">OASIS SARIF 2.1.0 (CI/CD Compatible)</option>
              <option value="csv">CSV (Findings Spreadsheet)</option>
              <option value="pdf">Executive PDF Report</option>
            </select>
          </div>

          <div className="sm:self-end w-full sm:w-auto">
            <button
              type="submit"
              disabled={generating || !selectedAssessmentId}
              className="w-full sm:w-auto px-5 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold rounded-lg flex items-center justify-center gap-2 shadow-lg shadow-emerald-900/30 transition-colors"
            >
              <Plus className="w-4 h-4" />
              {generating ? 'Compiling Report...' : 'Generate Report'}
            </button>
          </div>
        </form>
      </div>

      {/* Generated Reports Table */}
      <div className="bg-surface border border-border rounded-xl overflow-hidden">
        <div className="p-5 border-b border-border">
          <h3 className="font-semibold text-slate-100 text-sm">Available Downloads</h3>
        </div>

        {loading ? (
          <div className="p-12 text-center text-slate-400 text-xs">Loading available reports...</div>
        ) : reports.length === 0 ? (
          <div className="p-12 text-center text-slate-400 text-xs">
            No reports generated for this assessment yet. Choose a format above and click 'Generate Report'.
          </div>
        ) : (
          <div className="divide-y divide-border/60">
            {reports.map((rep) => (
              <div
                key={rep.id}
                className="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 hover:bg-surface-elevated/30 transition-colors"
              >
                <div className="flex items-center gap-3.5">
                  <div className="p-2.5 rounded-xl bg-surface-elevated border border-border">
                    {getFormatIcon(rep.format)}
                  </div>
                  <div>
                    <h4 className="font-mono text-sm font-semibold text-slate-200 uppercase">
                      {rep.format} Assessment Report
                    </h4>
                    <div className="flex items-center gap-3 text-xs text-slate-400 mt-0.5">
                      <span>Generated: {formatDate(rep.generated_at)}</span>
                      {rep.file_size_bytes && (
                        <span>Size: {(rep.file_size_bytes / 1024).toFixed(1)} KB</span>
                      )}
                    </div>
                  </div>
                </div>

                <a
                  href={api.getReportDownloadUrl(rep.id)}
                  download
                  className="px-4 py-2 bg-surface-elevated hover:bg-slate-700 text-slate-200 border border-border rounded-lg text-xs font-semibold flex items-center gap-2 transition-colors self-start sm:self-auto"
                >
                  <Download className="w-4 h-4 text-emerald-400" />
                  Download File
                </a>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
