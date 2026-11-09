import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../../lib/api';
import { DependencyGraphData, GraphNode } from '../../types';
import {
  Network,
  ShieldAlert,
  ArrowLeft,
  CheckCircle2,
  Package,
  Layers,
  Search,
  Filter,
} from 'lucide-react';

export const DependencyGraphView: React.FC = () => {
  const { id } = useParams<{ id: string }>();

  const [graphData, setGraphData] = useState<DependencyGraphData | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [onlyVulnerable, setOnlyVulnerable] = useState(false);

  useEffect(() => {
    if (!id) return;
    const loadGraph = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await api.getDependencyGraph(id);
        setGraphData(data);
        if (data.nodes.length > 0) {
          const vuln = data.nodes.find((n) => n.has_vulnerabilities);
          setSelectedNode(vuln || data.nodes[0]);
        }
      } catch (err: any) {
        setError(err.message || 'Failed to load dependency graph');
      } finally {
        setLoading(false);
      }
    };
    loadGraph();
  }, [id]);

  if (loading) {
    return <div className="p-12 text-center text-slate-400">Constructing dependency graph...</div>;
  }

  if (error || !graphData) {
    return (
      <div className="p-6 rounded-xl bg-red-950/40 border border-red-800 text-red-300">
        <h3 className="font-semibold text-lg">Unable to render graph</h3>
        <p className="text-sm mt-1">{error || 'No graph data found.'}</p>
        <Link
          to={`/assessments/${id}`}
          className="inline-flex items-center gap-2 mt-4 px-3 py-1.5 bg-surface-elevated rounded text-xs text-slate-200"
        >
          <ArrowLeft className="w-4 h-4" /> Return to Assessment
        </Link>
      </div>
    );
  }

  const filteredNodes = graphData.nodes.filter((n) => {
    if (onlyVulnerable && !n.has_vulnerabilities) return false;
    if (search && !n.name.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Link
              to={`/assessments/${id}`}
              className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1"
            >
              <ArrowLeft className="w-3.5 h-3.5" /> Assessment Details
            </Link>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2.5">
            <Network className="w-6 h-6 text-emerald-400" />
            Dependency Relationship & Attack Graph
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Interactive visualization of direct, transitive, and vulnerable software components
          </p>
        </div>
      </div>

      {/* Summary KPI Badges */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-surface border border-border">
          <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider block">
            Total Components
          </span>
          <span className="text-2xl font-bold font-mono text-slate-100 mt-1 block">
            {graphData.summary.total_components}
          </span>
        </div>
        <div className="p-4 rounded-xl bg-surface border border-border">
          <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider block">
            Direct Dependencies
          </span>
          <span className="text-2xl font-bold font-mono text-cyan-400 mt-1 block">
            {graphData.summary.direct_dependencies}
          </span>
        </div>
        <div className="p-4 rounded-xl bg-surface border border-border">
          <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider block">
            Transitive Dependencies
          </span>
          <span className="text-2xl font-bold font-mono text-slate-300 mt-1 block">
            {graphData.summary.transitive_dependencies}
          </span>
        </div>
        <div className="p-4 rounded-xl bg-surface border border-border">
          <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider block">
            Vulnerable Components
          </span>
          <span className="text-2xl font-bold font-mono text-red-400 mt-1 block">
            {graphData.summary.vulnerable_components}
          </span>
        </div>
      </div>

      {/* Main Graph Explorer Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Components List & Filter */}
        <div className="bg-surface border border-border rounded-xl p-4 flex flex-col h-[600px]">
          <div className="space-y-3 mb-3">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search package name..."
                className="w-full pl-8 pr-3 py-1.5 bg-surface-elevated border border-border rounded-lg text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
              />
            </div>
            <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={onlyVulnerable}
                onChange={(e) => setOnlyVulnerable(e.target.checked)}
                className="rounded text-emerald-500"
              />
              Show only vulnerable packages ({graphData.summary.vulnerable_components})
            </label>
          </div>

          <div className="flex-1 overflow-y-auto space-y-1.5 pr-1">
            {filteredNodes.map((node) => (
              <div
                key={node.id}
                onClick={() => setSelectedNode(node)}
                className={`p-2.5 rounded-lg border text-xs cursor-pointer transition-colors flex items-center justify-between ${
                  selectedNode?.id === node.id
                    ? 'bg-emerald-950/40 border-emerald-500 text-emerald-200'
                    : 'bg-surface-elevated/60 border-border hover:bg-surface-elevated text-slate-300'
                }`}
              >
                <div className="truncate">
                  <div className="font-semibold truncate">{node.name}</div>
                  <div className="text-[11px] text-slate-400 font-mono">v{node.version}</div>
                </div>

                <div className="flex items-center gap-1.5 shrink-0 ml-2">
                  {node.is_direct && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                      direct
                    </span>
                  )}
                  {node.has_vulnerabilities && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-950 text-red-300 border border-red-800 font-semibold animate-pulse">
                      CVE
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Component Deep Inspection & Attack Path */}
        <div className="lg:col-span-2 bg-surface border border-border rounded-xl p-6 flex flex-col justify-between h-[600px] overflow-y-auto">
          {selectedNode ? (
            <div className="space-y-6">
              <div className="border-b border-border pb-4 flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">
                      Component Inspector
                    </span>
                    {selectedNode.is_direct ? (
                      <span className="px-2 py-0.5 text-xs rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                        Direct Dependency
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 text-xs rounded bg-slate-800 text-slate-400 border border-slate-700">
                        Transitive Dependency
                      </span>
                    )}
                  </div>
                  <h2 className="text-xl font-bold font-mono text-slate-100">{selectedNode.name}</h2>
                  <div className="text-xs text-slate-400 font-mono mt-1">
                    Version: <span className="text-emerald-400">{selectedNode.version}</span>
                  </div>
                </div>

                {selectedNode.has_vulnerabilities ? (
                  <div className="p-3 bg-red-950/60 border border-red-800 rounded-xl text-center">
                    <ShieldAlert className="w-6 h-6 text-red-400 mx-auto mb-1" />
                    <span className="text-xs font-bold text-red-300 uppercase">Vulnerable</span>
                  </div>
                ) : (
                  <div className="p-3 bg-emerald-950/60 border border-emerald-800 rounded-xl text-center">
                    <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto mb-1" />
                    <span className="text-xs font-bold text-emerald-300 uppercase">Clean</span>
                  </div>
                )}
              </div>

              {/* PURL */}
              {selectedNode.purl && (
                <div>
                  <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold block mb-1">
                    Package URL (PURL)
                  </span>
                  <div className="p-2.5 rounded-lg bg-surface-elevated border border-border font-mono text-xs text-slate-300 truncate">
                    {selectedNode.purl}
                  </div>
                </div>
              )}

              {/* Vulnerabilities Associated */}
              <div>
                <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold block mb-2">
                  Known Advisories & CVEs
                </span>
                {selectedNode.vulnerabilities && selectedNode.vulnerabilities.length > 0 ? (
                  <div className="space-y-2">
                    {selectedNode.vulnerabilities.map((v, i) => (
                      <div
                        key={i}
                        className="p-3 rounded-lg bg-red-950/30 border border-red-800/80 text-xs space-y-1"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-red-400">{v.cve_id}</span>
                          <span className="px-2 py-0.5 rounded bg-red-900/60 text-red-200 text-[10px] font-semibold">
                            {v.severity}
                          </span>
                        </div>
                        <p className="text-slate-300 leading-relaxed">{v.description}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 rounded-lg bg-surface-elevated/40 border border-border text-xs text-slate-400">
                    No CVE records mapped to this specific version in OSV or Grype databases.
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="text-center p-12 text-slate-400">Select a component to inspect</div>
          )}
        </div>
      </div>
    </div>
  );
};
