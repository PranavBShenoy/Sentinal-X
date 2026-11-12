import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../../lib/api';
import { Project, Repository } from '../../types';
import { formatDate } from '../../lib/utils';
import {
  FolderGit2,
  Plus,
  GitBranch,
  Trash2,
  PlayCircle,
  ExternalLink,
  AlertCircle,
  X,
} from 'lucide-react';

export const ProjectsPage: React.FC = () => {
  const [projects, setProjects] = useState<Project[]>([]);
  const [reposMap, setReposMap] = useState<Record<string, Repository[]>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // New Project Modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [repoName, setRepoName] = useState('');
  const [cloneUrl, setCloneUrl] = useState('');
  const [defaultBranch, setDefaultBranch] = useState('main');
  const [creating, setCreating] = useState(false);

  const loadProjects = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getProjects();
      const projs = res.items || [];
      setProjects(projs);

      // Load repos for each project
      const map: Record<string, Repository[]> = {};
      await Promise.all(
        projs.map(async (p) => {
          try {
            const r = await api.getRepositories(p.id);
            map[p.id] = r;
          } catch {
            map[p.id] = [];
          }
        })
      );
      setReposMap(map);
    } catch (err: any) {
      setError(err.message || 'Failed to load projects');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadProjects();
  }, []);

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setError(null);
    try {
      const newProj = await api.createProject({ name, description });

      // If user provided repository details, register repository immediately
      if (cloneUrl) {
        await api.createRepository(newProj.id, {
          name: repoName || name.toLowerCase().replace(/\s+/g, '-'),
          clone_url: cloneUrl,
          default_branch: defaultBranch || 'main',
        });
      }

      setIsModalOpen(false);
      setName('');
      setDescription('');
      setRepoName('');
      setCloneUrl('');
      loadProjects();
    } catch (err: any) {
      setError(err.message || 'Failed to create project');
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteProject = async (projectId: string) => {
    if (!confirm('Are you sure you want to delete this project and all associated assessments?')) {
      return;
    }
    try {
      await api.deleteProject(projectId);
      loadProjects();
    } catch (err: any) {
      alert(err.message || 'Failed to delete project');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100 flex items-center gap-2.5">
            Security Projects
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Manage target repositories and continuous assessment configurations
          </p>
        </div>
        <button
          onClick={() => setIsModalOpen(true)}
          className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-medium rounded-lg text-sm flex items-center gap-2 shadow-lg shadow-emerald-900/30 transition-colors"
        >
          <Plus className="w-4 h-4" />
          New Project
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800 text-red-300 text-sm flex items-center gap-2.5">
          <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Projects Grid */}
      {loading ? (
        <div className="p-12 text-center text-slate-400">Loading projects...</div>
      ) : projects.length === 0 ? (
        <div className="bg-surface border border-border rounded-xl p-12 text-center">
          <FolderGit2 className="w-12 h-12 text-slate-500 mx-auto mb-3" />
          <h3 className="text-base font-semibold text-slate-200">No Projects Configured</h3>
          <p className="text-sm text-slate-400 mt-1 max-w-sm mx-auto">
            Get started by creating your first project and connecting a Git repository for automated
            security scans.
          </p>
          <button
            onClick={() => setIsModalOpen(true)}
            className="mt-4 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded-lg inline-flex items-center gap-1.5 transition-colors"
          >
            <Plus className="w-4 h-4" />
            Add First Project
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {projects.map((p) => {
            const repos = reposMap[p.id] || [];
            return (
              <div
                key={p.id}
                className="bg-surface border border-border rounded-xl p-5 hover:border-slate-600 transition-all flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-2.5">
                      <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        <FolderGit2 className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="font-semibold text-slate-100">{p.name}</h3>
                        <span className="text-[11px] text-slate-400">
                          Created {formatDate(p.created_at)}
                        </span>
                      </div>
                    </div>
                    <button
                      onClick={() => handleDeleteProject(p.id)}
                      className="p-1.5 rounded text-slate-500 hover:text-red-400 hover:bg-red-950/30 transition-colors"
                      title="Delete Project"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>

                  <p className="text-xs text-slate-300 mt-3 leading-relaxed">
                    {p.description || 'No project description provided.'}
                  </p>

                  {/* Connected Repositories */}
                  <div className="mt-4 pt-3 border-t border-border/60">
                    <div className="text-[11px] uppercase tracking-wider font-semibold text-slate-400 mb-2">
                      Connected Repositories ({repos.length})
                    </div>
                    {repos.length === 0 ? (
                      <div className="text-xs text-slate-500 italic">No repository linked yet.</div>
                    ) : (
                      <div className="space-y-1.5">
                        {repos.map((r) => (
                          <div
                            key={r.id}
                            className="flex items-center justify-between text-xs bg-surface-elevated/70 px-3 py-1.5 rounded-lg border border-border/80"
                          >
                            <span className="font-mono text-slate-200">{r.full_name || r.name}</span>
                            <span className="font-mono text-[11px] text-slate-400 flex items-center gap-1">
                              <GitBranch className="w-3 h-3 text-emerald-400" />
                              {r.default_branch}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                <div className="mt-5 pt-3 border-t border-border/60 flex items-center justify-end gap-2">
                  <Link
                    to={`/assessments/new?project_id=${p.id}`}
                    className="px-3 py-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 border border-emerald-500/30 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors"
                  >
                    <PlayCircle className="w-3.5 h-3.5" />
                    Run Assessment
                  </Link>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* New Project Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-2xl w-full max-w-lg p-6 relative shadow-2xl">
            <button
              onClick={() => setIsModalOpen(false)}
              className="absolute top-5 right-5 text-slate-400 hover:text-slate-200"
            >
              <X className="w-5 h-5" />
            </button>

            <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <FolderGit2 className="w-5 h-5 text-emerald-400" />
              Create Security Project
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Add a target project and optionally connect a Git repository.
            </p>

            <form onSubmit={handleCreateProject} className="mt-5 space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                  Project Name *
                </label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. Sentinel Core API"
                  className="w-full px-3.5 py-2 bg-surface-elevated border border-border rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                  Description
                </label>
                <textarea
                  rows={2}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Production microservice handling customer payments..."
                  className="w-full px-3.5 py-2 bg-surface-elevated border border-border rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="pt-2 border-t border-border/80">
                <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider block mb-2">
                  Repository Setup (Optional)
                </span>
                <div className="space-y-3">
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Clone URL / Local Path</label>
                    <input
                      type="text"
                      value={cloneUrl}
                      onChange={(e) => setCloneUrl(e.target.value)}
                      placeholder="https://github.com/org/repo.git or /path/to/repo"
                      className="w-full px-3.5 py-2 bg-surface-elevated border border-border rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500 font-mono text-xs"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">Repository Name</label>
                      <input
                        type="text"
                        value={repoName}
                        onChange={(e) => setRepoName(e.target.value)}
                        placeholder="repo-name"
                        className="w-full px-3.5 py-2 bg-surface-elevated border border-border rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500 font-mono text-xs"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">Default Branch</label>
                      <input
                        type="text"
                        value={defaultBranch}
                        onChange={(e) => setDefaultBranch(e.target.value)}
                        placeholder="main"
                        className="w-full px-3.5 py-2 bg-surface-elevated border border-border rounded-lg text-sm text-slate-100 focus:outline-none focus:border-emerald-500 font-mono text-xs"
                      />
                    </div>
                  </div>
                </div>
              </div>

              <div className="pt-4 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 bg-surface-elevated hover:bg-slate-700 text-slate-300 text-xs font-medium rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creating}
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold rounded-lg shadow-lg shadow-emerald-900/30"
                >
                  {creating ? 'Creating...' : 'Create Project'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
