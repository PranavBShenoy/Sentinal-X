import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  FolderGit2,
  PlayCircle,
  AlertOctagon,
  Wrench,
  FileText,
  Network,
} from 'lucide-react';
import { cn } from '../lib/utils';

const NAV_ITEMS = [
  { name: 'Dashboard', path: '/', icon: LayoutDashboard },
  { name: 'Projects', path: '/projects', icon: FolderGit2 },
  { name: 'Launch Scan', path: '/assessments/new', icon: PlayCircle },
  { name: 'Findings Explorer', path: '/findings', icon: AlertOctagon },
  { name: 'Remediation Hub', path: '/remediation', icon: Wrench },
  { name: 'Reports Center', path: '/reports', icon: FileText },
];

export const Sidebar: React.FC = () => {
  return (
    <aside className="w-64 border-r border-border bg-surface flex flex-col shrink-0 min-h-[calc(100vh-4rem)]">
      <div className="p-4 space-y-1">
        <div className="px-3 py-2 text-xs font-semibold text-slate-400 uppercase tracking-wider">
          Platform
        </div>
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-surface-elevated'
                )
              }
            >
              <Icon className="w-4 h-4 shrink-0" />
              {item.name}
            </NavLink>
          );
        })}
      </div>

      <div className="mt-auto p-4 border-t border-border/60">
        <div className="rounded-lg bg-surface-elevated/60 border border-border/80 p-3 text-xs text-slate-400 space-y-1.5">
          <div className="font-semibold text-slate-300 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            Security Core Active
          </div>
          <p className="text-[11px] leading-relaxed text-slate-400">
            SAST, Secret Detection, SBOM, Isolated Runtime & Risk Scoring.
          </p>
        </div>
      </div>
    </aside>
  );
};
