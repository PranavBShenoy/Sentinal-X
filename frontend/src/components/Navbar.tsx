import React from 'react';
import { Shield, LogOut, UserCircle } from 'lucide-react';
import { useAuth } from '../features/auth/AuthContext';

export const Navbar: React.FC = () => {
  const { user, logout } = useAuth();

  return (
    <header className="h-16 border-b border-border bg-surface px-6 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <span className="font-extrabold text-lg tracking-wider bg-gradient-to-r from-emerald-400 via-teal-300 to-cyan-400 bg-clip-text text-transparent">
            SENTINEL-X
          </span>
          <span className="ml-2 text-xs text-slate-400 border border-slate-700 rounded px-1.5 py-0.5 font-mono">
            v1.0.0
          </span>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {user && (
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 text-sm text-slate-300 bg-surface-elevated px-3 py-1.5 rounded-lg border border-border">
              <UserCircle className="w-4 h-4 text-emerald-400" />
              <span className="font-medium">{user.full_name || user.email}</span>
              <span className="text-xs text-slate-400 font-mono">({user.role})</span>
            </div>
            <button
              onClick={logout}
              className="p-2 rounded-lg text-slate-400 hover:text-red-400 hover:bg-red-950/30 border border-transparent hover:border-red-900 transition-colors"
              title="Sign Out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </header>
  );
};
