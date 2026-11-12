import React from 'react';
import { AssessmentStatus } from '../types';
import { cn } from '../lib/utils';
import { CheckCircle2, AlertTriangle, XCircle, Clock, Loader2 } from 'lucide-react';

interface StatusBadgeProps {
  status: AssessmentStatus | string;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, className }) => {
  switch (status) {
    case 'COMPLETED':
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-full bg-emerald-950/60 text-emerald-400 border border-emerald-800/80',
            className
          )}
        >
          <CheckCircle2 className="w-3.5 h-3.5" />
          Completed
        </span>
      );
    case 'PARTIAL':
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-full bg-amber-950/60 text-amber-400 border border-amber-800/80',
            className
          )}
        >
          <AlertTriangle className="w-3.5 h-3.5" />
          Partial Coverage
        </span>
      );
    case 'FAILED':
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-full bg-rose-950/60 text-rose-400 border border-rose-800/80',
            className
          )}
        >
          <XCircle className="w-3.5 h-3.5" />
          Failed
        </span>
      );
    case 'CREATED':
    case 'QUEUED':
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-full bg-slate-800/60 text-slate-300 border border-slate-700',
            className
          )}
        >
          <Clock className="w-3.5 h-3.5" />
          Queued
        </span>
      );
    default:
      return (
        <span
          className={cn(
            'inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-full bg-sky-950/60 text-sky-400 border border-sky-800/80 animate-pulse',
            className
          )}
        >
          <Loader2 className="w-3.5 h-3.5 animate-spin" />
          {status.replace(/_/g, ' ')}
        </span>
      );
  }
};
