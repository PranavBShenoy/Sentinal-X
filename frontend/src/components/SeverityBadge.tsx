import React from 'react';
import { Severity } from '../types';
import { cn } from '../lib/utils';

const SEVERITY_CONFIG: Record<
  Severity,
  { label: string; bg: string; text: string; border: string; dot: string }
> = {
  CRITICAL: {
    label: 'Critical',
    bg: 'bg-red-950/60',
    text: 'text-red-400',
    border: 'border-red-800/80',
    dot: 'bg-red-500',
  },
  HIGH: {
    label: 'High',
    bg: 'bg-orange-950/60',
    text: 'text-orange-400',
    border: 'border-orange-800/80',
    dot: 'bg-orange-500',
  },
  MEDIUM: {
    label: 'Medium',
    bg: 'bg-yellow-950/60',
    text: 'text-yellow-400',
    border: 'border-yellow-800/80',
    dot: 'bg-yellow-500',
  },
  LOW: {
    label: 'Low',
    bg: 'bg-blue-950/60',
    text: 'text-blue-400',
    border: 'border-blue-800/80',
    dot: 'bg-blue-500',
  },
  INFO: {
    label: 'Info',
    bg: 'bg-slate-900/60',
    text: 'text-slate-400',
    border: 'border-slate-800',
    dot: 'bg-slate-500',
  },
};

interface SeverityBadgeProps {
  severity: Severity | string | null | undefined;
  size?: 'sm' | 'md';
  className?: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  className,
}) => {
  const sevKey = (severity?.toUpperCase() || 'INFO') as Severity;
  const config = SEVERITY_CONFIG[sevKey] || SEVERITY_CONFIG.INFO;

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 font-medium rounded-full border',
        size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs',
        config.bg,
        config.text,
        config.border,
        className
      )}
    >
      <span className={cn('rounded-full', size === 'sm' ? 'w-1.5 h-1.5' : 'w-2 h-2', config.dot)} />
      {config.label}
    </span>
  );
};
