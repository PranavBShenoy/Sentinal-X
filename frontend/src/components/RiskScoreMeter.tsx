import React from 'react';
import { cn } from '../lib/utils';

interface RiskScoreMeterProps {
  score: number | null | undefined;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
}

export const RiskScoreMeter: React.FC<RiskScoreMeterProps> = ({
  score,
  size = 'md',
  showLabel = true,
}) => {
  const numericScore = typeof score === 'number' ? Math.max(0, Math.min(10, score)) : 0;

  // Determine color based on 0-10 scale
  let color = 'text-slate-400 border-slate-700 bg-slate-900/50';
  let barColor = 'bg-slate-500';
  let label = 'Clean';

  if (numericScore >= 9.0) {
    color = 'text-red-400 border-red-800 bg-red-950/40';
    barColor = 'bg-red-500';
    label = 'Critical Risk';
  } else if (numericScore >= 7.0) {
    color = 'text-orange-400 border-orange-800 bg-orange-950/40';
    barColor = 'bg-orange-500';
    label = 'High Risk';
  } else if (numericScore >= 4.0) {
    color = 'text-yellow-400 border-yellow-800 bg-yellow-950/40';
    barColor = 'bg-yellow-500';
    label = 'Medium Risk';
  } else if (numericScore > 0) {
    color = 'text-blue-400 border-blue-800 bg-blue-950/40';
    barColor = 'bg-blue-500';
    label = 'Low Risk';
  }

  if (size === 'sm') {
    return (
      <span className={cn('inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-mono text-xs border font-semibold', color)}>
        {score !== null && score !== undefined ? numericScore.toFixed(1) : 'N/A'}
      </span>
    );
  }

  if (size === 'lg') {
    return (
      <div className={cn('p-4 rounded-xl border flex flex-col items-center justify-center', color)}>
        <div className="text-4xl font-extrabold font-mono tracking-tight">
          {score !== null && score !== undefined ? numericScore.toFixed(1) : '--'}
        </div>
        <div className="text-xs uppercase tracking-wider font-semibold mt-1">
          {showLabel ? label : 'Risk Score'}
        </div>
        <div className="w-full bg-slate-800 h-1.5 rounded-full mt-3 overflow-hidden">
          <div
            className={cn('h-full rounded-full transition-all duration-500', barColor)}
            style={{ width: `${(numericScore / 10) * 100}%` }}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2">
      <span className={cn('px-2.5 py-1 rounded font-mono text-sm border font-semibold', color)}>
        {score !== null && score !== undefined ? numericScore.toFixed(1) : '--'}
      </span>
      {showLabel && <span className="text-xs text-slate-400">{label}</span>}
    </div>
  );
};
