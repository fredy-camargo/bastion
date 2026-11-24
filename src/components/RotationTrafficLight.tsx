import React from 'react';
import { RefreshCw } from 'lucide-react';
import { getRotationLabel, type RotationEvaluation } from '../utils/passwordRotation';

interface RotationTrafficLightProps {
  evaluation: RotationEvaluation;
  compact?: boolean;
  onRequestEdit?: () => void;
}

const TEXT_TONE: Record<RotationEvaluation['status'], string> = {
  fresh: 'text-emerald-400',
  soon: 'text-amber-300',
  due: 'text-rose-400',
  off: 'text-[#64748B]',
};

const PROGRESS_TONE: Record<RotationEvaluation['status'], string> = {
  fresh: 'bg-emerald-500',
  soon: 'bg-amber-400',
  due: 'bg-rose-500',
  off: 'bg-[#334054]',
};

const TrafficDots: React.FC<{ status: RotationEvaluation['status']; size?: 'sm' | 'md' }> = ({
  status,
  size = 'sm',
}) => {
  const dotSize = size === 'sm' ? 'h-2 w-2' : 'h-2.5 w-2.5';
  const padding = size === 'sm' ? 'px-1.5 py-1 gap-1' : 'px-2 py-1 gap-1.5';

  return (
    <span
      aria-hidden="true"
      className={`inline-flex items-center rounded-full border border-[#242C3A] bg-[#0A0C10] ${padding}`}
    >
      <span
        className={`${dotSize} rounded-full transition-opacity ${
          status === 'fresh'
            ? 'bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.75)]'
            : 'bg-[#242C3A]'
        }`}
      />
      <span
        className={`${dotSize} rounded-full transition-opacity ${
          status === 'soon'
            ? 'bg-amber-400 shadow-[0_0_6px_rgba(251,191,36,0.75)]'
            : 'bg-[#242C3A]'
        }`}
      />
      <span
        className={`${dotSize} rounded-full transition-opacity ${
          status === 'due'
            ? 'bg-rose-500 shadow-[0_0_6px_rgba(244,63,94,0.8)]'
            : 'bg-[#242C3A]'
        }`}
      />
    </span>
  );
};

export const RotationTrafficLight: React.FC<RotationTrafficLightProps> = ({
  evaluation,
  compact = false,
  onRequestEdit,
}) => {
  if (compact) {
    return (
      <span
        title={evaluation.tooltip}
        aria-label={evaluation.tooltip}
        className="inline-flex items-center gap-2 whitespace-nowrap"
      >
        <TrafficDots status={evaluation.status} size="sm" />
        <span className={`font-mono text-[11px] font-medium ${TEXT_TONE[evaluation.status]}`}>
          {evaluation.shortText}
        </span>
      </span>
    );
  }

  const lastChangedFormatted = new Date(evaluation.lastChangedAt).toLocaleDateString('es-ES', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
  });

  return (
    <div className="rounded-lg border border-[#242C3A] bg-[#161B24] p-3.5 space-y-2.5">
      <div className="flex items-start justify-between gap-2">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <TrafficDots status={evaluation.status} size="md" />
            <span className={`text-xs font-semibold ${TEXT_TONE[evaluation.status]}`}>
              {evaluation.statusLabel}
            </span>
          </div>
          <p className="text-xs text-[#F1F5F9]">{evaluation.detailText}</p>
        </div>

        {(evaluation.status === 'due' || evaluation.status === 'soon') && onRequestEdit && (
          <button
            type="button"
            onClick={onRequestEdit}
            className="inline-flex items-center gap-1 rounded border border-[#334054] bg-[#0F131A] px-2.5 py-1 text-[11px] font-medium text-[#F1F5F9] hover:border-amber-500/60 hover:text-amber-300 cursor-pointer whitespace-nowrap shrink-0"
          >
            <RefreshCw className="h-3 w-3" />
            <span>Cambiar clave</span>
          </button>
        )}
      </div>

      {evaluation.effectiveDays > 0 && (
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-[#0A0C10]">
          <div
            className={`h-full transition-all ${PROGRESS_TONE[evaluation.status]}`}
            style={{ width: `${evaluation.progressPercent}%` }}
          />
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-[#94A3B8] font-mono tabular-nums">
        <span>Último cambio: {lastChangedFormatted}</span>
        <span>
          {evaluation.usesDefault ? 'Predet.: ' : 'Propio: '}
          {getRotationLabel(evaluation.effectiveDays)}
        </span>
      </div>
    </div>
  );
};
