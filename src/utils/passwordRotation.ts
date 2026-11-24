import type { RotationIntervalDays, VaultEntry } from '../types/vault';

export const MS_PER_DAY = 24 * 60 * 60 * 1000;

export interface RotationOption {
  days: RotationIntervalDays;
  shortLabel: string;
  label: string;
  hint: string;
}

export const ROTATION_OPTIONS: readonly RotationOption[] = [
  {
    days: 0,
    shortLabel: 'Sin',
    label: 'Sin recordatorio',
    hint: 'Desactiva el semáforo visual (solo informativo)',
  },
  {
    days: 7,
    shortLabel: '7 d',
    label: 'Semanal (7 días)',
    hint: 'Para claves temporales o accesos muy sensibles',
  },
  {
    days: 30,
    shortLabel: '30 d',
    label: 'Mensual (30 días)',
    hint: 'Cuentas operativas de alta exposición',
  },
  {
    days: 90,
    shortLabel: '3 m',
    label: 'Trimestral (3 meses)',
    hint: 'Recomendado para bancos, servidores y trabajo',
  },
  {
    days: 180,
    shortLabel: '6 m',
    label: 'Semestral (6 meses)',
    hint: 'Estándar equilibrado para correo y uso personal',
  },
  {
    days: 365,
    shortLabel: '12 m',
    label: 'Anual (12 meses)',
    hint: 'Mantenimiento preventivo a largo plazo',
  },
] as const;

export type RotationStatus = 'off' | 'fresh' | 'soon' | 'due';

export interface RotationEvaluation {
  status: RotationStatus;
  effectiveDays: RotationIntervalDays;
  usesDefault: boolean;
  lastChangedAt: number;
  nextRotationAt: number | null;
  daysElapsed: number;
  daysRemaining: number | null;
  progressPercent: number;
  shortText: string;
  statusLabel: string;
  detailText: string;
  tooltip: string;
}

const OPTION_MAP = new Map<RotationIntervalDays, RotationOption>(
  ROTATION_OPTIONS.map((opt) => [opt.days, opt])
);

export function getRotationLabel(days: RotationIntervalDays): string {
  return OPTION_MAP.get(days)?.label ?? 'Semestral (6 meses)';
}

export function getRotationShortLabel(days: RotationIntervalDays): string {
  return OPTION_MAP.get(days)?.shortLabel ?? '6 m';
}

function formatDurationDays(absDays: number): string {
  const days = Math.max(1, Math.round(absDays));
  if (days === 1) return '1 día';
  if (days < 45) return `${days} días`;
  const months = Math.round(days / 30);
  if (months < 12) return months === 1 ? '1 mes' : `${months} meses`;
  const years = Math.round(days / 365);
  return years === 1 ? '1 año' : `${years} años`;
}

/**
 * Evaluates password age against the effective rotation cadence for a non-intrusive traffic light.
 */
export function evaluatePasswordRotation(
  entry: Pick<VaultEntry, 'createdAt' | 'updatedAt' | 'passwordUpdatedAt' | 'rotationIntervalDays'>,
  defaultRotationDays: RotationIntervalDays,
  now: number = Date.now()
): RotationEvaluation {
  const usesDefault = entry.rotationIntervalDays === undefined;
  const effectiveDays = entry.rotationIntervalDays ?? defaultRotationDays;
  const rawAnchor = entry.passwordUpdatedAt ?? entry.updatedAt ?? entry.createdAt;
  const lastChangedAt = Number.isFinite(rawAnchor) && rawAnchor >= 0 ? rawAnchor : now;

  if (effectiveDays === 0) {
    return {
      status: 'off',
      effectiveDays: 0,
      usesDefault,
      lastChangedAt,
      nextRotationAt: null,
      daysElapsed: Math.max(0, Math.floor((now - lastChangedAt) / MS_PER_DAY)),
      daysRemaining: null,
      progressPercent: 0,
      shortText: 'Sin',
      statusLabel: 'Sin recordatorio',
      detailText: 'Recordatorio desactivado',
      tooltip: 'Semáforo desactivado para esta credencial',
    };
  }

  const cycleMs = effectiveDays * MS_PER_DAY;
  const elapsedMs = Math.max(0, now - lastChangedAt);
  const ratio = elapsedMs / cycleMs;
  const daysElapsed = Math.floor(elapsedMs / MS_PER_DAY);
  const nextRotationAt = lastChangedAt + cycleMs;
  const diffDays = (nextRotationAt - now) / MS_PER_DAY;
  const daysRemaining = diffDays >= 0 ? Math.ceil(diffDays) : Math.floor(diffDays);
  const progressPercent = Math.max(0, Math.min(100, Math.round(ratio * 100)));

  let status: RotationStatus = 'fresh';
  let shortText = 'Vigente';
  let statusLabel = 'Vigente';
  let detailText = `Faltan ${formatDurationDays(Math.max(1, daysRemaining))}`;

  if (ratio >= 1.0) {
    status = 'due';
    shortText = 'Revisar';
    statusLabel = 'Sugerida para cambio';
    const overdueDays = Math.abs(Math.floor(diffDays));
    detailText =
      overdueDays <= 0
        ? 'Ciclo cumplido hoy'
        : `Ciclo cumplido hace ${formatDurationDays(overdueDays)}`;
  } else if (ratio >= 0.75) {
    status = 'soon';
    shortText = 'Pronto';
    statusLabel = 'Próxima a rotar';
    detailText =
      daysRemaining <= 1 ? 'Falta menos de 1 día' : `Faltan ${formatDurationDays(daysRemaining)}`;
  }

  const cadenceNote = usesDefault
    ? `Ciclo predeterminado: ${getRotationLabel(effectiveDays)}`
    : `Ciclo propio: ${getRotationLabel(effectiveDays)}`;

  return {
    status,
    effectiveDays,
    usesDefault,
    lastChangedAt,
    nextRotationAt,
    daysElapsed,
    daysRemaining,
    progressPercent,
    shortText,
    statusLabel,
    detailText,
    tooltip: `${statusLabel} · ${detailText} (${cadenceNote})`,
  };
}

const STATUS_PRIORITY: Record<RotationStatus, number> = {
  due: 0,
  soon: 1,
  fresh: 2,
  off: 3,
};

/**
 * Sorts entries with most urgent review suggestions first (`due` -> `soon` -> `fresh` -> `off`).
 */
export function compareRotationUrgency(a: RotationEvaluation, b: RotationEvaluation): number {
  const rankDiff = STATUS_PRIORITY[a.status] - STATUS_PRIORITY[b.status];
  if (rankDiff !== 0) return rankDiff;
  if (a.daysRemaining === null && b.daysRemaining === null) return 0;
  if (a.daysRemaining === null) return 1;
  if (b.daysRemaining === null) return -1;
  return a.daysRemaining - b.daysRemaining;
}
