import React from 'react';
import { EyeOff, Lock, ShieldCheck } from 'lucide-react';

interface PrivacyCurtainOverlayProps {
  visible: boolean;
  reason: string;
  onResume: () => void;
  onLockNow: () => void;
}

export const PrivacyCurtainOverlay: React.FC<PrivacyCurtainOverlayProps> = ({
  visible,
  reason,
  onResume,
  onLockNow,
}) => {
  if (!visible) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-[#0A0C10]/96 backdrop-blur-md p-6 no-select-secret"
      onContextMenu={(e) => e.preventDefault()}
    >
      <div className="w-full max-w-md rounded-xl border border-[#242C3A] bg-[#161B24] p-7 text-center space-y-5">
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-lg border border-amber-500/40 bg-amber-500/10 text-amber-400">
          <EyeOff className="h-6 w-6" />
        </div>
        <div className="space-y-1.5">
          <h2 className="font-display text-xl font-semibold text-[#F1F5F9]">
            Escudo de privacidad activo
          </h2>
          <p className="text-xs text-[#94A3B8] leading-relaxed">{reason}</p>
        </div>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-2.5 pt-2">
          <button
            type="button"
            onClick={onResume}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-md bg-amber-500 px-4 py-2 text-xs font-semibold text-[#0A0C10] hover:bg-amber-400 cursor-pointer whitespace-nowrap"
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            <span>Reanudar vista</span>
          </button>
          <button
            type="button"
            onClick={onLockNow}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-md border border-[#242C3A] bg-[#0F131A] px-4 py-2 text-xs font-medium text-[#F1F5F9] hover:border-red-500/50 hover:text-red-300 cursor-pointer whitespace-nowrap"
          >
            <Lock className="h-3.5 w-3.5" />
            <span>Bloquear y limpiar RAM</span>
          </button>
        </div>
      </div>
    </div>
  );
};
