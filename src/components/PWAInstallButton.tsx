import React, { useState } from 'react';
import { Download, MonitorDown, X } from 'lucide-react';
import { usePWAInstall } from '../hooks/usePWAInstall';

interface PWAInstallButtonProps {
  compact?: boolean;
}

export const PWAInstallButton: React.FC<PWAInstallButtonProps> = ({ compact = false }) => {
  const { isInstallable, isInstalled, isIOS, install } = usePWAInstall();
  const [showIOSGuide, setShowIOSGuide] = useState(false);

  if (isInstalled) {
    return null;
  }

  if (isInstallable) {
    return (
      <button
        type="button"
        onClick={() => void install()}
        className={`inline-flex items-center justify-center gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 text-xs font-medium text-amber-300 hover:bg-amber-500/20 transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
          compact ? 'px-3 py-1.5' : 'w-full px-3 py-2'
        }`}
      >
        <MonitorDown className="h-3.5 w-3.5" />
        <span>Instalar app de escritorio</span>
      </button>
    );
  }

  if (isIOS) {
    return (
      <>
        <button
          type="button"
          onClick={() => setShowIOSGuide(true)}
          className={`inline-flex items-center justify-center gap-2 rounded-md border border-[#242C3A] bg-[#161B24] text-xs font-medium text-[#F1F5F9] hover:border-[#334054] transition-colors cursor-pointer whitespace-nowrap shrink-0 ${
            compact ? 'px-3 py-1.5' : 'w-full px-3 py-2'
          }`}
        >
          <Download className="h-3.5 w-3.5 text-amber-400" />
          <span>Instalar sin conexión</span>
        </button>

        {showIOSGuide && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4">
            <div className="w-full max-w-sm rounded-xl border border-[#242C3A] bg-[#161B24] p-6">
              <div className="flex items-center justify-between">
                <h3 className="text-base font-semibold text-[#F1F5F9]">Instalar Bastión en iOS</h3>
                <button
                  type="button"
                  onClick={() => setShowIOSGuide(false)}
                  className="text-[#94A3B8] hover:text-[#F1F5F9] cursor-pointer"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
              <p className="mt-3 text-sm text-[#94A3B8] leading-relaxed">
                1. Pulsa el botón <strong className="text-[#F1F5F9]">Compartir</strong> en la barra de Safari.
                <br />
                2. Selecciona <strong className="text-[#F1F5F9]">Añadir a pantalla de inicio</strong> para abrir Bastión en modo aislado sin conexión.
              </p>
              <button
                type="button"
                onClick={() => setShowIOSGuide(false)}
                className="mt-5 w-full rounded-md bg-amber-500 px-4 py-2 text-xs font-semibold text-[#0A0C10] hover:bg-amber-400 cursor-pointer"
              >
                Entendido
              </button>
            </div>
          </div>
        )}
      </>
    );
  }

  return null;
};
