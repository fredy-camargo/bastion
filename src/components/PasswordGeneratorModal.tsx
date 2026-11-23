import React, { useEffect, useMemo, useState } from 'react';
import { Check, Copy, RefreshCw, X } from 'lucide-react';
import { calculateEntropyBits, generateSecurePassword } from '../crypto/engine';
import type { OcrNoiseLevel, PasswordGenOptions } from '../types/vault';
import { CanvasSecretViewer } from './CanvasSecretViewer';

interface PasswordGeneratorModalProps {
  noiseLevel: OcrNoiseLevel;
  onClose: () => void;
  onCopy: (password: string) => void;
  onApply?: (password: string) => void;
}

export const PasswordGeneratorModal: React.FC<PasswordGeneratorModalProps> = ({
  noiseLevel,
  onClose,
  onCopy,
  onApply,
}) => {
  const [options, setOptions] = useState<PasswordGenOptions>({
    length: 24,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
    excludeAmbiguous: true,
  });

  const [generated, setGenerated] = useState(() =>
    generateSecurePassword({
      length: 24,
      uppercase: true,
      lowercase: true,
      numbers: true,
      symbols: true,
      excludeAmbiguous: true,
    })
  );

  const [copiedFlag, setCopiedFlag] = useState(false);

  useEffect(() => {
    return () => {
      setGenerated('');
    };
  }, []);

  const handleClose = () => {
    setGenerated('');
    onClose();
  };

  const entropy = useMemo(() => calculateEntropyBits(generated), [generated]);

  const regenerate = (nextOpts: PasswordGenOptions = options) => {
    const clampedOpts: PasswordGenOptions = {
      ...nextOpts,
      length: Math.min(64, Math.max(12, Math.trunc(nextOpts.length) || 24)),
    };
    setOptions(clampedOpts);
    setGenerated(generateSecurePassword(clampedOpts));
    setCopiedFlag(false);
  };

  const toggleOption = (key: keyof Omit<PasswordGenOptions, 'length'>) => {
    const next = { ...options, [key]: !options[key] };
    if (!next.uppercase && !next.lowercase && !next.numbers && !next.symbols) {
      return;
    }
    regenerate(next);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4">
      <div className="w-full max-w-lg rounded-xl border border-[#242C3A] bg-[#161B24] p-6 space-y-5">
        <div className="flex items-center justify-between border-b border-[#242C3A] pb-3.5">
          <div>
            <h2 className="font-display text-lg font-semibold text-[#F1F5F9]">
              Generador criptográfico CSPRNG
            </h2>
            <p className="text-xs text-[#94A3B8] mt-0.5">
              Entropía nativa del sistema sin sesgo estadístico · Vista aislada en Canvas
            </p>
          </div>
          <button
            type="button"
            onClick={handleClose}
            className="rounded-md p-1.5 text-[#94A3B8] hover:bg-[#1C2330] hover:text-[#F1F5F9] cursor-pointer"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <CanvasSecretViewer
          secret={generated}
          noiseLevel={noiseLevel}
          label="Mantener para inspeccionar clave"
          height={54}
        />

        <div className="flex items-center justify-between text-xs font-mono tabular-nums text-[#94A3B8]">
          <span>Longitud: {options.length} caracteres</span>
          <span className="text-amber-400 font-medium">
            {entropy.bits} bits · {entropy.label}
          </span>
        </div>

        <input
          type="range"
          min={12}
          max={64}
          value={options.length}
          onChange={(e) => regenerate({ ...options, length: Number(e.target.value) })}
          className="w-full accent-amber-500 cursor-pointer"
        />

        <div className="grid grid-cols-2 gap-2.5 text-xs">
          {(
            [
              ['uppercase', 'Mayúsculas (A–Z)'],
              ['lowercase', 'Minúsculas (a–z)'],
              ['numbers', 'Dígitos (0–9)'],
              ['symbols', 'Símbolos (!@#$...)'],
              ['excludeAmbiguous', 'Excluir ambiguos (0O1lI)'],
            ] as const
          ).map(([key, label]) => (
            <label
              key={key}
              className="flex items-center gap-2.5 rounded-lg border border-[#242C3A] bg-[#0F131A] px-3 py-2.5 text-[#F1F5F9] cursor-pointer hover:border-[#334054]"
            >
              <input
                type="checkbox"
                checked={options[key]}
                onChange={() => toggleOption(key)}
                className="accent-amber-500"
              />
              <span>{label}</span>
            </label>
          ))}
        </div>

        <div className="flex items-center justify-between gap-2 pt-2 border-t border-[#242C3A]">
          <button
            type="button"
            onClick={() => regenerate()}
            className="inline-flex items-center gap-2 rounded-md border border-[#242C3A] bg-[#0F131A] px-3.5 py-2 text-xs font-medium text-[#F1F5F9] hover:border-[#334054] cursor-pointer whitespace-nowrap"
          >
            <RefreshCw className="h-3.5 w-3.5 text-amber-400" />
            <span>Regenerar</span>
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => {
                onCopy(generated);
                setCopiedFlag(true);
              }}
              className="inline-flex items-center gap-2 rounded-md border border-[#242C3A] bg-[#0F131A] px-3.5 py-2 text-xs font-medium text-[#F1F5F9] hover:border-amber-500/50 cursor-pointer whitespace-nowrap"
            >
              {copiedFlag ? (
                <Check className="h-3.5 w-3.5 text-emerald-400" />
              ) : (
                <Copy className="h-3.5 w-3.5 text-amber-400" />
              )}
              <span>{copiedFlag ? 'Copiada' : 'Copiar'}</span>
            </button>

            {onApply && (
              <button
                type="button"
                onClick={() => {
                  const value = generated;
                  setGenerated('');
                  onApply(value);
                  onClose();
                }}
                className="inline-flex items-center gap-2 rounded-md bg-amber-500 px-4 py-2 text-xs font-semibold text-[#0A0C10] hover:bg-amber-400 cursor-pointer whitespace-nowrap"
              >
                <span>Aplicar clave</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
