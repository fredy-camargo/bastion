import React, { useCallback, useMemo, useState } from 'react';
import { Delete, RotateCcw, Shuffle, Trash2 } from 'lucide-react';

interface SecureVirtualKeypadProps {
  onInsertChar: (ch: string) => void;
  onBackspace: () => void;
  onClear: () => void;
}

const LOWER_CHARS = 'abcdefghijklmnopqrstuvwxyz'.split('');
const UPPER_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');
const DIGIT_CHARS = '0123456789'.split('');
const SYMBOL_CHARS = '!@#$%^&*()-_=+[]{};:,.?/~'.split('');

function secureRandomInt(maxExclusive: number): number {
  if (maxExclusive <= 1) return 0;
  const maxUnbiased = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
  const buf = new Uint32Array(1);
  let val = 0;
  do {
    crypto.getRandomValues(buf);
    val = buf[0];
  } while (val >= maxUnbiased);
  return val % maxExclusive;
}

function cryptoShuffle<T>(items: T[]): T[] {
  const copy = [...items];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    const tmp = copy[i];
    copy[i] = copy[j];
    copy[j] = tmp;
  }
  return copy;
}

export const SecureVirtualKeypad: React.FC<SecureVirtualKeypadProps> = ({
  onInsertChar,
  onBackspace,
  onClear,
}) => {
  const [layer, setLayer] = useState<'lower' | 'upper' | 'symbols'>('lower');
  const [autoShuffle, setAutoShuffle] = useState(false);
  const [shuffleSeed, setShuffleSeed] = useState(0);

  const digits = useMemo(() => {
    void shuffleSeed;
    return cryptoShuffle(DIGIT_CHARS);
  }, [shuffleSeed]);

  const keys = useMemo(() => {
    void shuffleSeed;
    if (layer === 'upper') return cryptoShuffle(UPPER_CHARS);
    if (layer === 'symbols') return cryptoShuffle(SYMBOL_CHARS);
    return cryptoShuffle(LOWER_CHARS);
  }, [layer, shuffleSeed]);

  const handlePress = useCallback(
    (ch: string) => {
      onInsertChar(ch);
      if (autoShuffle) {
        setShuffleSeed((s) => s + 1);
      }
    },
    [autoShuffle, onInsertChar]
  );

  return (
    <div
      className="rounded-lg border border-[#242C3A] bg-[#0F131A] p-3 space-y-2.5 no-select-secret"
      onContextMenu={(e) => e.preventDefault()}
    >
      <div className="flex flex-wrap items-center justify-between gap-2 pb-1 border-b border-[#242C3A]">
        <div className="flex items-center gap-1 rounded-md bg-[#0A0C10] p-0.5 border border-[#242C3A]">
          <button
            type="button"
            onClick={() => setLayer('lower')}
            className={`px-2.5 py-1 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
              layer === 'lower'
                ? 'bg-[#1C2330] text-[#F1F5F9]'
                : 'text-[#94A3B8] hover:text-[#F1F5F9]'
            }`}
          >
            abc
          </button>
          <button
            type="button"
            onClick={() => setLayer('upper')}
            className={`px-2.5 py-1 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
              layer === 'upper'
                ? 'bg-[#1C2330] text-[#F1F5F9]'
                : 'text-[#94A3B8] hover:text-[#F1F5F9]'
            }`}
          >
            ABC
          </button>
          <button
            type="button"
            onClick={() => setLayer('symbols')}
            className={`px-2.5 py-1 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
              layer === 'symbols'
                ? 'bg-[#1C2330] text-[#F1F5F9]'
                : 'text-[#94A3B8] hover:text-[#F1F5F9]'
            }`}
          >
            #!%
          </button>
        </div>

        <div className="flex items-center gap-2">
          <label className="inline-flex items-center gap-1.5 text-xs text-[#94A3B8] cursor-pointer">
            <input
              type="checkbox"
              checked={autoShuffle}
              onChange={(e) => setAutoShuffle(e.target.checked)}
              className="accent-amber-500 rounded"
            />
            <span>Reordenar tras pulsar</span>
          </label>
          <button
            type="button"
            onClick={() => setShuffleSeed((s) => s + 1)}
            className="inline-flex items-center gap-1 rounded border border-[#242C3A] bg-[#161B24] px-2 py-1 text-xs text-[#F1F5F9] hover:border-[#334054] cursor-pointer whitespace-nowrap"
          >
            <Shuffle className="h-3 w-3 text-amber-400" />
            <span>Mezclar</span>
          </button>
        </div>
      </div>

      {/* Fila de dígitos mezclados */}
      <div className="grid grid-cols-10 gap-1">
        {digits.map((d) => (
          <button
            key={d}
            type="button"
            onClick={() => handlePress(d)}
            className="h-8 rounded border border-[#242C3A] bg-[#161B24] font-mono text-xs font-medium text-amber-300 hover:border-amber-500/50 hover:bg-[#1C2330] active:scale-95 transition-transform cursor-pointer"
          >
            {d}
          </button>
        ))}
      </div>

      {/* Matriz principal mezclada */}
      <div className="grid grid-cols-9 gap-1">
        {keys.map((ch) => (
          <button
            key={ch}
            type="button"
            onClick={() => handlePress(ch)}
            className="h-8 rounded border border-[#242C3A] bg-[#161B24] font-mono text-xs font-medium text-[#F1F5F9] hover:border-amber-500/50 hover:bg-[#1C2330] active:scale-95 transition-transform cursor-pointer"
          >
            {ch}
          </button>
        ))}
      </div>

      {/* Acciones del teclado */}
      <div className="flex items-center justify-between gap-2 pt-1">
        <button
          type="button"
          onClick={() => handlePress(' ')}
          className="flex-1 h-8 rounded border border-[#242C3A] bg-[#161B24] text-xs text-[#94A3B8] hover:text-[#F1F5F9] hover:bg-[#1C2330] cursor-pointer"
        >
          Espacio
        </button>
        <button
          type="button"
          onClick={onBackspace}
          className="inline-flex items-center gap-1.5 h-8 px-3 rounded border border-[#242C3A] bg-[#161B24] text-xs font-medium text-[#F1F5F9] hover:bg-[#1C2330] cursor-pointer whitespace-nowrap"
        >
          <Delete className="h-3.5 w-3.5" />
          <span>Borrar</span>
        </button>
        <button
          type="button"
          onClick={onClear}
          className="inline-flex items-center gap-1.5 h-8 px-3 rounded border border-[#242C3A] bg-[#161B24] text-xs font-medium text-red-400 hover:border-red-500/40 hover:bg-red-500/10 cursor-pointer whitespace-nowrap"
        >
          <Trash2 className="h-3.5 w-3.5" />
          <span>Vaciar</span>
        </button>
        <button
          type="button"
          onClick={() => {
            setLayer('lower');
            setShuffleSeed((s) => s + 1);
          }}
          title="Restablecer distribución"
          className="inline-flex items-center justify-center h-8 w-8 rounded border border-[#242C3A] bg-[#161B24] text-[#94A3B8] hover:text-[#F1F5F9] cursor-pointer"
        >
          <RotateCcw className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
};
