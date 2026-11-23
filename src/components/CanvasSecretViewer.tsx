import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Eye, ShieldAlert } from 'lucide-react';
import type { OcrNoiseLevel } from '../types/vault';

interface CanvasSecretViewerProps {
  secret: string;
  noiseLevel: OcrNoiseLevel;
  label?: string;
  height?: number;
}

function cryptoRandomFloat(): number {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return arr[0] / 0x100000000;
}

/**
 * Renderiza secretos únicamente en un lienzo <canvas> aislado sin nodos de texto en el DOM.
 * Incluye protección contra lectores de pantalla (aria-hidden), selección, clic derecho,
 * revelado solo mientras se mantiene pulsado (Hold-to-Reveal) y malla de ruido anti-OCR.
 */
export const CanvasSecretViewer: React.FC<CanvasSecretViewerProps> = ({
  secret,
  noiseLevel,
  label = 'Mantener para revelar',
  height = 56,
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const prevSecretRef = useRef<string>(secret);
  const [isRevealed, setIsRevealed] = useState(false);

  const wipeAndDrawMasked = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    const width = canvas.clientWidth || 360;
    const h = height;
    if (canvas.width !== Math.floor(width * dpr) || canvas.height !== Math.floor(h * dpr)) {
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(h * dpr);
    }

    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, h);

    // Fondo táctico acero oscuro
    ctx.fillStyle = '#0F131A';
    ctx.fillRect(0, 0, width, h);

    // Patrón diagonal sutil de protección
    ctx.strokeStyle = 'rgba(148, 163, 184, 0.08)';
    ctx.lineWidth = 1;
    for (let x = -h; x < width + h; x += 14) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x + h, h);
      ctx.stroke();
    }

    // Bloques enmascarados sin exponer longitud exacta (siempre 14 bloques fijos)
    const dotCount = 14;
    const startX = 18;
    const spacing = 14;
    ctx.fillStyle = '#475569';
    for (let i = 0; i < dotCount; i++) {
      ctx.beginPath();
      ctx.arc(startX + i * spacing, h / 2, 3, 0, Math.PI * 2);
      ctx.fill();
    }

    ctx.fillStyle = '#64748B';
    ctx.font = '500 11px "Public Sans", system-ui, sans-serif';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    ctx.fillText('Oculto en DOM · Canvas aislado', width - 14, h / 2);
  }, [height]);

  const drawProtectedSecret = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    const width = canvas.clientWidth || 360;
    const h = height;
    if (canvas.width !== Math.floor(width * dpr) || canvas.height !== Math.floor(h * dpr)) {
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(h * dpr);
    }

    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, h);

    // Fondo obsidiana con leve tinte ámbar
    ctx.fillStyle = '#0B0E14';
    ctx.fillRect(0, 0, width, h);

    const highNoise = noiseLevel === 'high';

    // Capa 1: Ruido de fondo de baja amplitud para dificultar binarización OCR
    const lineCount = highNoise ? 22 : 10;
    for (let i = 0; i < lineCount; i++) {
      ctx.strokeStyle = highNoise
        ? `rgba(245, 158, 11, ${0.06 + cryptoRandomFloat() * 0.08})`
        : `rgba(148, 163, 184, ${0.05 + cryptoRandomFloat() * 0.05})`;
      ctx.lineWidth = 0.8 + cryptoRandomFloat() * 0.7;
      ctx.beginPath();
      ctx.moveTo(cryptoRandomFloat() * width, cryptoRandomFloat() * h);
      ctx.lineTo(cryptoRandomFloat() * width, cryptoRandomFloat() * h);
      ctx.stroke();
    }

    // Capa 2: Puntos aleatorios anti-segmentación
    const speckleCount = highNoise ? 150 : 60;
    for (let i = 0; i < speckleCount; i++) {
      ctx.fillStyle =
        i % 3 === 0
          ? 'rgba(245, 158, 11, 0.16)'
          : 'rgba(148, 163, 184, 0.14)';
      ctx.fillRect(
        cryptoRandomFloat() * width,
        cryptoRandomFloat() * h,
        1.5,
        1.5
      );
    }

    // Capa 3: Dibujo carácter por carácter con micro-desplazamiento táctico legible al ojo humano
    const displayText = secret || '(vacío)';
    const paddingX = 14;
    const usableW = Math.max(80, width - paddingX * 2);
    const baseSize = displayText.length > 34 ? 12 : displayText.length > 24 ? 14 : 16;
    const charStep = Math.min(baseSize * 0.72, usableW / Math.max(displayText.length, 1));

    ctx.font = `600 ${baseSize}px "JetBrains Mono", monospace`;
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';

    let cursorX = paddingX;
    for (let i = 0; i < displayText.length; i++) {
      const ch = displayText[i];
      const jitterY = (cryptoRandomFloat() - 0.5) * (highNoise ? 2.6 : 1.2);
      const jitterRot = (cryptoRandomFloat() - 0.5) * (highNoise ? 0.09 : 0.04);

      ctx.save();
      ctx.translate(cursorX, h / 2 + jitterY);
      ctx.rotate(jitterRot);

      // Diferenciación visual sutil por clase de carácter para facilitar lectura humana
      if (/[0-9]/.test(ch)) {
        ctx.fillStyle = '#FBBF24'; // Ámbar claro para dígitos
      } else if (/[^a-zA-Z0-9]/.test(ch)) {
        ctx.fillStyle = '#38BDF8'; // Acero celeste para símbolos
      } else {
        ctx.fillStyle = '#F1F5F9'; // Titanio para letras
      }

      ctx.fillText(ch, 0, 0);
      ctx.restore();

      cursorX += charStep;
      if (cursorX > width - paddingX) break;
    }

    // Capa 4: Líneas de interferencia finas sobrepuestas
    if (highNoise) {
      ctx.strokeStyle = 'rgba(10, 12, 16, 0.38)';
      ctx.lineWidth = 1;
      for (let y = 10; y < h; y += 9) {
        ctx.beginPath();
        ctx.moveTo(0, y + (cryptoRandomFloat() - 0.5) * 2);
        ctx.lineTo(width, y + (cryptoRandomFloat() - 0.5) * 2);
        ctx.stroke();
      }
    }
  }, [height, noiseLevel, secret]);

  useEffect(() => {
    const canReveal = isRevealed && prevSecretRef.current === secret;
    if (!canReveal) {
      wipeAndDrawMasked();
      return;
    }

    drawProtectedSecret();
    const timer = window.setInterval(() => {
      drawProtectedSecret();
    }, 320);

    return () => window.clearInterval(timer);
  }, [isRevealed, secret, drawProtectedSecret, wipeAndDrawMasked]);

  // Immediate hide on blur, tab switch, pagehide, or privacy curtain activation
  useEffect(() => {
    const forceHide = () => setIsRevealed(false);
    window.addEventListener('blur', forceHide);
    window.addEventListener('pagehide', forceHide);
    window.addEventListener('bastion:hide-secrets', forceHide);
    document.addEventListener('visibilitychange', forceHide);
    window.addEventListener('resize', wipeAndDrawMasked);
    return () => {
      window.removeEventListener('blur', forceHide);
      window.removeEventListener('pagehide', forceHide);
      window.removeEventListener('bastion:hide-secrets', forceHide);
      document.removeEventListener('visibilitychange', forceHide);
      window.removeEventListener('resize', wipeAndDrawMasked);
    };
  }, [wipeAndDrawMasked]);

  // Wipe and hide when secret changes
  useEffect(() => {
    prevSecretRef.current = secret;
    setIsRevealed(false);
  }, [secret]);

  // Zero out canvas pixel buffer on unmount
  useEffect(() => {
    const canvas = canvasRef.current;
    return () => {
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      if (ctx) {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
      }
      canvas.width = 0;
      canvas.height = 0;
    };
  }, []);

  const startReveal = (e: React.PointerEvent | React.KeyboardEvent) => {
    e.preventDefault();
    setIsRevealed(true);
  };

  const stopReveal = () => {
    setIsRevealed(false);
  };

  return (
    <div className="space-y-2.5 no-select-secret">
      <div
        className="relative overflow-hidden rounded-lg border border-[#242C3A] bg-[#0F131A]"
        onContextMenu={(e) => e.preventDefault()}
        onDragStart={(e) => e.preventDefault()}
      >
        <canvas
          ref={canvasRef}
          aria-hidden="true"
          role="presentation"
          style={{ height: `${height}px` }}
          className="block w-full select-none pointer-events-none"
        />
      </div>

      <div className="flex items-center justify-between gap-3">
        <button
          type="button"
          onPointerDown={startReveal}
          onPointerUp={stopReveal}
          onPointerLeave={stopReveal}
          onPointerCancel={stopReveal}
          onKeyDown={(e) => {
            if (e.repeat) return;
            if (e.key === ' ' || e.key === 'Enter') startReveal(e);
          }}
          onKeyUp={stopReveal}
          onBlur={stopReveal}
          className={`inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-amber-500 ${
            isRevealed
              ? 'border-amber-500/70 bg-amber-500/15 text-amber-300'
              : 'border-[#242C3A] bg-[#161B24] text-[#F1F5F9] hover:border-[#334054] hover:bg-[#1C2330]'
          }`}
        >
          <Eye className="h-3.5 w-3.5" />
          <span>{isRevealed ? 'Soltar para ocultar' : label}</span>
        </button>

        <div className="flex items-center gap-1.5 text-xs text-[#94A3B8]">
          <ShieldAlert className="h-3.5 w-3.5 text-amber-500/80 shrink-0" />
          <span>
            Anti-OCR {noiseLevel === 'high' ? 'Alto' : 'Estándar'} · Sin texto DOM
          </span>
        </div>
      </div>
    </div>
  );
};
