import { useCallback, useEffect, useRef, useState } from 'react';

export interface ClipboardGuardState {
  activeLabel: string | null;
  activeEntryId: string | null;
  secondsRemaining: number;
  totalSeconds: number;
  statusMessage: string | null;
}

async function copyNativeDesktopClipboard(text: string): Promise<boolean> {
  try {
    const res = await fetch('/__bastion/clipboard/copy', {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'X-Bastion-Desktop': '1',
      },
      body: text,
      credentials: 'same-origin',
    });
    return res.ok;
  } catch {
    return false;
  }
}

async function clearNativeDesktopClipboard(): Promise<boolean> {
  try {
    const res = await fetch('/__bastion/clipboard/clear', {
      method: 'POST',
      headers: {
        'X-Bastion-Desktop': '1',
      },
      credentials: 'same-origin',
    });
    return res.ok;
  } catch {
    return false;
  }
}

async function writeClipboardSafe(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Fallback below when navigator.clipboard is unavailable or lacks document focus
  }

  const prevActive = document.activeElement as HTMLElement | null;
  const textarea = document.createElement('textarea');
  try {
    // execCommand('copy') requires a non-empty selection to overwrite the OS clipboard
    textarea.value = text === '' ? ' ' : text;
    textarea.setAttribute('readonly', 'true');
    textarea.setAttribute('aria-hidden', 'true');
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    textarea.style.pointerEvents = 'none';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.select();
    textarea.setSelectionRange(0, textarea.value.length);
    return document.execCommand('copy');
  } catch {
    return false;
  } finally {
    textarea.value = '';
    if (textarea.parentNode) {
      textarea.parentNode.removeChild(textarea);
    }
    if (prevActive && typeof prevActive.focus === 'function') {
      try {
        prevActive.focus({ preventScroll: true });
      } catch {
        // Ignore focus restoration errors
      }
    }
  }
}

export function useClipboardGuard(defaultTimeoutSec: number) {
  const safeDefaultTimeout = Math.max(5, Math.min(300, Math.trunc(defaultTimeoutSec) || 30));

  const [state, setState] = useState<ClipboardGuardState>({
    activeLabel: null,
    activeEntryId: null,
    secondsRemaining: 0,
    totalSeconds: safeDefaultTimeout,
    statusMessage: null,
  });

  const intervalRef = useRef<number | null>(null);
  const clearNoticeTimeoutRef = useRef<number | null>(null);
  const opSeqRef = useRef<number>(0);
  const pendingWipeRef = useRef<boolean>(false);

  const stopTimer = useCallback(() => {
    if (intervalRef.current !== null) {
      window.clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  }, []);

  const clearNoticeTimer = useCallback(() => {
    if (clearNoticeTimeoutRef.current !== null) {
      window.clearTimeout(clearNoticeTimeoutRef.current);
      clearNoticeTimeoutRef.current = null;
    }
  }, []);

  const scheduleNoticeClear = useCallback(
    (expectedOp: number, delayMs: number) => {
      clearNoticeTimer();
      clearNoticeTimeoutRef.current = window.setTimeout(() => {
        if (opSeqRef.current !== expectedOp) return;
        setState((prev) => ({ ...prev, statusMessage: null }));
      }, delayMs);
    },
    [clearNoticeTimer]
  );

  const wipeClipboardNow = useCallback(
    async (reason?: string) => {
      const myOp = ++opSeqRef.current;
      stopTimer();
      clearNoticeTimer();

      setState({
        activeLabel: null,
        activeEntryId: null,
        secondsRemaining: 0,
        totalSeconds: safeDefaultTimeout,
        statusMessage: null,
      });

      const wiped = (await clearNativeDesktopClipboard()) || (await writeClipboardSafe(''));
      if (opSeqRef.current !== myOp) return;

      if (wiped) {
        pendingWipeRef.current = false;
        setState((prev) => ({
          ...prev,
          statusMessage: reason ?? 'Portapapeles purgado de forma segura.',
        }));
        scheduleNoticeClear(myOp, 3200);
      } else {
        // Browser blocked background clipboard write; retry immediately on focus
        pendingWipeRef.current = true;
        setState((prev) => ({
          ...prev,
          statusMessage:
            'No se pudo purgar el portapapeles sin foco; se limpiará al volver o pulsa Purgar ahora.',
        }));
      }
    },
    [clearNoticeTimer, safeDefaultTimeout, scheduleNoticeClear, stopTimer]
  );

  const copySecretWithTimer = useCallback(
    async (value: string, label: string, entryId: string, timeoutOverride?: number) => {
      const myOp = ++opSeqRef.current;
      const duration = Math.max(
        5,
        Math.min(300, Math.trunc(timeoutOverride ?? safeDefaultTimeout) || safeDefaultTimeout)
      );

      stopTimer();
      clearNoticeTimer();
      pendingWipeRef.current = false;

      const ok = (await copyNativeDesktopClipboard(value)) || (await writeClipboardSafe(value));
      if (opSeqRef.current !== myOp) return false;

      if (!ok) {
        setState({
          activeLabel: null,
          activeEntryId: null,
          secondsRemaining: 0,
          totalSeconds: duration,
          statusMessage: 'No se pudo acceder al portapapeles del sistema.',
        });
        scheduleNoticeClear(myOp, 3600);
        return false;
      }

      const targetEnd = Date.now() + duration * 1000;
      setState({
        activeLabel: label,
        activeEntryId: entryId,
        secondsRemaining: duration,
        totalSeconds: duration,
        statusMessage: null,
      });

      intervalRef.current = window.setInterval(() => {
        if (opSeqRef.current !== myOp) {
          stopTimer();
          return;
        }
        const remaining = Math.max(0, Math.ceil((targetEnd - Date.now()) / 1000));
        if (remaining <= 0) {
          void wipeClipboardNow('Portapapeles borrado automáticamente al expirar el temporizador.');
        } else {
          setState((prev) => ({
            ...prev,
            secondsRemaining: remaining,
          }));
        }
      }, 250);

      return true;
    },
    [clearNoticeTimer, safeDefaultTimeout, scheduleNoticeClear, stopTimer, wipeClipboardNow]
  );

  // Retry any deferred clipboard wipe as soon as the window regains focus
  useEffect(() => {
    const retryIfPending = () => {
      if (pendingWipeRef.current && !document.hidden) {
        void wipeClipboardNow('Portapapeles purgado automáticamente al recuperar el foco.');
      }
    };
    window.addEventListener('focus', retryIfPending);
    document.addEventListener('visibilitychange', retryIfPending);
    return () => {
      window.removeEventListener('focus', retryIfPending);
      document.removeEventListener('visibilitychange', retryIfPending);
    };
  }, [wipeClipboardNow]);

  useEffect(() => {
    return () => {
      opSeqRef.current += 1;
      stopTimer();
      clearNoticeTimer();
    };
  }, [clearNoticeTimer, stopTimer]);

  return {
    clipboardState: state,
    copySecretWithTimer,
    wipeClipboardNow,
  };
}
