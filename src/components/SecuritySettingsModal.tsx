import React, { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, CheckCircle2, KeyRound, Shield, X } from 'lucide-react';
import { calculateEntropyBits, KDF_ITERATIONS } from '../crypto/engine';
import type { RotationIntervalDays, SecuritySettings } from '../types/vault';
import { ROTATION_OPTIONS } from '../utils/passwordRotation';

interface SecuritySettingsModalProps {
  settings: SecuritySettings;
  onClose: () => void;
  onSaveSettings: (next: SecuritySettings) => Promise<void>;
  onRotateMasterPassword: (newMasterPassword: string) => Promise<void>;
}

export const SecuritySettingsModal: React.FC<SecuritySettingsModalProps> = ({
  settings,
  onClose,
  onSaveSettings,
  onRotateMasterPassword,
}) => {
  const [draft, setDraft] = useState<SecuritySettings>({ ...settings });
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);

  // Rotación de clave maestra
  const [newPass, setNewPass] = useState('');
  const [confirmPass, setConfirmPass] = useState('');
  const [rotateBusy, setRotateBusy] = useState(false);
  const [rotateMsg, setRotateMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  useEffect(() => {
    return () => {
      setNewPass('');
      setConfirmPass('');
    };
  }, []);

  const handleClose = () => {
    setNewPass('');
    setConfirmPass('');
    onClose();
  };

  const entropy = useMemo(() => calculateEntropyBits(newPass), [newPass]);

  const handleSave = async () => {
    if (saving) return;
    setSaveError(null);
    setSaving(true);
    try {
      await onSaveSettings(draft);
      handleClose();
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'No se pudieron guardar los ajustes.');
    } finally {
      setSaving(false);
    }
  };

  const handleRotate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (rotateBusy) return;
    setRotateMsg(null);
    if (newPass.length < 10) {
      setRotateMsg({ type: 'err', text: 'La nueva clave maestra debe tener al menos 10 caracteres.' });
      return;
    }
    if (newPass !== confirmPass) {
      setRotateMsg({ type: 'err', text: 'Las claves maestras no coinciden.' });
      return;
    }
    setRotateBusy(true);
    try {
      await onRotateMasterPassword(newPass);
      setNewPass('');
      setConfirmPass('');
      setRotateMsg({
        type: 'ok',
        text: 'Clave maestra rotada en RAM con nueva sal de 256 bits y bóveda re-cifrada.',
      });
    } catch (err) {
      setRotateMsg({
        type: 'err',
        text: err instanceof Error ? err.message : 'No se pudo rotar la clave maestra.',
      });
    } finally {
      setRotateBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4">
      <div className="w-full max-w-2xl rounded-xl border border-[#242C3A] bg-[#161B24] p-6 space-y-6 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between border-b border-[#242C3A] pb-3.5">
          <div>
            <h2 className="font-display text-lg font-semibold text-[#F1F5F9]">
              Protocolo de seguridad y blindaje
            </h2>
            <p className="text-xs text-[#94A3B8] mt-0.5 font-mono tabular-nums">
              AES-256-GCM · PBKDF2-SHA512 ({KDF_ITERATIONS.toLocaleString('es-ES')} iter.) · HKDF-SHA512
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

        {/* Temporizadores y Blindaje Visual */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-[#94A3B8]">
              Autoborrado del portapapeles
            </label>
            <div className="flex items-center gap-1 rounded-lg bg-[#0A0C10] p-1 border border-[#242C3A]">
              {([15, 30, 60] as const).map((sec) => (
                <button
                  key={sec}
                  type="button"
                  onClick={() => setDraft((d) => ({ ...d, clipboardTimeoutSec: sec }))}
                  className={`flex-1 py-1.5 text-xs font-mono tabular-nums font-medium rounded-md transition-colors cursor-pointer ${
                    draft.clipboardTimeoutSec === sec
                      ? 'bg-[#1C2330] text-amber-300'
                      : 'text-[#94A3B8] hover:text-[#F1F5F9]'
                  }`}
                >
                  {sec} s
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-[#94A3B8]">
              Bloqueo por inactividad (limpia RAM)
            </label>
            <div className="flex items-center gap-1 rounded-lg bg-[#0A0C10] p-1 border border-[#242C3A]">
              {([1, 3, 5, 15] as const).map((min) => (
                <button
                  key={min}
                  type="button"
                  onClick={() => setDraft((d) => ({ ...d, autoLockMinutes: min }))}
                  className={`flex-1 py-1.5 text-xs font-mono tabular-nums font-medium rounded-md transition-colors cursor-pointer ${
                    draft.autoLockMinutes === min
                      ? 'bg-[#1C2330] text-amber-300'
                      : 'text-[#94A3B8] hover:text-[#F1F5F9]'
                  }`}
                >
                  {min} min
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-[#94A3B8]">
              Nivel de interferencia anti-OCR en Canvas
            </label>
            <div className="flex items-center gap-1 rounded-lg bg-[#0A0C10] p-1 border border-[#242C3A]">
              {(
                [
                  ['standard', 'Estándar'],
                  ['high', 'Alto (Máximo anti-IA)'],
                ] as const
              ).map(([lvl, text]) => (
                <button
                  key={lvl}
                  type="button"
                  onClick={() => setDraft((d) => ({ ...d, ocrNoiseLevel: lvl }))}
                  className={`flex-1 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                    draft.ocrNoiseLevel === lvl
                      ? 'bg-[#1C2330] text-amber-300'
                      : 'text-[#94A3B8] hover:text-[#F1F5F9]'
                  }`}
                >
                  {text}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-2 flex flex-col justify-end">
            <label className="flex items-start gap-2.5 rounded-lg border border-[#242C3A] bg-[#0F131A] p-3 cursor-pointer">
              <input
                type="checkbox"
                checked={draft.lockOnBlur}
                onChange={(e) => setDraft((d) => ({ ...d, lockOnBlur: e.target.checked }))}
                className="mt-0.5 accent-amber-500"
              />
              <span className="text-xs text-[#F1F5F9]">
                Bloquear bóveda inmediatamente al cambiar de pestaña o ventana
              </span>
            </label>
          </div>
        </div>

        {/* Semáforo de rotación de contraseñas */}
        <div className="rounded-lg border border-[#242C3A] bg-[#0F131A] p-4 space-y-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <label className="text-xs font-semibold text-[#F1F5F9]">
              Semáforo de rotación de contraseñas (periodicidad predeterminada)
            </label>
            <span className="text-[11px] font-mono text-amber-300">
              {ROTATION_OPTIONS.find((o) => o.days === draft.defaultRotationDays)?.label}
            </span>
          </div>
          <div className="grid grid-cols-3 sm:grid-cols-6 gap-1.5 rounded-lg bg-[#0A0C10] p-1 border border-[#242C3A]">
            {ROTATION_OPTIONS.map((opt) => (
              <button
                key={opt.days}
                type="button"
                title={`${opt.label} — ${opt.hint}`}
                onClick={() =>
                  setDraft((d) => ({
                    ...d,
                    defaultRotationDays: opt.days as RotationIntervalDays,
                  }))
                }
                className={`py-1.5 px-2 text-xs font-mono tabular-nums font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                  draft.defaultRotationDays === opt.days
                    ? 'bg-[#1C2330] text-amber-300'
                    : 'text-[#94A3B8] hover:text-[#F1F5F9]'
                }`}
              >
                {opt.shortLabel}
              </button>
            ))}
          </div>
          <p className="text-[11px] text-[#94A3B8] leading-relaxed">
            Guía exclusivamente visual para recordar renovaciones periódicas (verde = vigente, ámbar = próxima, rojo = sugerida para cambio). No envía alertas ni bloquea el acceso; puedes personalizar cada credencial individualmente.
          </p>
        </div>

        <label className="flex items-start gap-3 rounded-lg border border-[#242C3A] bg-[#0F131A] p-3.5 cursor-pointer">
          <input
            type="checkbox"
            checked={draft.ephemeralMode}
            onChange={(e) => setDraft((d) => ({ ...d, ephemeralMode: e.target.checked }))}
            className="mt-0.5 accent-amber-500"
          />
          <div>
            <p className="text-xs font-medium text-[#F1F5F9]">
              Modo efímero sin IndexedDB (solo archivos .bvault manuales)
            </p>
            <p className="text-xs text-[#94A3B8] mt-0.5">
              Al activar esta opción, se elimina el sobre cifrado de IndexedDB y todos los cambios viven únicamente en memoria RAM hasta que exportes un archivo .bvault.
            </p>
          </div>
        </label>

        {/* Rotación de clave maestra */}
        <form
          onSubmit={handleRotate}
          autoComplete="off"
          className="rounded-lg border border-[#242C3A] bg-[#0F131A] p-4 space-y-3"
        >
          <div className="flex items-center gap-2 text-xs font-semibold text-[#F1F5F9]">
            <KeyRound className="h-4 w-4 text-amber-400" />
            <span>Rotar clave maestra de la bóveda</span>
          </div>
          <p className="text-xs text-[#94A3B8]">
            Genera una nueva sal criptográfica de 256 bits, deriva una nueva llave AES-256-GCM en RAM y re-cifra toda la bóveda.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <input
              type="password"
              value={newPass}
              onChange={(e) => setNewPass(e.target.value)}
              placeholder="Nueva clave maestra (mín. 10 car.)"
              autoComplete="new-password"
              spellCheck={false}
              data-1p-ignore="true"
              data-lpignore="true"
              className="w-full rounded-md border border-[#242C3A] bg-[#0A0C10] px-3 py-2 font-mono text-xs text-[#F1F5F9] focus:border-amber-500 focus:outline-none"
            />
            <input
              type="password"
              value={confirmPass}
              onChange={(e) => setConfirmPass(e.target.value)}
              placeholder="Confirmar nueva clave maestra"
              autoComplete="new-password"
              spellCheck={false}
              data-1p-ignore="true"
              data-lpignore="true"
              className="w-full rounded-md border border-[#242C3A] bg-[#0A0C10] px-3 py-2 font-mono text-xs text-[#F1F5F9] focus:border-amber-500 focus:outline-none"
            />
          </div>
          {newPass.length > 0 && (
            <p className="text-xs font-mono tabular-nums text-[#94A3B8]">
              Entropía de la nueva clave: <span className="text-amber-400">{entropy.bits} bits · {entropy.label}</span>
            </p>
          )}
          {rotateMsg && (
            <div
              className={`rounded-md border px-3 py-2 text-xs flex items-center gap-2 ${
                rotateMsg.type === 'ok'
                  ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200'
                  : 'border-red-500/40 bg-red-500/10 text-red-200'
              }`}
            >
              {rotateMsg.type === 'ok' ? (
                <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
              ) : (
                <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
              )}
              <span>{rotateMsg.text}</span>
            </div>
          )}
          <div className="flex justify-end">
            <button
              type="submit"
              disabled={rotateBusy || !newPass}
              className="inline-flex items-center gap-1.5 rounded-md border border-amber-500/50 bg-amber-500/10 px-3.5 py-1.5 text-xs font-medium text-amber-300 hover:bg-amber-500/20 disabled:opacity-50 cursor-pointer whitespace-nowrap"
            >
              <Shield className="h-3.5 w-3.5" />
              <span>{rotateBusy ? 'Re-cifrando bóveda...' : 'Rotar clave maestra'}</span>
            </button>
          </div>
        </form>

        {saveError && (
          <div className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-200 flex items-center gap-2">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
            <span>{saveError}</span>
          </div>
        )}

        <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#242C3A]">
          <button
            type="button"
            onClick={handleClose}
            className="rounded-md border border-[#242C3A] bg-[#0F131A] px-4 py-2 text-xs font-medium text-[#94A3B8] hover:text-[#F1F5F9] cursor-pointer"
          >
            Cancelar
          </button>
          <button
            type="button"
            disabled={saving}
            onClick={() => void handleSave()}
            className="rounded-md bg-amber-500 px-4 py-2 text-xs font-semibold text-[#0A0C10] hover:bg-amber-400 disabled:opacity-60 cursor-pointer whitespace-nowrap"
          >
            {saving ? 'Guardando...' : 'Guardar ajustes'}
          </button>
        </div>
      </div>
    </div>
  );
};
