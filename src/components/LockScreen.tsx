import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Cpu,
  FileUp,
  Keyboard,
  Lock,
  Shield,
  ShieldCheck,
  Trash2,
  WifiOff,
} from 'lucide-react';
import { calculateEntropyBits, KDF_ITERATIONS } from '../crypto/engine';
import type { EncryptedVaultEnvelope } from '../types/vault';
import { PWAInstallButton } from './PWAInstallButton';
import { SecureVirtualKeypad } from './SecureVirtualKeypad';
import { readAndValidateBvaultFile } from './vaultFileSecurity';

interface LockScreenProps {
  hasExistingVault: boolean;
  storedVaultUpdatedAt: number | null;
  lockReason: string | null;
  onCreateVault: (masterPassword: string, ephemeralMode: boolean) => Promise<void>;
  onUnlockVault: (masterPassword: string) => Promise<void>;
  onUnlockFromFile: (envelope: EncryptedVaultEnvelope, masterPassword: string, persistLocal: boolean) => Promise<void>;
  onWipeLocalVault: () => Promise<void>;
}

export const LockScreen: React.FC<LockScreenProps> = ({
  hasExistingVault,
  storedVaultUpdatedAt,
  lockReason,
  onCreateVault,
  onUnlockVault,
  onUnlockFromFile,
  onWipeLocalVault,
}) => {
  const [mode, setMode] = useState<'unlock' | 'create' | 'import'>(
    hasExistingVault ? 'unlock' : 'create'
  );
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [ephemeralMode, setEphemeralMode] = useState(false);
  const [persistImported, setPersistImported] = useState(true);
  const [showKeypad, setShowKeypad] = useState(false);
  const [keypadTarget, setKeypadTarget] = useState<'primary' | 'confirm'>('primary');
  const [pendingEnvelope, setPendingEnvelope] = useState<EncryptedVaultEnvelope | null>(null);
  const [pendingFileName, setPendingFileName] = useState<string>('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmWipe, setConfirmWipe] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const entropy = useMemo(() => calculateEntropyBits(password), [password]);

  useEffect(() => {
    return () => {
      setPassword('');
      setConfirmPassword('');
      setPendingEnvelope(null);
    };
  }, []);

  const switchMode = (next: 'unlock' | 'create' | 'import') => {
    if (busy) return;
    setMode(next);
    setPassword('');
    setConfirmPassword('');
    setError(null);
    setConfirmWipe(false);
  };

  const handleFilePick = async (e: React.ChangeEvent<HTMLInputElement>) => {
    setError(null);
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file || busy) return;
    try {
      const parsed = await readAndValidateBvaultFile(file);
      setPendingEnvelope(parsed);
      setPendingFileName(file.name);
      setMode('import');
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'No se pudo leer el archivo .bvault. Verifica que sea un archivo exportado por Bastión.'
      );
      setPendingEnvelope(null);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setError(null);

    if (mode === 'create') {
      if (password.length < 10) {
        setError('La clave maestra debe tener al menos 10 caracteres para garantizar seguridad local.');
        return;
      }
      if (password !== confirmPassword) {
        setError('Las contraseñas maestras no coinciden.');
        return;
      }
      setBusy(true);
      try {
        await onCreateVault(password, ephemeralMode);
        setPassword('');
        setConfirmPassword('');
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Error al inicializar la bóveda.');
      } finally {
        setBusy(false);
      }
      return;
    }

    if (mode === 'import') {
      if (!pendingEnvelope) {
        setError('Selecciona primero un archivo .bvault cifrado.');
        return;
      }
      if (!password) {
        setError('Introduce la clave de descifrado de este archivo .bvault.');
        return;
      }
      setBusy(true);
      try {
        await onUnlockFromFile(pendingEnvelope, password, persistImported);
        setPassword('');
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Error al descifrar el archivo.');
      } finally {
        setBusy(false);
      }
      return;
    }

    if (!password) {
      setError('Introduce tu clave maestra para derivar la llave en memoria RAM.');
      return;
    }

    setBusy(true);
    try {
      await onUnlockVault(password);
      setPassword('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'No se pudo desbloquear la bóveda.');
    } finally {
      setBusy(false);
    }
  };

  const insertChar = (ch: string) => {
    if (mode === 'create' && keypadTarget === 'confirm') {
      setConfirmPassword((p) => p + ch);
    } else {
      setPassword((p) => p + ch);
    }
  };

  const handleBackspace = () => {
    if (mode === 'create' && keypadTarget === 'confirm') {
      setConfirmPassword((p) => p.slice(0, -1));
    } else {
      setPassword((p) => p.slice(0, -1));
    }
  };

  const handleClear = () => {
    if (mode === 'create' && keypadTarget === 'confirm') {
      setConfirmPassword('');
    } else {
      setPassword('');
    }
  };

  const entropyToneClass =
    entropy.tone === 'amber'
      ? 'text-amber-400'
      : entropy.tone === 'emerald'
      ? 'text-emerald-400'
      : entropy.tone === 'warning'
      ? 'text-amber-300'
      : entropy.tone === 'danger'
      ? 'text-red-400'
      : 'text-[#94A3B8]';

  const entropyBarWidth = Math.min(100, Math.round((entropy.bits / 128) * 100));
  const entropyBarColor =
    entropy.tone === 'amber'
      ? 'bg-amber-500'
      : entropy.tone === 'emerald'
      ? 'bg-emerald-500'
      : entropy.tone === 'warning'
      ? 'bg-amber-400'
      : 'bg-red-500';

  return (
    <div className="min-h-screen bg-[#0A0C10] text-[#F1F5F9] flex flex-col">
      {/* Barra superior 3 zonas */}
      <header className="h-16 border-b border-[#242C3A] bg-[#0F131A] px-6 flex items-center justify-between gap-8">
        <div className="flex items-center gap-2.5 whitespace-nowrap shrink-0">
          <Shield className="h-5 w-5 text-amber-500" />
          <span className="font-display text-lg font-semibold tracking-tight text-[#F1F5F9]">
            Bastión
          </span>
        </div>

        <div className="hidden md:flex items-center gap-3 text-xs text-[#94A3B8] font-mono tabular-nums">
          <span>AES-256-GCM</span>
          <span aria-hidden="true">·</span>
          <span>PBKDF2-SHA512 ({KDF_ITERATIONS.toLocaleString('es-ES')} iter.)</span>
          <span aria-hidden="true">·</span>
          <span>Clave exclusiva en RAM</span>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <PWAInstallButton compact />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="inline-flex items-center gap-2 rounded-md border border-[#242C3A] bg-[#161B24] px-3.5 py-2 text-xs font-medium text-[#F1F5F9] hover:border-[#334054] hover:bg-[#1C2330] transition-colors cursor-pointer whitespace-nowrap shrink-0"
          >
            <FileUp className="h-3.5 w-3.5 text-amber-400" />
            <span>Abrir archivo .bvault</span>
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".bvault,.json,application/json"
            onChange={handleFilePick}
            className="hidden"
          />
        </div>
      </header>

      {/* Cuerpo principal en dos columnas equilibradas en escritorio */}
      <main className="flex-1 flex items-center justify-center px-6 py-10">
        <div className="w-full max-w-5xl grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
          {/* Panel izquierdo: Arquitectura de aislamiento y garantías reales */}
          <section className="lg:col-span-5 flex flex-col justify-between rounded-xl border border-[#242C3A] bg-[#0F131A] p-7">
            <div className="space-y-6">
              <div className="space-y-2.5">
                <p className="text-xs font-medium text-amber-400">
                  Bóveda criptográfica de escritorio sin conexión
                </p>
                <h1 className="font-display text-3xl font-semibold tracking-tight text-[#F1F5F9] leading-tight">
                  Tus contraseñas aisladas en memoria volátil
                </h1>
                <p className="text-sm text-[#94A3B8] leading-relaxed">
                  La clave maestra nunca se almacena ni se transmite. Se deriva en tiempo real dentro de la memoria RAM y se purga automáticamente al bloquear o cerrar la ventana.
                </p>
              </div>

              <div className="space-y-4 pt-2 border-t border-[#242C3A]">
                <div className="flex items-start gap-3">
                  <Cpu className="h-4 w-4 text-amber-400 mt-0.5 shrink-0" />
                  <div>
                    <p className="text-sm font-medium text-[#F1F5F9]">Clave maestra no extraíble en RAM</p>
                    <p className="text-xs text-[#94A3B8] mt-0.5 leading-relaxed">
                      Derivación PBKDF2-HMAC-SHA512 más separación de dominio HKDF hacia una llave AES-256-GCM marcada como no exportable.
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <WifiOff className="h-4 w-4 text-amber-400 mt-0.5 shrink-0" />
                  <div>
                    <p className="text-sm font-medium text-[#F1F5F9]">Aislamiento total sin red</p>
                    <p className="text-xs text-[#94A3B8] mt-0.5 leading-relaxed">
                      Fuentes locales empaquetadas, política CSP sin salidas externas y persistencia local únicamente de bloques ya cifrados.
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <ShieldCheck className="h-4 w-4 text-amber-400 mt-0.5 shrink-0" />
                  <div>
                    <p className="text-sm font-medium text-[#F1F5F9]">Escudo anti-IA y anti-lectores</p>
                    <p className="text-xs text-[#94A3B8] mt-0.5 leading-relaxed">
                      Renderizado en lienzo Canvas aislado con ruido anti-OCR, revelado al mantener pulsado y teclado virtual aleatorio.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <div className="pt-6 mt-6 border-t border-[#242C3A] flex flex-wrap items-center justify-between gap-2 text-xs text-[#94A3B8] font-mono tabular-nums">
              <span>Verificación AEAD 128-bit</span>
              <span>
                {storedVaultUpdatedAt
                  ? `Último cifrado: ${new Date(storedVaultUpdatedAt).toLocaleString('es-ES', {
                      day: '2-digit',
                      month: '2-digit',
                      hour: '2-digit',
                      minute: '2-digit',
                    })}`
                  : 'Sin bóveda local todavía'}
              </span>
            </div>
          </section>

          {/* Panel derecho: Acceso / Creación / Importación */}
          <section className="lg:col-span-7 rounded-xl border border-[#242C3A] bg-[#161B24] p-7 flex flex-col justify-between">
            <div className="space-y-6">
              {/* Selector de flujo */}
              <div className="flex items-center justify-between gap-4 border-b border-[#242C3A] pb-4">
                <div className="flex items-center gap-1 rounded-lg bg-[#0A0C10] p-1 border border-[#242C3A]">
                  {hasExistingVault && (
                    <button
                      type="button"
                      onClick={() => switchMode('unlock')}
                      className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                        mode === 'unlock'
                          ? 'bg-[#1C2330] text-[#F1F5F9]'
                          : 'text-[#94A3B8] hover:text-[#F1F5F9]'
                      }`}
                    >
                      Desbloquear bóveda
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => switchMode('create')}
                    className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                      mode === 'create'
                        ? 'bg-[#1C2330] text-[#F1F5F9]'
                        : 'text-[#94A3B8] hover:text-[#F1F5F9]'
                    }`}
                  >
                    {hasExistingVault ? 'Nueva bóveda' : 'Crear bóveda'}
                  </button>
                  <button
                    type="button"
                    onClick={() => switchMode('import')}
                    className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                      mode === 'import'
                        ? 'bg-[#1C2330] text-[#F1F5F9]'
                        : 'text-[#94A3B8] hover:text-[#F1F5F9]'
                    }`}
                  >
                    Importar .bvault
                  </button>
                </div>

                <button
                  type="button"
                  onClick={() => setShowKeypad((v) => !v)}
                  className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors cursor-pointer whitespace-nowrap ${
                    showKeypad
                      ? 'border-amber-500/60 bg-amber-500/10 text-amber-300'
                      : 'border-[#242C3A] bg-[#0F131A] text-[#94A3B8] hover:text-[#F1F5F9]'
                  }`}
                >
                  <Keyboard className="h-3.5 w-3.5" />
                  <span>Teclado seguro</span>
                </button>
              </div>

              {lockReason && (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-xs text-amber-200 flex items-center gap-2.5">
                  <Lock className="h-4 w-4 text-amber-400 shrink-0" />
                  <span>{lockReason}</span>
                </div>
              )}

              <form onSubmit={handleSubmit} className="space-y-5" autoComplete="off">
                {mode === 'import' && (
                  <div className="space-y-2">
                    <label className="block text-xs font-medium text-[#94A3B8]">
                      Archivo cifrado local (.bvault)
                    </label>
                    <div className="flex items-center justify-between gap-3 rounded-lg border border-[#242C3A] bg-[#0F131A] px-4 py-3">
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-[#F1F5F9] truncate">
                          {pendingFileName || 'Ningún archivo cargado'}
                        </p>
                        <p className="text-xs text-[#94A3B8] font-mono tabular-nums mt-0.5">
                          {pendingEnvelope
                            ? `${pendingEnvelope.cipher} · ${pendingEnvelope.iterations.toLocaleString('es-ES')} iter.`
                            : 'Selecciona un respaldo .bvault exportado previamente'}
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={() => fileInputRef.current?.click()}
                        className="rounded-md border border-[#242C3A] bg-[#161B24] px-3 py-1.5 text-xs font-medium text-[#F1F5F9] hover:border-[#334054] cursor-pointer whitespace-nowrap shrink-0"
                      >
                        Examinar
                      </button>
                    </div>
                  </div>
                )}

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label htmlFor="master-pass" className="text-xs font-medium text-[#94A3B8]">
                      {mode === 'import'
                        ? 'Clave de descifrado del archivo'
                        : mode === 'create'
                        ? 'Define tu clave maestra única'
                        : 'Clave maestra de la bóveda'}
                    </label>
                    <span className="text-xs font-mono tabular-nums text-[#94A3B8]">
                      {password.length} car.
                    </span>
                  </div>
                  <input
                    id="master-pass"
                    type="password"
                    value={password}
                    onFocus={() => setKeypadTarget('primary')}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Introduce una frase maestra robusta..."
                    autoComplete="new-password"
                    spellCheck={false}
                    data-1p-ignore="true"
                    data-lpignore="true"
                    className="w-full rounded-lg border border-[#242C3A] bg-[#0A0C10] px-4 py-3 font-mono text-sm text-[#F1F5F9] placeholder:text-[#475569] focus:border-amber-500 focus:outline-none transition-colors"
                  />

                  {mode === 'create' && (
                    <div className="space-y-1.5 pt-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-[#94A3B8]">Entropía estimada</span>
                        <span className={`font-mono tabular-nums font-medium ${entropyToneClass}`}>
                          {entropy.bits} bits · {entropy.label}
                        </span>
                      </div>
                      <div className="h-1.5 w-full overflow-hidden rounded-full bg-[#0A0C10]">
                        <div
                          className={`h-full transition-all duration-150 ${entropyBarColor}`}
                          style={{ width: `${entropyBarWidth}%` }}
                        />
                      </div>
                    </div>
                  )}
                </div>

                {mode === 'create' && (
                  <div className="space-y-2">
                    <label htmlFor="master-confirm" className="block text-xs font-medium text-[#94A3B8]">
                      Confirmar clave maestra
                    </label>
                    <input
                      id="master-confirm"
                      type="password"
                      value={confirmPassword}
                      onFocus={() => setKeypadTarget('confirm')}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      placeholder="Repite la clave maestra exactamente..."
                      autoComplete="new-password"
                      spellCheck={false}
                      data-1p-ignore="true"
                      data-lpignore="true"
                      className="w-full rounded-lg border border-[#242C3A] bg-[#0A0C10] px-4 py-3 font-mono text-sm text-[#F1F5F9] placeholder:text-[#475569] focus:border-amber-500 focus:outline-none transition-colors"
                    />
                  </div>
                )}

                {showKeypad && (
                  <SecureVirtualKeypad
                    onInsertChar={insertChar}
                    onBackspace={handleBackspace}
                    onClear={handleClear}
                  />
                )}

                {mode === 'create' && (
                  <label className="flex items-start gap-3 rounded-lg border border-[#242C3A] bg-[#0F131A] p-3.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={ephemeralMode}
                      onChange={(e) => setEphemeralMode(e.target.checked)}
                      className="mt-0.5 accent-amber-500"
                    />
                    <div>
                      <p className="text-xs font-medium text-[#F1F5F9]">
                        Modo efímero puro (sin persistencia en IndexedDB)
                      </p>
                      <p className="text-xs text-[#94A3B8] mt-0.5">
                        Los datos viven solo durante esta sesión en RAM. Deberás exportar un archivo .bvault antes de cerrar.
                      </p>
                    </div>
                  </label>
                )}

                {mode === 'import' && (
                  <label className="flex items-start gap-3 rounded-lg border border-[#242C3A] bg-[#0F131A] p-3.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={persistImported}
                      onChange={(e) => setPersistImported(e.target.checked)}
                      className="mt-0.5 accent-amber-500"
                    />
                    <div>
                      <p className="text-xs font-medium text-[#F1F5F9]">
                        Conservar bloque cifrado localmente en este equipo
                      </p>
                      <p className="text-xs text-[#94A3B8] mt-0.5">
                        Si lo desactivas, el archivo se abrirá solo en memoria RAM sin escribir en IndexedDB.
                      </p>
                    </div>
                  </label>
                )}

                {mode === 'create' && hasExistingVault && (
                  <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-xs text-red-200 flex items-start gap-2.5">
                    <AlertTriangle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
                    <span>
                      Ya existe una bóveda cifrada en este navegador. Crear una nueva sin modo efímero reemplazará el almacenamiento local actual.
                    </span>
                  </div>
                )}

                {error && (
                  <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-xs text-red-200 flex items-start gap-2.5">
                    <AlertTriangle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
                    <span>{error}</span>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={busy}
                  className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-amber-500 px-5 py-3 text-sm font-semibold text-[#0A0C10] hover:bg-amber-400 disabled:opacity-60 transition-colors cursor-pointer"
                >
                  <span>
                    {busy
                      ? 'Derivando llave AES-256-GCM en RAM...'
                      : mode === 'create'
                      ? 'Inicializar bóveda cifrada'
                      : mode === 'import'
                      ? 'Descifrar archivo en RAM'
                      : 'Desbloquear bóveda'}
                  </span>
                  {!busy && <ArrowRight className="h-4 w-4" />}
                </button>
              </form>
            </div>

            {hasExistingVault && mode === 'unlock' && (
              <div className="mt-6 pt-4 border-t border-[#242C3A] flex items-center justify-between gap-4">
                <p className="text-xs text-[#94A3B8]">
                  Sin recuperación remota: si olvidas la clave maestra, el texto cifrado es irrecuperable.
                </p>
                {!confirmWipe ? (
                  <button
                    type="button"
                    onClick={() => setConfirmWipe(true)}
                    className="inline-flex items-center gap-1.5 text-xs text-[#94A3B8] hover:text-red-400 transition-colors cursor-pointer whitespace-nowrap shrink-0"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    <span>Purgar bóveda</span>
                  </button>
                ) : (
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => setConfirmWipe(false)}
                      className="text-xs text-[#94A3B8] hover:text-[#F1F5F9] cursor-pointer"
                    >
                      Cancelar
                    </button>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={async () => {
                        if (busy) return;
                        setError(null);
                        setBusy(true);
                        try {
                          await onWipeLocalVault();
                          setConfirmWipe(false);
                          setMode('create');
                        } catch (err) {
                          setError(
                            err instanceof Error
                              ? err.message
                              : 'No se pudo purgar la bóveda local.'
                          );
                        } finally {
                          setBusy(false);
                        }
                      }}
                      className="rounded bg-red-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-red-500 disabled:opacity-60 cursor-pointer"
                    >
                      Confirmar borrado
                    </button>
                  </div>
                )}
              </div>
            )}
          </section>
        </div>
      </main>
    </div>
  );
};
