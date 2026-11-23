import React, { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  FileKey2,
  FileUp,
  ShieldCheck,
  X,
} from 'lucide-react';
import {
  createStandaloneEncryptedExport,
  decryptVaultEnvelope,
  encryptVaultWithKey,
  generateUuid,
} from '../crypto/engine';
import {
  DEFAULT_CATEGORIES,
  type EncryptedVaultEnvelope,
  type VaultCategory,
  type VaultEntry,
  type VaultPayload,
} from '../types/vault';
import { readAndValidateBvaultFile, sanitizeImportedPayload } from './vaultFileSecurity';

interface ExportImportModalProps {
  initialTab?: 'export' | 'import';
  payload: VaultPayload;
  ramKey: CryptoKey;
  ramSaltB64: string;
  ramIterations: number;
  onClose: () => void;
  onImportCommit: (
    nextCategories: VaultCategory[],
    nextEntries: VaultEntry[],
    summaryText: string
  ) => Promise<void>;
}

type ConflictPolicy = 'merge_keep_both' | 'merge_update' | 'replace_all';

export const ExportImportModal: React.FC<ExportImportModalProps> = ({
  initialTab = 'export',
  payload,
  ramKey,
  ramSaltB64,
  ramIterations,
  onClose,
  onImportCommit,
}) => {
  const [tab, setTab] = useState<'export' | 'import'>(initialTab);

  // Estado de exportación
  const [exportScope, setExportScope] = useState<string>('all');
  const [keyMode, setKeyMode] = useState<'ram' | 'custom'>('ram');
  const [customPass, setCustomPass] = useState('');
  const [customConfirm, setCustomConfirm] = useState('');
  const [exportBusy, setExportBusy] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [exportSuccess, setExportSuccess] = useState<string | null>(null);

  // Estado de importación
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [importFileName, setImportFileName] = useState<string>('');
  const [importEnvelope, setImportEnvelope] = useState<EncryptedVaultEnvelope | null>(null);
  const [importPass, setImportPass] = useState('');
  const [importBusy, setImportBusy] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [decryptedPreview, setDecryptedPreview] = useState<VaultPayload | null>(null);
  const [policy, setPolicy] = useState<ConflictPolicy>('merge_keep_both');
  const [confirmReplaceAll, setConfirmReplaceAll] = useState(false);

  const clearSecrets = () => {
    setCustomPass('');
    setCustomConfirm('');
    setImportPass('');
    setImportEnvelope(null);
    setImportFileName('');
    setDecryptedPreview(null);
    setConfirmReplaceAll(false);
  };

  useEffect(() => {
    return () => {
      setCustomPass('');
      setCustomConfirm('');
      setImportPass('');
      setImportEnvelope(null);
      setDecryptedPreview(null);
    };
  }, []);

  const handleClose = () => {
    clearSecrets();
    onClose();
  };

  const handleSwitchTab = (nextTab: 'export' | 'import') => {
    setTab(nextTab);
    setExportError(null);
    setExportSuccess(null);
    setImportError(null);
    clearSecrets();
  };

  const entriesToExport =
    exportScope === 'all'
      ? payload.entries
      : payload.entries.filter((e) => e.categoryId === exportScope);

  const handleExport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (exportBusy) return;
    setExportError(null);
    setExportSuccess(null);

    if (entriesToExport.length === 0) {
      setExportError('No hay credenciales en el ámbito seleccionado para exportar.');
      return;
    }

    if (keyMode === 'custom') {
      if (customPass.length < 10) {
        setExportError('La clave de respaldo debe tener al menos 10 caracteres.');
        return;
      }
      if (customPass !== customConfirm) {
        setExportError('Las claves de respaldo no coinciden.');
        return;
      }
    }

    setExportBusy(true);
    try {
      const relevantCatIds = new Set(entriesToExport.map((item) => item.categoryId));
      const exportPayload: VaultPayload = {
        version: payload.version,
        categories:
          exportScope === 'all'
            ? payload.categories
            : payload.categories.filter((c) => relevantCatIds.has(c.id)),
        entries: entriesToExport,
        settings: payload.settings,
        updatedAt: Date.now(),
      };

      const scopeTag = exportScope === 'all' ? 'export-full' : 'export-category';
      let envelope: EncryptedVaultEnvelope;

      if (keyMode === 'ram') {
        envelope = await encryptVaultWithKey(
          exportPayload,
          ramKey,
          ramSaltB64,
          ramIterations,
          scopeTag
        );
      } else {
        envelope = await createStandaloneEncryptedExport(exportPayload, customPass, scopeTag);
      }

      const blob = new Blob([JSON.stringify(envelope, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const stamp = new Date()
        .toISOString()
        .replace(/[-:T]/g, '')
        .slice(0, 12);
      const a = document.createElement('a');
      a.href = url;
      a.rel = 'noopener';
      a.download = `bastion-respaldo-${stamp}.bvault`;
      document.body.appendChild(a);
      try {
        a.click();
      } finally {
        if (a.parentNode) {
          a.parentNode.removeChild(a);
        }
        URL.revokeObjectURL(url);
      }

      setCustomPass('');
      setCustomConfirm('');
      setExportSuccess(
        `Archivo .bvault cifrado localmente con AES-256-GCM (${entriesToExport.length} credenciales).`
      );
    } catch (err) {
      setExportError(err instanceof Error ? err.message : 'Error al generar el archivo cifrado.');
    } finally {
      setExportBusy(false);
    }
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    setImportError(null);
    setDecryptedPreview(null);
    setConfirmReplaceAll(false);
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file || importBusy) return;
    try {
      const parsed = await readAndValidateBvaultFile(file);
      setImportEnvelope(parsed);
      setImportFileName(file.name);
    } catch (err) {
      setImportError(
        err instanceof Error
          ? err.message
          : 'Archivo ilegible o corrupto. Selecciona un archivo .bvault válido.'
      );
      setImportEnvelope(null);
      setImportFileName('');
    }
  };

  const handleDecryptPreview = async (e: React.FormEvent) => {
    e.preventDefault();
    if (importBusy) return;
    setImportError(null);
    if (!importEnvelope) {
      setImportError('Selecciona un archivo .bvault primero.');
      return;
    }
    if (!importPass) {
      setImportError('Introduce la clave de descifrado del archivo.');
      return;
    }
    setImportBusy(true);
    try {
      const { payload: incoming } = await decryptVaultEnvelope(importEnvelope, importPass);
      const sanitized = sanitizeImportedPayload(incoming, DEFAULT_CATEGORIES);
      setDecryptedPreview({
        ...incoming,
        categories: sanitized.categories,
        entries: sanitized.entries,
      });
      setConfirmReplaceAll(false);
      setImportPass('');
    } catch (err) {
      setImportError(err instanceof Error ? err.message : 'Error al descifrar el respaldo.');
    } finally {
      setImportBusy(false);
    }
  };

  const existingIds = new Set(payload.entries.map((e) => e.id));
  const conflictCount = decryptedPreview
    ? decryptedPreview.entries.filter((e) => existingIds.has(e.id)).length
    : 0;

  const handleCommitImport = async () => {
    if (!decryptedPreview || importBusy) return;
    if (policy === 'replace_all' && !confirmReplaceAll) {
      setImportError('Confirma explícitamente que deseas reemplazar toda la bóveda actual.');
      return;
    }
    setImportError(null);
    setImportBusy(true);
    try {
      const { categories: safeCategories, entries: safeEntries } = sanitizeImportedPayload(
        decryptedPreview,
        DEFAULT_CATEGORIES
      );

      if (policy === 'replace_all') {
        await onImportCommit(
          safeCategories,
          safeEntries,
          `Bóveda reemplazada con ${safeEntries.length} credenciales importadas.`
        );
        handleClose();
        return;
      }

      // Fusión de categorías sin duplicar IDs
      const catMap = new Map<string, VaultCategory>();
      for (const c of payload.categories) catMap.set(c.id, c);
      for (const c of safeCategories) {
        if (!catMap.has(c.id)) catMap.set(c.id, c);
      }

      const entryMap = new Map<string, VaultEntry>();
      for (const item of payload.entries) entryMap.set(item.id, item);

      let added = 0;
      let updated = 0;

      for (const inc of safeEntries) {
        if (!entryMap.has(inc.id)) {
          entryMap.set(inc.id, inc);
          added++;
        } else if (policy === 'merge_update') {
          entryMap.set(inc.id, { ...inc, updatedAt: Date.now() });
          updated++;
        } else {
          // Conservar ambos con nuevo ID
          const newId = generateUuid();
          entryMap.set(newId, {
            ...inc,
            id: newId,
            title: `${inc.title} (importada)`,
            updatedAt: Date.now(),
          });
          added++;
        }
      }

      await onImportCommit(
        Array.from(catMap.values()),
        Array.from(entryMap.values()),
        `Importación completada: ${added} añadidas, ${updated} actualizadas.`
      );
      handleClose();
    } catch (err) {
      setImportError(err instanceof Error ? err.message : 'No se pudo completar la importación.');
    } finally {
      setImportBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4">
      <div className="w-full max-w-xl rounded-xl border border-[#242C3A] bg-[#161B24] p-6 space-y-5 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between border-b border-[#242C3A] pb-3.5">
          <div>
            <h2 className="font-display text-lg font-semibold text-[#F1F5F9]">
              Respaldo e intercambio cifrado local
            </h2>
            <p className="text-xs text-[#94A3B8] mt-0.5">
              Archivos .bvault autenticados con AES-256-GCM sin tráfico de red
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

        {/* Selector de pestaña */}
        <div className="flex items-center gap-1 rounded-lg bg-[#0A0C10] p-1 border border-[#242C3A] w-fit">
          <button
            type="button"
            onClick={() => handleSwitchTab('export')}
            className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
              tab === 'export'
                ? 'bg-[#1C2330] text-[#F1F5F9]'
                : 'text-[#94A3B8] hover:text-[#F1F5F9]'
            }`}
          >
            Exportar .bvault
          </button>
          <button
            type="button"
            onClick={() => handleSwitchTab('import')}
            className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
              tab === 'import'
                ? 'bg-[#1C2330] text-[#F1F5F9]'
                : 'text-[#94A3B8] hover:text-[#F1F5F9]'
            }`}
          >
            Importar .bvault
          </button>
        </div>

        {tab === 'export' ? (
          <form onSubmit={handleExport} autoComplete="off" className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="export-scope" className="block text-xs font-medium text-[#94A3B8]">
                Ámbito de exportación
              </label>
              <select
                id="export-scope"
                value={exportScope}
                onChange={(e) => setExportScope(e.target.value)}
                className="w-full rounded-lg border border-[#242C3A] bg-[#0A0C10] px-3.5 py-2.5 text-sm text-[#F1F5F9] focus:border-amber-500 focus:outline-none"
              >
                <option value="all">
                  Toda la bóveda ({payload.entries.length} credenciales)
                </option>
                {payload.categories.map((cat) => {
                  const count = payload.entries.filter((e) => e.categoryId === cat.id).length;
                  return (
                    <option key={cat.id} value={cat.id}>
                      Categoría: {cat.name} ({count})
                    </option>
                  );
                })}
              </select>
            </div>

            <div className="space-y-2">
              <p className="text-xs font-medium text-[#94A3B8]">Clave de cifrado del archivo</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                <button
                  type="button"
                  onClick={() => setKeyMode('ram')}
                  className={`text-left rounded-lg border p-3 transition-colors cursor-pointer ${
                    keyMode === 'ram'
                      ? 'border-amber-500/70 bg-amber-500/10'
                      : 'border-[#242C3A] bg-[#0F131A] hover:border-[#334054]'
                  }`}
                >
                  <p className="text-xs font-semibold text-[#F1F5F9]">Clave maestra en RAM</p>
                  <p className="text-xs text-[#94A3B8] mt-1">
                    Usa la llave AES-256-GCM actual con un nuevo vector IV CSPRNG.
                  </p>
                </button>
                <button
                  type="button"
                  onClick={() => setKeyMode('custom')}
                  className={`text-left rounded-lg border p-3 transition-colors cursor-pointer ${
                    keyMode === 'custom'
                      ? 'border-amber-500/70 bg-amber-500/10'
                      : 'border-[#242C3A] bg-[#0F131A] hover:border-[#334054]'
                  }`}
                >
                  <p className="text-xs font-semibold text-[#F1F5F9]">Clave de respaldo dedicada</p>
                  <p className="text-xs text-[#94A3B8] mt-1">
                    Deriva una nueva sal de 256 bits independiente para traslado seguro.
                  </p>
                </button>
              </div>
            </div>

            {keyMode === 'custom' && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="block text-xs text-[#94A3B8]">Frase de respaldo</label>
                  <input
                    type="password"
                    value={customPass}
                    onChange={(e) => setCustomPass(e.target.value)}
                    placeholder="Mínimo 10 caracteres"
                    autoComplete="new-password"
                    spellCheck={false}
                    data-1p-ignore="true"
                    data-lpignore="true"
                    className="w-full rounded-lg border border-[#242C3A] bg-[#0A0C10] px-3 py-2 font-mono text-xs text-[#F1F5F9] focus:border-amber-500 focus:outline-none"
                  />
                </div>
                <div className="space-y-1">
                  <label className="block text-xs text-[#94A3B8]">Confirmar frase</label>
                  <input
                    type="password"
                    value={customConfirm}
                    onChange={(e) => setCustomConfirm(e.target.value)}
                    placeholder="Repetir frase"
                    autoComplete="new-password"
                    spellCheck={false}
                    data-1p-ignore="true"
                    data-lpignore="true"
                    className="w-full rounded-lg border border-[#242C3A] bg-[#0A0C10] px-3 py-2 font-mono text-xs text-[#F1F5F9] focus:border-amber-500 focus:outline-none"
                  />
                </div>
              </div>
            )}

            {exportError && (
              <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3.5 py-2.5 text-xs text-red-200 flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
                <span>{exportError}</span>
              </div>
            )}

            {exportSuccess && (
              <div className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3.5 py-2.5 text-xs text-emerald-200 flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                <span>{exportSuccess}</span>
              </div>
            )}

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#242C3A]">
              <button
                type="button"
                onClick={handleClose}
                className="rounded-md border border-[#242C3A] bg-[#0F131A] px-4 py-2 text-xs font-medium text-[#94A3B8] hover:text-[#F1F5F9] cursor-pointer"
              >
                Cerrar
              </button>
              <button
                type="submit"
                disabled={exportBusy}
                className="inline-flex items-center gap-2 rounded-md bg-amber-500 px-4 py-2 text-xs font-semibold text-[#0A0C10] hover:bg-amber-400 disabled:opacity-60 cursor-pointer whitespace-nowrap"
              >
                <Download className="h-3.5 w-3.5" />
                <span>{exportBusy ? 'Cifrando sobre...' : 'Descargar archivo .bvault'}</span>
              </button>
            </div>
          </form>
        ) : (
          <div className="space-y-4">
            <input
              ref={fileInputRef}
              type="file"
              accept=".bvault,.json,application/json"
              onChange={(e) => void handleFileChange(e)}
              className="hidden"
            />

            {!decryptedPreview ? (
              <form onSubmit={handleDecryptPreview} autoComplete="off" className="space-y-4">
                <div className="flex items-center justify-between gap-3 rounded-lg border border-[#242C3A] bg-[#0F131A] px-4 py-3.5">
                  <div className="flex items-center gap-3 min-w-0">
                    <FileKey2 className="h-5 w-5 text-amber-400 shrink-0" />
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-[#F1F5F9] truncate">
                        {importFileName || 'Selecciona un archivo .bvault local'}
                      </p>
                      <p className="text-xs text-[#94A3B8] font-mono tabular-nums">
                        {importEnvelope
                          ? `${importEnvelope.cipher} · ${importEnvelope.iterations.toLocaleString('es-ES')} iter.`
                          : 'Lectura 100% local en memoria del dispositivo'}
                      </p>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    className="inline-flex items-center gap-1.5 rounded-md border border-[#242C3A] bg-[#161B24] px-3 py-1.5 text-xs font-medium text-[#F1F5F9] hover:border-[#334054] cursor-pointer whitespace-nowrap shrink-0"
                  >
                    <FileUp className="h-3.5 w-3.5 text-amber-400" />
                    <span>Examinar</span>
                  </button>
                </div>

                <div className="space-y-1.5">
                  <label className="block text-xs font-medium text-[#94A3B8]">
                    Clave de descifrado del archivo .bvault
                  </label>
                  <input
                    type="password"
                    value={importPass}
                    onChange={(e) => setImportPass(e.target.value)}
                    placeholder="Introduce la clave maestra o de respaldo usada al exportar..."
                    autoComplete="new-password"
                    spellCheck={false}
                    data-1p-ignore="true"
                    data-lpignore="true"
                    className="w-full rounded-lg border border-[#242C3A] bg-[#0A0C10] px-3.5 py-2.5 font-mono text-sm text-[#F1F5F9] focus:border-amber-500 focus:outline-none"
                  />
                </div>

                {importError && (
                  <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3.5 py-2.5 text-xs text-red-200 flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
                    <span>{importError}</span>
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
                    type="submit"
                    disabled={importBusy || !importEnvelope}
                    className="inline-flex items-center gap-2 rounded-md bg-amber-500 px-4 py-2 text-xs font-semibold text-[#0A0C10] hover:bg-amber-400 disabled:opacity-60 cursor-pointer whitespace-nowrap"
                  >
                    <ShieldCheck className="h-3.5 w-3.5" />
                    <span>{importBusy ? 'Verificando AES-GCM...' : 'Descifrar y previsualizar'}</span>
                  </button>
                </div>
              </form>
            ) : (
              <div className="space-y-4">
                <div className="rounded-lg border border-emerald-500/35 bg-emerald-500/10 p-4 space-y-1">
                  <div className="flex items-center gap-2 text-xs font-semibold text-emerald-300">
                    <CheckCircle2 className="h-4 w-4" />
                    <span>Integridad criptográfica AEAD verificada</span>
                  </div>
                  <p className="text-xs text-[#F1F5F9] font-mono tabular-nums">
                    {decryptedPreview.entries.length} credenciales · {decryptedPreview.categories.length} categorías · {conflictCount} coincidencias con registros actuales
                  </p>
                </div>

                <div className="space-y-2">
                  <p className="text-xs font-medium text-[#94A3B8]">Estrategia de fusión en RAM</p>
                  {(
                    [
                      [
                        'merge_keep_both',
                        'Fusionar y conservar ambos',
                        'Añade todas las credenciales y crea copia independiente si existe el mismo ID.',
                      ],
                      [
                        'merge_update',
                        'Fusionar y actualizar existentes',
                        'Mantiene tus credenciales actuales y actualiza los registros con ID coincidente.',
                      ],
                      [
                        'replace_all',
                        'Reemplazar bóveda completa',
                        'Sustituye todas las entradas y categorías actuales por las del archivo.',
                      ],
                    ] as const
                  ).map(([val, title, desc]) => (
                    <label
                      key={val}
                      className={`flex items-start gap-3 rounded-lg border p-3 cursor-pointer transition-colors ${
                        policy === val
                          ? 'border-amber-500/70 bg-amber-500/10'
                          : 'border-[#242C3A] bg-[#0F131A]'
                      }`}
                    >
                      <input
                        type="radio"
                        name="import-policy"
                        checked={policy === val}
                        onChange={() => {
                          setPolicy(val);
                          setConfirmReplaceAll(false);
                          setImportError(null);
                        }}
                        className="mt-0.5 accent-amber-500"
                      />
                      <div>
                        <p className="text-xs font-medium text-[#F1F5F9]">{title}</p>
                        <p className="text-xs text-[#94A3B8] mt-0.5">{desc}</p>
                      </div>
                    </label>
                  ))}
                </div>

                {policy === 'replace_all' && (
                  <label className="flex items-start gap-2.5 rounded-lg border border-red-500/40 bg-red-500/10 p-3 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={confirmReplaceAll}
                      onChange={(e) => setConfirmReplaceAll(e.target.checked)}
                      className="mt-0.5 accent-red-500"
                    />
                    <span className="text-xs text-red-200">
                      Confirmo que esta acción sobrescribirá permanentemente las{' '}
                      <strong>{payload.entries.length}</strong> credenciales actuales de la bóveda.
                    </span>
                  </label>
                )}

                {importError && (
                  <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3.5 py-2.5 text-xs text-red-200 flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
                    <span>{importError}</span>
                  </div>
                )}

                <div className="flex items-center justify-end gap-2 pt-2 border-t border-[#242C3A]">
                  <button
                    type="button"
                    onClick={() => {
                      setDecryptedPreview(null);
                      setConfirmReplaceAll(false);
                      setImportError(null);
                    }}
                    className="rounded-md border border-[#242C3A] bg-[#0F131A] px-4 py-2 text-xs font-medium text-[#94A3B8] hover:text-[#F1F5F9] cursor-pointer"
                  >
                    Volver
                  </button>
                  <button
                    type="button"
                    disabled={importBusy || (policy === 'replace_all' && !confirmReplaceAll)}
                    onClick={() => void handleCommitImport()}
                    className="inline-flex items-center gap-2 rounded-md bg-amber-500 px-4 py-2 text-xs font-semibold text-[#0A0C10] hover:bg-amber-400 disabled:opacity-60 cursor-pointer whitespace-nowrap"
                  >
                    <span>{importBusy ? 'Aplicando y cifrando...' : 'Confirmar importación'}</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
