import React, { useEffect, useMemo, useState } from 'react';
import {
  Check,
  Copy,
  Edit3,
  KeyRound,
  Keyboard,
  Lock,
  Plus,
  Save,
  Star,
  Trash2,
  Wand2,
  X,
} from 'lucide-react';
import { calculateEntropyBits } from '../crypto/engine';
import type { OcrNoiseLevel, VaultCategory, VaultEntry } from '../types/vault';
import { CanvasSecretViewer } from './CanvasSecretViewer';
import { SecureVirtualKeypad } from './SecureVirtualKeypad';

interface EntryInspectorProps {
  entry: VaultEntry | null;
  isCreating: boolean;
  categories: VaultCategory[];
  defaultCategoryId: string;
  noiseLevel: OcrNoiseLevel;
  activeCopiedEntryId: string | null;
  clipboardSecondsLeft: number;
  onSave: (data: Omit<VaultEntry, 'id' | 'createdAt' | 'updatedAt'>, existingId?: string) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
  onCancelCreate: () => void;
  onCopyField: (value: string, label: string, entryId: string) => void;
  onOpenGeneratorForDraft: (applyCb: (pw: string) => void) => void;
  onStartCreate: () => void;
}

export const EntryInspector: React.FC<EntryInspectorProps> = ({
  entry,
  isCreating,
  categories,
  defaultCategoryId,
  noiseLevel,
  activeCopiedEntryId,
  clipboardSecondsLeft,
  onSave,
  onDelete,
  onCancelCreate,
  onCopyField,
  onOpenGeneratorForDraft,
  onStartCreate,
}) => {
  const [editing, setEditing] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [showKeypad, setShowKeypad] = useState(false);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const [title, setTitle] = useState('');
  const [categoryId, setCategoryId] = useState(defaultCategoryId);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [url, setUrl] = useState('');
  const [notes, setNotes] = useState('');
  const [favorite, setFavorite] = useState(false);

  const inFormMode = isCreating || editing;

  useEffect(() => {
    setConfirmDelete(false);
    setFormError(null);
    setShowKeypad(false);

    if (isCreating) {
      setEditing(false);
      setTitle('');
      setCategoryId(defaultCategoryId || categories[0]?.id || 'cat-personal');
      setUsername('');
      setPassword('');
      setUrl('');
      setNotes('');
      setFavorite(false);
    } else if (entry) {
      setEditing(false);
      setTitle(entry.title);
      setCategoryId(entry.categoryId);
      setUsername(entry.username);
      setPassword(entry.password);
      setUrl(entry.url);
      setNotes(entry.notes);
      setFavorite(entry.favorite);
    } else {
      // Clear draft secrets from RAM when no entry is selected
      setEditing(false);
      setTitle('');
      setCategoryId(defaultCategoryId || categories[0]?.id || 'cat-personal');
      setUsername('');
      setPassword('');
      setUrl('');
      setNotes('');
      setFavorite(false);
    }
  }, [entry, isCreating, defaultCategoryId, categories]);

  useEffect(() => {
    return () => {
      setTitle('');
      setUsername('');
      setPassword('');
      setUrl('');
      setNotes('');
    };
  }, []);

  const handleCancelForm = () => {
    setFormError(null);
    setShowKeypad(false);
    if (isCreating) {
      setTitle('');
      setUsername('');
      setPassword('');
      setUrl('');
      setNotes('');
      setFavorite(false);
      onCancelCreate();
      return;
    }
    setEditing(false);
    if (entry) {
      setTitle(entry.title);
      setCategoryId(entry.categoryId);
      setUsername(entry.username);
      setPassword(entry.password);
      setUrl(entry.url);
      setNotes(entry.notes);
      setFavorite(entry.favorite);
    } else {
      setTitle('');
      setUsername('');
      setPassword('');
      setUrl('');
      setNotes('');
      setFavorite(false);
    }
  };

  const entropy = useMemo(
    () => calculateEntropyBits(inFormMode ? password : entry?.password ?? ''),
    [inFormMode, password, entry?.password]
  );

  const categoryName = useMemo(() => {
    const id = entry?.categoryId;
    return categories.find((c) => c.id === id)?.name ?? 'General';
  }, [categories, entry?.categoryId]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (saving) return;
    setFormError(null);

    if (!title.trim()) {
      setFormError('Asigna un nombre identificador a esta credencial.');
      return;
    }
    if (!password) {
      setFormError('Introduce o genera una contraseña antes de guardar.');
      return;
    }

    setSaving(true);
    try {
      await onSave(
        {
          title: title.trim(),
          categoryId,
          username: username.trim(),
          password,
          url: url.trim(),
          notes: notes.trim(),
          favorite,
        },
        isCreating ? undefined : entry?.id
      );
      setEditing(false);
      setShowKeypad(false);
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Error al cifrar y guardar el registro.');
    } finally {
      setSaving(false);
    }
  };

  // Estado vacío del inspector
  if (!entry && !isCreating) {
    return (
      <aside className="w-full xl:w-[420px] shrink-0 border-t xl:border-t-0 xl:border-l border-[#242C3A] bg-[#0F131A] p-6 flex flex-col items-center justify-center text-center">
        <div className="max-w-xs space-y-3">
          <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-lg border border-[#242C3A] bg-[#161B24] text-amber-400">
            <KeyRound className="h-5 w-5" />
          </div>
          <h3 className="font-display text-base font-semibold text-[#F1F5F9]">
            Inspector de credenciales
          </h3>
          <p className="text-xs text-[#94A3B8] leading-relaxed">
            Selecciona un registro de la lista para inspeccionarlo en el visor Canvas anti-IA o crea una nueva credencial cifrada.
          </p>
          <button
            type="button"
            onClick={onStartCreate}
            className="mt-2 inline-flex items-center gap-2 rounded-md bg-amber-500 px-4 py-2 text-xs font-semibold text-[#0A0C10] hover:bg-amber-400 cursor-pointer whitespace-nowrap"
          >
            <Plus className="h-3.5 w-3.5" />
            <span>Nueva credencial</span>
          </button>
        </div>
      </aside>
    );
  }

  if (inFormMode) {
    return (
      <aside className="w-full xl:w-[420px] shrink-0 border-t xl:border-t-0 xl:border-l border-[#242C3A] bg-[#0F131A] p-6 overflow-y-auto">
        <div className="flex items-center justify-between border-b border-[#242C3A] pb-3.5 mb-5">
          <div>
            <h3 className="font-display text-base font-semibold text-[#F1F5F9]">
              {isCreating ? 'Nueva credencial cifrada' : 'Editar credencial'}
            </h3>
            <p className="text-xs text-[#94A3B8] mt-0.5">
              Se cifrará con AES-256-GCM en RAM al guardar
            </p>
          </div>
          <button
            type="button"
            onClick={handleCancelForm}
            className="rounded-md p-1.5 text-[#94A3B8] hover:bg-[#161B24] hover:text-[#F1F5F9] cursor-pointer"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4" autoComplete="off">
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-[#94A3B8]">Título del servicio</label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Ej. Banco Nacional · Servidor Producción"
              autoComplete="off"
              spellCheck={false}
              data-1p-ignore="true"
              data-lpignore="true"
              className="w-full rounded-lg border border-[#242C3A] bg-[#0A0C10] px-3.5 py-2 text-sm text-[#F1F5F9] placeholder:text-[#475569] focus:border-amber-500 focus:outline-none"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-[#94A3B8]">Categoría</label>
              <select
                value={categoryId}
                onChange={(e) => setCategoryId(e.target.value)}
                className="w-full rounded-lg border border-[#242C3A] bg-[#0A0C10] px-3 py-2 text-xs text-[#F1F5F9] focus:border-amber-500 focus:outline-none"
              >
                {categories.map((cat) => (
                  <option key={cat.id} value={cat.id}>
                    {cat.name}
                  </option>
                ))}
              </select>
            </div>

            <div className="flex items-end">
              <label className="flex w-full items-center gap-2 rounded-lg border border-[#242C3A] bg-[#161B24] px-3 py-2 text-xs text-[#F1F5F9] cursor-pointer">
                <input
                  type="checkbox"
                  checked={favorite}
                  onChange={(e) => setFavorite(e.target.checked)}
                  className="accent-amber-500"
                />
                <span>Marcar favorita</span>
              </label>
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-[#94A3B8]">Usuario o correo</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="usuario@dominio.com"
              autoComplete="off"
              spellCheck={false}
              autoCorrect="off"
              autoCapitalize="off"
              data-1p-ignore="true"
              data-lpignore="true"
              className="w-full rounded-lg border border-[#242C3A] bg-[#0A0C10] px-3.5 py-2 font-mono text-xs text-[#F1F5F9] placeholder:text-[#475569] focus:border-amber-500 focus:outline-none"
            />
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <label className="text-xs font-medium text-[#94A3B8]">Contraseña secreta</label>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setShowKeypad((v) => !v)}
                  className={`inline-flex items-center gap-1 rounded border px-2 py-1 text-[11px] font-medium cursor-pointer ${
                    showKeypad
                      ? 'border-amber-500/60 bg-amber-500/10 text-amber-300'
                      : 'border-[#242C3A] bg-[#161B24] text-[#94A3B8] hover:text-[#F1F5F9]'
                  }`}
                >
                  <Keyboard className="h-3 w-3" />
                  <span>Teclado</span>
                </button>
                <button
                  type="button"
                  onClick={() => onOpenGeneratorForDraft((pw) => setPassword(pw))}
                  className="inline-flex items-center gap-1 rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-[11px] font-medium text-amber-300 hover:bg-amber-500/20 cursor-pointer"
                >
                  <Wand2 className="h-3 w-3" />
                  <span>Generar</span>
                </button>
              </div>
            </div>

            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Introduce o genera una clave segura"
              autoComplete="new-password"
              spellCheck={false}
              data-1p-ignore="true"
              data-lpignore="true"
              className="w-full rounded-lg border border-[#242C3A] bg-[#0A0C10] px-3.5 py-2 font-mono text-sm text-[#F1F5F9] placeholder:text-[#475569] focus:border-amber-500 focus:outline-none"
            />

            <div className="flex items-center justify-between text-xs font-mono tabular-nums text-[#94A3B8]">
              <span>{password.length} caracteres</span>
              <span className="text-amber-400">
                {entropy.bits} bits · {entropy.label}
              </span>
            </div>

            {password.length > 0 && (
              <CanvasSecretViewer
                secret={password}
                noiseLevel={noiseLevel}
                label="Mantener para verificar en Canvas"
                height={48}
              />
            )}

            {showKeypad && (
              <SecureVirtualKeypad
                onInsertChar={(c) => setPassword((p) => p + c)}
                onBackspace={() => setPassword((p) => p.slice(0, -1))}
                onClear={() => setPassword('')}
              />
            )}
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-[#94A3B8]">URL o host (opcional)</label>
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https:// o ssh://servidor.local"
              autoComplete="off"
              spellCheck={false}
              autoCorrect="off"
              autoCapitalize="off"
              data-1p-ignore="true"
              data-lpignore="true"
              className="w-full rounded-lg border border-[#242C3A] bg-[#0A0C10] px-3.5 py-2 font-mono text-xs text-[#F1F5F9] placeholder:text-[#475569] focus:border-amber-500 focus:outline-none"
            />
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-[#94A3B8]">
              Notas seguras / códigos de recuperación
            </label>
            <textarea
              rows={3}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Claves de recuperación, PIN o detalles internos..."
              autoComplete="off"
              spellCheck={false}
              autoCorrect="off"
              autoCapitalize="off"
              data-1p-ignore="true"
              data-lpignore="true"
              className="w-full rounded-lg border border-[#242C3A] bg-[#0A0C10] px-3.5 py-2 font-mono text-xs text-[#F1F5F9] placeholder:text-[#475569] focus:border-amber-500 focus:outline-none resize-none"
            />
          </div>

          {formError && (
            <p className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-200">
              {formError}
            </p>
          )}

          <div className="flex items-center justify-end gap-2 pt-3 border-t border-[#242C3A]">
            <button
              type="button"
              onClick={handleCancelForm}
              className="rounded-md border border-[#242C3A] bg-[#161B24] px-3.5 py-2 text-xs font-medium text-[#94A3B8] hover:text-[#F1F5F9] cursor-pointer"
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={saving}
              className="inline-flex items-center gap-1.5 rounded-md bg-amber-500 px-4 py-2 text-xs font-semibold text-[#0A0C10] hover:bg-amber-400 disabled:opacity-60 cursor-pointer whitespace-nowrap"
            >
              <Save className="h-3.5 w-3.5" />
              <span>{saving ? 'Cifrando...' : 'Guardar credencial'}</span>
            </button>
          </div>
        </form>
      </aside>
    );
  }

  // Modo inspección protegida
  const isCopiedNow = activeCopiedEntryId === entry!.id && clipboardSecondsLeft > 0;

  return (
    <aside className="w-full xl:w-[420px] shrink-0 border-t xl:border-t-0 xl:border-l border-[#242C3A] bg-[#0F131A] p-6 overflow-y-auto flex flex-col justify-between gap-6">
      <div className="space-y-6">
        {/* Cabecera sin badges recargados */}
        <div className="space-y-2 border-b border-[#242C3A] pb-4">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <h3 className="font-display text-lg font-semibold text-[#F1F5F9] truncate">
                  {entry!.title}
                </h3>
                {entry!.favorite && (
                  <Star className="h-4 w-4 fill-amber-400 text-amber-400 shrink-0" />
                )}
              </div>
              <p className="mt-1 text-xs text-[#94A3B8]">
                {categoryName} <span aria-hidden="true">·</span> Entropía{' '}
                <span className="font-mono tabular-nums text-[#F1F5F9]">
                  {entropy.bits} bits ({entropy.label})
                </span>
              </p>
            </div>

            <button
              type="button"
              onClick={() => setEditing(true)}
              className="inline-flex items-center gap-1.5 rounded-md border border-[#242C3A] bg-[#161B24] px-3 py-1.5 text-xs font-medium text-[#F1F5F9] hover:border-[#334054] cursor-pointer whitespace-nowrap shrink-0"
            >
              <Edit3 className="h-3.5 w-3.5 text-amber-400" />
              <span>Editar</span>
            </button>
          </div>
        </div>

        {/* Usuario */}
        <div className="space-y-1.5">
          <p className="text-xs font-medium text-[#94A3B8]">Usuario / Identificador</p>
          <div className="flex items-center justify-between gap-2 rounded-lg border border-[#242C3A] bg-[#161B24] px-3.5 py-2.5">
            <span className="font-mono text-xs text-[#F1F5F9] truncate">
              {entry!.username || 'Sin usuario especificado'}
            </span>
            {entry!.username && (
              <button
                type="button"
                onClick={() => onCopyField(entry!.username, `Usuario de ${entry!.title}`, entry!.id)}
                className="inline-flex items-center gap-1 text-xs font-medium text-amber-400 hover:text-amber-300 cursor-pointer whitespace-nowrap shrink-0"
              >
                <Copy className="h-3.5 w-3.5" />
                <span>Copiar</span>
              </button>
            )}
          </div>
        </div>

        {/* Contraseña en Canvas anti-IA + botón copiar con temporizador */}
        <div className="space-y-2.5">
          <div className="flex items-center justify-between">
            <p className="text-xs font-medium text-[#94A3B8]">Contraseña protegida</p>
            <button
              type="button"
              onClick={() =>
                onCopyField(entry!.password, `Contraseña de ${entry!.title}`, entry!.id)
              }
              className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-colors cursor-pointer whitespace-nowrap ${
                isCopiedNow
                  ? 'bg-emerald-500/20 border border-emerald-500/50 text-emerald-300'
                  : 'bg-amber-500 text-[#0A0C10] hover:bg-amber-400'
              }`}
            >
              {isCopiedNow ? (
                <>
                  <Check className="h-3.5 w-3.5" />
                  <span className="font-mono tabular-nums">
                    En portapapeles ({clipboardSecondsLeft}s)
                  </span>
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" />
                  <span>Copiar contraseña</span>
                </>
              )}
            </button>
          </div>

          <CanvasSecretViewer
            secret={entry!.password}
            noiseLevel={noiseLevel}
            label="Mantener para revelar"
            height={58}
          />
        </div>

        {/* URL / Host */}
        {entry!.url && (
          <div className="space-y-1.5">
            <p className="text-xs font-medium text-[#94A3B8]">Dirección / Host (sin enlace externo)</p>
            <div className="flex items-center justify-between gap-2 rounded-lg border border-[#242C3A] bg-[#161B24] px-3.5 py-2.5">
              <span className="font-mono text-xs text-[#94A3B8] truncate">{entry!.url}</span>
              <button
                type="button"
                onClick={() => onCopyField(entry!.url, `Dirección de ${entry!.title}`, entry!.id)}
                className="text-xs font-medium text-amber-400 hover:text-amber-300 cursor-pointer whitespace-nowrap shrink-0"
              >
                Copiar
              </button>
            </div>
          </div>
        )}

        {/* Notas secretas protegidas en Canvas */}
        {entry!.notes && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <p className="text-xs font-medium text-[#94A3B8]">Notas seguras (blindaje Canvas)</p>
              <button
                type="button"
                onClick={() => onCopyField(entry!.notes, `Notas de ${entry!.title}`, entry!.id)}
                className="text-xs font-medium text-amber-400 hover:text-amber-300 cursor-pointer"
              >
                Copiar nota
              </button>
            </div>
            <CanvasSecretViewer
              secret={entry!.notes.replace(/\s+/g, ' ')}
              noiseLevel={noiseLevel}
              label="Mantener para revelar nota"
              height={50}
            />
          </div>
        )}
      </div>

      {/* Pie de metadatos y borrado */}
      <div className="pt-4 border-t border-[#242C3A] space-y-3">
        <div className="flex items-center justify-between text-xs text-[#94A3B8] font-mono tabular-nums">
          <span className="inline-flex items-center gap-1.5">
            <Lock className="h-3.5 w-3.5 text-emerald-400" />
            <span>AES-256-GCM</span>
          </span>
          <span>
            Modificado:{' '}
            {new Date(entry!.updatedAt).toLocaleDateString('es-ES', {
              day: '2-digit',
              month: 'short',
              year: 'numeric',
            })}
          </span>
        </div>

        <div className="flex items-center justify-between">
          {!confirmDelete ? (
            <button
              type="button"
              onClick={() => setConfirmDelete(true)}
              className="inline-flex items-center gap-1.5 text-xs text-[#94A3B8] hover:text-red-400 transition-colors cursor-pointer"
            >
              <Trash2 className="h-3.5 w-3.5" />
              <span>Eliminar credencial</span>
            </button>
          ) : (
            <div className="flex w-full items-center justify-between rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2">
              <span className="text-xs text-red-200">¿Eliminar permanentemente?</span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setConfirmDelete(false)}
                  className="text-xs text-[#94A3B8] hover:text-[#F1F5F9] cursor-pointer"
                >
                  No
                </button>
                <button
                  type="button"
                  onClick={() => void onDelete(entry!.id)}
                  className="rounded bg-red-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-red-500 cursor-pointer"
                >
                  Eliminar
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </aside>
  );
};
