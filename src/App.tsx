import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Check,
  Clock,
  Copy,
  EyeOff,
  Folder,
  FolderPlus,
  KeyRound,
  Lock,
  Plus,
  Search,
  Shield,
  ShieldCheck,
  Star,
  Trash2,
  User,
  X,
} from 'lucide-react';
import { EntryInspector } from './components/EntryInspector';
import { ExportImportModal } from './components/ExportImportModal';
import { LockScreen } from './components/LockScreen';
import { PasswordGeneratorModal } from './components/PasswordGeneratorModal';
import { PrivacyCurtainOverlay } from './components/PrivacyCurtainOverlay';
import { PWAInstallButton } from './components/PWAInstallButton';
import { RotationTrafficLight } from './components/RotationTrafficLight';
import { SecuritySettingsModal } from './components/SecuritySettingsModal';
import { sanitizeImportedPayload } from './components/vaultFileSecurity';
import {
  calculateEntropyBits,
  decryptVaultEnvelope,
  deriveMasterKey,
  encodeBase64,
  encryptVaultWithKey,
  generateSaltBytes,
  generateUuid,
  KDF_ITERATIONS,
} from './crypto/engine';
import { useClipboardGuard } from './hooks/useClipboardGuard';
import {
  clearUnlockLockout,
  deleteStoredEnvelope,
  getUnlockLockoutStatus,
  loadStoredEnvelope,
  recordUnlockFailure,
  saveStoredEnvelope,
} from './storage/indexedDb';
import {
  DEFAULT_CATEGORIES,
  DEFAULT_SECURITY_SETTINGS,
  type EncryptedVaultEnvelope,
  type SecuritySettings,
  type VaultCategory,
  type VaultEntry,
  type VaultPayload,
} from './types/vault';
import {
  compareRotationUrgency,
  evaluatePasswordRotation,
  type RotationEvaluation,
} from './utils/passwordRotation';

interface RamVaultSession {
  key: CryptoKey; // extractable: false, exclusivamente en RAM
  saltB64: string;
  iterations: number;
  payload: VaultPayload;
}

export default function App() {
  const [bootLoading, setBootLoading] = useState(true);
  const [storedEnvelope, setStoredEnvelope] = useState<EncryptedVaultEnvelope | null>(null);
  const [session, setSession] = useState<RamVaultSession | null>(null);
  const [lockReason, setLockReason] = useState<string | null>(null);

  // Estado de navegación y filtros en RAM
  const [selectedFilter, setSelectedFilter] = useState<string>('all'); // 'all' | 'favorites' | 'review' | categoryId
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState<'updated' | 'title' | 'entropy' | 'rotation'>('updated');
  const [selectedEntryId, setSelectedEntryId] = useState<string | null>(null);
  const [isCreatingEntry, setIsCreatingEntry] = useState(false);

  // Creación rápida de categorías personalizadas
  const [addingCategory, setAddingCategory] = useState(false);
  const [newCategoryName, setNewCategoryName] = useState('');

  // Modales y overlays
  const [showGenerator, setShowGenerator] = useState(false);
  const [generatorApplyCallback, setGeneratorApplyCallback] = useState<
    ((pw: string) => void) | null
  >(null);
  const [backupModalTab, setBackupModalTab] = useState<'export' | 'import' | null>(null);
  const [showSettingsModal, setShowSettingsModal] = useState(false);

  // Cortina de privacidad anti-captura y anti-agentes
  const [curtainVisible, setCurtainVisible] = useState(false);
  const [curtainReason, setCurtainReason] = useState(
    'La vista ha sido ocultada para impedir lecturas accidentales o captura de pantalla.'
  );

  // Notificación discreta de operaciones
  const [notice, setNotice] = useState<string | null>(null);
  const noticeTimerRef = useRef<number | null>(null);

  // Refs para sincronización libre de condiciones de carrera en RAM
  const sessionRef = useRef<RamVaultSession | null>(null);
  const sessionEpochRef = useRef<number>(0);
  const workspaceRef = useRef<HTMLDivElement | null>(null);

  // Temporizador de inactividad en RAM
  const [secondsUntilAutoLock, setSecondsUntilAutoLock] = useState<number>(300);
  const lastActivityRef = useRef<number>(Date.now());

  const updateSessionState = useCallback((next: RamVaultSession | null) => {
    sessionRef.current = next;
    setSession(next);
  }, []);

  const currentSettings = session?.payload.settings ?? DEFAULT_SECURITY_SETTINGS;
  const { clipboardState, copySecretWithTimer, wipeClipboardNow } = useClipboardGuard(
    currentSettings.clipboardTimeoutSec
  );

  const showNotice = useCallback((msg: string) => {
    setNotice(msg);
    if (noticeTimerRef.current !== null) {
      window.clearTimeout(noticeTimerRef.current);
    }
    noticeTimerRef.current = window.setTimeout(() => {
      setNotice(null);
      noticeTimerRef.current = null;
    }, 3600);
  }, []);

  useEffect(() => {
    return () => {
      if (noticeTimerRef.current !== null) {
        window.clearTimeout(noticeTimerRef.current);
      }
    };
  }, []);

  // Carga inicial del sobre cifrado desde IndexedDB (jamás descifra automáticamente)
  useEffect(() => {
    let active = true;
    loadStoredEnvelope()
      .then((env) => {
        if (active) {
          setStoredEnvelope(env);
          setBootLoading(false);
        }
      })
      .catch(() => {
        if (active) setBootLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  // Bloqueo inmediato y limpieza de RAM + Portapapeles
  const lockVault = useCallback(
    (reason?: string) => {
      sessionEpochRef.current += 1;
      window.dispatchEvent(new CustomEvent('bastion:hide-secrets'));
      void wipeClipboardNow();
      if (noticeTimerRef.current !== null) {
        window.clearTimeout(noticeTimerRef.current);
        noticeTimerRef.current = null;
      }
      updateSessionState(null);
      setSelectedFilter('all');
      setSelectedEntryId(null);
      setIsCreatingEntry(false);
      setSearchQuery('');
      setAddingCategory(false);
      setNewCategoryName('');
      setShowGenerator(false);
      setGeneratorApplyCallback(null);
      setBackupModalTab(null);
      setShowSettingsModal(false);
      setCurtainVisible(false);
      setNotice(null);
      setSecondsUntilAutoLock(0);
      setLockReason(
        reason ?? 'Bóveda bloqueada. La clave maestra y los datos descifrados fueron purgados de la RAM.'
      );
    },
    [updateSessionState, wipeClipboardNow]
  );

  // Persiste un nuevo VaultPayload cifrándolo con la CryptoKey en RAM
  const persistPayload = useCallback(
    async (
      nextPayload: VaultPayload,
      overrideSession?: RamVaultSession,
      expectedEpoch?: number
    ): Promise<boolean> => {
      const targetEpoch = expectedEpoch ?? sessionEpochRef.current;
      if (targetEpoch !== sessionEpochRef.current) {
        return false;
      }
      const activeSession = overrideSession ?? sessionRef.current;
      if (!activeSession) {
        return false;
      }

      const updatedPayload: VaultPayload = {
        ...nextPayload,
        updatedAt: Date.now(),
      };

      const updatedSession: RamVaultSession = {
        ...activeSession,
        payload: updatedPayload,
      };

      if (updatedPayload.settings.ephemeralMode) {
        await deleteStoredEnvelope();
        if (targetEpoch !== sessionEpochRef.current) return false;
        updateSessionState(updatedSession);
        setStoredEnvelope(null);
      } else {
        const envelope = await encryptVaultWithKey(
          updatedPayload,
          activeSession.key,
          activeSession.saltB64,
          activeSession.iterations,
          'local-vault'
        );
        if (targetEpoch !== sessionEpochRef.current) return false;
        await saveStoredEnvelope(envelope);
        if (targetEpoch !== sessionEpochRef.current) return false;
        updateSessionState(updatedSession);
        setStoredEnvelope(envelope);
      }

      return true;
    },
    [updateSessionState]
  );

  // Inicializar nueva bóveda
  const handleCreateVault = useCallback(
    async (masterPassword: string, ephemeralMode: boolean) => {
      const opEpoch = ++sessionEpochRef.current;
      const saltBytes = generateSaltBytes();
      const saltB64 = encodeBase64(saltBytes);
      const key = await deriveMasterKey(masterPassword, saltBytes, KDF_ITERATIONS);
      if (opEpoch !== sessionEpochRef.current) return;

      const initialPayload: VaultPayload = {
        version: 1,
        categories: [...DEFAULT_CATEGORIES],
        entries: [],
        settings: {
          ...DEFAULT_SECURITY_SETTINGS,
          ephemeralMode,
        },
        updatedAt: Date.now(),
      };

      const nextSession: RamVaultSession = {
        key,
        saltB64,
        iterations: KDF_ITERATIONS,
        payload: initialPayload,
      };

      const persisted = await persistPayload(initialPayload, nextSession, opEpoch);
      if (!persisted || opEpoch !== sessionEpochRef.current) return;

      setLockReason(null);
      setSelectedFilter('all');
      setSelectedEntryId(null);
      setIsCreatingEntry(true);
      lastActivityRef.current = Date.now();
      showNotice(
        ephemeralMode
          ? 'Bóveda efímera inicializada exclusivamente en memoria RAM.'
          : 'Bóveda AES-256-GCM inicializada. La clave maestra reside solo en RAM.'
      );
    },
    [persistPayload, showNotice]
  );

  // Desbloquear bóveda almacenada en IndexedDB
  const handleUnlockVault = useCallback(
    async (masterPassword: string) => {
      if (!storedEnvelope) {
        throw new Error('No se encontró ninguna bóveda cifrada almacenada en este equipo.');
      }

      const lockout = await getUnlockLockoutStatus().catch(() => null);
      if (lockout?.isLocked) {
        const waitSec = Math.max(1, Math.ceil(lockout.remainingMs / 1000));
        throw new Error(
          `Demasiados intentos fallidos. Espera ${waitSec} s antes de volver a intentar.`
        );
      }

      const opEpoch = ++sessionEpochRef.current;
      let unlocked: Awaited<ReturnType<typeof decryptVaultEnvelope>>;
      try {
        unlocked = await decryptVaultEnvelope(storedEnvelope, masterPassword);
      } catch (err) {
        const status = await recordUnlockFailure().catch(() => null);
        if (status?.isLocked) {
          const waitSec = Math.max(1, Math.ceil(status.remainingMs / 1000));
          throw new Error(
            `Clave maestra incorrecta. Bloqueo temporal activo durante ${waitSec} s.`
          );
        }
        throw err;
      }

      await clearUnlockLockout().catch(() => {});
      if (opEpoch !== sessionEpochRef.current) return;

      const { key, payload } = unlocked;
      updateSessionState({
        key,
        saltB64: storedEnvelope.salt,
        iterations: storedEnvelope.iterations,
        payload,
      });
      setLockReason(null);
      setSelectedFilter('all');
      setSelectedEntryId(payload.entries[0]?.id ?? null);
      setIsCreatingEntry(false);
      lastActivityRef.current = Date.now();
    },
    [storedEnvelope, updateSessionState]
  );

  // Desbloquear directamente desde un archivo .bvault
  const handleUnlockFromFile = useCallback(
    async (
      envelope: EncryptedVaultEnvelope,
      masterPassword: string,
      persistLocal: boolean
    ) => {
      const opEpoch = ++sessionEpochRef.current;
      const { key, payload } = await decryptVaultEnvelope(envelope, masterPassword);
      if (opEpoch !== sessionEpochRef.current) return;

      const sanitized = sanitizeImportedPayload(payload, DEFAULT_CATEGORIES);
      const mergedPayload: VaultPayload = {
        ...payload,
        categories: sanitized.categories,
        entries: sanitized.entries,
        settings: {
          ...DEFAULT_SECURITY_SETTINGS,
          ...(payload.settings ?? {}),
          ephemeralMode: !persistLocal,
        },
        updatedAt: Date.now(),
      };

      const nextSession: RamVaultSession = {
        key,
        saltB64: envelope.salt,
        iterations: envelope.iterations,
        payload: mergedPayload,
      };

      const persisted = await persistPayload(mergedPayload, nextSession, opEpoch);
      if (!persisted || opEpoch !== sessionEpochRef.current) return;

      setLockReason(null);
      setSelectedFilter('all');
      setSelectedEntryId(mergedPayload.entries[0]?.id ?? null);
      setIsCreatingEntry(false);
      lastActivityRef.current = Date.now();
      showNotice(`Archivo .bvault descifrado en RAM (${mergedPayload.entries.length} credenciales).`);
    },
    [persistPayload, showNotice]
  );

  const handleWipeLocalVault = useCallback(async () => {
    sessionEpochRef.current += 1;
    await deleteStoredEnvelope();
    setStoredEnvelope(null);
    setLockReason('Almacenamiento cifrado local purgado de IndexedDB.');
  }, []);

  const isUnlocked = session !== null;
  const autoLockMinutes = currentSettings.autoLockMinutes;
  const lockOnBlur = currentSettings.lockOnBlur;

  // Bloquea interacción de teclado/DOM bajo la cortina de privacidad
  useEffect(() => {
    const el = workspaceRef.current as (HTMLDivElement & { inert: boolean }) | null;
    if (el) {
      el.inert = curtainVisible;
    }
    if (curtainVisible) {
      window.dispatchEvent(new CustomEvent('bastion:hide-secrets'));
    }
  }, [curtainVisible]);

  // Gestión de actividad, auto-bloqueo, pérdida de foco y atajos de teclado
  useEffect(() => {
    if (!isUnlocked) return;

    const timeoutSeconds = autoLockMinutes * 60;
    lastActivityRef.current = Date.now();
    setSecondsUntilAutoLock(timeoutSeconds);

    const markActivity = () => {
      lastActivityRef.current = Date.now();
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      markActivity();
      if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === 'l') {
        e.preventDefault();
        lockVault('Bloqueo táctico activado mediante atajo Ctrl+Shift+L.');
      } else if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === 'p') {
        e.preventDefault();
        setCurtainReason('Cortina de privacidad activada manualmente (Ctrl+Shift+P).');
        setCurtainVisible((v) => !v);
      }
    };

    const handleVisibilityOrBlur = (e: Event) => {
      if (e.type === 'visibilitychange' && !document.hidden) {
        return;
      }
      if (lockOnBlur) {
        lockVault('Bloqueo automático activado al cambiar de ventana o pestaña.');
      } else if (document.hidden) {
        window.dispatchEvent(new CustomEvent('bastion:hide-secrets'));
        setCurtainReason(
          'La pestaña pasó a segundo plano. La vista quedó cubierta contra captura de pantalla.'
        );
        setCurtainVisible(true);
      }
    };

    const handlePageUnload = () => {
      lockVault('Sesión cerrada y memoria RAM purgada.');
    };

    window.addEventListener('pointerdown', markActivity);
    window.addEventListener('keydown', handleKeyDown);
    window.addEventListener('blur', handleVisibilityOrBlur);
    document.addEventListener('visibilitychange', handleVisibilityOrBlur);
    window.addEventListener('pagehide', handlePageUnload);
    window.addEventListener('beforeunload', handlePageUnload);

    const tick = window.setInterval(() => {
      const elapsed = Math.floor((Date.now() - lastActivityRef.current) / 1000);
      const remaining = Math.max(0, timeoutSeconds - elapsed);
      setSecondsUntilAutoLock(remaining);
      if (remaining <= 0) {
        lockVault(
          `Sesión expirada tras ${autoLockMinutes} min de inactividad. Memoria RAM purgada.`
        );
      }
    }, 1000);

    return () => {
      window.removeEventListener('pointerdown', markActivity);
      window.removeEventListener('keydown', handleKeyDown);
      window.removeEventListener('blur', handleVisibilityOrBlur);
      document.removeEventListener('visibilitychange', handleVisibilityOrBlur);
      window.removeEventListener('pagehide', handlePageUnload);
      window.removeEventListener('beforeunload', handlePageUnload);
      window.clearInterval(tick);
    };
  }, [isUnlocked, autoLockMinutes, lockOnBlur, lockVault]);

  // Operaciones CRUD en RAM + re-cifrado inmediato
  const handleSaveEntry = useCallback(
    async (
      data: Omit<VaultEntry, 'id' | 'createdAt' | 'updatedAt' | 'passwordUpdatedAt'>,
      existingId?: string
    ) => {
      const active = sessionRef.current;
      if (!active) return;
      const opEpoch = sessionEpochRef.current;
      const now = Date.now();
      let targetId = existingId;
      let nextEntries: VaultEntry[];

      if (existingId) {
        const { rotationIntervalDays, ...restData } = data;
        nextEntries = active.payload.entries.map((item) => {
          if (item.id !== existingId) return item;
          const passwordChanged = item.password !== data.password;
          const nextEntry: VaultEntry = {
            ...item,
            ...restData,
            updatedAt: now,
            passwordUpdatedAt: passwordChanged
              ? now
              : (item.passwordUpdatedAt ?? item.updatedAt ?? item.createdAt),
          };
          if (rotationIntervalDays !== undefined) {
            nextEntry.rotationIntervalDays = rotationIntervalDays;
          } else {
            delete nextEntry.rotationIntervalDays;
          }
          return nextEntry;
        });
      } else {
        targetId = generateUuid();
        const created: VaultEntry = {
          ...data,
          id: targetId,
          createdAt: now,
          updatedAt: now,
          passwordUpdatedAt: now,
        };
        if (data.rotationIntervalDays === undefined) {
          delete created.rotationIntervalDays;
        }
        nextEntries = [created, ...active.payload.entries];
      }

      const ok = await persistPayload(
        {
          ...active.payload,
          entries: nextEntries,
        },
        active,
        opEpoch
      );
      if (!ok || opEpoch !== sessionEpochRef.current) return;

      setIsCreatingEntry(false);
      setSelectedEntryId(targetId ?? null);
      showNotice(
        existingId
          ? 'Credencial actualizada y re-cifrada con AES-256-GCM.'
          : 'Nueva credencial cifrada y añadida a la bóveda.'
      );
    },
    [persistPayload, showNotice]
  );

  const handleDeleteEntry = useCallback(
    async (id: string) => {
      const active = sessionRef.current;
      if (!active) return;
      const opEpoch = sessionEpochRef.current;
      const nextEntries = active.payload.entries.filter((e) => e.id !== id);
      const ok = await persistPayload(
        {
          ...active.payload,
          entries: nextEntries,
        },
        active,
        opEpoch
      );
      if (!ok || opEpoch !== sessionEpochRef.current) return;
      if (selectedEntryId === id) {
        setSelectedEntryId(nextEntries[0]?.id ?? null);
      }
      showNotice('Credencial eliminada de la bóveda.');
    },
    [persistPayload, selectedEntryId, showNotice]
  );

  const handleToggleFavorite = useCallback(
    async (entry: VaultEntry, e: React.MouseEvent) => {
      e.stopPropagation();
      const active = sessionRef.current;
      if (!active) return;
      const opEpoch = sessionEpochRef.current;
      const nextEntries = active.payload.entries.map((item) =>
        item.id === entry.id
          ? { ...item, favorite: !item.favorite, updatedAt: Date.now() }
          : item
      );
      await persistPayload(
        {
          ...active.payload,
          entries: nextEntries,
        },
        active,
        opEpoch
      );
    },
    [persistPayload]
  );

  const handleAddCategory = async (e: React.FormEvent) => {
    e.preventDefault();
    const active = sessionRef.current;
    if (!active) return;
    const opEpoch = sessionEpochRef.current;
    const clean = newCategoryName.trim();
    if (!clean) return;
    const newCat: VaultCategory = {
      id: `cat-${generateUuid().slice(0, 8)}`,
      name: clean,
      isDefault: false,
    };
    const ok = await persistPayload(
      {
        ...active.payload,
        categories: [...active.payload.categories, newCat],
      },
      active,
      opEpoch
    );
    if (!ok || opEpoch !== sessionEpochRef.current) return;
    setNewCategoryName('');
    setAddingCategory(false);
    setSelectedFilter(newCat.id);
    showNotice(`Categoría "${clean}" creada.`);
  };

  const handleDeleteCategory = async (catId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const active = sessionRef.current;
    if (!active) return;
    const opEpoch = sessionEpochRef.current;
    const fallbackCatId = active.payload.categories[0]?.id ?? 'cat-personal';
    const nextCategories = active.payload.categories.filter((c) => c.id !== catId);
    const nextEntries = active.payload.entries.map((entry) =>
      entry.categoryId === catId ? { ...entry, categoryId: fallbackCatId } : entry
    );
    const ok = await persistPayload(
      {
        ...active.payload,
        categories: nextCategories,
        entries: nextEntries,
      },
      active,
      opEpoch
    );
    if (!ok || opEpoch !== sessionEpochRef.current) return;
    if (selectedFilter === catId) {
      setSelectedFilter('all');
    }
    showNotice('Categoría eliminada; las credenciales se movieron a la categoría principal.');
  };

  const handleSaveSettings = useCallback(
    async (nextSettings: SecuritySettings) => {
      const active = sessionRef.current;
      if (!active) return;
      const opEpoch = sessionEpochRef.current;
      const ok = await persistPayload(
        {
          ...active.payload,
          settings: nextSettings,
        },
        active,
        opEpoch
      );
      if (!ok || opEpoch !== sessionEpochRef.current) return;
      showNotice('Parámetros de seguridad actualizados.');
    },
    [persistPayload, showNotice]
  );

  const handleRotateMasterPassword = useCallback(
    async (newMasterPassword: string) => {
      const active = sessionRef.current;
      if (!active) return;
      const opEpoch = sessionEpochRef.current;
      const freshSaltBytes = generateSaltBytes();
      const freshSaltB64 = encodeBase64(freshSaltBytes);
      const freshKey = await deriveMasterKey(newMasterPassword, freshSaltBytes, KDF_ITERATIONS);
      if (opEpoch !== sessionEpochRef.current || !sessionRef.current) return;

      const rotatedSession: RamVaultSession = {
        key: freshKey,
        saltB64: freshSaltB64,
        iterations: KDF_ITERATIONS,
        payload: sessionRef.current.payload,
      };
      const ok = await persistPayload(sessionRef.current.payload, rotatedSession, opEpoch);
      if (!ok || opEpoch !== sessionEpochRef.current) return;
      showNotice('Clave maestra rotada en RAM y bóveda re-cifrada.');
    },
    [persistPayload, showNotice]
  );

  const handleImportCommit = useCallback(
    async (
      nextCategories: VaultCategory[],
      nextEntries: VaultEntry[],
      summaryText: string
    ) => {
      const active = sessionRef.current;
      if (!active) return;
      const opEpoch = sessionEpochRef.current;
      const ok = await persistPayload(
        {
          ...active.payload,
          categories: nextCategories,
          entries: nextEntries,
        },
        active,
        opEpoch
      );
      if (!ok || opEpoch !== sessionEpochRef.current) return;
      setSelectedEntryId(nextEntries[0]?.id ?? null);
      setIsCreatingEntry(false);
      showNotice(summaryText);
    },
    [persistPayload, showNotice]
  );

  const rotationById = useMemo(() => {
    const map = new Map<string, RotationEvaluation>();
    if (!session) return map;
    const defaultDays = session.payload.settings.defaultRotationDays;
    const now = Date.now();
    for (const entry of session.payload.entries) {
      map.set(entry.id, evaluatePasswordRotation(entry, defaultDays, now));
    }
    return map;
  }, [session]);

  const reviewCount = useMemo(() => {
    let count = 0;
    for (const rot of rotationById.values()) {
      if (rot.status === 'due' || rot.status === 'soon') {
        count += 1;
      }
    }
    return count;
  }, [rotationById]);

  // Entradas filtradas y ordenadas
  const visibleEntries = useMemo(() => {
    if (!session) return [];
    const q = searchQuery.trim().toLowerCase();
    const list = session.payload.entries.filter((entry) => {
      if (selectedFilter === 'favorites' && !entry.favorite) return false;
      if (selectedFilter === 'review') {
        const st = rotationById.get(entry.id)?.status;
        if (st !== 'due' && st !== 'soon') return false;
      }
      if (
        selectedFilter !== 'all' &&
        selectedFilter !== 'favorites' &&
        selectedFilter !== 'review' &&
        entry.categoryId !== selectedFilter
      ) {
        return false;
      }
      if (!q) return true;
      return (
        entry.title.toLowerCase().includes(q) ||
        entry.username.toLowerCase().includes(q) ||
        entry.url.toLowerCase().includes(q)
      );
    });

    return [...list].sort((a, b) => {
      if (sortBy === 'title') return a.title.localeCompare(b.title, 'es');
      if (sortBy === 'entropy') {
        return calculateEntropyBits(a.password).bits - calculateEntropyBits(b.password).bits;
      }
      if (sortBy === 'rotation') {
        const ra = rotationById.get(a.id);
        const rb = rotationById.get(b.id);
        if (ra && rb) {
          const cmp = compareRotationUrgency(ra, rb);
          if (cmp !== 0) return cmp;
        }
      }
      return b.updatedAt - a.updatedAt;
    });
  }, [session, selectedFilter, searchQuery, sortBy, rotationById]);

  const selectedEntry = useMemo(() => {
    if (!session || !selectedEntryId) return null;
    return session.payload.entries.find((e) => e.id === selectedEntryId) ?? null;
  }, [session, selectedEntryId]);

  const categoryNameMap = useMemo(() => {
    const map = new Map<string, string>();
    if (session) {
      for (const c of session.payload.categories) {
        map.set(c.id, c.name);
      }
    }
    return map;
  }, [session]);

  if (bootLoading) {
    return (
      <div className="min-h-screen bg-[#0A0C10] flex items-center justify-center text-xs text-[#94A3B8] font-mono">
        Inicializando módulo criptográfico local...
      </div>
    );
  }

  if (!session) {
    return (
      <LockScreen
        hasExistingVault={storedEnvelope !== null}
        storedVaultUpdatedAt={storedEnvelope?.updatedAt ?? null}
        lockReason={lockReason}
        onCreateVault={handleCreateVault}
        onUnlockVault={handleUnlockVault}
        onUnlockFromFile={handleUnlockFromFile}
        onWipeLocalVault={handleWipeLocalVault}
      />
    );
  }

  const autoLockMin = Math.floor(secondsUntilAutoLock / 60);
  const autoLockSec = secondsUntilAutoLock % 60;
  const formattedAutoLock = `${String(autoLockMin).padStart(2, '0')}:${String(autoLockSec).padStart(2, '0')}`;

  const activeCategoryLabel =
    selectedFilter === 'all'
      ? 'Todas las credenciales'
      : selectedFilter === 'favorites'
      ? 'Favoritas'
      : selectedFilter === 'review'
      ? 'Por revisar (semáforo)'
      : categoryNameMap.get(selectedFilter) ?? 'Categoría';

  return (
    <div className="h-screen bg-[#0A0C10] text-[#F1F5F9] flex flex-col overflow-hidden">
      <div
        ref={workspaceRef}
        aria-hidden={curtainVisible}
        className="flex-1 flex flex-col min-h-0 overflow-hidden"
      >
      {/* Barra superior 3 zonas (Contrato estricto) */}
      <header className="h-15 shrink-0 border-b border-[#242C3A] bg-[#0F131A] px-6 flex items-center justify-between gap-8">
        {/* Zona 1: Marca en una línea */}
        <div className="flex items-center gap-2.5 whitespace-nowrap shrink-0">
          <Shield className="h-5 w-5 text-amber-500" />
          <span className="font-display text-lg font-semibold tracking-tight text-[#F1F5F9]">
            Bastión
          </span>
        </div>

        {/* Zona 2: Enlaces de navegación de texto limpio */}
        <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-[#94A3B8]">
          <button
            type="button"
            onClick={() => {
              setShowGenerator(false);
              setBackupModalTab(null);
              setShowSettingsModal(false);
            }}
            className="text-[#F1F5F9] hover:text-amber-400 transition-colors cursor-pointer whitespace-nowrap shrink-0"
          >
            Credenciales
          </button>
          <button
            type="button"
            onClick={() => {
              setGeneratorApplyCallback(null);
              setShowGenerator(true);
            }}
            className="hover:text-[#F1F5F9] transition-colors cursor-pointer whitespace-nowrap shrink-0"
          >
            Generador
          </button>
          <button
            type="button"
            onClick={() => setBackupModalTab('export')}
            className="hover:text-[#F1F5F9] transition-colors cursor-pointer whitespace-nowrap shrink-0"
          >
            Respaldo .bvault
          </button>
          <button
            type="button"
            onClick={() => setShowSettingsModal(true)}
            className="hover:text-[#F1F5F9] transition-colors cursor-pointer whitespace-nowrap shrink-0"
          >
            Seguridad
          </button>
        </nav>

        {/* Zona 3: 1 acción primaria */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() => lockVault()}
            className="inline-flex items-center gap-2 rounded-md bg-amber-500 px-4 py-2 text-xs font-semibold text-[#0A0C10] hover:bg-amber-400 transition-colors cursor-pointer whitespace-nowrap shrink-0"
          >
            <Lock className="h-3.5 w-3.5" />
            <span>Bloquear bóveda</span>
          </button>
        </div>
      </header>

      {/* Espacio de trabajo principal de 3 columnas */}
      <div className="flex-1 flex flex-col lg:flex-row min-h-0 overflow-hidden">
        {/* Barra lateral izquierda: Categorías y utilidades */}
        <aside className="w-full lg:w-[260px] shrink-0 border-b lg:border-b-0 lg:border-r border-[#242C3A] bg-[#0F131A] flex flex-col justify-between overflow-y-auto">
          <div className="p-4 space-y-5">
            {/* Vistas globales */}
            <div className="space-y-1">
              <button
                type="button"
                onClick={() => setSelectedFilter('all')}
                className={`w-full flex items-center justify-between rounded-md px-3 py-2 text-xs font-medium transition-colors cursor-pointer ${
                  selectedFilter === 'all'
                    ? 'bg-[#161B24] text-[#F1F5F9] border border-[#242C3A]'
                    : 'text-[#94A3B8] hover:bg-[#161B24]/60 hover:text-[#F1F5F9] border border-transparent'
                }`}
              >
                <span className="inline-flex items-center gap-2.5 truncate">
                  <KeyRound className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                  <span className="truncate">Todas las credenciales</span>
                </span>
                <span className="font-mono tabular-nums text-[11px] text-[#94A3B8]">
                  {session.payload.entries.length}
                </span>
              </button>

              <button
                type="button"
                onClick={() => setSelectedFilter('favorites')}
                className={`w-full flex items-center justify-between rounded-md px-3 py-2 text-xs font-medium transition-colors cursor-pointer ${
                  selectedFilter === 'favorites'
                    ? 'bg-[#161B24] text-[#F1F5F9] border border-[#242C3A]'
                    : 'text-[#94A3B8] hover:bg-[#161B24]/60 hover:text-[#F1F5F9] border border-transparent'
                }`}
              >
                <span className="inline-flex items-center gap-2.5 truncate">
                  <Star className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                  <span className="truncate">Favoritas</span>
                </span>
                <span className="font-mono tabular-nums text-[11px] text-[#94A3B8]">
                  {session.payload.entries.filter((e) => e.favorite).length}
                </span>
              </button>

              <button
                type="button"
                onClick={() => setSelectedFilter('review')}
                className={`w-full flex items-center justify-between rounded-md px-3 py-2 text-xs font-medium transition-colors cursor-pointer ${
                  selectedFilter === 'review'
                    ? 'bg-[#161B24] text-[#F1F5F9] border border-[#242C3A]'
                    : 'text-[#94A3B8] hover:bg-[#161B24]/60 hover:text-[#F1F5F9] border border-transparent'
                }`}
              >
                <span className="inline-flex items-center gap-2.5 truncate">
                  <span
                    aria-hidden="true"
                    className={`h-2.5 w-2.5 rounded-full shrink-0 ${
                      reviewCount > 0 ? 'bg-amber-400' : 'bg-emerald-500/70'
                    }`}
                  />
                  <span className="truncate">Por revisar</span>
                </span>
                <span
                  className={`font-mono tabular-nums text-[11px] ${
                    reviewCount > 0 ? 'text-amber-300' : 'text-[#94A3B8]'
                  }`}
                >
                  {reviewCount}
                </span>
              </button>
            </div>

            {/* Categorías */}
            <div className="space-y-2">
              <div className="flex items-center justify-between px-2">
                <span className="text-xs font-medium text-[#94A3B8]">Categorías</span>
                <button
                  type="button"
                  onClick={() => setAddingCategory((v) => !v)}
                  title="Crear categoría"
                  className="inline-flex items-center gap-1 text-xs text-amber-400 hover:text-amber-300 cursor-pointer"
                >
                  <FolderPlus className="h-3.5 w-3.5" />
                  <span>Nueva</span>
                </button>
              </div>

              {addingCategory && (
                <form onSubmit={handleAddCategory} autoComplete="off" className="flex items-center gap-1.5 px-1">
                  <input
                    type="text"
                    value={newCategoryName}
                    onChange={(e) => setNewCategoryName(e.target.value)}
                    placeholder="Nombre de categoría..."
                    autoComplete="off"
                    spellCheck={false}
                    data-1p-ignore="true"
                    data-lpignore="true"
                    autoFocus
                    className="flex-1 min-w-0 rounded-md border border-[#242C3A] bg-[#0A0C10] px-2.5 py-1.5 text-xs text-[#F1F5F9] focus:border-amber-500 focus:outline-none"
                  />
                  <button
                    type="submit"
                    className="rounded-md bg-amber-500 px-2.5 py-1.5 text-xs font-semibold text-[#0A0C10] hover:bg-amber-400 cursor-pointer"
                  >
                    OK
                  </button>
                </form>
              )}

              <div className="space-y-0.5">
                {session.payload.categories.map((cat) => {
                  const count = session.payload.entries.filter(
                    (e) => e.categoryId === cat.id
                  ).length;
                  const active = selectedFilter === cat.id;
                  return (
                    <div
                      key={cat.id}
                      onClick={() => setSelectedFilter(cat.id)}
                      role="button"
                      tabIndex={0}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') setSelectedFilter(cat.id);
                      }}
                      className={`group flex items-center justify-between rounded-md px-3 py-2 text-xs transition-colors cursor-pointer ${
                        active
                          ? 'bg-[#161B24] text-[#F1F5F9] border border-[#242C3A]'
                          : 'text-[#94A3B8] hover:bg-[#161B24]/60 hover:text-[#F1F5F9] border border-transparent'
                      }`}
                    >
                      <span className="inline-flex items-center gap-2.5 min-w-0">
                        <Folder className="h-3.5 w-3.5 shrink-0 text-[#64748B] group-hover:text-amber-400" />
                        <span className="truncate">{cat.name}</span>
                      </span>
                      <div className="flex items-center gap-1.5 shrink-0">
                        {!cat.isDefault && (
                          <button
                            type="button"
                            onClick={(e) => void handleDeleteCategory(cat.id, e)}
                            title="Eliminar categoría"
                            className="opacity-0 group-hover:opacity-100 text-[#94A3B8] hover:text-red-400 cursor-pointer"
                          >
                            <Trash2 className="h-3 w-3" />
                          </button>
                        )}
                        <span className="font-mono tabular-nums text-[11px] text-[#94A3B8]">
                          {count}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Accesos móviles a herramientas */}
            <div className="flex flex-wrap gap-2 md:hidden pt-2 border-t border-[#242C3A]">
              <button
                type="button"
                onClick={() => {
                  setGeneratorApplyCallback(null);
                  setShowGenerator(true);
                }}
                className="rounded-md border border-[#242C3A] bg-[#161B24] px-3 py-1.5 text-xs text-[#F1F5F9]"
              >
                Generador
              </button>
              <button
                type="button"
                onClick={() => setBackupModalTab('export')}
                className="rounded-md border border-[#242C3A] bg-[#161B24] px-3 py-1.5 text-xs text-[#F1F5F9]"
              >
                Respaldo .bvault
              </button>
              <button
                type="button"
                onClick={() => setShowSettingsModal(true)}
                className="rounded-md border border-[#242C3A] bg-[#161B24] px-3 py-1.5 text-xs text-[#F1F5F9]"
              >
                Seguridad
              </button>
            </div>
          </div>

          {/* Base de la barra lateral: Escudo rápido, PWA y temporizador RAM */}
          <div className="p-4 border-t border-[#242C3A] space-y-3">
            <button
              type="button"
              onClick={() => {
                setCurtainReason('Cortina de privacidad activada manualmente.');
                setCurtainVisible(true);
              }}
              className="w-full inline-flex items-center justify-center gap-2 rounded-md border border-[#242C3A] bg-[#161B24] px-3 py-2 text-xs font-medium text-[#F1F5F9] hover:border-amber-500/50 hover:bg-[#1C2330] transition-colors cursor-pointer whitespace-nowrap"
            >
              <EyeOff className="h-3.5 w-3.5 text-amber-400" />
              <span>Escudo de pantalla</span>
            </button>

            <PWAInstallButton />

            <div className="pt-1 space-y-1 text-[11px] text-[#94A3B8] font-mono tabular-nums">
              <div className="flex items-center justify-between">
                <span>Autobloqueo RAM</span>
                <span className="text-[#F1F5F9]">{formattedAutoLock}</span>
              </div>
              <div className="flex items-center justify-between">
                <span>Almacenamiento</span>
                <span className={session.payload.settings.ephemeralMode ? 'text-amber-400' : 'text-emerald-400'}>
                  {session.payload.settings.ephemeralMode ? 'Solo RAM' : 'Cifrado local'}
                </span>
              </div>
            </div>
          </div>
        </aside>

        {/* Columna central: Buscador, temporizador de portapapeles y tabla densa */}
        <main className="flex-1 flex flex-col min-w-0 min-h-0 bg-[#0A0C10]">
          {/* Barra contextual de herramientas */}
          <div className="shrink-0 border-b border-[#242C3A] px-6 py-4 flex flex-wrap items-center justify-between gap-4">
            <div className="min-w-0">
              <h1 className="font-display text-xl font-semibold text-[#F1F5F9] truncate">
                {activeCategoryLabel}
              </h1>
              <p className="text-xs text-[#94A3B8] mt-0.5 font-mono tabular-nums">
                {visibleEntries.length}{' '}
                {visibleEntries.length === 1 ? 'registro' : 'registros'} · Sin conexión · Anti-OCR{' '}
                {session.payload.settings.ocrNoiseLevel === 'high' ? 'Alto' : 'Estándar'}
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2.5">
              <div className="relative">
                <Search className="h-3.5 w-3.5 text-[#64748B] absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Buscar en RAM..."
                  autoComplete="off"
                  spellCheck={false}
                  autoCorrect="off"
                  autoCapitalize="off"
                  data-1p-ignore="true"
                  data-lpignore="true"
                  className="w-52 sm:w-64 rounded-md border border-[#242C3A] bg-[#0F131A] pl-9 pr-3 py-2 text-xs text-[#F1F5F9] placeholder:text-[#475569] focus:border-amber-500 focus:outline-none"
                />
              </div>

              <select
                value={sortBy}
                onChange={(e) =>
                  setSortBy(e.target.value as 'updated' | 'title' | 'entropy' | 'rotation')
                }
                aria-label="Ordenar credenciales"
                className="rounded-md border border-[#242C3A] bg-[#0F131A] px-3 py-2 text-xs text-[#F1F5F9] focus:border-amber-500 focus:outline-none"
              >
                <option value="updated">Más recientes</option>
                <option value="rotation">Vigencia (revisar primero)</option>
                <option value="title">Alfabético (A–Z)</option>
                <option value="entropy">Menor entropía primero</option>
              </select>

              <button
                type="button"
                onClick={() => {
                  setIsCreatingEntry(true);
                  setSelectedEntryId(null);
                }}
                className="inline-flex items-center gap-1.5 rounded-md bg-amber-500 px-3.5 py-2 text-xs font-semibold text-[#0A0C10] hover:bg-amber-400 transition-colors cursor-pointer whitespace-nowrap shrink-0"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>Nueva credencial</span>
              </button>
            </div>
          </div>

          {/* Barra activa de temporizador de portapapeles */}
          {clipboardState.secondsRemaining > 0 && (
            <div className="shrink-0 border-b border-amber-500/30 bg-amber-500/10 px-6 py-2.5 flex items-center justify-between gap-4">
              <div className="flex items-center gap-3 min-w-0">
                <Clock className="h-4 w-4 text-amber-400 shrink-0" />
                <div className="min-w-0">
                  <p className="text-xs text-amber-100 truncate">
                    Copiado: <span className="font-medium">{clipboardState.activeLabel}</span> · Borrado automático en{' '}
                    <span className="font-mono tabular-nums font-semibold text-amber-300">
                      {clipboardState.secondsRemaining} s
                    </span>
                  </p>
                  <div className="mt-1 h-1 w-48 max-w-full overflow-hidden rounded-full bg-[#0A0C10]">
                    <div
                      className="h-full bg-amber-500 transition-all duration-200"
                      style={{
                        width: `${Math.round(
                          (clipboardState.secondsRemaining / Math.max(1, clipboardState.totalSeconds)) * 100
                        )}%`,
                      }}
                    />
                  </div>
                </div>
              </div>

              <button
                type="button"
                onClick={() => void wipeClipboardNow('Portapapeles purgado manualmente.')}
                className="rounded-md border border-amber-500/50 bg-[#0A0C10] px-3 py-1 text-xs font-medium text-amber-300 hover:bg-amber-500/20 cursor-pointer whitespace-nowrap shrink-0"
              >
                Purgar ahora
              </button>
            </div>
          )}

          {/* Mensaje discreto de confirmación (portapapeles o cifrado) */}
          {(notice || clipboardState.statusMessage) && clipboardState.secondsRemaining === 0 && (
            <div className="shrink-0 border-b border-[#242C3A] bg-[#0F131A] px-6 py-2 flex items-center justify-between gap-3 text-xs text-emerald-300">
              <div className="flex items-center gap-2 min-w-0">
                <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
                <span className="truncate">{notice ?? clipboardState.statusMessage}</span>
              </div>
              <button
                type="button"
                onClick={() => setNotice(null)}
                className="text-[#94A3B8] hover:text-[#F1F5F9] cursor-pointer"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          )}

          {/* Tabla densa de credenciales */}
          <div className="flex-1 overflow-y-auto">
            {visibleEntries.length === 0 ? (
              <div className="h-full flex items-center justify-center p-8 text-center">
                <div className="max-w-sm space-y-3">
                  <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-lg border border-[#242C3A] bg-[#161B24] text-amber-400">
                    <Shield className="h-5 w-5" />
                  </div>
                  <h2 className="font-display text-base font-semibold text-[#F1F5F9]">
                    {session.payload.entries.length === 0
                      ? 'Tu bóveda cifrada está lista'
                      : 'Sin coincidencias para este filtro'}
                  </h2>
                  <p className="text-xs text-[#94A3B8] leading-relaxed">
                    {session.payload.entries.length === 0
                      ? 'Añade tu primera credencial o importa un respaldo local .bvault. Todas las claves se cifran en memoria con AES-256-GCM.'
                      : 'Ajusta el término de búsqueda o cambia de categoría para visualizar otros registros.'}
                  </p>
                  <div className="flex items-center justify-center gap-2 pt-2">
                    <button
                      type="button"
                      onClick={() => {
                        setIsCreatingEntry(true);
                        setSelectedEntryId(null);
                      }}
                      className="inline-flex items-center gap-1.5 rounded-md bg-amber-500 px-4 py-2 text-xs font-semibold text-[#0A0C10] hover:bg-amber-400 cursor-pointer whitespace-nowrap"
                    >
                      <Plus className="h-3.5 w-3.5" />
                      <span>Crear primera credencial</span>
                    </button>
                    {session.payload.entries.length === 0 && (
                      <button
                        type="button"
                        onClick={() => setBackupModalTab('import')}
                        className="rounded-md border border-[#242C3A] bg-[#161B24] px-3.5 py-2 text-xs font-medium text-[#F1F5F9] hover:border-[#334054] cursor-pointer whitespace-nowrap"
                      >
                        Importar .bvault
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <table className="w-full text-left border-collapse">
                <thead className="sticky top-0 z-10 bg-[#0F131A] border-b border-[#242C3A] text-xs font-medium text-[#94A3B8]">
                  <tr>
                    <th className="py-2.5 pl-6 pr-3">Servicio</th>
                    <th className="py-2.5 px-3 hidden sm:table-cell">Usuario</th>
                    <th className="py-2.5 px-3 hidden md:table-cell">Categoría</th>
                    <th className="py-2.5 px-3">Vigencia</th>
                    <th className="py-2.5 px-3 text-right hidden sm:table-cell">Entropía</th>
                    <th className="py-2.5 pl-3 pr-6 text-right">Acciones</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1C2330] text-sm">
                  {visibleEntries.map((entry) => {
                    const isSelected = !isCreatingEntry && selectedEntryId === entry.id;
                    const rep = calculateEntropyBits(entry.password);
                    const rot =
                      rotationById.get(entry.id) ??
                      evaluatePasswordRotation(entry, currentSettings.defaultRotationDays);
                    const isCopied =
                      clipboardState.activeEntryId === entry.id &&
                      clipboardState.secondsRemaining > 0;
                    const entropyTextClass =
                      rep.tone === 'amber'
                        ? 'text-amber-400'
                        : rep.tone === 'emerald'
                        ? 'text-emerald-400'
                        : rep.tone === 'danger'
                        ? 'text-red-400'
                        : 'text-[#94A3B8]';

                    return (
                      <tr
                        key={entry.id}
                        onClick={() => {
                          setIsCreatingEntry(false);
                          setSelectedEntryId(entry.id);
                        }}
                        className={`h-12 transition-colors cursor-pointer ${
                          isSelected
                            ? 'bg-[#161B24]'
                            : 'hover:bg-[#0F131A]'
                        }`}
                      >
                        <td className="py-2.5 pl-6 pr-3">
                          <div className="flex items-center gap-2.5 min-w-0">
                            <button
                              type="button"
                              onClick={(e) => void handleToggleFavorite(entry, e)}
                              aria-label="Alternar favorito"
                              className="text-[#475569] hover:text-amber-400 cursor-pointer shrink-0"
                            >
                              <Star
                                className={`h-3.5 w-3.5 ${
                                  entry.favorite ? 'fill-amber-400 text-amber-400' : ''
                                }`}
                              />
                            </button>
                            <span
                              className={`font-medium truncate max-w-[180px] sm:max-w-[220px] ${
                                isSelected ? 'text-amber-300' : 'text-[#F1F5F9]'
                              }`}
                            >
                              {entry.title}
                            </span>
                          </div>
                        </td>
                        <td className="py-2.5 px-3 hidden sm:table-cell font-mono text-xs text-[#94A3B8] max-w-[190px] truncate">
                          {entry.username || '—'}
                        </td>
                        <td className="py-2.5 px-3 hidden md:table-cell text-xs text-[#94A3B8] whitespace-nowrap">
                          {categoryNameMap.get(entry.categoryId) ?? 'General'}
                        </td>
                        <td className="py-2.5 px-3 whitespace-nowrap">
                          <RotationTrafficLight evaluation={rot} compact />
                        </td>
                        <td className="py-2.5 px-3 hidden sm:table-cell text-right font-mono text-xs tabular-nums whitespace-nowrap">
                          <span className={entropyTextClass}>{rep.bits} b</span>
                        </td>
                        <td className="py-2.5 pl-3 pr-6 text-right">
                          <div
                            className="inline-flex items-center justify-end gap-1.5"
                            onClick={(e) => e.stopPropagation()}
                          >
                            {entry.username && (
                              <button
                                type="button"
                                title="Copiar usuario"
                                onClick={() =>
                                  void copySecretWithTimer(
                                    entry.username,
                                    `Usuario de ${entry.title}`,
                                    entry.id
                                  )
                                }
                                className="inline-flex items-center justify-center h-7 w-7 rounded border border-[#242C3A] bg-[#0F131A] text-[#94A3B8] hover:border-[#334054] hover:text-[#F1F5F9] cursor-pointer"
                              >
                                <User className="h-3.5 w-3.5" />
                              </button>
                            )}
                            <button
                              type="button"
                              title="Copiar contraseña con temporizador"
                              onClick={() =>
                                void copySecretWithTimer(
                                  entry.password,
                                  `Contraseña de ${entry.title}`,
                                  entry.id
                                )
                              }
                              className={`inline-flex items-center gap-1 h-7 px-2.5 rounded border text-xs font-medium transition-colors cursor-pointer whitespace-nowrap ${
                                isCopied
                                  ? 'border-emerald-500/50 bg-emerald-500/15 text-emerald-300'
                                  : 'border-[#242C3A] bg-[#161B24] text-[#F1F5F9] hover:border-amber-500/60 hover:text-amber-300'
                              }`}
                            >
                              {isCopied ? (
                                <>
                                  <Check className="h-3 w-3" />
                                  <span className="font-mono tabular-nums">
                                    {clipboardState.secondsRemaining}s
                                  </span>
                                </>
                              ) : (
                                <>
                                  <Copy className="h-3 w-3 text-amber-400" />
                                  <span>Copiar</span>
                                </>
                              )}
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </main>

        {/* Inspector lateral derecho */}
        <EntryInspector
          entry={selectedEntry}
          isCreating={isCreatingEntry}
          categories={session.payload.categories}
          defaultCategoryId={
            selectedFilter !== 'all' &&
            selectedFilter !== 'favorites' &&
            selectedFilter !== 'review'
              ? selectedFilter
              : session.payload.categories[0]?.id ?? 'cat-personal'
          }
          defaultRotationDays={currentSettings.defaultRotationDays}
          noiseLevel={session.payload.settings.ocrNoiseLevel}
          activeCopiedEntryId={clipboardState.activeEntryId}
          clipboardSecondsLeft={clipboardState.secondsRemaining}
          onSave={handleSaveEntry}
          onDelete={handleDeleteEntry}
          onCancelCreate={() => setIsCreatingEntry(false)}
          onCopyField={(val, lbl, id) => {
            void copySecretWithTimer(val, lbl, id);
          }}
          onOpenGeneratorForDraft={(cb) => {
            setGeneratorApplyCallback(() => cb);
            setShowGenerator(true);
          }}
          onStartCreate={() => {
            setIsCreatingEntry(true);
            setSelectedEntryId(null);
          }}
        />
      </div>

      {/* Modales y Cortina de Privacidad */}
      {showGenerator && (
        <PasswordGeneratorModal
          noiseLevel={session.payload.settings.ocrNoiseLevel}
          onClose={() => {
            setShowGenerator(false);
            setGeneratorApplyCallback(null);
          }}
          onCopy={(pw) => {
            void copySecretWithTimer(pw, 'Contraseña generada', 'generator');
          }}
          onApply={generatorApplyCallback ?? undefined}
        />
      )}

      {backupModalTab && (
        <ExportImportModal
          initialTab={backupModalTab}
          payload={session.payload}
          ramKey={session.key}
          ramSaltB64={session.saltB64}
          ramIterations={session.iterations}
          onClose={() => setBackupModalTab(null)}
          onImportCommit={handleImportCommit}
        />
      )}

      {showSettingsModal && (
        <SecuritySettingsModal
          settings={session.payload.settings}
          onClose={() => setShowSettingsModal(false)}
          onSaveSettings={handleSaveSettings}
          onRotateMasterPassword={handleRotateMasterPassword}
        />
      )}
      </div>

      <PrivacyCurtainOverlay
        visible={curtainVisible}
        reason={curtainReason}
        onResume={() => setCurtainVisible(false)}
        onLockNow={() => lockVault()}
      />
    </div>
  );
}
