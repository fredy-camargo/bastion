import { sanitizeEnvelope } from '../crypto/engine';
import type { EncryptedVaultEnvelope, UnlockLockoutStatus } from '../types/vault';

const DB_NAME = 'bastion_encrypted_vault_db';
const DB_VERSION = 2;
const STORE_NAME = 'envelopes';
const META_STORE_NAME = 'security_meta';
const PRIMARY_KEY = 'primary_vault';
const LOCKOUT_KEY = 'unlock_guard_v1';

const FREE_UNLOCK_ATTEMPTS = 3;
const BASE_LOCKOUT_MS = 5_000;
const MAX_LOCKOUT_MS = 15 * 60_000;
const MAX_CLOCK_SKEW_MS = 60_000;
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

interface PersistedLockoutRecord {
  failedAttempts: number;
  lastFailedAt: number;
  lockedUntil: number | null;
}

let memoryLockoutState: PersistedLockoutRecord = {
  failedAttempts: 0,
  lastFailedAt: 0,
  lockedUntil: null,
};

function hasIndexedDb(): boolean {
  return typeof indexedDB !== 'undefined' && indexedDB !== null;
}

function isSafeRecord(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    return false;
  }
  for (const key of Object.getOwnPropertyNames(value)) {
    if (DANGEROUS_KEYS.has(key)) {
      return false;
    }
  }
  return true;
}

function openVaultDb(): Promise<IDBDatabase> {
  if (!hasIndexedDb()) {
    return Promise.reject(new Error('IndexedDB no está disponible en este entorno.'));
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    const finishReject = (err: Error) => {
      if (settled) return;
      settled = true;
      reject(err);
    };

    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
      if (!db.objectStoreNames.contains(META_STORE_NAME)) {
        db.createObjectStore(META_STORE_NAME);
      }
      if (request.transaction) {
        request.transaction.onabort = () => {
          finishReject(
            request.transaction?.error ?? new Error('Actualización de esquema IndexedDB abortada.')
          );
        };
      }
    };

    request.onblocked = () => {
      finishReject(
        new Error('La base de datos IndexedDB está bloqueada por otra pestaña o sesión activa.')
      );
    };

    request.onsuccess = () => {
      if (settled) {
        request.result.close();
        return;
      }
      settled = true;
      resolve(request.result);
    };

    request.onerror = () => {
      finishReject(request.error ?? new Error('No se pudo abrir IndexedDB local.'));
    };
  });
}

async function withStore<T>(
  storeName: string,
  mode: IDBTransactionMode,
  execute: (
    store: IDBObjectStore,
    tx: IDBTransaction,
    db: IDBDatabase,
    resolve: (val: T) => void,
    reject: (err: Error) => void
  ) => void
): Promise<T> {
  const db = await openVaultDb();
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const safeResolve = (value: T) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const safeReject = (err: unknown) => {
      if (settled) return;
      settled = true;
      try {
        db.close();
      } catch {
        // Ignore close errors during failure cleanup
      }
      reject(err instanceof Error ? err : new Error(String(err)));
    };

    try {
      const tx = db.transaction(storeName, mode);
      const store = tx.objectStore(storeName);

      tx.onabort = () => {
        safeReject(tx.error ?? new Error('Transacción IndexedDB abortada.'));
      };
      tx.onerror = () => {
        safeReject(tx.error ?? new Error('Error en la transacción de IndexedDB.'));
      };

      execute(store, tx, db, safeResolve, safeReject);
    } catch (err) {
      safeReject(err);
    }
  });
}

export async function loadStoredEnvelope(): Promise<EncryptedVaultEnvelope | null> {
  return withStore<EncryptedVaultEnvelope | null>(
    STORE_NAME,
    'readonly',
    (store, tx, db, resolve, reject) => {
      let resultValue: EncryptedVaultEnvelope | null = null;
      const req = store.get(PRIMARY_KEY);

      req.onsuccess = () => {
        if (req.result === undefined || req.result === null) {
          resultValue = null;
          return;
        }
        try {
          resultValue = sanitizeEnvelope(req.result);
        } catch {
          reject(
            new Error(
              'El sobre cifrado almacenado en IndexedDB está corrupto o no cumple el esquema de Bastión.'
            )
          );
        }
      };

      req.onerror = () => {
        reject(req.error ?? new Error('Error al leer la bóveda cifrada local.'));
      };

      tx.oncomplete = () => {
        db.close();
        resolve(resultValue);
      };
    }
  );
}

export async function saveStoredEnvelope(envelope: EncryptedVaultEnvelope): Promise<void> {
  const cleanEnvelope = sanitizeEnvelope(envelope);

  return withStore<void>(STORE_NAME, 'readwrite', (store, tx, db, resolve, reject) => {
    const req = store.put(cleanEnvelope, PRIMARY_KEY);
    req.onerror = () => {
      reject(req.error ?? new Error('Error al persistir el bloque cifrado en IndexedDB.'));
    };
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
  });
}

export async function deleteStoredEnvelope(): Promise<void> {
  await withStore<void>(STORE_NAME, 'readwrite', (store, tx, db, resolve, reject) => {
    const req = store.delete(PRIMARY_KEY);
    req.onerror = () => {
      reject(req.error ?? new Error('Error al eliminar la bóveda local.'));
    };
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
  });

  await clearUnlockLockout().catch(() => {
    memoryLockoutState = { failedAttempts: 0, lastFailedAt: 0, lockedUntil: null };
  });
}

export function computeLockoutDurationMs(failedAttempts: number): number {
  if (!Number.isSafeInteger(failedAttempts) || failedAttempts <= FREE_UNLOCK_ATTEMPTS) {
    return 0;
  }
  const exponent = failedAttempts - FREE_UNLOCK_ATTEMPTS - 1;
  return Math.min(MAX_LOCKOUT_MS, BASE_LOCKOUT_MS * 2 ** Math.min(exponent, 20));
}

function buildLockoutStatus(record: PersistedLockoutRecord, now: number): UnlockLockoutStatus {
  const remainingMs =
    record.lockedUntil !== null && record.lockedUntil > now ? record.lockedUntil - now : 0;
  return {
    failedAttempts: record.failedAttempts,
    lockedUntil: remainingMs > 0 ? record.lockedUntil : null,
    remainingMs,
    isLocked: remainingMs > 0,
  };
}

function validateLockoutRecord(raw: unknown, now: number): PersistedLockoutRecord | null {
  if (!isSafeRecord(raw)) return null;
  if (
    typeof raw.failedAttempts !== 'number' ||
    !Number.isSafeInteger(raw.failedAttempts) ||
    raw.failedAttempts < 0 ||
    raw.failedAttempts > 10_000
  ) {
    return null;
  }
  if (
    typeof raw.lastFailedAt !== 'number' ||
    !Number.isFinite(raw.lastFailedAt) ||
    raw.lastFailedAt < 0 ||
    raw.lastFailedAt > now + MAX_CLOCK_SKEW_MS
  ) {
    return null;
  }
  if (
    raw.lockedUntil !== null &&
    (typeof raw.lockedUntil !== 'number' ||
      !Number.isFinite(raw.lockedUntil) ||
      raw.lockedUntil < raw.lastFailedAt ||
      raw.lockedUntil - raw.lastFailedAt > MAX_LOCKOUT_MS)
  ) {
    return null;
  }

  return {
    failedAttempts: raw.failedAttempts,
    lastFailedAt: raw.lastFailedAt,
    lockedUntil: raw.lockedUntil,
  };
}

async function readLockoutRecord(now: number): Promise<PersistedLockoutRecord> {
  if (!hasIndexedDb()) {
    return memoryLockoutState;
  }

  try {
    return await withStore<PersistedLockoutRecord>(
      META_STORE_NAME,
      'readonly',
      (store, tx, db, resolve, reject) => {
        let record: PersistedLockoutRecord = memoryLockoutState;
        const req = store.get(LOCKOUT_KEY);
        req.onsuccess = () => {
          if (req.result === undefined || req.result === null) {
            record = memoryLockoutState;
            return;
          }
          const validated = validateLockoutRecord(req.result, now);
          if (!validated) {
            // Fail-closed ante corrupción o manipulación del registro de bloqueo
            const fallbackAttempts = Math.max(
              memoryLockoutState.failedAttempts,
              FREE_UNLOCK_ATTEMPTS + 1
            );
            record = {
              failedAttempts: fallbackAttempts,
              lastFailedAt: now,
              lockedUntil: now + computeLockoutDurationMs(fallbackAttempts),
            };
            return;
          }
          record =
            validated.failedAttempts >= memoryLockoutState.failedAttempts
              ? validated
              : memoryLockoutState;
        };
        req.onerror = () => {
          reject(req.error ?? new Error('Error al leer estado de bloqueo.'));
        };
        tx.oncomplete = () => {
          db.close();
          memoryLockoutState = record;
          resolve(record);
        };
      }
    );
  } catch {
    return memoryLockoutState;
  }
}

async function writeLockoutRecord(record: PersistedLockoutRecord): Promise<void> {
  memoryLockoutState = record;
  if (!hasIndexedDb()) return;

  try {
    await withStore<void>(META_STORE_NAME, 'readwrite', (store, tx, db, resolve, reject) => {
      const req = store.put(record, LOCKOUT_KEY);
      req.onerror = () => {
        reject(req.error ?? new Error('Error al guardar estado de bloqueo.'));
      };
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
    });
  } catch {
    // Mantiene el espejo en RAM si IndexedDB falla temporalmente
  }
}

export async function getUnlockLockoutStatus(now: number = Date.now()): Promise<UnlockLockoutStatus> {
  const record = await readLockoutRecord(now);
  return buildLockoutStatus(record, now);
}

export async function recordUnlockFailure(now: number = Date.now()): Promise<UnlockLockoutStatus> {
  const current = await readLockoutRecord(now);
  const nextAttempts = current.failedAttempts + 1;
  const durationMs = computeLockoutDurationMs(nextAttempts);
  const nextRecord: PersistedLockoutRecord = {
    failedAttempts: nextAttempts,
    lastFailedAt: now,
    lockedUntil: durationMs > 0 ? now + durationMs : null,
  };
  await writeLockoutRecord(nextRecord);
  return buildLockoutStatus(nextRecord, now);
}

export async function clearUnlockLockout(): Promise<void> {
  memoryLockoutState = { failedAttempts: 0, lastFailedAt: 0, lockedUntil: null };
  if (!hasIndexedDb()) return;

  await withStore<void>(META_STORE_NAME, 'readwrite', (store, tx, db, resolve, reject) => {
    const req = store.delete(LOCKOUT_KEY);
    req.onerror = () => {
      reject(req.error ?? new Error('Error al limpiar estado de bloqueo.'));
    };
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
  });
}
