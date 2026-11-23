import { isValidEnvelope } from '../crypto/engine';
import type {
  EncryptedVaultEnvelope,
  VaultCategory,
  VaultEntry,
  VaultPayload,
} from '../types/vault';

/** Maximum allowed size for an imported .bvault file (10 MiB) to prevent memory exhaustion / DoS. */
export const MAX_BVAULT_FILE_BYTES = 10 * 1024 * 1024;

const MAX_IMPORT_CATEGORIES = 500;
const MAX_IMPORT_ENTRIES = 50_000;
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function sanitizePlainValue(value: unknown, depth = 0): unknown {
  if (depth > 32) {
    throw new Error('Estructura JSON excesivamente anidada.');
  }
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizePlainValue(item, depth + 1));
  }
  const clean: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (DANGEROUS_KEYS.has(k)) continue;
    clean[k] = sanitizePlainValue(v, depth + 1);
  }
  return clean;
}

/**
 * Parses JSON text while stripping __proto__, constructor, and prototype keys
 * to prevent prototype pollution from untrusted .bvault files.
 */
export function parseJsonSafe(rawText: string): unknown {
  const parsed: unknown = JSON.parse(rawText, (key, value) =>
    DANGEROUS_KEYS.has(key) ? undefined : value
  );
  return sanitizePlainValue(parsed);
}

/**
 * Reads a user-selected .bvault file with strict size bounds and validates its cryptographic envelope.
 */
export async function readAndValidateBvaultFile(file: File): Promise<EncryptedVaultEnvelope> {
  if (file.size <= 0) {
    throw new Error('El archivo seleccionado está vacío.');
  }
  if (file.size > MAX_BVAULT_FILE_BYTES) {
    throw new Error('El archivo supera el límite máximo permitido de 10 MiB.');
  }

  const rawText = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(typeof reader.result === 'string' ? reader.result : '');
    reader.onerror = () => reject(new Error('No se pudo leer el archivo seleccionado.'));
    reader.readAsText(file);
  });

  const parsed = parseJsonSafe(rawText);
  if (!isValidEnvelope(parsed)) {
    throw new Error('El archivo no cumple el esquema criptográfico autenticado de Bastión.');
  }

  return parsed;
}

function asSafeString(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback;
}

function asSafeTimestamp(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : fallback;
}

/**
 * Sanitizes decrypted categories and entries into clean plain objects with validated primitive types
 * before merging or replacing state in RAM.
 */
export function sanitizeImportedPayload(
  incoming: VaultPayload,
  fallbackCategories: VaultCategory[]
): { categories: VaultCategory[]; entries: VaultEntry[] } {
  const now = Date.now();
  const rawCategories = Array.isArray(incoming.categories) ? incoming.categories : [];
  const rawEntries = Array.isArray(incoming.entries) ? incoming.entries : [];

  if (rawCategories.length > MAX_IMPORT_CATEGORIES) {
    throw new Error(`El respaldo excede el límite de ${MAX_IMPORT_CATEGORIES} categorías.`);
  }
  if (rawEntries.length > MAX_IMPORT_ENTRIES) {
    throw new Error(`El respaldo excede el límite de ${MAX_IMPORT_ENTRIES} credenciales.`);
  }

  const categories: VaultCategory[] = [];
  const seenCatIds = new Set<string>();
  for (const item of rawCategories) {
    if (!item || typeof item !== 'object') continue;
    const rec = item as unknown as Record<string, unknown>;
    const id = asSafeString(rec.id).trim();
    const name = asSafeString(rec.name).trim();
    if (!id || !name || seenCatIds.has(id)) continue;
    seenCatIds.add(id);
    categories.push({
      id,
      name: name.slice(0, 120),
      isDefault: Boolean(rec.isDefault),
    });
  }

  const safeCategories =
    categories.length > 0
      ? categories
      : fallbackCategories.map((c) => ({ id: c.id, name: c.name, isDefault: Boolean(c.isDefault) }));

  const validCatIds = new Set(safeCategories.map((c) => c.id));
  const defaultCatId = safeCategories[0]?.id ?? 'cat-personal';

  const entries: VaultEntry[] = [];
  const seenEntryIds = new Set<string>();
  for (const item of rawEntries) {
    if (!item || typeof item !== 'object') continue;
    const rec = item as unknown as Record<string, unknown>;
    const id = asSafeString(rec.id).trim();
    const title = asSafeString(rec.title).trim();
    const password = asSafeString(rec.password);
    if (!id || !title || seenEntryIds.has(id)) continue;
    seenEntryIds.add(id);

    const rawCatId = asSafeString(rec.categoryId).trim();
    const categoryId = validCatIds.has(rawCatId) ? rawCatId : defaultCatId;

    entries.push({
      id,
      title: title.slice(0, 200),
      categoryId,
      username: asSafeString(rec.username).slice(0, 320),
      password,
      url: asSafeString(rec.url).slice(0, 2048),
      notes: asSafeString(rec.notes).slice(0, 20_000),
      favorite: Boolean(rec.favorite),
      createdAt: asSafeTimestamp(rec.createdAt, now),
      updatedAt: asSafeTimestamp(rec.updatedAt, now),
    });
  }

  return { categories: safeCategories, entries };
}
