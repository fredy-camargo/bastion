import {
  ALLOWED_ROTATION_INTERVAL_DAYS,
  DEFAULT_SECURITY_SETTINGS,
  VAULT_LIMITS,
  type EncryptedVaultEnvelope,
  type EntropyReport,
  type PasswordGenOptions,
  type RotationIntervalDays,
  type SecuritySettings,
  type VaultCategory,
  type VaultEntry,
  type VaultPayload,
} from '../types/vault';

export const KDF_ITERATIONS = 600_000;
export const MIN_KDF_ITERATIONS = VAULT_LIMITS.MIN_KDF_ITERATIONS;
export const MAX_KDF_ITERATIONS = VAULT_LIMITS.MAX_KDF_ITERATIONS;
export const MAX_ENVELOPE_BYTES = VAULT_LIMITS.MAX_ENVELOPE_BYTES;

const HKDF_INFO = 'BASTION-VAULT-AES256GCM-KEY-V1';
const DANGEROUS_OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const CANONICAL_BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const MAX_B64_CIPHERTEXT_CHARS = Math.ceil(VAULT_LIMITS.MAX_ENVELOPE_BYTES / 3) * 4 + 64;
const ALLOWED_CLIPBOARD_TIMEOUTS = new Set<number>([15, 30, 60]);
const ALLOWED_AUTOLOCK_MINUTES = new Set<number>([1, 3, 5, 15]);
const ALLOWED_ROTATION_DAYS_SET = new Set<number>(ALLOWED_ROTATION_INTERVAL_DAYS);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    return false;
  }
  const ownKeys = Object.getOwnPropertyNames(value);
  for (const key of ownKeys) {
    if (DANGEROUS_OBJECT_KEYS.has(key)) {
      return false;
    }
  }
  return true;
}

function safeJsonReviver(key: string, value: unknown): unknown {
  if (DANGEROUS_OBJECT_KEYS.has(key)) {
    throw new Error('Contenido JSON rechazado por clave de prototipo prohibida.');
  }
  return value;
}

function parseSafeJson(rawText: string, maxChars: number = MAX_ENVELOPE_BYTES): unknown {
  if (typeof rawText !== 'string' || rawText.length === 0 || rawText.length > maxChars) {
    throw new Error('El documento JSON está vacío o supera el tamaño máximo permitido.');
  }
  return JSON.parse(rawText, safeJsonReviver);
}

function getValidBase64ByteLength(b64: unknown, maxChars: number): number | null {
  if (
    typeof b64 !== 'string' ||
    b64.length === 0 ||
    b64.length > maxChars ||
    b64.length % 4 !== 0 ||
    !CANONICAL_BASE64_RE.test(b64)
  ) {
    return null;
  }
  let padding = 0;
  if (b64.endsWith('==')) padding = 2;
  else if (b64.endsWith('=')) padding = 1;
  return (b64.length / 4) * 3 - padding;
}

function isValidKdfIterations(iterations: unknown): iterations is number {
  return (
    typeof iterations === 'number' &&
    Number.isSafeInteger(iterations) &&
    iterations >= MIN_KDF_ITERATIONS &&
    iterations <= MAX_KDF_ITERATIONS
  );
}

function isValidScope(scope: unknown): scope is EncryptedVaultEnvelope['scope'] {
  return scope === 'local-vault' || scope === 'export-full' || scope === 'export-category';
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

function base64ToBytes(b64: string, maxChars: number = MAX_B64_CIPHERTEXT_CHARS): Uint8Array {
  if (getValidBase64ByteLength(b64, maxChars) === null) {
    throw new Error('Cadena Base64 inválida o fuera de límites.');
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function assertNoAadDelimiter(value: string, fieldName: string): void {
  if (value.includes('|') || /[\r\n\0]/.test(value)) {
    throw new Error(`Metadato AAD inválido en ${fieldName}.`);
  }
}

function buildAadBytes(params: {
  format: string;
  version: number;
  cipher: string;
  kdf: string;
  iterations: number;
  salt: string;
  scope: string;
}): Uint8Array {
  assertNoAadDelimiter(params.format, 'format');
  assertNoAadDelimiter(params.cipher, 'cipher');
  assertNoAadDelimiter(params.kdf, 'kdf');
  assertNoAadDelimiter(params.salt, 'salt');
  assertNoAadDelimiter(params.scope, 'scope');
  const encoder = new TextEncoder();
  return encoder.encode(
    `${params.format}|v${params.version}|${params.cipher}|${params.kdf}|${params.iterations}|${params.salt}|${params.scope}`
  );
}

function assertBoundedString(value: unknown, maxLen: number, fieldName: string, allowEmpty = true): string {
  if (typeof value !== 'string') {
    throw new Error(`Campo "${fieldName}" inválido: se esperaba texto.`);
  }
  if (!allowEmpty && value.length === 0) {
    throw new Error(`Campo "${fieldName}" no puede estar vacío.`);
  }
  if (value.length > maxLen) {
    throw new Error(`Campo "${fieldName}" supera la longitud máxima permitida.`);
  }
  return value;
}

function sanitizeCategory(raw: unknown): VaultCategory {
  if (!isPlainObject(raw)) {
    throw new Error('Categoría corrupta en la bóveda.');
  }
  const id = assertBoundedString(raw.id, VAULT_LIMITS.MAX_ID_LENGTH, 'category.id', false);
  const name = assertBoundedString(raw.name, VAULT_LIMITS.MAX_TITLE_LENGTH, 'category.name', true);
  if (raw.isDefault !== undefined && typeof raw.isDefault !== 'boolean') {
    throw new Error('Campo "category.isDefault" inválido.');
  }
  const category: VaultCategory = { id, name };
  if (raw.isDefault !== undefined) {
    category.isDefault = raw.isDefault;
  }
  return category;
}

function sanitizeEntry(raw: unknown): VaultEntry {
  if (!isPlainObject(raw)) {
    throw new Error('Registro de credencial corrupto en la bóveda.');
  }
  const id = assertBoundedString(raw.id, VAULT_LIMITS.MAX_ID_LENGTH, 'entry.id', false);
  const title = assertBoundedString(raw.title, VAULT_LIMITS.MAX_TITLE_LENGTH, 'entry.title', true);
  const categoryId = assertBoundedString(raw.categoryId, VAULT_LIMITS.MAX_ID_LENGTH, 'entry.categoryId', false);
  const username = assertBoundedString(raw.username, VAULT_LIMITS.MAX_USERNAME_LENGTH, 'entry.username', true);
  const password = assertBoundedString(raw.password, VAULT_LIMITS.MAX_PASSWORD_LENGTH, 'entry.password', true);
  const url = assertBoundedString(raw.url, VAULT_LIMITS.MAX_URL_LENGTH, 'entry.url', true);
  const notes = assertBoundedString(raw.notes, VAULT_LIMITS.MAX_NOTES_LENGTH, 'entry.notes', true);

  if (typeof raw.favorite !== 'boolean') {
    throw new Error('Campo "entry.favorite" inválido.');
  }
  if (typeof raw.createdAt !== 'number' || !Number.isFinite(raw.createdAt) || raw.createdAt < 0) {
    throw new Error('Campo "entry.createdAt" inválido.');
  }
  if (typeof raw.updatedAt !== 'number' || !Number.isFinite(raw.updatedAt) || raw.updatedAt < 0) {
    throw new Error('Campo "entry.updatedAt" inválido.');
  }
  if (
    raw.passwordUpdatedAt !== undefined &&
    (typeof raw.passwordUpdatedAt !== 'number' ||
      !Number.isFinite(raw.passwordUpdatedAt) ||
      raw.passwordUpdatedAt < 0)
  ) {
    throw new Error('Campo "entry.passwordUpdatedAt" inválido.');
  }
  if (
    raw.rotationIntervalDays !== undefined &&
    (typeof raw.rotationIntervalDays !== 'number' ||
      !ALLOWED_ROTATION_DAYS_SET.has(raw.rotationIntervalDays))
  ) {
    throw new Error('Campo "entry.rotationIntervalDays" inválido.');
  }

  const entry: VaultEntry = {
    id,
    title,
    categoryId,
    username,
    password,
    url,
    notes,
    favorite: raw.favorite,
    createdAt: raw.createdAt,
    updatedAt: raw.updatedAt,
  };
  if (raw.passwordUpdatedAt !== undefined) {
    entry.passwordUpdatedAt = raw.passwordUpdatedAt;
  }
  if (raw.rotationIntervalDays !== undefined) {
    entry.rotationIntervalDays = raw.rotationIntervalDays as RotationIntervalDays;
  }
  return entry;
}

function sanitizeSecuritySettings(raw: unknown): SecuritySettings {
  if (raw === undefined) {
    return { ...DEFAULT_SECURITY_SETTINGS };
  }
  if (!isPlainObject(raw)) {
    throw new Error('Configuración de seguridad corrupta en la bóveda.');
  }

  const clipboardTimeoutSec =
    raw.clipboardTimeoutSec === undefined
      ? DEFAULT_SECURITY_SETTINGS.clipboardTimeoutSec
      : raw.clipboardTimeoutSec;
  if (typeof clipboardTimeoutSec !== 'number' || !ALLOWED_CLIPBOARD_TIMEOUTS.has(clipboardTimeoutSec)) {
    throw new Error('Valor inválido para clipboardTimeoutSec.');
  }

  const autoLockMinutes =
    raw.autoLockMinutes === undefined
      ? DEFAULT_SECURITY_SETTINGS.autoLockMinutes
      : raw.autoLockMinutes;
  if (typeof autoLockMinutes !== 'number' || !ALLOWED_AUTOLOCK_MINUTES.has(autoLockMinutes)) {
    throw new Error('Valor inválido para autoLockMinutes.');
  }

  const lockOnBlur =
    raw.lockOnBlur === undefined ? DEFAULT_SECURITY_SETTINGS.lockOnBlur : raw.lockOnBlur;
  if (typeof lockOnBlur !== 'boolean') {
    throw new Error('Valor inválido para lockOnBlur.');
  }

  const ocrNoiseLevel =
    raw.ocrNoiseLevel === undefined ? DEFAULT_SECURITY_SETTINGS.ocrNoiseLevel : raw.ocrNoiseLevel;
  if (ocrNoiseLevel !== 'standard' && ocrNoiseLevel !== 'high') {
    throw new Error('Valor inválido para ocrNoiseLevel.');
  }

  const ephemeralMode =
    raw.ephemeralMode === undefined ? DEFAULT_SECURITY_SETTINGS.ephemeralMode : raw.ephemeralMode;
  if (typeof ephemeralMode !== 'boolean') {
    throw new Error('Valor inválido para ephemeralMode.');
  }

  const defaultRotationDays =
    raw.defaultRotationDays === undefined
      ? DEFAULT_SECURITY_SETTINGS.defaultRotationDays
      : raw.defaultRotationDays;
  if (
    typeof defaultRotationDays !== 'number' ||
    !ALLOWED_ROTATION_DAYS_SET.has(defaultRotationDays)
  ) {
    throw new Error('Valor inválido para defaultRotationDays.');
  }

  return {
    clipboardTimeoutSec: clipboardTimeoutSec as SecuritySettings['clipboardTimeoutSec'],
    autoLockMinutes: autoLockMinutes as SecuritySettings['autoLockMinutes'],
    lockOnBlur,
    ocrNoiseLevel,
    ephemeralMode,
    defaultRotationDays: defaultRotationDays as RotationIntervalDays,
  };
}

function validateAndSanitizePayload(raw: unknown): VaultPayload {
  if (!isPlainObject(raw)) {
    throw new Error('Integridad estructural inválida dentro de la bóveda.');
  }
  if (!Array.isArray(raw.categories) || !Array.isArray(raw.entries)) {
    throw new Error('Integridad estructural inválida dentro de la bóveda.');
  }
  if (raw.categories.length > VAULT_LIMITS.MAX_CATEGORIES) {
    throw new Error('La bóveda excede el límite máximo de categorías permitido.');
  }
  if (raw.entries.length > VAULT_LIMITS.MAX_ENTRIES) {
    throw new Error('La bóveda excede el límite máximo de credenciales permitido.');
  }

  const version = raw.version === undefined ? 1 : raw.version;
  if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 1 || version > 100) {
    throw new Error('Versión de esquema de bóveda inválida.');
  }

  const updatedAt = raw.updatedAt === undefined ? Date.now() : raw.updatedAt;
  if (typeof updatedAt !== 'number' || !Number.isFinite(updatedAt) || updatedAt < 0) {
    throw new Error('Marca temporal de bóveda inválida.');
  }

  return {
    version,
    categories: raw.categories.map(sanitizeCategory),
    entries: raw.entries.map(sanitizeEntry),
    settings: sanitizeSecuritySettings(raw.settings),
    updatedAt,
  };
}

function parseValidatedEnvelope(raw: unknown): EncryptedVaultEnvelope | null {
  if (!isPlainObject(raw)) return null;
  if (
    raw.format !== 'BASTION_VAULT' ||
    raw.version !== 1 ||
    raw.cipher !== 'AES-256-GCM' ||
    raw.kdf !== 'PBKDF2-HMAC-SHA512+HKDF-SHA512' ||
    !isValidKdfIterations(raw.iterations) ||
    !isValidScope(raw.scope) ||
    typeof raw.updatedAt !== 'number' ||
    !Number.isFinite(raw.updatedAt) ||
    raw.updatedAt < 0
  ) {
    return null;
  }

  const saltBytesLen = getValidBase64ByteLength(raw.salt, 64);
  if (saltBytesLen !== VAULT_LIMITS.SALT_BYTES) return null;

  const ivBytesLen = getValidBase64ByteLength(raw.iv, 32);
  if (ivBytesLen !== VAULT_LIMITS.IV_BYTES) return null;

  const cipherBytesLen = getValidBase64ByteLength(raw.ciphertext, MAX_B64_CIPHERTEXT_CHARS);
  if (
    cipherBytesLen === null ||
    cipherBytesLen < VAULT_LIMITS.GCM_TAG_BYTES ||
    cipherBytesLen > VAULT_LIMITS.MAX_ENVELOPE_BYTES
  ) {
    return null;
  }

  return {
    format: 'BASTION_VAULT',
    version: 1,
    cipher: 'AES-256-GCM',
    kdf: 'PBKDF2-HMAC-SHA512+HKDF-SHA512',
    iterations: raw.iterations,
    salt: raw.salt as string,
    iv: raw.iv as string,
    scope: raw.scope,
    updatedAt: raw.updatedAt,
    ciphertext: raw.ciphertext as string,
  };
}

export function sanitizeEnvelope(raw: unknown): EncryptedVaultEnvelope {
  const envelope = parseValidatedEnvelope(raw);
  if (!envelope) {
    throw new Error('El archivo o sobre cifrado no corresponde al formato auténtico de Bastión.');
  }
  return envelope;
}

export function parseEnvelopeJson(rawText: string): EncryptedVaultEnvelope {
  const parsed = parseSafeJson(rawText, VAULT_LIMITS.MAX_ENVELOPE_BYTES);
  return sanitizeEnvelope(parsed);
}

export function generateSaltBytes(): Uint8Array {
  const salt = new Uint8Array(VAULT_LIMITS.SALT_BYTES); // 256-bit salt
  crypto.getRandomValues(salt);
  return salt;
}

export function generateIvBytes(): Uint8Array {
  const iv = new Uint8Array(VAULT_LIMITS.IV_BYTES); // 96-bit GCM nonce
  crypto.getRandomValues(iv);
  return iv;
}

export function encodeBase64(bytes: Uint8Array): string {
  return bytesToBase64(bytes);
}

/**
 * Deriva una CryptoKey AES-256-GCM NO EXTRAÍBLE (extractable: false) alojada únicamente en RAM.
 * Pipeline: PBKDF2-HMAC-SHA512 (600,000 iteraciones) -> HKDF-SHA512 -> AES-256-GCM.
 */
export async function deriveMasterKey(
  masterPassword: string,
  saltBytes: Uint8Array,
  iterations: number = KDF_ITERATIONS
): Promise<CryptoKey> {
  if (typeof masterPassword !== 'string' || masterPassword.length === 0) {
    throw new Error('La clave maestra debe ser una cadena no vacía.');
  }
  if (!(saltBytes instanceof Uint8Array) || saltBytes.length < 16 || saltBytes.length > 64) {
    throw new Error('La sal criptográfica es inválida (longitud mínima requerida: 16 bytes).');
  }
  if (!isValidKdfIterations(iterations)) {
    throw new Error(
      `Número de iteraciones KDF fuera de rango seguro (${MIN_KDF_ITERATIONS}-${MAX_KDF_ITERATIONS}).`
    );
  }

  const encoder = new TextEncoder();
  const passwordBytes = encoder.encode(masterPassword);
  const infoBytes = encoder.encode(HKDF_INFO);
  let intermediateBits: Uint8Array | null = null;

  try {
    const baseKey = await crypto.subtle.importKey(
      'raw',
      passwordBytes as unknown as BufferSource,
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const pbkdf2Buffer = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        hash: 'SHA-512',
        salt: saltBytes as unknown as BufferSource,
        iterations,
      },
      baseKey,
      256
    );

    intermediateBits = new Uint8Array(pbkdf2Buffer);

    const hkdfKey = await crypto.subtle.importKey(
      'raw',
      intermediateBits as unknown as BufferSource,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );

    const aesKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-512',
        salt: saltBytes as unknown as BufferSource,
        info: infoBytes as unknown as BufferSource,
      },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false, // extractable = false: la clave no puede exportarse desde WebCrypto RAM
      ['encrypt', 'decrypt']
    );

    return aesKey;
  } finally {
    // Limpieza inmediata de buffers intermedios en memoria
    passwordBytes.fill(0);
    infoBytes.fill(0);
    if (intermediateBits) {
      intermediateBits.fill(0);
    }
  }
}

export async function encryptVaultWithKey(
  payload: VaultPayload,
  key: CryptoKey,
  saltB64: string,
  iterations: number = KDF_ITERATIONS,
  scope: EncryptedVaultEnvelope['scope'] = 'local-vault'
): Promise<EncryptedVaultEnvelope> {
  if (
    !key ||
    key.type !== 'secret' ||
    key.extractable !== false ||
    key.algorithm?.name !== 'AES-GCM'
  ) {
    throw new Error('La CryptoKey de cifrado debe ser AES-GCM no extraíble.');
  }
  if (!isValidKdfIterations(iterations)) {
    throw new Error('Número de iteraciones KDF inválido.');
  }
  if (getValidBase64ByteLength(saltB64, 64) !== VAULT_LIMITS.SALT_BYTES) {
    throw new Error('Sal Base64 inválida: se requieren 32 bytes (256 bits).');
  }
  if (!isValidScope(scope)) {
    throw new Error('Ámbito de cifrado inválido.');
  }

  const sanitizedPayload = validateAndSanitizePayload(payload);
  const ivBytes = generateIvBytes();
  const encoder = new TextEncoder();

  const header = {
    format: 'BASTION_VAULT' as const,
    version: 1 as const,
    cipher: 'AES-256-GCM' as const,
    kdf: 'PBKDF2-HMAC-SHA512+HKDF-SHA512' as const,
    iterations,
    salt: saltB64,
    scope,
  };

  let plaintextBytes: Uint8Array | null = null;
  let aadBytes: Uint8Array | null = null;

  try {
    plaintextBytes = encoder.encode(JSON.stringify(sanitizedPayload));
    aadBytes = buildAadBytes(header);

    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: ivBytes as unknown as BufferSource,
        additionalData: aadBytes as unknown as BufferSource,
        tagLength: 128,
      },
      key,
      plaintextBytes as unknown as BufferSource
    );

    return {
      ...header,
      iv: bytesToBase64(ivBytes),
      updatedAt: Date.now(),
      ciphertext: bytesToBase64(new Uint8Array(encryptedBuffer)),
    };
  } finally {
    if (plaintextBytes) {
      plaintextBytes.fill(0);
    }
    if (aadBytes) {
      aadBytes.fill(0);
    }
  }
}

export function isValidEnvelope(raw: unknown): raw is EncryptedVaultEnvelope {
  return parseValidatedEnvelope(raw) !== null;
}

export async function decryptVaultEnvelope(
  envelope: EncryptedVaultEnvelope,
  masterPassword: string
): Promise<{ key: CryptoKey; payload: VaultPayload }> {
  if (typeof masterPassword !== 'string' || masterPassword.length === 0) {
    throw new Error('Introduce una clave maestra válida.');
  }

  const cleanEnvelope = sanitizeEnvelope(envelope);
  const saltBytes = base64ToBytes(cleanEnvelope.salt, 64);
  const ivBytes = base64ToBytes(cleanEnvelope.iv, 32);
  const cipherBytes = base64ToBytes(cleanEnvelope.ciphertext, MAX_B64_CIPHERTEXT_CHARS);

  if (
    saltBytes.length !== VAULT_LIMITS.SALT_BYTES ||
    ivBytes.length !== VAULT_LIMITS.IV_BYTES ||
    cipherBytes.length < VAULT_LIMITS.GCM_TAG_BYTES
  ) {
    throw new Error('Longitud de parámetros criptográficos inválida en el sobre cifrado.');
  }

  const aadBytes = buildAadBytes(cleanEnvelope);
  const key = await deriveMasterKey(masterPassword, saltBytes, cleanEnvelope.iterations);

  let decryptedBytes: Uint8Array | null = null;
  try {
    const plainBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ivBytes as unknown as BufferSource,
        additionalData: aadBytes as unknown as BufferSource,
        tagLength: 128,
      },
      key,
      cipherBytes as unknown as BufferSource
    );

    decryptedBytes = new Uint8Array(plainBuffer);
    const jsonString = new TextDecoder('utf-8', { fatal: true }).decode(decryptedBytes);
    const parsed = parseSafeJson(jsonString, VAULT_LIMITS.MAX_ENVELOPE_BYTES);
    const validatedPayload = validateAndSanitizePayload(parsed);

    return { key, payload: validatedPayload };
  } catch (err) {
    if (err instanceof DOMException && err.name === 'OperationError') {
      throw new Error(
        'Clave maestra incorrecta o integridad criptográfica alterada (fallo de verificación AES-GCM).'
      );
    }
    throw err;
  } finally {
    aadBytes.fill(0);
    if (decryptedBytes) {
      decryptedBytes.fill(0);
    }
  }
}

export async function createStandaloneEncryptedExport(
  payload: VaultPayload,
  passphrase: string,
  scope: 'export-full' | 'export-category'
): Promise<EncryptedVaultEnvelope> {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new Error('La clave de respaldo no puede estar vacía.');
  }
  if (scope !== 'export-full' && scope !== 'export-category') {
    throw new Error('Ámbito de exportación inválido.');
  }
  const saltBytes = generateSaltBytes();
  const saltB64 = bytesToBase64(saltBytes);
  const exportKey = await deriveMasterKey(passphrase, saltBytes, KDF_ITERATIONS);
  return encryptVaultWithKey(payload, exportKey, saltB64, KDF_ITERATIONS, scope);
}

/**
 * Generador criptográfico CSPRNG sin sesgo de módulo (rejection sampling).
 */
function secureRandomInt(maxExclusive: number): number {
  if (!Number.isSafeInteger(maxExclusive) || maxExclusive <= 0 || maxExclusive > 0x100000000) {
    throw new RangeError('maxExclusive debe ser un entero positivo dentro de 32 bits.');
  }
  const maxUnbiased = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
  const buf = new Uint32Array(1);
  try {
    let val = 0;
    do {
      crypto.getRandomValues(buf);
      val = buf[0];
    } while (val >= maxUnbiased);
    return val % maxExclusive;
  } finally {
    buf.fill(0);
  }
}

export function generateSecurePassword(options: PasswordGenOptions): string {
  if (
    !options ||
    typeof options.length !== 'number' ||
    !Number.isSafeInteger(options.length) ||
    options.length < 1 ||
    options.length > VAULT_LIMITS.MAX_GENERATED_PASSWORD_LENGTH
  ) {
    throw new RangeError(
      `La longitud de contraseña debe estar entre 1 y ${VAULT_LIMITS.MAX_GENERATED_PASSWORD_LENGTH}.`
    );
  }

  const sets: string[] = [];
  const ambig = /[0O1lI|`'"]/g;

  const clean = (chars: string) => (options.excludeAmbiguous ? chars.replace(ambig, '') : chars);

  if (options.uppercase) sets.push(clean('ABCDEFGHIJKLMNOPQRSTUVWXYZ'));
  if (options.lowercase) sets.push(clean('abcdefghijklmnopqrstuvwxyz'));
  if (options.numbers) sets.push(clean('0123456789'));
  if (options.symbols) sets.push(clean('!@#$%^&*()-_=+[]{};:,.<>?/~'));

  if (sets.length === 0) {
    sets.push(clean('abcdefghijklmnopqrstuvwxyz0123456789'));
  }

  const allChars = sets.join('');
  if (allChars.length === 0) {
    throw new Error('El conjunto de caracteres resultante está vacío.');
  }

  const result: string[] = [];
  try {
    // Garantiza al menos un carácter de cada conjunto activo
    for (const set of sets) {
      if (result.length < options.length && set.length > 0) {
        result.push(set[secureRandomInt(set.length)]);
      }
    }

    while (result.length < options.length) {
      result.push(allChars[secureRandomInt(allChars.length)]);
    }

    // Mezcla criptográfica Fisher-Yates
    for (let i = result.length - 1; i > 0; i--) {
      const j = secureRandomInt(i + 1);
      const tmp = result[i];
      result[i] = result[j];
      result[j] = tmp;
    }

    return result.join('');
  } finally {
    result.fill('');
  }
}

export function calculateEntropyBits(password: string): EntropyReport {
  if (!password) {
    return { bits: 0, label: 'Crítica', tone: 'danger' };
  }

  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += 33;

  const uniqueRatio = new Set(password).size / password.length;
  const rawBits = password.length * Math.log2(Math.max(pool, 1));
  const adjustedBits = Math.round(rawBits * (0.65 + 0.35 * uniqueRatio));

  if (adjustedBits < 40) {
    return { bits: adjustedBits, label: 'Crítica', tone: 'danger' };
  }
  if (adjustedBits < 60) {
    return { bits: adjustedBits, label: 'Débil', tone: 'warning' };
  }
  if (adjustedBits < 80) {
    return { bits: adjustedBits, label: 'Aceptable', tone: 'neutral' };
  }
  if (adjustedBits < 110) {
    return { bits: adjustedBits, label: 'Fuerte', tone: 'emerald' };
  }
  return { bits: adjustedBits, label: 'Grado militar', tone: 'amber' };
}

export function generateUuid(): string {
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  try {
    crypto.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  } finally {
    bytes.fill(0);
  }
}
