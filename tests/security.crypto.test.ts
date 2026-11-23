import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  KDF_ITERATIONS,
  MIN_KDF_ITERATIONS,
  MAX_KDF_ITERATIONS,
  createStandaloneEncryptedExport,
  decryptVaultEnvelope,
  deriveMasterKey,
  encodeBase64,
  encryptVaultWithKey,
  generateIvBytes,
  generateSaltBytes,
  generateSecurePassword,
  generateUuid,
  isValidEnvelope,
  parseEnvelopeJson,
  sanitizeEnvelope,
} from '../src/crypto/engine';
import {
  clearUnlockLockout,
  computeLockoutDurationMs,
  deleteStoredEnvelope,
  getUnlockLockoutStatus,
  loadStoredEnvelope,
  recordUnlockFailure,
  saveStoredEnvelope,
} from '../src/storage/indexedDb';
import {
  DEFAULT_CATEGORIES,
  DEFAULT_SECURITY_SETTINGS,
  type EncryptedVaultEnvelope,
  type VaultPayload,
} from '../src/types/vault';

const TEST_ITERATIONS = MIN_KDF_ITERATIONS; // 100,000 iteraciones para tests rápidos con KDF real

function makeSamplePayload(): VaultPayload {
  const now = 1_700_000_000_000;
  return {
    version: 1,
    categories: [...DEFAULT_CATEGORIES],
    entries: [
      {
        id: 'entry-1',
        title: 'Banco Principal',
        categoryId: 'cat-finanzas',
        username: 'andres@example.com',
        password: 'S3cur3!Vault#Password99',
        url: 'https://banco.example.com',
        notes: 'Token físico requerido',
        favorite: true,
        createdAt: now,
        updatedAt: now,
      },
    ],
    settings: { ...DEFAULT_SECURITY_SETTINGS },
    updatedAt: now,
  };
}

function buildAad(env: EncryptedVaultEnvelope): Uint8Array {
  return new TextEncoder().encode(
    `${env.format}|v${env.version}|${env.cipher}|${env.kdf}|${env.iterations}|${env.salt}|${env.scope}`
  );
}

// Mock ligero en memoria para IndexedDB en Node.js
function installMockIndexedDb(options?: {
  corruptEnvelopeOnRead?: unknown;
  corruptLockoutOnRead?: unknown;
  failReadError?: boolean;
  abortTx?: boolean;
}) {
  const stores = new Map<string, Map<string, unknown>>();
  let openConnections = 0;
  let closedConnections = 0;

  const ensureStore = (name: string) => {
    let map = stores.get(name);
    if (!map) {
      map = new Map<string, unknown>();
      stores.set(name, map);
    }
    return map;
  };

  const makeMockDb = () => {
    openConnections++;
    let closed = false;
    const dbObj = {
      objectStoreNames: {
        contains: (name: string) => stores.has(name),
      },
      createObjectStore: (name: string) => {
        ensureStore(name);
        return {};
      },
      close: () => {
        if (!closed) {
          closed = true;
          closedConnections++;
        }
      },
      transaction: (storeName: string, _mode: IDBTransactionMode) => {
        const storeMap = ensureStore(storeName);
        const tx: Record<string, unknown> = {
          error: null,
          oncomplete: null,
          onerror: null,
          onabort: null,
          objectStore: () => ({
            get: (key: string) => {
              const req: Record<string, unknown> = {
                result: undefined,
                error: null,
                onsuccess: null,
                onerror: null,
              };
              queueMicrotask(() => {
                if (options?.failReadError) {
                  req.error = new Error('Simulated IDB read failure');
                  (req.onerror as (() => void) | null)?.();
                  return;
                }
                if (options?.abortTx) {
                  tx.error = new Error('Simulated IDB abort');
                  (tx.onabort as (() => void) | null)?.();
                  return;
                }
                if (storeName === 'envelopes' && options && 'corruptEnvelopeOnRead' in options) {
                  req.result = options.corruptEnvelopeOnRead;
                } else if (
                  storeName === 'security_meta' &&
                  options &&
                  'corruptLockoutOnRead' in options
                ) {
                  req.result = options.corruptLockoutOnRead;
                } else {
                  req.result = storeMap.get(key);
                }
                (req.onsuccess as (() => void) | null)?.();
                (tx.oncomplete as (() => void) | null)?.();
              });
              return req;
            },
            put: (value: unknown, key: string) => {
              const req: Record<string, unknown> = {
                error: null,
                onerror: null,
              };
              queueMicrotask(() => {
                if (options?.abortTx) {
                  tx.error = new Error('Simulated IDB put abort');
                  (tx.onabort as (() => void) | null)?.();
                  return;
                }
                storeMap.set(key, value);
                (tx.oncomplete as (() => void) | null)?.();
              });
              return req;
            },
            delete: (key: string) => {
              const req: Record<string, unknown> = {
                error: null,
                onerror: null,
              };
              queueMicrotask(() => {
                storeMap.delete(key);
                (tx.oncomplete as (() => void) | null)?.();
              });
              return req;
            },
          }),
        };
        return tx;
      },
    };
    return dbObj;
  };

  const mockFactory = {
    open: (_name: string, _version?: number) => {
      const req: Record<string, unknown> = {
        result: null,
        error: null,
        transaction: null,
        onupgradeneeded: null,
        onsuccess: null,
        onerror: null,
        onblocked: null,
      };
      queueMicrotask(() => {
        const db = makeMockDb();
        req.result = db;
        (req.onupgradeneeded as (() => void) | null)?.();
        (req.onsuccess as (() => void) | null)?.();
      });
      return req;
    },
  };

  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'indexedDB');
  Object.defineProperty(globalThis, 'indexedDB', {
    configurable: true,
    writable: true,
    value: mockFactory,
  });

  return {
    stores,
    getCounts: () => ({ openConnections, closedConnections }),
    restore: () => {
      if (descriptor) {
        Object.defineProperty(globalThis, 'indexedDB', descriptor);
      } else {
        delete (globalThis as Record<string, unknown>).indexedDB;
      }
    },
  };
}

describe('Bastión Crypto Engine — Seguridad KDF, AEAD, Memoria y Esquemas', () => {
  const originalCryptoDesc = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  const realCrypto = globalThis.crypto;
  const realSubtle = realCrypto.subtle;

  afterEach(() => {
    if (originalCryptoDesc) {
      Object.defineProperty(globalThis, 'crypto', originalCryptoDesc);
    }
  });

  it('deriva CryptoKey AES-256-GCM estrictamente no extraíble (extractable: false)', async () => {
    const salt = generateSaltBytes();
    assert.equal(salt.length, 32);

    const key = await deriveMasterKey('MasterPassphrase!2026', salt, TEST_ITERATIONS);
    assert.equal(key.type, 'secret');
    assert.equal(key.extractable, false);
    assert.equal(key.algorithm.name, 'AES-GCM');

    await assert.rejects(async () => {
      await crypto.subtle.exportKey('raw', key);
    });
  });

  it('rechaza parámetros KDF inseguros o vectores DoS en deriveMasterKey', async () => {
    const salt = generateSaltBytes();
    await assert.rejects(() => deriveMasterKey('', salt, TEST_ITERATIONS));
    await assert.rejects(() => deriveMasterKey('ValidPass123!', new Uint8Array(8), TEST_ITERATIONS));
    await assert.rejects(() => deriveMasterKey('ValidPass123!', salt, MIN_KDF_ITERATIONS - 1));
    await assert.rejects(() => deriveMasterKey('ValidPass123!', salt, MAX_KDF_ITERATIONS + 1));
    await assert.rejects(() => deriveMasterKey('ValidPass123!', salt, Number.POSITIVE_INFINITY));
    await assert.rejects(() => deriveMasterKey('ValidPass123!', salt, 600_000.5));
  });

  it('genera IVs de 96 bits únicos y realiza cifrado/descifrado AES-256-GCM con AAD', async () => {
    const iv1 = generateIvBytes();
    const iv2 = generateIvBytes();
    assert.equal(iv1.length, 12);
    assert.equal(iv2.length, 12);
    assert.notEqual(encodeBase64(iv1), encodeBase64(iv2));

    const salt = generateSaltBytes();
    const saltB64 = encodeBase64(salt);
    const key = await deriveMasterKey('StrongMaster#2026!', salt, TEST_ITERATIONS);
    const payload = makeSamplePayload();

    const envelope = await encryptVaultWithKey(payload, key, saltB64, TEST_ITERATIONS, 'local-vault');
    assert.equal(isValidEnvelope(envelope), true);
    assert.equal(KDF_ITERATIONS, 600_000);

    const decrypted = await decryptVaultEnvelope(envelope, 'StrongMaster#2026!');
    assert.equal(decrypted.key.extractable, false);
    assert.deepEqual(decrypted.payload, payload);
  });

  it('impide downgrade o sustitución de metadatos protegidos por AAD (scope, iterations)', async () => {
    const salt = generateSaltBytes();
    const key = await deriveMasterKey('AadProtectionTest!99', salt, TEST_ITERATIONS);
    const envelope = await encryptVaultWithKey(
      makeSamplePayload(),
      key,
      encodeBase64(salt),
      TEST_ITERATIONS,
      'export-full'
    );

    const tamperedScope: EncryptedVaultEnvelope = { ...envelope, scope: 'local-vault' };
    await assert.rejects(
      () => decryptVaultEnvelope(tamperedScope, 'AadProtectionTest!99'),
      /integridad criptográfica alterada/i
    );

    const tamperedIter: EncryptedVaultEnvelope = { ...envelope, iterations: TEST_ITERATIONS + 1 };
    await assert.rejects(
      () => decryptVaultEnvelope(tamperedIter, 'AadProtectionTest!99'),
      /integridad criptográfica alterada/i
    );

    await assert.rejects(
      () => decryptVaultEnvelope(envelope, 'WrongPassword!99'),
      /Clave maestra incorrecta/i
    );
  });

  it('rechaza CryptoKey extraíble en encryptVaultWithKey', async () => {
    const extractableKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    const saltB64 = encodeBase64(generateSaltBytes());
    await assert.rejects(
      () =>
        encryptVaultWithKey(makeSamplePayload(), extractableKey, saltB64, TEST_ITERATIONS, 'local-vault'),
      /no extraíble/i
    );
  });

  it('valida estrictamente formato, longitudes Base64 y bloquea DoS/prototype pollution en sobres', async () => {
    const salt = generateSaltBytes();
    const key = await deriveMasterKey('EnvelopeValidation!22', salt, TEST_ITERATIONS);
    const valid = await encryptVaultWithKey(
      makeSamplePayload(),
      key,
      encodeBase64(salt),
      TEST_ITERATIONS,
      'local-vault'
    );

    // Longitud inválida de salt (16B en lugar de 32B) e IV (8B en lugar de 12B)
    assert.equal(isValidEnvelope({ ...valid, salt: encodeBase64(new Uint8Array(16)) }), false);
    assert.equal(isValidEnvelope({ ...valid, iv: encodeBase64(new Uint8Array(8)) }), false);
    // Ciphertext menor a 16B (tag GCM mínimo)
    assert.equal(isValidEnvelope({ ...valid, ciphertext: encodeBase64(new Uint8Array(15)) }), false);
    // Base64 inválido
    assert.equal(isValidEnvelope({ ...valid, iv: '@@@not-base64@@@' }), false);
    // Iteraciones DoS
    assert.equal(isValidEnvelope({ ...valid, iterations: Number.POSITIVE_INFINITY }), false);
    assert.equal(isValidEnvelope({ ...valid, iterations: MAX_KDF_ITERATIONS + 1 }), false);
    assert.equal(isValidEnvelope({ ...valid, iterations: 99_999 }), false);
    // UpdatedAt inválido
    assert.equal(isValidEnvelope({ ...valid, updatedAt: Number.NaN }), false);
    assert.equal(isValidEnvelope({ ...valid, updatedAt: -5 }), false);

    // Prototype pollution via JSON.parse
    const pollutedJson = JSON.stringify(valid).replace(
      '"version":1',
      '"version":1,"__proto__":{"polluted":"yes"}'
    );
    assert.throws(() => parseEnvelopeJson(pollutedJson), /clave de prototipo prohibida/i);

    const withOwnProto = Object.defineProperty({ ...valid }, '__proto__', {
      value: { polluted: true },
      enumerable: true,
      configurable: true,
    });
    assert.equal(isValidEnvelope(withOwnProto), false);
    assert.throws(() => sanitizeEnvelope(withOwnProto));

    // Límite de tamaño anti-DoS en parseEnvelopeJson
    const oversized = ' '.repeat(10 * 1024 * 1024 + 10);
    assert.throws(() => parseEnvelopeJson(oversized), /tamaño máximo/i);
    assert.equal((({}) as Record<string, unknown>).polluted, undefined);
  });

  it('bloquea prototype pollution y corrupción estructural dentro del JSON descifrado', async () => {
    const salt = generateSaltBytes();
    const saltB64 = encodeBase64(salt);
    const key = await deriveMasterKey('InsidePayloadTest!1', salt, TEST_ITERATIONS);

    const buildMaliciousEnvelope = async (rawJson: string): Promise<EncryptedVaultEnvelope> => {
      const iv = generateIvBytes();
      const base: EncryptedVaultEnvelope = {
        format: 'BASTION_VAULT',
        version: 1,
        cipher: 'AES-256-GCM',
        kdf: 'PBKDF2-HMAC-SHA512+HKDF-SHA512',
        iterations: TEST_ITERATIONS,
        salt: saltB64,
        iv: encodeBase64(iv),
        scope: 'export-full',
        updatedAt: Date.now(),
        ciphertext: '',
      };
      const ct = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv as unknown as BufferSource,
          additionalData: buildAad(base) as unknown as BufferSource,
          tagLength: 128,
        },
        key,
        new TextEncoder().encode(rawJson) as unknown as BufferSource
      );
      base.ciphertext = encodeBase64(new Uint8Array(ct));
      return base;
    };

    const pollutedPayloadJson =
      '{"version":1,"categories":[],"entries":[],"settings":{"__proto__":{"isAdmin":true},"clipboardTimeoutSec":30,"autoLockMinutes":5,"lockOnBlur":false,"ocrNoiseLevel":"high","ephemeralMode":false},"updatedAt":1700000000000}';
    const pollutedEnv = await buildMaliciousEnvelope(pollutedPayloadJson);
    await assert.rejects(
      () => decryptVaultEnvelope(pollutedEnv, 'InsidePayloadTest!1'),
      /clave de prototipo prohibida/i
    );
    assert.equal((({}) as Record<string, unknown>).isAdmin, undefined);

    // Settings manipulados (downgrade de autoLockMinutes a valor no permitido)
    const badSettingsJson = JSON.stringify({
      ...makeSamplePayload(),
      settings: { ...DEFAULT_SECURITY_SETTINGS, autoLockMinutes: 99999 },
    });
    const badSettingsEnv = await buildMaliciousEnvelope(badSettingsJson);
    await assert.rejects(
      () => decryptVaultEnvelope(badSettingsEnv, 'InsidePayloadTest!1'),
      /autoLockMinutes/i
    );

    // Entrada sin campos requeridos (evita crash en UI)
    const badEntryJson = JSON.stringify({
      ...makeSamplePayload(),
      entries: [{ id: 'x1' }],
    });
    const badEntryEnv = await buildMaliciousEnvelope(badEntryJson);
    await assert.rejects(() => decryptVaultEnvelope(badEntryEnv, 'InsidePayloadTest!1'));

    // Compatibilidad legacy: payload mínimo sin campo settings se normaliza con defaults seguros
    const legacyMinimal = JSON.stringify({
      version: 1,
      categories: DEFAULT_CATEGORIES,
      entries: [],
      updatedAt: 1700000000000,
    });
    const legacyEnv = await buildMaliciousEnvelope(legacyMinimal);
    const decLegacy = await decryptVaultEnvelope(legacyEnv, 'InsidePayloadTest!1');
    assert.deepEqual(decLegacy.payload.settings, DEFAULT_SECURITY_SETTINGS);
  });

  it('limpia buffers sensibles Uint8Array en bloques finally (éxito y error)', async () => {
    const capturedBuffers: Uint8Array[] = [];
    let forceDeriveBitsThrow = false;

    const wrappedSubtle = {
      importKey: async (
        format: KeyFormat,
        keyData: BufferSource,
        algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | AesKeyAlgorithm,
        extractable: boolean,
        keyUsages: KeyUsage[]
      ) => {
        if (keyData instanceof Uint8Array) {
          capturedBuffers.push(keyData);
        }
        return realSubtle.importKey(
          format as 'raw',
          keyData,
          algorithm,
          extractable,
          keyUsages
        );
      },
      deriveBits: async (
        algorithm: Pbkdf2Params,
        baseKey: CryptoKey,
        length: number
      ) => {
        if (forceDeriveBitsThrow) {
          throw new Error('Forced PBKDF2 failure');
        }
        return realSubtle.deriveBits(algorithm, baseKey, length);
      },
      deriveKey: realSubtle.deriveKey.bind(realSubtle),
      encrypt: async (
        algorithm: AesGcmParams,
        key: CryptoKey,
        data: BufferSource
      ) => {
        if (data instanceof Uint8Array) {
          capturedBuffers.push(data);
        }
        return realSubtle.encrypt(algorithm, key, data);
      },
      decrypt: async (
        algorithm: AesGcmParams,
        key: CryptoKey,
        data: BufferSource
      ) => {
        const buf = await realSubtle.decrypt(algorithm, key, data);
        capturedBuffers.push(new Uint8Array(buf));
        return buf;
      },
    };

    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: {
        getRandomValues: realCrypto.getRandomValues.bind(realCrypto),
        randomUUID: realCrypto.randomUUID.bind(realCrypto),
        subtle: wrappedSubtle,
      },
    });

    const salt = generateSaltBytes();
    const saltB64 = encodeBase64(salt);
    const key = await deriveMasterKey('MemoryWipeTest!2026', salt, TEST_ITERATIONS);
    const env = await encryptVaultWithKey(
      makeSamplePayload(),
      key,
      saltB64,
      TEST_ITERATIONS,
      'local-vault'
    );
    await decryptVaultEnvelope(env, 'MemoryWipeTest!2026');

    assert.ok(capturedBuffers.length >= 4);
    for (const buf of capturedBuffers) {
      assert.equal(
        buf.every((byte) => byte === 0),
        true,
        'Buffer sensible no fue puesto a cero en finally'
      );
    }

    // Camino de error post-descifrado (JSON inválido dentro del sobre) -> debe limpiar decryptedBytes
    capturedBuffers.length = 0;
    const ivBad = generateIvBytes();
    const badJsonEnv: EncryptedVaultEnvelope = {
      format: 'BASTION_VAULT',
      version: 1,
      cipher: 'AES-256-GCM',
      kdf: 'PBKDF2-HMAC-SHA512+HKDF-SHA512',
      iterations: TEST_ITERATIONS,
      salt: saltB64,
      iv: encodeBase64(ivBad),
      scope: 'export-full',
      updatedAt: Date.now(),
      ciphertext: '',
    };
    const badCt = await realSubtle.encrypt(
      {
        name: 'AES-GCM',
        iv: ivBad as unknown as BufferSource,
        additionalData: buildAad(badJsonEnv) as unknown as BufferSource,
        tagLength: 128,
      },
      key,
      new TextEncoder().encode('{invalid-json') as unknown as BufferSource
    );
    badJsonEnv.ciphertext = encodeBase64(new Uint8Array(badCt));

    await assert.rejects(() => decryptVaultEnvelope(badJsonEnv, 'MemoryWipeTest!2026'));
    assert.ok(capturedBuffers.length >= 3);
    for (const buf of capturedBuffers) {
      assert.equal(
        buf.every((byte) => byte === 0),
        true,
        'Buffer sensible no fue limpiado tras excepción de parseo'
      );
    }

    // Camino de error en deriveMasterKey -> debe limpiar passwordBytes
    capturedBuffers.length = 0;
    forceDeriveBitsThrow = true;
    await assert.rejects(() => deriveMasterKey('WipeOnKdfError!1', salt, TEST_ITERATIONS));
    assert.equal(capturedBuffers.length, 1);
    assert.equal(
      capturedBuffers[0].every((byte) => byte === 0),
      true,
      'passwordBytes no fue limpiado tras fallo KDF'
    );
  });

  it('genera contraseñas CSPRNG sin sesgo de módulo, respeta ambiguos y acota longitud', () => {
    assert.throws(() =>
      generateSecurePassword({
        length: 0,
        uppercase: true,
        lowercase: true,
        numbers: true,
        symbols: false,
        excludeAmbiguous: true,
      })
    );
    assert.throws(() =>
      generateSecurePassword({
        length: 10_000,
        uppercase: true,
        lowercase: true,
        numbers: true,
        symbols: false,
        excludeAmbiguous: true,
      })
    );

    // Fallback sin conjuntos seleccionados también excluye ambiguos si se solicita
    const fallbackPw = generateSecurePassword({
      length: 48,
      uppercase: false,
      lowercase: false,
      numbers: false,
      symbols: false,
      excludeAmbiguous: true,
    });
    assert.equal(fallbackPw.length, 48);
    assert.equal(/[0O1lI|`'"]/.test(fallbackPw), false);

    // Verifica que incluye al menos un carácter de cada conjunto activo
    const fullPw = generateSecurePassword({
      length: 24,
      uppercase: true,
      lowercase: true,
      numbers: true,
      symbols: true,
      excludeAmbiguous: true,
    });
    assert.equal(fullPw.length, 24);
    assert.match(fullPw, /[A-Z]/);
    assert.match(fullPw, /[a-z]/);
    assert.match(fullPw, /[0-9]/);
    assert.match(fullPw, /[^a-zA-Z0-9]/);
    assert.equal(/[0O1lI|`'"]/.test(fullPw), false);

    const uuid = generateUuid();
    assert.match(uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  });

  it('createStandaloneEncryptedExport cifra de forma autónoma con sal nueva e iterable', async () => {
    const payload = makeSamplePayload();
    const exported = await createStandaloneEncryptedExport(
      payload,
      'BackupPassphrase!2026',
      'export-category'
    );
    assert.equal(exported.scope, 'export-category');
    assert.equal(exported.iterations, KDF_ITERATIONS);
    assert.equal(isValidEnvelope(exported), true);
  });
});

describe('Bastión Storage IndexedDB — Integridad Fail-Closed y Bloqueo por Fuerza Bruta', () => {
  it('guarda, lee y elimina sobres válidos cerrando siempre las conexiones IDB', async () => {
    const mock = installMockIndexedDb();
    try {
      const salt = generateSaltBytes();
      const key = await deriveMasterKey('StorageTestKey!2026', salt, TEST_ITERATIONS);
      const env = await encryptVaultWithKey(
        makeSamplePayload(),
        key,
        encodeBase64(salt),
        TEST_ITERATIONS,
        'local-vault'
      );

      assert.equal(await loadStoredEnvelope(), null);
      await saveStoredEnvelope(env);
      const loaded = await loadStoredEnvelope();
      assert.deepEqual(loaded, env);

      await deleteStoredEnvelope();
      assert.equal(await loadStoredEnvelope(), null);

      const counts = mock.getCounts();
      assert.equal(counts.openConnections, counts.closedConnections);
    } finally {
      mock.restore();
    }
  });

  it('falla cerrado ante sobres corruptos, prototype pollution, errores IDB o ausencia de indexedDB', async () => {
    // 1. Corrupto en IndexedDB
    const corruptMock = installMockIndexedDb({
      corruptEnvelopeOnRead: { format: 'BASTION_VAULT', version: 1, bad: true },
    });
    try {
      await assert.rejects(() => loadStoredEnvelope(), /corrupto/i);
      const counts = corruptMock.getCounts();
      assert.equal(counts.openConnections, counts.closedConnections);
    } finally {
      corruptMock.restore();
    }

    // 2. Error en req.onerror cierra conexión DB
    const errMock = installMockIndexedDb({ failReadError: true });
    try {
      await assert.rejects(() => loadStoredEnvelope(), /Simulated IDB read failure/);
      const counts = errMock.getCounts();
      assert.equal(counts.openConnections, counts.closedConnections);
    } finally {
      errMock.restore();
    }

    // 3. Aborto en transacción cierra conexión DB
    const abortMock = installMockIndexedDb({ abortTx: true });
    try {
      await assert.rejects(() => loadStoredEnvelope(), /Simulated IDB abort/);
      const counts = abortMock.getCounts();
      assert.equal(counts.openConnections, counts.closedConnections);
    } finally {
      abortMock.restore();
    }

    // 4. saveStoredEnvelope rechaza sobre inválido antes de abrir IDB
    const cleanMock = installMockIndexedDb();
    try {
      await assert.rejects(() =>
        saveStoredEnvelope({ format: 'FAKE' } as unknown as EncryptedVaultEnvelope)
      );
      assert.equal(cleanMock.getCounts().openConnections, 0);
    } finally {
      cleanMock.restore();
    }

    // 5. Sin indexedDB global -> falla cerrado
    await assert.rejects(() => loadStoredEnvelope(), /IndexedDB no está disponible/i);
  });

  it('aplica backoff exponencial persistente ante fuerza bruta y falla cerrado si se manipula', async () => {
    const mock = installMockIndexedDb();
    try {
      await clearUnlockLockout();
      const t0 = 1_700_000_000_000;

      assert.equal(computeLockoutDurationMs(3), 0);
      assert.equal(computeLockoutDurationMs(4), 5_000);
      assert.equal(computeLockoutDurationMs(5), 10_000);
      assert.equal(computeLockoutDurationMs(6), 20_000);

      for (let i = 1; i <= 3; i++) {
        const s = await recordUnlockFailure(t0 + i * 100);
        assert.equal(s.failedAttempts, i);
        assert.equal(s.isLocked, false);
      }

      const lock4 = await recordUnlockFailure(t0 + 1000);
      assert.equal(lock4.failedAttempts, 4);
      assert.equal(lock4.isLocked, true);
      assert.equal(lock4.remainingMs, 5_000);

      const stillLocked = await getUnlockLockoutStatus(t0 + 3000);
      assert.equal(stillLocked.isLocked, true);
      assert.equal(stillLocked.remainingMs, 3_000);

      await clearUnlockLockout();
      const resetStatus = await getUnlockLockoutStatus(t0 + 4000);
      assert.equal(resetStatus.failedAttempts, 0);
      assert.equal(resetStatus.isLocked, false);
    } finally {
      mock.restore();
    }

    // Manipulación del registro security_meta -> fail-closed con bloqueo activo
    const tamperedMetaMock = installMockIndexedDb({
      corruptLockoutOnRead: { failedAttempts: -99, lastFailedAt: 0, lockedUntil: null },
    });
    try {
      const tNow = 1_700_000_010_000;
      const status = await getUnlockLockoutStatus(tNow);
      assert.equal(status.isLocked, true);
      assert.ok(status.remainingMs >= 5_000);
    } finally {
      tamperedMetaMock.restore();
    }
  });
});
