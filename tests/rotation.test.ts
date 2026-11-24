import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  decryptVaultEnvelope,
  deriveMasterKey,
  encodeBase64,
  encryptVaultWithKey,
  generateIvBytes,
  generateSaltBytes,
  MIN_KDF_ITERATIONS,
} from '../src/crypto/engine';
import { sanitizeImportedPayload } from '../src/components/vaultFileSecurity';
import {
  DEFAULT_CATEGORIES,
  DEFAULT_SECURITY_SETTINGS,
  type EncryptedVaultEnvelope,
  type VaultEntry,
  type VaultPayload,
} from '../src/types/vault';
import {
  compareRotationUrgency,
  evaluatePasswordRotation,
  MS_PER_DAY,
} from '../src/utils/passwordRotation';

function makeEntry(overrides: Partial<VaultEntry> = {}): VaultEntry {
  const baseTime = 1_700_000_000_000;
  return {
    id: 'entry-rot-1',
    title: 'Cuenta de prueba',
    categoryId: 'cat-correo',
    username: 'usuario@example.com',
    password: 'StrongPassword#2026',
    url: 'https://example.com',
    notes: '',
    favorite: false,
    createdAt: baseTime,
    updatedAt: baseTime,
    passwordUpdatedAt: baseTime,
    ...overrides,
  };
}

describe('Semáforo de rotación de contraseñas — evaluación visual y prioridades', () => {
  const base = 1_700_000_000_000;

  it('evalúa estado off cuando la periodicidad efectiva es 0 (global o por entrada)', () => {
    const offGlobal = evaluatePasswordRotation(makeEntry(), 0, base + 400 * MS_PER_DAY);
    assert.equal(offGlobal.status, 'off');
    assert.equal(offGlobal.effectiveDays, 0);
    assert.equal(offGlobal.usesDefault, true);
    assert.equal(offGlobal.nextRotationAt, null);

    const offEntry = evaluatePasswordRotation(
      makeEntry({ rotationIntervalDays: 0 }),
      90,
      base + 200 * MS_PER_DAY
    );
    assert.equal(offEntry.status, 'off');
    assert.equal(offEntry.usesDefault, false);
  });

  it('respeta umbrales exactos: verde (<75%), ámbar (>=75% y <100%), rojo (>=100%)', () => {
    const e30 = makeEntry({ rotationIntervalDays: 30, passwordUpdatedAt: base });

    const fresh = evaluatePasswordRotation(e30, 180, base + 22 * MS_PER_DAY); // 22/30 = 73.3%
    assert.equal(fresh.status, 'fresh');
    assert.equal(fresh.daysRemaining, 8);

    const soonEdge = evaluatePasswordRotation(e30, 180, base + 22.5 * MS_PER_DAY); // 75%
    assert.equal(soonEdge.status, 'soon');

    const dueEdge = evaluatePasswordRotation(e30, 180, base + 30 * MS_PER_DAY); // 100%
    assert.equal(dueEdge.status, 'due');
    assert.equal(dueEdge.daysRemaining, 0);

    const overdue = evaluatePasswordRotation(e30, 180, base + 35 * MS_PER_DAY);
    assert.equal(overdue.status, 'due');
    assert.equal(overdue.daysRemaining, -5);
  });

  it('soporta entradas legacy sin passwordUpdatedAt ni rotationIntervalDays y reloj atrasado', () => {
    const legacy = makeEntry({
      createdAt: base,
      updatedAt: base + 10 * MS_PER_DAY,
      passwordUpdatedAt: undefined,
      rotationIntervalDays: undefined,
    });

    // Usa updatedAt como ancla y hereda global 90d
    const res = evaluatePasswordRotation(legacy, 90, base + 20 * MS_PER_DAY);
    assert.equal(res.status, 'fresh');
    assert.equal(res.effectiveDays, 90);
    assert.equal(res.usesDefault, true);
    assert.equal(res.daysElapsed, 10);

    // Reloj atrasado no produce negativos
    const skewed = evaluatePasswordRotation(legacy, 90, base);
    assert.equal(skewed.status, 'fresh');
    assert.equal(skewed.daysElapsed, 0);
    assert.equal(skewed.progressPercent, 0);
  });

  it('ordena por urgencia visual: due -> soon -> fresh -> off', () => {
    const now = base + 100 * MS_PER_DAY;
    const dueVeryOld = evaluatePasswordRotation(
      makeEntry({ rotationIntervalDays: 30, passwordUpdatedAt: base }),
      180,
      now
    );
    const dueRecent = evaluatePasswordRotation(
      makeEntry({ rotationIntervalDays: 90, passwordUpdatedAt: base }),
      180,
      now
    );
    const soon = evaluatePasswordRotation(
      makeEntry({ rotationIntervalDays: 30, passwordUpdatedAt: now - 25 * MS_PER_DAY }),
      180,
      now
    );
    const fresh = evaluatePasswordRotation(
      makeEntry({ rotationIntervalDays: 180, passwordUpdatedAt: now - 10 * MS_PER_DAY }),
      180,
      now
    );
    const off = evaluatePasswordRotation(
      makeEntry({ rotationIntervalDays: 0, passwordUpdatedAt: base }),
      180,
      now
    );

    const sorted = [off, fresh, dueRecent, soon, dueVeryOld].sort(compareRotationUrgency);
    assert.deepEqual(
      sorted.map((r) => r.status),
      ['due', 'due', 'soon', 'fresh', 'off']
    );
    assert.equal(sorted[0], dueVeryOld);
    assert.equal(sorted[1], dueRecent);
  });
});

describe('Persistencia cifrada, compatibilidad legacy y validación fail-closed', () => {
  it('cifra y descifra passwordUpdatedAt, rotationIntervalDays y defaultRotationDays', async () => {
    const salt = generateSaltBytes();
    const saltB64 = encodeBase64(salt);
    const key = await deriveMasterKey('MasterPassphrase!2026', salt, MIN_KDF_ITERATIONS);

    const now = 1_700_000_000_000;
    const payload: VaultPayload = {
      version: 1,
      categories: [...DEFAULT_CATEGORIES],
      entries: [
        makeEntry({ id: 'a', passwordUpdatedAt: now - 5 * MS_PER_DAY, rotationIntervalDays: 7 }),
        makeEntry({ id: 'b', passwordUpdatedAt: now }),
      ],
      settings: {
        ...DEFAULT_SECURITY_SETTINGS,
        defaultRotationDays: 90,
      },
      updatedAt: now,
    };

    const envelope = await encryptVaultWithKey(
      payload,
      key,
      saltB64,
      MIN_KDF_ITERATIONS,
      'local-vault'
    );
    const decrypted = await decryptVaultEnvelope(envelope, 'MasterPassphrase!2026');

    assert.equal(decrypted.payload.settings.defaultRotationDays, 90);
    assert.equal(decrypted.payload.entries[0].rotationIntervalDays, 7);
    assert.equal(decrypted.payload.entries[0].passwordUpdatedAt, now - 5 * MS_PER_DAY);
    assert.equal(decrypted.payload.entries[1].rotationIntervalDays, undefined);
  });

  it('mantiene compatibilidad con bóvedas legacy v1.0.0 sin campos de rotación', async () => {
    const salt = generateSaltBytes();
    const saltB64 = encodeBase64(salt);
    const key = await deriveMasterKey('MasterPassphrase!2026', salt, MIN_KDF_ITERATIONS);

    const legacyPayload = {
      version: 1,
      categories: [...DEFAULT_CATEGORIES],
      entries: [
        {
          id: 'legacy-1',
          title: 'Banco Legacy',
          categoryId: 'cat-finanzas',
          username: 'user',
          password: 'LegacyPassword!123',
          url: '',
          notes: '',
          favorite: true,
          createdAt: 1_700_000_000_000,
          updatedAt: 1_700_000_000_000,
        },
      ],
      settings: {
        clipboardTimeoutSec: 30,
        autoLockMinutes: 5,
        lockOnBlur: false,
        ocrNoiseLevel: 'high',
        ephemeralMode: false,
      },
      updatedAt: 1_700_000_000_000,
    } as unknown as VaultPayload;

    const envelope = await encryptVaultWithKey(
      legacyPayload,
      key,
      saltB64,
      MIN_KDF_ITERATIONS,
      'local-vault'
    );
    const decrypted = await decryptVaultEnvelope(envelope, 'MasterPassphrase!2026');
    assert.equal(decrypted.payload.settings.defaultRotationDays, 180);
    assert.equal(decrypted.payload.entries[0].passwordUpdatedAt, undefined);
    assert.equal(decrypted.payload.entries[0].rotationIntervalDays, undefined);
  });

  it('rechaza fail-closed valores manipulados tanto al cifrar como al descifrar', async () => {
    const salt = generateSaltBytes();
    const saltB64 = encodeBase64(salt);
    const key = await deriveMasterKey('MasterPassphrase!2026', salt, MIN_KDF_ITERATIONS);

    const badSettingPayload = {
      version: 1,
      categories: [...DEFAULT_CATEGORIES],
      entries: [],
      settings: {
        ...DEFAULT_SECURITY_SETTINGS,
        defaultRotationDays: 45,
      },
      updatedAt: 1_700_000_000_000,
    } as unknown as VaultPayload;

    await assert.rejects(
      () => encryptVaultWithKey(badSettingPayload, key, saltB64, MIN_KDF_ITERATIONS, 'local-vault'),
      /defaultRotationDays/
    );

    const badEntryPayload = {
      version: 1,
      categories: [...DEFAULT_CATEGORIES],
      entries: [makeEntry({ rotationIntervalDays: -7 as never })],
      settings: { ...DEFAULT_SECURITY_SETTINGS },
      updatedAt: 1_700_000_000_000,
    } as unknown as VaultPayload;

    await assert.rejects(
      () => encryptVaultWithKey(badEntryPayload, key, saltB64, MIN_KDF_ITERATIONS, 'local-vault'),
      /rotationIntervalDays/
    );

    const sealRawPayload = async (rawJson: string): Promise<EncryptedVaultEnvelope> => {
      const iv = generateIvBytes();
      const env: EncryptedVaultEnvelope = {
        format: 'BASTION_VAULT',
        version: 1,
        cipher: 'AES-256-GCM',
        kdf: 'PBKDF2-HMAC-SHA512+HKDF-SHA512',
        iterations: MIN_KDF_ITERATIONS,
        salt: saltB64,
        iv: encodeBase64(iv),
        scope: 'local-vault',
        updatedAt: Date.now(),
        ciphertext: '',
      };
      const aad = new TextEncoder().encode(
        `${env.format}|v${env.version}|${env.cipher}|${env.kdf}|${env.iterations}|${env.salt}|${env.scope}`
      );
      const ct = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv as unknown as BufferSource,
          additionalData: aad as unknown as BufferSource,
          tagLength: 128,
        },
        key,
        new TextEncoder().encode(rawJson) as unknown as BufferSource
      );
      env.ciphertext = encodeBase64(new Uint8Array(ct));
      return env;
    };

    const forgedSettingEnv = await sealRawPayload(JSON.stringify(badSettingPayload));
    await assert.rejects(
      () => decryptVaultEnvelope(forgedSettingEnv, 'MasterPassphrase!2026'),
      /defaultRotationDays/
    );

    const forgedEntryEnv = await sealRawPayload(JSON.stringify(badEntryPayload));
    await assert.rejects(
      () => decryptVaultEnvelope(forgedEntryEnv, 'MasterPassphrase!2026'),
      /rotationIntervalDays/
    );

    const forgedTimestampEnv = await sealRawPayload(
      JSON.stringify({
        ...badEntryPayload,
        entries: [makeEntry({ passwordUpdatedAt: -1 })],
      })
    );
    await assert.rejects(
      () => decryptVaultEnvelope(forgedTimestampEnv, 'MasterPassphrase!2026'),
      /passwordUpdatedAt/
    );
  });

  it('sanitizeImportedPayload conserva rotación válida y descarta valores fuera de catálogo', () => {
    const incoming = {
      version: 1,
      categories: [...DEFAULT_CATEGORIES],
      entries: [
        makeEntry({ id: 'ok', rotationIntervalDays: 365, passwordUpdatedAt: 1_700_000_123_000 }),
        makeEntry({
          id: 'bad',
          rotationIntervalDays: 999 as never,
          passwordUpdatedAt: -50,
        }),
      ],
      settings: { ...DEFAULT_SECURITY_SETTINGS },
      updatedAt: 1_700_000_000_000,
    } as unknown as VaultPayload;

    const clean = sanitizeImportedPayload(incoming, DEFAULT_CATEGORIES);
    assert.equal(clean.entries[0].rotationIntervalDays, 365);
    assert.equal(clean.entries[0].passwordUpdatedAt, 1_700_000_123_000);
    assert.equal(clean.entries[1].rotationIntervalDays, undefined);
    assert.equal(clean.entries[1].passwordUpdatedAt, undefined);
  });
});
