export type OcrNoiseLevel = 'standard' | 'high';

export interface VaultCategory {
  id: string;
  name: string;
  isDefault?: boolean;
}

export interface VaultEntry {
  id: string;
  title: string;
  categoryId: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  favorite: boolean;
  createdAt: number;
  updatedAt: number;
}

export interface SecuritySettings {
  clipboardTimeoutSec: 15 | 30 | 60;
  autoLockMinutes: 1 | 3 | 5 | 15;
  lockOnBlur: boolean;
  ocrNoiseLevel: OcrNoiseLevel;
  ephemeralMode: boolean;
}

export interface VaultPayload {
  version: number;
  categories: VaultCategory[];
  entries: VaultEntry[];
  settings: SecuritySettings;
  updatedAt: number;
}

export interface EncryptedVaultEnvelope {
  format: 'BASTION_VAULT';
  version: 1;
  cipher: 'AES-256-GCM';
  kdf: 'PBKDF2-HMAC-SHA512+HKDF-SHA512';
  iterations: number;
  salt: string; // Base64 32 bytes (256-bit)
  iv: string; // Base64 12 bytes (96-bit)
  scope: 'local-vault' | 'export-full' | 'export-category';
  updatedAt: number;
  ciphertext: string; // Base64 ciphertext + 128-bit GCM auth tag
}

export interface PasswordGenOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
}

export interface EntropyReport {
  bits: number;
  label: 'Crítica' | 'Débil' | 'Aceptable' | 'Fuerte' | 'Grado militar';
  tone: 'danger' | 'warning' | 'neutral' | 'emerald' | 'amber';
}

export interface UnlockLockoutStatus {
  failedAttempts: number;
  lockedUntil: number | null;
  remainingMs: number;
  isLocked: boolean;
}

export const VAULT_LIMITS = {
  MIN_KDF_ITERATIONS: 100_000,
  MAX_KDF_ITERATIONS: 5_000_000,
  SALT_BYTES: 32,
  IV_BYTES: 12,
  GCM_TAG_BYTES: 16,
  MAX_ENVELOPE_BYTES: 10 * 1024 * 1024,
  MAX_CATEGORIES: 500,
  MAX_ENTRIES: 25_000,
  MAX_ID_LENGTH: 256,
  MAX_TITLE_LENGTH: 1024,
  MAX_USERNAME_LENGTH: 2048,
  MAX_PASSWORD_LENGTH: 16_384,
  MAX_URL_LENGTH: 4096,
  MAX_NOTES_LENGTH: 65_536,
  MAX_GENERATED_PASSWORD_LENGTH: 512,
} as const;

export const DEFAULT_CATEGORIES: VaultCategory[] = [
  { id: 'cat-finanzas', name: 'Bancos y Finanzas', isDefault: true },
  { id: 'cat-trabajo', name: 'Trabajo y Corporativo', isDefault: true },
  { id: 'cat-correo', name: 'Correo Electrónico', isDefault: true },
  { id: 'cat-servidores', name: 'Servidores y SSH', isDefault: true },
  { id: 'cat-personal', name: 'Cuentas Personales', isDefault: true },
  { id: 'cat-notas', name: 'Notas y Claves API', isDefault: true },
];

export const DEFAULT_SECURITY_SETTINGS: SecuritySettings = {
  clipboardTimeoutSec: 30,
  autoLockMinutes: 5,
  lockOnBlur: false,
  ocrNoiseLevel: 'high',
  ephemeralMode: false,
};
