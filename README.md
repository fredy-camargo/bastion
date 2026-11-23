# Bastión — Bóveda Criptográfica Local (v1.0.0)

Gestor de contraseñas **100 % offline (Zero-Network, Client-Only)** con cifrado **AES-256-GCM en memoria RAM**, derivación de claves **PBKDF2-SHA256 + HKDF**, aislamiento visual anti-IA/OCR y almacenamiento cifrado local en IndexedDB.

---

## Arquitectura y Controles de Seguridad

- **Cifrado autenticado AES-256-GCM (Web Crypto API):** Llave maestra derivada en memoria como `CryptoKey` no extraíble (`extractable: false`), con IV aleatorio de 96 bits (CSPRNG), AAD vinculada a versión/iteraciones y limpieza explícita de buffers `Uint8Array` en bloques `finally`.
- **Resistencia anti-fuerza bruta y anti-corrupción:** Bloqueo exponencial persistente en IndexedDB (`security_meta`, 3 intentos libres y backoff hasta 15 min) con comportamiento *fail-closed*, validación estricta de sobres `.bvault` (límite 10 MiB, longitudes canónicas Base64) y protección contra *prototype pollution*.
- **Protección visual y de sesión en RAM:** Renderizado de secretos sobre `<canvas>` con ruido dinámico anti-OCR, teclado virtual mezclado con CSPRNG sin sesgo de módulo, cortina de privacidad con `inert`, borrado automático del portapapeles con reintento diferido y auto-bloqueo por inactividad/ocultación (`visibilitychange`, `blur`, `pagehide`).
- **Endurecimiento Web/PWA:** Content Security Policy estricta (`script-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`, `form-action 'none'`), `Referrer-Policy: no-referrer` y cabeceras `COOP`/`CORP`/`X-Frame-Options: DENY`.

---

## Requisitos y Comandos de Desarrollo

- **Node.js** `20+` y **npm** `10+`
- Para generar el ejecutable nativo de Windows (`Bastion.exe`): Windows 10/11 con .NET Framework 4.x, Python + Pillow (`PIL`) y Microsoft Edge o Google Chrome instalado.

```bash
# Instalar dependencias exactas desde package-lock.json
npm ci

# Servidor de desarrollo local (solo 127.0.0.1:3000)
npm run dev

# Verificación de tipos TypeScript
npm run lint

# Pruebas unitarias defensivas de criptografía y almacenamiento
npm test

# Compilación de producción (genera dist/)
npm run build

# Compilar ejecutable Windows Bastion.exe y acceso directo en Escritorio
npm run desktop:build
```

---

## Ejecutable de Escritorio Windows (`Bastion.exe`)

Para usar Bastión como aplicación de escritorio aislada sin consola ni servidor Node en ejecución:

1. Compila la aplicación y el lanzador con `npm run desktop:build` (o haz doble clic en [`scripts/Iniciar_Bastion.bat`](scripts/Iniciar_Bastion.bat)).
2. Ejecuta **`Bastion.exe`** o el acceso directo **`Bastión`** creado en el Escritorio.
3. El lanzador levanta un servidor estático embebido exclusivo en `http://127.0.0.1:4173` con todas las cabeceras de seguridad OWASP y abre la bóveda en una ventana de aplicación aislada (`--disable-extensions`).
4. **Persistencia de la bóveda:** Los datos cifrados de IndexedDB se almacenan localmente en el perfil aislado `%LOCALAPPDATA%\Bastion\Profile`. Se recomienda exportar respaldos periódicos `.bvault` desde la propia interfaz.

> Nota: `Bastion.exe` y `Bastion.ico` se generan localmente y están excluidos del repositorio Git (`.gitignore`).

---

## Versionado y Rollback en Git

La versión inicial limpia y auditada queda etiquetada como **`v1.0.0`** en `main`.

- **Volver a la versión inicial estable (`v1.0.0`):**
  ```bash
  git checkout v1.0.0
  ```
- **Crear una nueva versión al actualizar librerías o parches de seguridad:**
  ```bash
  git checkout -b release/v1.1.0
  # Aplicar actualizaciones, ejecutar npm run lint && npm test && npm run build
  git commit -am "chore(security): bump dependencies for v1.1.0"
  git tag -a v1.1.0 -m "Bastión v1.1.0"
  git push origin release/v1.1.0 --tags
  ```

---

## Documentación Offline

- Manual de usuario: [`docs/manual-usuario.html`](docs/manual-usuario.html)
- Manual de arquitectura y despliegue: [`docs/manual-arquitecto.html`](docs/manual-arquitecto.html)
