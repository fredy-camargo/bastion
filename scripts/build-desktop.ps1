param(
  [switch]$RebuildWeb
)

$ErrorActionPreference = "Stop"

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$DistIndex = Join-Path $RootDir "dist\index.html"
$SourcePng = Join-Path $RootDir "public\pwa-512x512.png"
$IconPath = Join-Path $RootDir "Bastion.ico"
$LauncherCs = Join-Path $RootDir "scripts\BastionLauncher.cs"
$ExePath = Join-Path $RootDir "Bastion.exe"
$CscPath = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

$OAcute = [char]0x00F3
$EmDash = [char]0x2014
$AppTitle = "Basti${OAcute}n"
$ShortcutDesc = "${AppTitle} ${EmDash} B${OAcute}veda Criptogr${([char]0x00E1)}fica Local"

Push-Location $RootDir
try {
  if ($RebuildWeb -or -not (Test-Path $DistIndex)) {
    Write-Host "[1/4] Compilando aplicacion web de produccion (vite build)..."
    npm run build
    if ($LASTEXITCODE -ne 0) {
      throw "Fallo npm run build con codigo $LASTEXITCODE"
    }
  } else {
    Write-Host "[1/4] Compilacion web dist/ detectada."
  }

  if (-not (Test-Path $SourcePng)) {
    throw "No se encontro el icono fuente: $SourcePng"
  }

  Write-Host "[2/4] Generando icono nativo multi-resolucion Bastion.ico..."
  python -c "from PIL import Image; img = Image.open(r'$SourcePng').convert('RGBA'); img.save(r'$IconPath', format='ICO', sizes=[(16,16),(32,32),(48,48),(64,64),(128,128),(256,256)])"
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $IconPath)) {
    throw "No se pudo generar $IconPath"
  }

  if (-not (Test-Path $CscPath)) {
    throw "No se encontro el compilador C# de .NET Framework en $CscPath"
  }

  Write-Host "[3/4] Compilando ejecutable nativo Bastion.exe..."
  & $CscPath /nologo /optimize+ /target:winexe /win32icon:"$IconPath" /r:System.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /out:"$ExePath" "$LauncherCs"
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $ExePath)) {
    throw "Fallo la compilacion de Bastion.exe"
  }

  Write-Host "[4/4] Creando acceso directo en el Escritorio..."
  $DesktopDir = [Environment]::GetFolderPath("Desktop")
  $ShortcutPath = Join-Path $DesktopDir "${AppTitle}.lnk"
  $Shell = New-Object -ComObject WScript.Shell
  $Shortcut = $Shell.CreateShortcut($ShortcutPath)
  $Shortcut.TargetPath = $ExePath
  $Shortcut.WorkingDirectory = $RootDir
  $Shortcut.IconLocation = "$IconPath,0"
  $Shortcut.Description = $ShortcutDesc
  $Shortcut.Save()

  Write-Host "Completado:"
  Write-Host " - Ejecutable: $ExePath"
  Write-Host " - Acceso directo: $ShortcutPath"
} finally {
  Pop-Location
}
