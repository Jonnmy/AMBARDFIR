#Requires -Version 2.0
<#
.SYNOPSIS
    Convierte un estado guardado de Hyper-V (.vmrs, o .bin + .vsv) a una imagen
    de memoria RAW fisica analizable directamente por Volatility 3 / MemProcFS.
.DESCRIPTION
    Usa la API OFICIAL de Microsoft VmSavedStateDumpProvider (vmsavedstatedumpprovider.dll,
    parte del Windows 10/11 SDK) via P/Invoke. Es el mismo mecanismo que emplean
    MemProcFS y LeechCore. NO requiere Dokany, NO monta unidades, NO necesita
    simbolos: lee la memoria fisica del huesped y la vuelca secuencialmente a un
    archivo .raw.

    Secuencia de la API (documentada por Microsoft, sample rawmemtofile.cpp):
      LoadSavedStateFile(vmrs)  /  LoadSavedStateFiles(bin, vsv)
      GetGuestRawSavedMemorySize(handle) -> tamano total
      ReadGuestRawSavedMemory(handle, offset, buffer, size) -> en bucle
      ReleaseSavedStateFiles(handle)

    Resolucion del DLL (en orden):
      1. -DllPath explicito
      2. Carpeta de herramientas del framework (junto a este script o en
         Volcados\Virtual\vmsavedstate\)
      3. Windows SDK instalado: Windows Kits\10\bin\10.0.*\x64\
      4. PATH del sistema
.PARAMETER SavedStatePath
    Ruta al .vmrs (config >= 6.2) o al .bin (config < 6.2). Obligatorio.
.PARAMETER VsvPath
    Ruta al .vsv (solo cuando SavedStatePath es un .bin). Opcional.
.PARAMETER OutputRaw
    Ruta del archivo .raw de salida. Obligatorio.
.PARAMETER DllPath
    Ruta explicita a vmsavedstatedumpprovider.dll. Opcional.
.NOTES
    Codigos de salida (uno por causa: antes tres causas distintas compartian el
    3 y el framework las diagnosticaba todas como "falta el DLL"):
      0  conversion correcta
      1  error durante la conversion (HRESULT o E/S)
      3  vmsavedstatedumpprovider.dll no encontrado
      4  este proceso de PowerShell es de 32 bits (el proveedor solo existe x64)
      5  el DLL se encontro pero LoadLibrary fallo (dependencias, VC++ runtime)
      6  el archivo de estado guardado de entrada no existe o no es legible
      7  el directorio de salida no existe o no se pudo escribir en el
    Requiere Windows x64. En Windows 7/8 la API no existe (el estado guardado de
    Hyper-V de esos hosts es .bin/.vsv y se convierte en una maquina de analisis
    moderna con el SDK).
#>
param(
    [Parameter(Mandatory=$true)][string]$SavedStatePath,
    [string]$VsvPath = "",
    [Parameter(Mandatory=$true)][string]$OutputRaw,
    [string]$DllPath = ""
)

$ErrorActionPreference = "Stop"

# Directorio del script (capturado a nivel de script; $PSScriptRoot es PS3+,
# esta forma funciona tambien en PowerShell 2.0).
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Colores ANSI solo en Win10 build 10586 o superior. El soporte de secuencias VT
# llego con la 1511, NO con la 10240 de salida ni con la LTSB 2015: en 10240-10585
# mirar solo Major -ge 10 encendia los colores donde la consola no los interpreta y
# se imprimian los codigos de escape crudos. Es el MISMO umbral que usa
# AMBARDFIR.bat para calcular ANSI_OK.
$osv = [Environment]::OSVersion.Version
$vtOk = $false
if ($osv.Major -gt 10) { $vtOk = $true }
if ($osv.Major -eq 10 -and $osv.Build -ge 10586) { $vtOk = $true }
if ($vtOk) {
    $ESC = [char]27
    $CYAN = "$ESC[1;36m"; $YELLOW = "$ESC[1;33m"; $RED = "$ESC[1;31m"
    $GREEN = "$ESC[1;32m"; $DIM = "$ESC[0;90m"; $RESET = "$ESC[0m"
} else {
    $CYAN=''; $YELLOW=''; $RED=''; $GREEN=''; $DIM=''; $RESET=''
}

# El proveedor solo existe en x64. Si este proceso de PowerShell es de 32 bits,
# LoadLibrary devolveria Win32=193 (formato de imagen no valido), un error que no
# dice nada al operador. Se comprueba antes con [IntPtr]::Size, que funciona en
# PowerShell 2.0 (Is64BitProcess es 3.0+).
if ([IntPtr]::Size -ne 8) {
    Write-Host "${RED}[-] Este conversor requiere PowerShell de 64 bits.${RESET}"
    Write-Host "${DIM}    vmsavedstatedumpprovider.dll solo se publica para x64 y no puede${RESET}"
    Write-Host "${DIM}    cargarse en un proceso de 32 bits. Use %SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe${RESET}"
    Write-Host "${DIM}    desde un proceso de 32 bits, o %SystemRoot%\System32\WindowsPowerShell desde uno de 64.${RESET}"
    exit 4
}

# ---------------------------------------------------------------------------
# Validacion de rutas ANTES de tocar la API. Sin esto, un archivo de entrada
# inexistente aparecia como "LoadSavedStateFile fallo (HRESULT=0x...)" -que
# suena a estado guardado corrupto- y un directorio de salida inexistente
# lanzaba una excepcion .NET no capturada (ErrorActionPreference=Stop) que
# volcaba una traza al operador y salia 1, indistinguible de un fallo de
# conversion real.
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $SavedStatePath -PathType Leaf)) {
    Write-Host "${RED}[-] El archivo de estado guardado no existe: $SavedStatePath${RESET}"
    Write-Host "${DIM}    Se esperaba un .vmrs (config >= 6.2) o un .bin (config < 6.2).${RESET}"
    exit 6
}
# ---------------------------------------------------------------------------
# LA SONDA ABRE CON FILE_SHARE_READ|FILE_SHARE_WRITE, NO CON OpenRead.
#
# OpenRead pide unicamente FILE_SHARE_READ, y eso hacia que esta comprobacion
# previa fuese MAS ESTRICTA QUE EL LECTOR AL QUE PROTEGE. Consecuencia medida
# contra una VM real encendida: con un checkpoint estandar activo Hyper-V mantiene el
# .vmrs abierto para escritura, asi que la sonda fallaba y el conversor salia con
# codigo 6 declarando el archivo "no legible" SIN HABER INTENTADO NADA.
#
# Medicion sobre el mismo archivo (checkpoint activo, VM Running):
#     OpenRead / FILE_SHARE_READ ........ falla: "used by another process"
#     FILE_SHARE_READ|FILE_SHARE_WRITE .. abre y lee
#     LoadSavedStateFile (API oficial) .. HRESULT 0x00000000, y
#     GetGuestRawSavedMemorySize ........ 2.654.994.432 bytes de memoria
#
# Es decir: la API SI podia leerlo y la via recomendada de adquisicion de RAM de
# Hyper-V estaba inutilizada por su propia comprobacion. Es la misma clase de
# defecto que ya se corrigio en la adquisicion en caliente de VMware, donde
# qemu-img y HashMyFiles leen extents vivos precisamente porque piden
# FILE_SHARE_WRITE.
#
# La sonda se conserva -sirve para distinguir "no existe / sin permisos / ruta
# invalida" de un fallo de conversion- pero ahora pide lo mismo que el lector.
# ---------------------------------------------------------------------------
try {
    $fsProbe = [System.IO.File]::Open(
        (Resolve-Path -LiteralPath $SavedStatePath).Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite)
    $fsProbe.Close()
} catch {
    Write-Host "${RED}[-] El archivo de estado guardado no es legible: $SavedStatePath${RESET}"
    Write-Host "${DIM}    $($_.Exception.Message)${RESET}"
    exit 6
}
$SavedStatePath = (Resolve-Path -LiteralPath $SavedStatePath).Path
if ($VsvPath) {
    if (-not (Test-Path -LiteralPath $VsvPath -PathType Leaf)) {
        Write-Host "${RED}[-] El .vsv indicado no existe: $VsvPath${RESET}"
        exit 6
    }
    $VsvPath = (Resolve-Path -LiteralPath $VsvPath).Path
}

# [System.IO.File]::Open resuelve rutas relativas contra el directorio actual
# del PROCESO, no contra la ubicacion del script: una invocacion manual con
# ruta relativa -que es la que documenta el propio FORMAT_NOTE.txt- escribiria
# el .raw en un sitio distinto del esperado. Se absolutiza aqui.
$outLeaf = [System.IO.Path]::GetFileName($OutputRaw)
if (-not $outLeaf) {
    Write-Host "${RED}[-] -OutputRaw no incluye un nombre de archivo: $OutputRaw${RESET}"
    exit 7
}
$outDir = [System.IO.Path]::GetDirectoryName($OutputRaw)
if (-not $outDir) { $outDir = (Get-Location).Path }
if (-not (Test-Path -LiteralPath $outDir -PathType Container)) {
    Write-Host "${RED}[-] El directorio de salida no existe: $outDir${RESET}"
    Write-Host "${DIM}    Cree la carpeta destino antes de convertir.${RESET}"
    exit 7
}
$OutputRaw = Join-Path (Resolve-Path -LiteralPath $outDir).Path $outLeaf

# ---------------------------------------------------------------------------
# Resolver la ruta del DLL de la API
# ---------------------------------------------------------------------------
function Resolve-ProviderDll {
    param([string]$Explicit)

    if ($Explicit -and (Test-Path -LiteralPath $Explicit)) { return (Resolve-Path -LiteralPath $Explicit).Path }

    $scriptDir = $script:ScriptDir
    $candidates = @(
        (Join-Path $scriptDir "vmsavedstatedumpprovider.dll"),
        (Join-Path $scriptDir "..\herramientas\Volcados\Virtual\vmsavedstate\vmsavedstatedumpprovider.dll"),
        (Join-Path $scriptDir "..\herramientas\Volcados\Virtual\vm2dump\vmsavedstatedumpprovider.dll")
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { return (Resolve-Path -LiteralPath $c).Path }
    }

    # Windows SDK instalado: tomar la version mas reciente disponible
    $sdkRoots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "${env:ProgramFiles}\Windows Kits\10\bin"
    )
    foreach ($root in $sdkRoots) {
        if (Test-Path -LiteralPath $root) {
            # 'Sort-Object FullName -Descending' es orden de CADENA: "10.0.9..."
            # gana a "10.0.22621..." y se elegia un SDK mas antiguo. Se ordena por
            # la version parseada del segmento 10.0.x.y de la ruta.
            $hits = @(Get-ChildItem -Path $root -Recurse -Filter "vmsavedstatedumpprovider.dll" -ErrorAction SilentlyContinue |
                      Where-Object { $_.FullName -match "\\x64\\" })
            if ($hits.Count -gt 0) {
                $ranked = $hits | ForEach-Object {
                    $v = [version]'0.0.0.0'
                    $m = [regex]::Match($_.FullName, '\\(\d+\.\d+\.\d+(\.\d+)?)\\')
                    if ($m.Success) { try { $v = [version]$m.Groups[1].Value } catch { } }
                    New-Object PSObject -Property @{ Ver = $v; Path = $_.FullName }
                } | Sort-Object -Property Ver -Descending
                return @($ranked)[0].Path
            }
        }
    }

    # PATH del sistema. Una entrada con comillas o con caracteres invalidos para
    # una ruta -habitual en PATH heredados- hace que Join-Path/Test-Path lancen,
    # y con $ErrorActionPreference='Stop' eso mataba el script con una traza en
    # vez del 'exit 3' limpio. Cada entrada se aisla en su propio try/catch.
    $envPath = $env:Path -split ';'
    foreach ($p in $envPath) {
        if ($p) {
            try {
                $pc = $p.Trim().Trim('"')
                if ($pc) {
                    $c = Join-Path $pc "vmsavedstatedumpprovider.dll"
                    if (Test-Path -LiteralPath $c) { return $c }
                }
            } catch { }
        }
    }
    return $null
}

$resolvedDll = Resolve-ProviderDll -Explicit $DllPath
if (-not $resolvedDll) {
    Write-Host "${RED}[-] No se encontro vmsavedstatedumpprovider.dll.${RESET}"
    Write-Host "${DIM}    Es parte del Windows 10/11 SDK. Opciones:${RESET}"
    Write-Host "${DIM}    - Instale el Windows SDK en la maquina de analisis, o${RESET}"
    Write-Host "${DIM}    - Copie vmsavedstatedumpprovider.dll (x64) a:${RESET}"
    Write-Host "${DIM}      Sistema\herramientas\Volcados\Virtual\vmsavedstate\${RESET}"
    exit 3
}

$dllDir = Split-Path -Parent $resolvedDll
Write-Host "${DIM}[i] Proveedor: $resolvedDll${RESET}"

# ---------------------------------------------------------------------------
# P/Invoke de la API VmSavedStateDumpProvider. Se precarga el DLL por ruta
# absoluta con LoadLibrary para que los DllImport (por nombre) resuelvan al
# modulo ya cargado, sin depender de que el DLL este en el directorio actual.
# ---------------------------------------------------------------------------
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class HvSavedState {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetDllDirectory(string lpPathName);

    // VM_SAVED_STATE_DUMP_HANDLE es un puntero opaco -> IntPtr.
    [DllImport("vmsavedstatedumpprovider.dll", CharSet=CharSet.Unicode)]
    public static extern int LoadSavedStateFile(string VmrsFile, out IntPtr Handle);

    [DllImport("vmsavedstatedumpprovider.dll", CharSet=CharSet.Unicode)]
    public static extern int LoadSavedStateFiles(string BinFile, string VsvFile, out IntPtr Handle);

    [DllImport("vmsavedstatedumpprovider.dll")]
    public static extern int GetGuestRawSavedMemorySize(IntPtr Handle, out ulong Size);

    [DllImport("vmsavedstatedumpprovider.dll")]
    public static extern int ReadGuestRawSavedMemory(IntPtr Handle, ulong Offset, byte[] Buffer, uint BufferSize, out uint BytesRead);

    [DllImport("vmsavedstatedumpprovider.dll")]
    public static extern int ReleaseSavedStateFiles(IntPtr Handle);

    public static IntPtr Preload(string dir, string fullPath) {
        SetDllDirectory(dir);
        return LoadLibrary(fullPath);
    }
}
'@ -Language CSharp -ErrorAction Stop

# Precargar el DLL por ruta absoluta
$hMod = [HvSavedState]::Preload($dllDir, $resolvedDll)
if ($hMod -eq [IntPtr]::Zero) {
    $werr = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Host "${RED}[-] Se encontro el DLL pero LoadLibrary fallo (Win32=$werr).${RESET}"
    Write-Host "${DIM}    Ruta: $resolvedDll${RESET}"
    Write-Host "${DIM}    El DLL EXISTE: el fallo es de carga, no de ausencia. Causas habituales:${RESET}"
    Write-Host "${DIM}    falta el runtime de Visual C++ x64, el DLL es de otra arquitectura,${RESET}"
    Write-Host "${DIM}    o requiere componentes de Hyper-V no presentes en este equipo.${RESET}"
    exit 5
}

# ---------------------------------------------------------------------------
# Abrir el estado guardado (.vmrs, o .bin + .vsv)
# ---------------------------------------------------------------------------
$handle = [IntPtr]::Zero
$ext = [System.IO.Path]::GetExtension($SavedStatePath).ToLowerInvariant()

Write-Host "${CYAN}[*] Abriendo estado guardado: $SavedStatePath${RESET}"
$hr = 0
if ($ext -eq ".bin") {
    if (-not $VsvPath -or -not (Test-Path -LiteralPath $VsvPath)) {
        Write-Host "${RED}[-] Para un .bin se requiere tambien su .vsv (parametro -VsvPath).${RESET}"
        exit 1
    }
    $hr = [HvSavedState]::LoadSavedStateFiles($SavedStatePath, $VsvPath, [ref]$handle)
} else {
    # .vmrs (y cualquier otra extension moderna se intenta como vmrs)
    $hr = [HvSavedState]::LoadSavedStateFile($SavedStatePath, [ref]$handle)
}

if ($hr -ne 0 -or $handle -eq [IntPtr]::Zero) {
    Write-Host ("${RED}[-] LoadSavedStateFile fallo (HRESULT=0x{0:X8}).${RESET}" -f $hr)
    exit 1
}

$exitCode = 0
try {
    # Tamano total de la memoria fisica del huesped
    $size = [uint64]0
    $hr = [HvSavedState]::GetGuestRawSavedMemorySize($handle, [ref]$size)
    if ($hr -ne 0 -or $size -eq 0) {
        Write-Host ("${RED}[-] GetGuestRawSavedMemorySize fallo (HRESULT=0x{0:X8}, size=$size).${RESET}" -f $hr)
        $exitCode = 1
    } else {
        $sizeMB = [math]::Round($size / 1MB, 1)
        Write-Host "${CYAN}[*] Memoria fisica del huesped: $size bytes (${sizeMB} MB)${RESET}"
        Write-Host "${CYAN}[*] Escribiendo imagen RAW: $OutputRaw${RESET}"

        $chunk = 2MB
        $buffer = New-Object byte[] $chunk
        $fs = $null
        try {
            $fs = [System.IO.File]::Open($OutputRaw, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
        } catch {
            Write-Host "${RED}[-] No se pudo crear el archivo de salida: $OutputRaw${RESET}"
            Write-Host "${DIM}    $($_.Exception.Message)${RESET}"
            Write-Host "${DIM}    Compruebe permisos de escritura y espacio libre en el destino.${RESET}"
            $exitCode = 7
        }
        # Guarda deliberada: sin ella una excepcion al abrir el destino se
        # propagaba sin capturar y el operador veia una traza de .NET.
        if ($fs) {
        try {
            $offset = [uint64]0
            $lastPct = -1
            while ($offset -lt $size) {
                $toRead = [uint32]([math]::Min([uint64]$chunk, $size - $offset))
                $read = [uint32]0
                $hr = [HvSavedState]::ReadGuestRawSavedMemory($handle, $offset, $buffer, $toRead, [ref]$read)
                if ($hr -ne 0) {
                    Write-Host ("`n${RED}[-] ReadGuestRawSavedMemory fallo en offset $offset (HRESULT=0x{0:X8}).${RESET}" -f $hr)
                    Write-Host "${DIM}    La conversion se aborta: NO se rellena con ceros, porque una imagen${RESET}"
                    Write-Host "${DIM}    completada a base de relleno se presentaria como memoria leida y no lo es.${RESET}"
                    Write-Host "${DIM}    Causa posible en invitados con mas de ~3,5 GB asignados: el hueco MMIO${RESET}"
                    Write-Host "${DIM}    por debajo de 4 GB. Este conversor lee el espacio como un rango unico y${RESET}"
                    Write-Host "${DIM}    contiguo; si su invitado tiene ese hueco, use MemProcFS/LeechCore sobre el${RESET}"
                    Write-Host "${DIM}    .vmrs original, que si enumera los fragmentos fisicos por separado.${RESET}"
                    $exitCode = 1
                    break
                }
                if ($read -eq 0) {
                    Write-Host "`n${YELLOW}[!] Lectura devolvio 0 bytes antes de completar; imagen truncada.${RESET}"
                    $exitCode = 1
                    break
                }
                $fs.Write($buffer, 0, $read)
                $offset += $read

                $pct = [int](($offset * 100) / $size)
                if ($pct -ne $lastPct) {
                    Write-Host -NoNewline ("`r${DIM}    Progreso: $pct% ($offset / $size bytes)${RESET}   ")
                    $lastPct = $pct
                }
            }
            Write-Host ""
        } finally {
            $fs.Close()
        }
        }

        # -------------------------------------------------------------------
        # Comprobacion de que lo escrito es una imagen utilizable, no solo un
        # archivo creado. Sin esto, un disco lleno o un fallo a mitad dejaban un
        # .raw corto y el framework lo anunciaba como exito.
        # -------------------------------------------------------------------
        if ($exitCode -eq 0) {
            $escrito = (Get-Item -LiteralPath $OutputRaw).Length

            if ($escrito -ne $size) {
                Write-Host ("${RED}[-] Imagen incompleta: se escribieron $escrito de $size bytes.${RESET}")
                Write-Host "${DIM}    Compruebe el espacio libre en el destino. La imagen no es utilizable.${RESET}"
                $exitCode = 1
            }
            elseif ($escrito % 4096 -ne 0) {
                # La memoria fisica se vuelca en paginas de 4 KiB; un tamano no
                # alineado indica que la fuente no era un estado guardado valido.
                Write-Host ("${YELLOW}[!] Tamano no alineado a pagina de 4096 bytes ($escrito).${RESET}")
                Write-Host "${DIM}    Se conserva la imagen, pero verifiquela antes de darla por buena.${RESET}"
            }
            # No se intenta adivinar si la imagen "tiene contenido" muestreando
            # paginas: en una VM con mas RAM asignada que usada hay regiones
            # enormes a cero de forma legitima, y un muestreo pequeno las toma
            # por imagen vacia. La unica comprobacion valida de legibilidad es
            # que un analizador lea las estructuras del kernel (Volatility 3
            # windows.info). ESO NO SE HACE AQUI Y EL FRAMEWORK TAMPOCO LO
            # EJECUTA: solo sugiere la linea de comandos. Por eso lo unico que
            # este script puede afirmar del .raw es su tamano y su alineacion,
            # y asi se declara en el archivo .info.txt que acompana a la imagen.
        }

        if ($exitCode -eq 0) {
            # Hash de la imagen convertida, para la cadena de custodia: el .raw es
            # un producto derivado y necesita su propia huella, distinta de la del
            # .vmrs de origen.
            $sha = $null
            try {
                $sha256 = [System.Security.Cryptography.SHA256]::Create()
                $fsh = [System.IO.File]::OpenRead($OutputRaw)
                try   { $sha = ([BitConverter]::ToString($sha256.ComputeHash($fsh))).Replace("-", "").ToLowerInvariant() }
                # Clear() y no Dispose(): en el CLR 2 de PowerShell 2.0 Dispose() no es
                # publico en HashAlgorithm y lanzaria aqui con el hash ya calculado.
                finally { $fsh.Close(); $sha256.Clear() }
            } catch {
                Write-Host "${DIM}[i] No se pudo calcular el SHA-256 de la imagen: $($_.Exception.Message)${RESET}"
            }

            Write-Host "${GREEN}[+] Conversion completada: $OutputRaw${RESET}"
            Write-Host "${DIM}    Tamano : $escrito bytes${RESET}"
            Write-Host "${YELLOW}[i] SUPUESTO DECLARADO: la imagen se ha escrito leyendo el espacio del${RESET}"
            Write-Host "${DIM}    invitado como un rango UNICO y CONTIGUO de 0 a $size. No se ha${RESET}"
            Write-Host "${DIM}    enumerado el mapa de fragmentos fisicos, asi que el desplazamiento en el${RESET}"
            Write-Host "${DIM}    archivo solo equivale a direccion fisica del invitado si ese espacio no${RESET}"
            Write-Host "${DIM}    tiene huecos (invitados con mas de ~3,5 GB suelen tener hueco MMIO).${RESET}"
            Write-Host "${DIM}    Verificado de esta imagen: solo tamano y alineacion a 4096. NO se ha${RESET}"
            Write-Host "${DIM}    comprobado que sea analizable: eso lo decide el analizador, no este script.${RESET}"
            if ($sha) {
                Write-Host "${DIM}    SHA-256: $sha${RESET}"
                $rutaHash = [System.IO.Path]::ChangeExtension($OutputRaw, ".raw.sha256")
                try {
                    Set-Content -LiteralPath $rutaHash -Value "$sha  $([System.IO.Path]::GetFileName($OutputRaw))" -Encoding ASCII
                    Write-Host "${DIM}    Huella escrita en: $rutaHash${RESET}"
                } catch {
                    Write-Host "${DIM}[i] No se pudo escribir el archivo de huella: $($_.Exception.Message)${RESET}"
                }
            }

            # El supuesto de disposicion de la memoria y el alcance real de lo
            # verificado tienen que viajar CON la imagen, no solo por pantalla:
            # quien la analice meses despues no vera esta consola.
            $rutaInfo = [System.IO.Path]::ChangeExtension($OutputRaw, ".raw.info.txt")
            try {
                $info = @()
                $info += "ARTEFACTO DERIVADO - imagen de memoria del invitado convertida"
                $info += "Origen              : $SavedStatePath"
                if ($VsvPath) { $info += "Origen (.vsv)       : $VsvPath" }
                $info += "Salida              : $OutputRaw"
                $info += "Tamano              : $escrito bytes"
                if ($sha) { $info += "SHA-256 de la salida: $sha" }
                $info += "Convertido UTC      : $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss'))"
                $info += "API                 : VmSavedStateDumpProvider (Microsoft) - $resolvedDll"
                $info += ""
                $info += "SUPUESTO DECLARADO SOBRE LA DISPOSICION DE LA MEMORIA:"
                $info += "  La imagen se produjo leyendo GetGuestRawSavedMemorySize y volcando el"
                $info += "  rango completo de forma secuencial, es decir tratando el espacio fisico"
                $info += "  del invitado como UN SOLO bloque contiguo. NO se enumero el mapa de"
                $info += "  fragmentos fisicos que la API tambien expone. Consecuencia: el"
                $info += "  desplazamiento dentro de este archivo equivale a direccion fisica del"
                $info += "  invitado UNICAMENTE si ese espacio no contiene huecos. Los invitados con"
                $info += "  mas de unos 3,5 GB asignados suelen tener un hueco MMIO por debajo de"
                $info += "  4 GB; en esos casos las direcciones pueden estar desplazadas y conviene"
                $info += "  analizar el .vmrs original con MemProcFS/LeechCore, que si enumera los"
                $info += "  fragmentos por separado."
                $info += ""
                $info += "ALCANCE DE LO VERIFICADO EN ESTA IMAGEN:"
                $info += "  - Los bytes escritos coinciden con el tamano anunciado por la API."
                $info += "  - El tamano esta alineado a pagina de 4096 bytes (o se advirtio si no)."
                $info += "  NO se ha comprobado que la imagen sea analizable. Para comprobarlo hay que"
                $info += "  ejecutar un analizador, por ejemplo:"
                $info += "     vol.py -f ""$OutputRaw"" windows.info"
                $info += "  Ni este script ni el framework ejecutan Volatility: solo lo sugieren."
                Set-Content -LiteralPath $rutaInfo -Value $info -Encoding ASCII
                Write-Host "${DIM}    Supuestos y alcance en: $rutaInfo${RESET}"
            } catch {
                Write-Host "${DIM}[i] No se pudo escribir el archivo de supuestos: $($_.Exception.Message)${RESET}"
            }
        }
    }
} finally {
    [HvSavedState]::ReleaseSavedStateFiles($handle) | Out-Null
}

exit $exitCode
