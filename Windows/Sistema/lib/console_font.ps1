#Requires -Version 2.0
<#
.SYNOPSIS
    Agranda la letra de la consola y maximiza la ventana del framework.
.DESCRIPTION
    El framework se presenta en proyector, donde la letra por defecto de la consola
    (16 px) queda ilegible a distancia. Se sube a 22 px con SetCurrentConsoleFontEx.

    RESTRICCION QUE MANDA SOBRE EL TAMANO: la interfaz tiene un lienzo FIJO de 74
    columnas (PANEL_W en el .bat). Una letra mas grande reduce las columnas que caben
    en la pantalla fisica, asi que un tamano elegido a ciegas partiria los marcos y
    los menus. Por eso NO se fija 22 px a la fuerza: se pide 22 y, si con ese cuerpo
    no caben 74 columnas, se baja al siguiente tamano de la lista hasta que caben.
    Se prefiere una letra algo menor a una interfaz rota.

    DEGRADACION: SetCurrentConsoleFontEx aparece en Windows Vista. En XP no existe y
    la llamada falla; el script lo detecta, no toca nada y sale con codigo 0 para que
    el arranque continue. La letra pequena es un inconveniente estetico, no un fallo
    de adquisicion: nada de lo que hace este script afecta a la evidencia.

    Traza opcional: si FORENSIC_FONT_DEBUG esta definida se imprime lo que se midio
    y lo que se aplico. Sin ella no escribe nada en pantalla.
.NOTES
    Los campos de CONSOLE_FONT_INFOEX que el API declara SHORT se marcan [int16].
    "[short]" NO es un acelerador de tipo de PowerShell: usarlo hace que el script
    falle en silencio, lo que ya costo una depuracion en este proyecto.
#>

$ErrorActionPreference = 'Stop'
$traza = [bool]$env:FORENSIC_FONT_DEBUG
function Decir($m) { if ($traza) { Write-Host "[fuente] $m" } }

# Columnas que la interfaz necesita, y tamanos candidatos de mayor a menor.
$COLUMNAS_MIN = 74
$CANDIDATOS   = @(22, 20, 18, 16)

try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class ConsolaFuente {

    public const int STD_OUTPUT_HANDLE = -11;
    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint FILE_SHARE_READ = 1;
    public const uint FILE_SHARE_WRITE = 2;
    public const uint OPEN_EXISTING = 3;

    [StructLayout(LayoutKind.Sequential)]
    public struct COORD { public short X; public short Y; }

    // El API declara FaceName como WCHAR[32]; se marshalea con tamano fijo para que
    // el struct mida lo que espera el kernel. Un tamano distinto lo rechaza entero.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CONSOLE_FONT_INFOEX {
        public uint  cbSize;
        public uint  nFont;
        public COORD dwFontSize;
        public uint  FontFamily;
        public uint  FontWeight;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string FaceName;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetStdHandle(int nStdHandle);

    // Se abre CONOUT$ explicitamente: cuando la salida esta redirigida, el handle
    // estandar NO es la consola y SetCurrentConsoleFontEx falla con ERROR_INVALID_HANDLE.
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess,
        uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetCurrentConsoleFontEx(IntPtr hConsoleOutput,
        bool bMaximumWindow, ref CONSOLE_FONT_INFOEX lpConsoleCurrentFontEx);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetCurrentConsoleFontEx(IntPtr hConsoleOutput,
        bool bMaximumWindow, ref CONSOLE_FONT_INFOEX lpConsoleCurrentFontEx);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern COORD GetLargestConsoleWindowSize(IntPtr hConsoleOutput);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    public static IntPtr AbrirConsola() {
        return CreateFileW("CONOUT$", GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero,
                           OPEN_EXISTING, 0, IntPtr.Zero);
    }
}
'@ -Language CSharp
}
catch {
    Decir "Add-Type fallo: $($_.Exception.Message). No se cambia la letra."
    exit 0
}

# --- 1) Maximizar la ventana (3 = SW_MAXIMIZE) --------------------------------
# Va antes de medir columnas: el tamano de ventana maximo depende de la ventana ya
# maximizada, no de la que habia al arrancar.
try {
    $hw = [ConsolaFuente]::GetConsoleWindow()
    if ($hw -ne [IntPtr]::Zero) { [void][ConsolaFuente]::ShowWindow($hw, 3) }
    Decir "ventana maximizada"
} catch { Decir "no se pudo maximizar: $($_.Exception.Message)" }

# --- 2) Abrir la consola real ------------------------------------------------
$h = [IntPtr]::Zero
try { $h = [ConsolaFuente]::AbrirConsola() } catch { }
if ($h -eq [IntPtr]::Zero -or $h -eq [IntPtr](-1)) {
    Decir "no hay consola accesible (salida redirigida?). No se cambia la letra."
    exit 0
}

try {
    $f = New-Object ConsolaFuente+CONSOLE_FONT_INFOEX
    $f.cbSize = [uint32][Runtime.InteropServices.Marshal]::SizeOf($f)
    if (-not [ConsolaFuente]::GetCurrentConsoleFontEx($h, $false, [ref]$f)) {
        Decir "GetCurrentConsoleFontEx no disponible (Windows XP?). Se deja la letra actual."
        exit 0   # el finally cierra el handle
    }
    Decir ("letra actual: '{0}' {1}x{2}" -f $f.FaceName, $f.dwFontSize.X, $f.dwFontSize.Y)

    # Se guarda la letra completa: restaurar solo el tamano dejaba la cara Consolas.
    $original = $f
    $aplicado = $null

    foreach ($px in $CANDIDATOS) {
        # El COORD se rellena en su propia variable y se asigna entero: $f.dwFontSize.Y
        # escribe en una COPIA del struct anidado (medido: el alto se quedaba en 0).
        $c = New-Object ConsolaFuente+COORD
        $c.X = [int16]0     # 0 = ancho que corresponda al alto pedido
        $c.Y = [int16]$px
        $f.dwFontSize = $c
        # Consolas es monoespaciada y viaja con Windows desde Vista; con FaceName
        # vacio el kernel puede caer en una fuente raster que ignora el tamano.
        $f.FaceName   = 'Consolas'
        $f.FontFamily = 54          # FF_MODERN | TMPF_TRUETYPE | TMPF_FIXED_PITCH
        $f.FontWeight = 400

        if (-not [ConsolaFuente]::SetCurrentConsoleFontEx($h, $false, [ref]$f)) {
            Decir "$px px rechazado por el sistema"
            continue
        }
        $max = [ConsolaFuente]::GetLargestConsoleWindowSize($h)
        Decir ("$px px -> caben {0} columnas x {1} filas" -f $max.X, $max.Y)
        if ($max.X -ge $COLUMNAS_MIN) { $aplicado = $px; break }
        Decir "$px px deja menos de $COLUMNAS_MIN columnas: se prueba uno menor"
    }

    if (-not $aplicado) {
        # Ningun candidato sirvio: se restaura la letra original para no dejar la
        # consola en un estado intermedio elegido por un intento fallido.
        [void][ConsolaFuente]::SetCurrentConsoleFontEx($h, $false, [ref]$original)
        Decir "ningun tamano permite $COLUMNAS_MIN columnas: se restaura el original"
        exit 0
    }

    # --- 3) Volver a maximizar ------------------------------------------------
    # NO se toca el ancho del bufer ni el de la ventana a proposito. El lienzo de 74
    # columnas ya es fijo dentro del framework, precisamente para convivir con una
    # ventana maximizada mas ancha; forzar la ventana a 74 columnas cambiaria el
    # aspecto que el framework ya tiene resuelto, y reducir el bufer por debajo de la
    # ventana actual lo rechaza el API ("size specified is too large or too small").
    # Lo que si hace falta es remaximizar: al cambiar el cuerpo de la letra, Windows
    # conserva el tamano en pixeles de la ventana, de modo que quedaria mas pequena en
    # filas y columnas de las que permite la pantalla.
    try {
        $hw = [ConsolaFuente]::GetConsoleWindow()
        if ($hw -ne [IntPtr]::Zero) { [void][ConsolaFuente]::ShowWindow($hw, 3) }
    } catch { }

    Decir "aplicado: $aplicado px"
}
catch {
    Decir "fallo inesperado: $($_.Exception.Message)"
}
finally {
    if ($h -ne [IntPtr]::Zero -and $h -ne [IntPtr](-1)) { [void][ConsolaFuente]::CloseHandle($h) }
}
exit 0
