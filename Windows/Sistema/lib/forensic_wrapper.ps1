#Requires -Version 2.0
<#
.SYNOPSIS
    Wrapper forense con proteccion CTRL+C para herramientas de adquisicion.
.DESCRIPTION
    Inicia la herramienta forense en un grupo de proceso aislado (CREATE_NEW_PROCESS_GROUP)
    para que CTRL+C del teclado no llegue directamente a la herramienta.
    Intercepta la senal via SetConsoleCtrlHandler, muestra dialogo de confirmacion,
    y solo termina el proceso si el usuario lo confirma explicitamente.
    Codigos de salida: 0=exitoso, 1=error, 2=abortado por usuario.
#>
param(
    [Parameter(Mandatory=$true)][string]$CmdFile,
    [string]$Description = "Adquisicion forense",
    [string]$CmdCodePage = "",
    # Idioma de la interfaz que eligio el operador en AMBARDFIR.bat (ES o EN). El
    # dialogo de CTRL+C es el mas critico del framework y salia siempre en espanol.
    [string]$Lang = "ES"
)

# Texto segun idioma. Funcion simple y no hashtable de recursos: son pocos
# mensajes y asi cada uno se lee en su sitio. Compatible con PowerShell 2.0.
function T([string]$es, [string]$en) { if ($Lang -eq "EN") { $en } else { $es } }

# Colores ANSI solo en Win10 build 10586+ (el soporte de secuencias VT se anadio
# en 1511, NO en la 10240 de salida ni en la LTSB 2015). Mirar solo Major -ge 10
# encendia los colores en 10240-10585, donde la consola NO interpreta VT: el
# operador veia los codigos de escape crudos justo en el dialogo de aborto de
# CTRL+C, el momento en que el mensaje mas importa. El umbral es el MISMO que
# aplica AMBARDFIR.bat para calcular ANSI_OK.
$osv = [Environment]::OSVersion.Version
$vtOk = $false
if ($osv.Major -gt 10) { $vtOk = $true }
if ($osv.Major -eq 10 -and $osv.Build -ge 10586) { $vtOk = $true }
if ($vtOk) {
    $ESC     = [char]27
    $CYAN    = "${ESC}[1;36m"
    $YELLOW  = "${ESC}[1;33m"
    $RED     = "${ESC}[1;31m"
    $GREEN   = "${ESC}[1;32m"
    $RESET   = "${ESC}[0m"
} else {
    $CYAN = ''; $YELLOW = ''; $RED = ''; $GREEN = ''; $RESET = ''
}

# ---------------------------------------------------------------------------
# Tipos P/Invoke: SetConsoleCtrlHandler + CreateProcess + WaitForSingleObject
# ---------------------------------------------------------------------------
# Add-Type en try/catch, igual que launch_noctrlc.ps1: si la compilacion en C#
# no es posible (.NET inaccesible, politica que bloquea Add-Type, csc.exe ausente)
# el wrapper moria con una traza de PowerShell y el framework reportaba
# "adquisicion fallida" sin decir por que. Con exit 99 el .bat sabe que el comando
# NI SE LANZO -el archivo temporal sigue intacto- y lo repite por la via degradada
# en vez de dar por fallida una adquisicion que nunca empezo.
try {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class ForensicCtrl {

    // --- CTRL+C interception ---
    public delegate bool CtrlHandlerDelegate(uint ctrlType);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetConsoleCtrlHandler(CtrlHandlerDelegate handler, bool add);

    // Overload IntPtr para manipular el FLAG "ignorar CTRL+C" del proceso
    // (NULL+TRUE = ignorar, NULL+FALSE = procesar). Es un atributo separado de
    // la lista de handlers y se HEREDA de launch_noctrlc.ps1.
    [DllImport("kernel32.dll", SetLastError=true, EntryPoint="SetConsoleCtrlHandler")]
    public static extern bool SetConsoleCtrlFlag(IntPtr handler, bool add);

    private static CtrlHandlerDelegate _ctrlHandler;
    public  static volatile bool Interrupted = false;

    private static bool OnCtrl(uint ctrlType) {
        if (ctrlType == 0 || ctrlType == 1) { // CTRL_C_EVENT or CTRL_BREAK_EVENT
            Interrupted = true;
            return true; // consumed - do not propagate to default handler
        }
        return false;
    }

    public static void RegisterHandler() {
        // CRITICO: este proceso HEREDA el flag "ignorar CTRL+C" del lanzador
        // (launch_noctrlc.ps1). Con ese flag activo Windows NUNCA invoca los
        // handlers registrados -> CTRL+C parece muerto durante la adquisicion.
        // Registrar un handler NO limpia el flag: hay que limpiarlo explicito.
        SetConsoleCtrlFlag(IntPtr.Zero, false);
        _ctrlHandler = new CtrlHandlerDelegate(OnCtrl);
        SetConsoleCtrlHandler(_ctrlHandler, true);
    }
    public static void UnregisterHandler() {
        SetConsoleCtrlHandler(_ctrlHandler, false);
        // Restaurar "ignorar CTRL+C" para el resto de vida del proceso: evita
        // que un CTRL+C tardio mate al wrapper durante la limpieza final.
        SetConsoleCtrlFlag(IntPtr.Zero, true);
    }
    public static void ResetInterrupt()    { Interrupted = false; }

    // --- CreateProcess ---
    // STARTUPINFO con alineamiento NATURAL (portable x86 y x64).
    // No se usa padding manual: el marshaller de .NET inserta el relleno
    // correcto segun el tamano real de IntPtr (4 bytes en x86, 8 en x64).
    // En x64 el struct mide 104 bytes; en x86 mide 68 bytes. En ambos casos
    // si.cb = Marshal.SizeOf(...) calcula el valor correcto en tiempo de ejecucion.
    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO {
        public  int    cb;            // DWORD
        public  IntPtr lpReserved;    // LPWSTR
        public  IntPtr lpDesktop;     // LPWSTR
        public  IntPtr lpTitle;       // LPWSTR
        public  int    dwX;           // DWORD
        public  int    dwY;           // DWORD
        public  int    dwXSize;       // DWORD
        public  int    dwYSize;       // DWORD
        public  int    dwXCountChars; // DWORD
        public  int    dwYCountChars; // DWORD
        public  int    dwFillAttribute; // DWORD
        public  int    dwFlags;       // DWORD
        public  short  wShowWindow;   // WORD
        public  short  cbReserved2;   // WORD
        public  IntPtr lpReserved2;   // LPBYTE
        public  IntPtr hStdInput;     // HANDLE
        public  IntPtr hStdOutput;    // HANDLE
        public  IntPtr hStdError;     // HANDLE
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int    dwProcessId;
        public int    dwThreadId;
    }

    const uint CREATE_NEW_PROCESS_GROUP = 0x00000200;

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CreateProcessW(
        string              lpApplicationName,
        StringBuilder       lpCommandLine,
        IntPtr              lpProcessAttributes,
        IntPtr              lpThreadAttributes,
        bool                bInheritHandles,
        uint                dwCreationFlags,
        IntPtr              lpEnvironment,
        string              lpCurrentDirectory,
        ref STARTUPINFO     lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll")]
    public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll")]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    // --- Suspend/Resume process (ntdll) ---
    [DllImport("ntdll.dll")]
    public static extern int NtSuspendProcess(IntPtr hProcess);
    [DllImport("ntdll.dll")]
    public static extern int NtResumeProcess(IntPtr hProcess);

    // -----------------------------------------------------------------------
    // ARBOL DE PROCESOS (Toolhelp32). El wrapper lanza "cmd.exe /d /s /c <tool>":
    // el handle que guardamos es el de cmd, pero la herramienta real (dd,
    // robocopy, adb...) es un NIETO. Suspender/matar solo a cmd deja a la
    // herramienta viva: sigue escribiendo encima del dialogo y la adquisicion
    // continua aunque el operador aborte. Estas funciones aplican la accion a
    // TODOS los descendientes.
    // -----------------------------------------------------------------------
    const uint TH32CS_SNAPPROCESS    = 0x00000002;
    const uint PROCESS_SUSPEND_RESUME = 0x0800;
    const uint PROCESS_TERMINATE      = 0x0001;

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct PROCESSENTRY32W {
        public uint   dwSize;
        public uint   cntUsage;
        public uint   th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint   th32ModuleID;
        public uint   cntThreads;
        public uint   th32ParentProcessID;
        public int    pcPriClassBase;
        public uint   dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
    static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
    static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    // BFS: raiz primero, luego hijos, nietos, etc.
    static List<uint> GetProcessTree(uint rootPid) {
        List<uint> result = new List<uint>();
        result.Add(rootPid);
        IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == IntPtr.Zero || snap == new IntPtr(-1)) return result;
        List<uint[]> pairs = new List<uint[]>();
        PROCESSENTRY32W pe = new PROCESSENTRY32W();
        pe.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32W));
        if (Process32FirstW(snap, ref pe)) {
            do {
                pairs.Add(new uint[] { pe.th32ProcessID, pe.th32ParentProcessID });
            } while (Process32NextW(snap, ref pe));
        }
        CloseHandle(snap);
        int i = 0;
        while (i < result.Count) {
            uint parent = result[i]; i++;
            foreach (uint[] p in pairs) {
                if (p[1] == parent && p[0] != parent && !result.Contains(p[0]))
                    result.Add(p[0]);
            }
        }
        return result;
    }

    public static void SuspendTree(int rootPid) {
        List<uint> pids = GetProcessTree((uint)rootPid);
        foreach (uint pid in pids) {
            IntPtr h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
            if (h != IntPtr.Zero) { NtSuspendProcess(h); CloseHandle(h); }
        }
    }

    public static void ResumeTree(int rootPid) {
        List<uint> pids = GetProcessTree((uint)rootPid);
        foreach (uint pid in pids) {
            IntPtr h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
            if (h != IntPtr.Zero) { NtResumeProcess(h); CloseHandle(h); }
        }
    }

    // Mata la raiz (cmd) PRIMERO para que no lance el siguiente comando de una
    // cadena "a & b", y despues a todos los descendientes (dd, robocopy...).
    public static void KillTree(int rootPid) {
        List<uint> pids = GetProcessTree((uint)rootPid);
        foreach (uint pid in pids) {
            IntPtr h = OpenProcess(PROCESS_TERMINATE, false, pid);
            if (h != IntPtr.Zero) { TerminateProcess(h, 1); CloseHandle(h); }
        }
    }

    /// <summary>
    /// Starts a process in a new process group (isolated from parent console CTRL+C).
    /// Returns the process handle (caller must CloseHandle), sets pid. IntPtr.Zero on failure.
    /// </summary>
    public static IntPtr StartIsolated(string fullCommandLine, out int pid) {
        pid = -1;
        var si  = new STARTUPINFO();
        si.cb   = System.Runtime.InteropServices.Marshal.SizeOf(typeof(STARTUPINFO));
        PROCESS_INFORMATION pi;
        var buf = new StringBuilder(fullCommandLine.Length + 4);
        buf.Append(fullCommandLine);
        bool ok = CreateProcessW(
            null, buf,
            IntPtr.Zero, IntPtr.Zero,
            true,                          // bInheritHandles - child writes to our console
            CREATE_NEW_PROCESS_GROUP,      // isolated from keyboard CTRL+C
            IntPtr.Zero, null,
            ref si, out pi);
        if (!ok) return IntPtr.Zero;
        pid = pi.dwProcessId;
        CloseHandle(pi.hThread);
        return pi.hProcess;
    }
}
'@ -Language CSharp -ErrorAction Stop
}
catch {
    Write-Host "${YELLOW}[WRAPPER] $(T "No se pudieron compilar los tipos P/Invoke" "Could not compile the P/Invoke types"): $($_.Exception.Message)${RESET}"
    Write-Host "${YELLOW}[WRAPPER] $(T "La proteccion de CTRL+C no esta disponible en este host." "CTRL+C protection is not available on this host.")${RESET}"
    exit 99
}

# ---------------------------------------------------------------------------
# Leer linea de comando del archivo temporal
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $CmdFile)) {
    Write-Host "${RED}[WRAPPER-ERROR] $(T "Archivo de comando no encontrado" "Command file not found"): $CmdFile${RESET}"
    exit 1
}
# El archivo lo escribe cmd.exe con 'echo >': los bytes salen en la pagina de
# codigos ACTIVA DE LA CONSOLA, no en la OEM del sistema. Medido: con la consola
# en 65001 la ene se escribe C3 B1 (UTF-8) y con la consola en 850 se escribe A4.
# AMBARDFIR.bat pone la consola en UTF-8, asi que dar por hecha la pagina OEM
# corrompia toda ruta con tilde o ene (C:\Maquinas\nino, usuarios con acento) y la
# herramienta atacaba una ruta inexistente. El .bat pasa en -CmdCodePage la pagina
# que quedo REALMENTE activa -no la que pidio, porque en XP el cambio no surte
# efecto-. Si no llega nada utilizable se cae a la OEM, que es el comportamiento
# de una consola sin chcp. Compatible con PowerShell 2.0.
$cmdEnc = $null
if ($CmdCodePage -match '^[0-9]+$') {
    try { $cmdEnc = [System.Text.Encoding]::GetEncoding([int]$CmdCodePage) } catch { $cmdEnc = $null }
}
if ($cmdEnc -eq $null) {
    $cmdEnc = [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
}
$cmdLines = [System.IO.File]::ReadAllLines($CmdFile, $cmdEnc)
# Eliminar el archivo temporal inmediatamente tras leerlo (contiene rutas de evidencia)
Remove-Item -LiteralPath $CmdFile -Force -ErrorAction SilentlyContinue
# Comprobar que hay linea ANTES de indexar: con un archivo de 0 bytes (disco
# lleno, redireccion fallida) el indice [0] lanzaba IndexOutOfRange y el guard
# de "archivo vacio" de mas abajo era codigo inalcanzable.
if ($cmdLines.Count -eq 0) {
    Write-Host "${RED}[WRAPPER-ERROR] $(T "Archivo de comando vacio." "Command file is empty.")${RESET}"
    exit 1
}
$cmdLine = $cmdLines[0].Trim()
# No se usa [string]::IsNullOrWhiteSpace: existe desde .NET 4.0 y en un Windows 7
# con PowerShell 2.0 (CLR 2.0) lanza "Method invocation failed", rompiendo TODA
# adquisicion en el mismo sistema que el resto del script declara soportar.
if ($cmdLine -eq $null -or $cmdLine -eq '') {
    Write-Host "${RED}[WRAPPER-ERROR] $(T "Archivo de comando vacio." "Command file is empty.")${RESET}"
    exit 1
}

# ---------------------------------------------------------------------------
# Registrar interceptor CTRL+C y lanzar proceso aislado
# ---------------------------------------------------------------------------
[ForensicCtrl]::RegisterHandler()

Write-Host ""
Write-Host "${CYAN}[WRAPPER] $Description${RESET}"
Write-Host "${CYAN}[i] $(T "Modo DFIR: proceso aislado de CTRL+C. Confirmacion requerida para abortar." "DFIR mode: process isolated from CTRL+C. Confirmation required to abort.")${RESET}"
Write-Host ""

$procPid  = 0
# /d: sin /d, cmd ejecuta el comando de HKCU/HKLM\Software\Microsoft\Command Processor\AutoRun
# antes de la herramienta. En un equipo comprometido eso es codigo del host corriendo
# dentro de cada adquisicion, justo lo que el framework evita en el resto de su diseno.
$hProcess = [ForensicCtrl]::StartIsolated("cmd.exe /d /s /c `"$cmdLine`"", [ref]$procPid)

if ($hProcess -eq [IntPtr]::Zero -or $procPid -le 0) {
    $win32err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Host "${RED}[WRAPPER-ERROR] $(T "CreateProcess fallo." "CreateProcess failed.") Win32 error: $win32err${RESET}"
    [ForensicCtrl]::UnregisterHandler()
    exit 1
}

$aborted  = $false
$exitCode = 0

# ---------------------------------------------------------------------------
# Bucle de monitorizacion - poll 300ms, revisar Interrupted flag
# ---------------------------------------------------------------------------
:monitorLoop while ($true) {
    # WAIT_OBJECT_0 = 0x0 (proceso termino), WAIT_TIMEOUT = 0x102
    $waitResult = [ForensicCtrl]::WaitForSingleObject($hProcess, 300)

    if ($waitResult -eq 0) {
        # Proceso termino normalmente
        $rawCode = [uint32]0
        [ForensicCtrl]::GetExitCodeProcess($hProcess, [ref]$rawCode) | Out-Null
        # $rawCode es [uint32]: herramientas como WinPmem pueden devolver 0xFFFFFFFF
        # (4294967295), que desborda Int32. El CONTRATO de salida de este wrapper es
        # 0/1/2 y no puede cambiarse: :ACQUIRE y sus ~30 llamadas interpretan el 2 como
        # "abortado por el operador", asi que una herramienta que devolviera 2 pasaria
        # por cancelada. Pero aplastar el codigo a 1 PERDIA informacion real:
        # ewfacquire, ftkimager, dc3dd y qemu-img distinguen tipos de fallo por codigo
        # y eso no llegaba a la cadena de custodia. Se conserva el contrato Y se
        # publica el codigo REAL en un canal aparte: un archivo "<CmdFile>.rc" que
        # :ACQUIRE lee y registra. [IO.File]::WriteAllText es compatible con PS 2.0.
        if ($rawCode -eq [uint32]0) { $exitCode = 0 } else { $exitCode = 1 }
        try { [System.IO.File]::WriteAllText("$CmdFile.rc", [string]$rawCode) } catch { }
        break monitorLoop
    }

    if ([ForensicCtrl]::Interrupted) {
        [ForensicCtrl]::ResetInterrupt()

        # Suspender el ARBOL COMPLETO (cmd + dd/robocopy/adb...) para que deje
        # de escribir en la consola mientras se muestra el dialogo. Suspender
        # solo el cmd hijo NO detiene a la herramienta real (nieto): seguiria
        # pisando el dialogo y la adquisicion continuaria.
        [ForensicCtrl]::SuspendTree($procPid)

        # try/catch obligatorio: si PromptForChoice falla (host no interactivo,
        # stdin redirigido) el arbol quedaria SUSPENDIDO para siempre, con la
        # herramienta reteniendo el archivo de evidencia a medio escribir y sin
        # forma de continuar ni abortar. Ante cualquier fallo se reanuda y se
        # continua la adquisicion, que es la opcion segura en DFIR.
        $decision = 0
        try {

        Write-Host ""
        Write-Host "${YELLOW}==========================================================${RESET}"
        Write-Host "${YELLOW} [!] $(T "SOLICITUD DE INTERRUPCION DETECTADA" "INTERRUPT REQUEST DETECTED") (CTRL+C / BREAK) ${RESET}"
        Write-Host "${YELLOW}     $(T "Herramienta" "Tool"): $Description${RESET}"
        Write-Host "${RED}     $(T "ADVERTENCIA: Abortar ahora dejara la evidencia INCOMPLETA." "WARNING: Aborting now will leave the evidence INCOMPLETE.")${RESET}"
        Write-Host "${RED}     $(T "Una imagen parcial puede ser inadmisible en procedimiento judicial." "A partial image may be inadmissible in legal proceedings.")${RESET}"
        Write-Host "${YELLOW}==========================================================${RESET}"
        Write-Host ""

        # New-Object (no ::new) para compatibilidad con PowerShell 2.0/3.0/4.0 (Win7/8).
        $choices = [System.Management.Automation.Host.ChoiceDescription[]] @(
            (New-Object System.Management.Automation.Host.ChoiceDescription `
                (T "&Continuar" "&Continue"),
                (T "Ignorar la interrupcion y continuar la adquisicion (RECOMENDADO para DFIR)" "Ignore the interrupt and continue the acquisition (RECOMMENDED for DFIR)")),
            (New-Object System.Management.Automation.Host.ChoiceDescription `
                (T "&Abortar" "&Abort"),
                (T "Terminar el proceso ahora (la evidencia quedara INCOMPLETA)" "Terminate the process now (the evidence will be INCOMPLETE)"))
        )
        $decision = $Host.UI.PromptForChoice(
            (T "INTERRUPCION FORENSE" "FORENSIC INTERRUPT"),
            (T "Desea continuar la adquisicion o abortarla?" "Continue the acquisition or abort it?"),
            $choices,
            0   # default: Continuar
        )

        }
        catch {
            Write-Host "${YELLOW}[i] $(T "No se pudo mostrar el dialogo de confirmacion" "Could not show the confirmation dialog") ($($_.Exception.Message)).${RESET}"
            Write-Host "${YELLOW}[i] $(T "Se CONTINUA la adquisicion para no dejar la evidencia a medias." "The acquisition CONTINUES so the evidence is not left half-written.")${RESET}"
            $decision = 0
        }

        if ($decision -eq 1) {
            Write-Host ""
            Write-Host "${RED}[ABORT] $(T "Terminando proceso forense a solicitud del usuario..." "Terminating the forensic process at the operator request...")${RESET}"
            Write-Host "${RED}[-] $(T "DOCUMENTAR en cadena de custodia: evidencia puede estar incompleta." "RECORD in the chain of custody: the evidence may be incomplete.")${RESET}"
            # Matar el ARBOL COMPLETO: cmd primero (no encadena mas comandos) y
            # despues la herramienta real. TerminateProcess funciona suspendido.
            [ForensicCtrl]::KillTree($procPid)
            [ForensicCtrl]::WaitForSingleObject($hProcess, 5000) | Out-Null
            $aborted = $true
            # El codigo real de una herramienta terminada a la fuerza no dice nada de
            # su resultado: se declara la causa, no un numero que induciria a error.
            try { [System.IO.File]::WriteAllText("$CmdFile.rc", "ABORTADO_POR_OPERADOR") } catch { }
            break monitorLoop
        } else {
            # Reanudar el arbol completo tras confirmar que el operador continua
            [ForensicCtrl]::ResumeTree($procPid)
            Write-Host ""
            Write-Host "${GREEN}[OK] $(T "Adquisicion continuando - interrupcion ignorada." "Acquisition continuing - interrupt ignored.")${RESET}"
            Write-Host ""
        }
    }
}

[ForensicCtrl]::CloseHandle($hProcess) | Out-Null
[ForensicCtrl]::UnregisterHandler()

if ($aborted)       { exit 2 }
if ($exitCode -ne 0){ exit 1 }
exit 0
