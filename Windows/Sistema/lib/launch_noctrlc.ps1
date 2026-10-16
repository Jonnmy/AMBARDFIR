#Requires -Version 2.0
<#
.SYNOPSIS
    Lanzador que aisla CTRL+C del interprete de comandos (cmd.exe) del framework.
.DESCRIPTION
    Cuando el usuario pulsa CTRL+C durante una adquisicion, el evento llega a TODOS
    los procesos de la consola, incluido el cmd.exe que ejecuta AMBARDFIR.bat.
    cmd.exe responde con el prompt "Terminate batch job (Y/N)?" y, si el usuario
    contesta Y, sale del framework por completo.

    Este lanzador llama a SetConsoleCtrlHandler(NULL, TRUE) para que ESTE proceso
    IGNORE CTRL+C. Ese atributo se HEREDA por los procesos hijos, de modo que el
    cmd.exe del menu (lanzado aqui) tambien lo ignora -> no aparece el prompt
    "Terminate batch job". El wrapper de adquisicion (nieto) anade su PROPIO handler
    con SetConsoleCtrlHandler(handler, TRUE), que se ejecuta ANTES en la cadena LIFO,
    por lo que SIGUE recibiendo y gestionando CTRL+C con su dialogo de confirmacion.

    Codigos de salida:
        0..N  codigo de salida real del cmd hijo (uso normal)
        99    fallo del lanzador (Add-Type/CreateProcess) -> el .bat debe continuar
              en modo degradado (sin aislamiento de CTRL+C).
.NOTES
    Compatibilidad: requiere PowerShell 2.0+ (Add-Type). Si no esta disponible, el
    .bat omite este paso (degradacion elegante en sistemas antiguos como Windows XP
    sin Windows Management Framework).
#>
param(
    [Parameter(Mandatory=$true)][string]$Bat
)

try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class NoCtrlCLauncher {

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);

    // Alineamiento NATURAL (sin Pack ni padding manual): el marshaller de .NET
    // inserta el relleno correcto segun IntPtr (4 bytes x86, 8 bytes x64).
    // Portable a Windows de 32 y 64 bits.
    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO {
        public  int    cb;
        private IntPtr lpReserved;
        private IntPtr lpDesktop;
        private IntPtr lpTitle;
        public  int    dwX;
        public  int    dwY;
        public  int    dwXSize;
        public  int    dwYSize;
        public  int    dwXCountChars;
        public  int    dwYCountChars;
        public  int    dwFillAttribute;
        public  int    dwFlags;
        public  short  wShowWindow;
        public  short  cbReserved2;
        private IntPtr lpReserved2;
        private IntPtr hStdInput;
        private IntPtr hStdOutput;
        private IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int    dwProcessId;
        public int    dwThreadId;
    }

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CreateProcessW(
        string lpApplicationName,
        StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32.dll")]
    public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    /// <summary>
    /// Ignora CTRL+C en este proceso (heredado por hijos) y lanza cmd hijo en la
    /// MISMA consola y MISMO grupo de procesos (dwCreationFlags=0). Devuelve el
    /// codigo de salida del hijo, o -1 si CreateProcess falla.
    /// </summary>
    public static int Run(string fullCommandLine) {
        // NULL + add=true => este proceso IGNORA CTRL+C; se hereda por el cmd hijo.
        SetConsoleCtrlHandler(IntPtr.Zero, true);

        var si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
        PROCESS_INFORMATION pi;
        var buf = new StringBuilder(fullCommandLine.Length + 4);
        buf.Append(fullCommandLine);

        bool ok = CreateProcessW(
            null, buf,
            IntPtr.Zero, IntPtr.Zero,
            true,   // bInheritHandles: comparte handles de consola (mismo terminal)
            0,      // sin flags: misma consola, mismo grupo, hereda ignore-CTRL+C
            IntPtr.Zero, null,
            ref si, out pi);

        if (!ok) return -1;
        CloseHandle(pi.hThread);
        WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);   // INFINITE
        uint code;
        GetExitCodeProcess(pi.hProcess, out code);
        CloseHandle(pi.hProcess);
        return unchecked((int)code);
    }
}
'@ -Language CSharp -ErrorAction Stop
}
catch {
    # Add-Type fallo (sistema antiguo / .NET no disponible): senalar degradacion.
    exit 99
}

# Ejecutar el .bat dentro de un cmd hijo que hereda el "ignorar CTRL+C".
# /c: el cmd termina cuando el .bat sale (cierre limpio del menu via opcion Salir).
# /d: no ejecuta el AutoRun del registro (Command Processor), que en un equipo
#     comprometido seria codigo del host corriendo dentro del framework.
# /s + comillas dobles exteriores: cmd quita solo el par exterior y conserva el
#     interior. Sin /s, una carpeta con ( ) & o ^ en el nombre hacia que cmd
#     descartara las comillas de la ruta y el .bat no arrancaba.
$cmd = 'cmd.exe /d /s /c ""' + $Bat + '""'
try {
    $rc = [NoCtrlCLauncher]::Run($cmd)
}
catch {
    exit 99
}

if ($rc -lt 0) { exit 99 }   # CreateProcess fallo -> modo degradado en el .bat
exit $rc
