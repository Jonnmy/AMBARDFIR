# AMBARDFIR

Framework de adquisición forense para Windows, en batch y PowerShell, bilingüe (ES/EN).
Cubre RAM, discos físicos y lógicos, máquinas virtuales (VMware, VirtualBox, Hyper-V, QEMU),
contenedores Docker, dispositivos Android (ADB) y triaje con KAPE. Registra cadena de custodia,
hashes SHA-256 y un inventario de herramientas, siguiendo ISO/IEC 27037, NIST SP 800-86 y RFC 3227.

Documentación técnica: https://euclides-angeles.pages.dev/ambar-forensics/Documentacion_Tecnica.es

## Estructura

```
Windows/
  AMBARDFIR.bat                 Punto de entrada (se autoeleva)
  Sistema/lib/                  Scripts PowerShell del framework
  Sistema/herramientas/         Herramientas de terceros (NO versionadas)
    Utilidades/*.ps1            Motores propios: listado de discos de VM y evaluación de cifrado
```

## Herramientas de terceros

No se incluyen en el repositorio. Cada una va en `Windows/Sistema/herramientas/`, en esta ruta:

| Ruta | Herramienta | Origen |
|---|---|---|
| `Adquisicion/Discos/dc3dd/dc3dd.exe` | dc3dd | Build para Windows de dc3dd (DoD Cyber Crime Center) |
| `Adquisicion/Discos/dd/dd.exe` | dd | dd for Windows (chrysocome.net) |
| `Adquisicion/Discos/ewf/ewfacquire.exe` | libewf | https://github.com/libyal/libewf |
| `Adquisicion/Discos/ftk/ftkimager.exe` | FTK Imager CLI | Exterro |
| `Hashes/HashMyFiles/` | HashMyFiles (x64 y x32) | https://www.nirsoft.net/utils/hash_my_files.html |
| `platform-tools/adb.exe` | Android SDK Platform-Tools | https://developer.android.com/tools/releases/platform-tools |
| `Terminal/terminal-<versión>/` | Windows Terminal portable (opcional) | https://github.com/microsoft/terminal/releases |
| `Triaje/kape/kape.exe` | KAPE | Kroll |
| `Utilidades/7zip/7zr.exe` | 7-Zip | https://www.7-zip.org |
| `Virtualizacion/QEMU/qemu-img.exe` | qemu-img | https://qemu.weilnetz.de/w64/ |
| `Virtualizacion/VirtualBox/` | VBoxManage (respaldo; se prefiere el instalado) | https://www.virtualbox.org |
| `Virtualizacion/VMware/vmrun/`, `vdiskmanager/` | vmrun y vmware-vdiskmanager | VMware Workstation |
| `Volcados/RAM/comae/x64/DumpIt.exe` (y `x86/`) | DumpIt | Magnet Forensics (Comae) |
| `Volcados/RAM/winpmem/winpmem_mini_x64_rc2.exe` (y `_x86.exe`) | WinPmem | https://github.com/Velocidex/WinPmem |
| `Volcados/Virtual/vmsavedstate/vmsavedstatedumpprovider.dll` | VmSavedStateDumpProvider (x64) | Windows 10/11 SDK |
| `volatility3-develop/` | Volatility 3 (opcional, análisis) | https://github.com/volatilityfoundation/volatility3 |

Al arrancar, el framework genera `Herramientas_SHA256.txt` con la ruta, versión y SHA-256 de cada
binario que usa, y marca como ausente lo que falte.

## Uso

Ejecutar `Windows\AMBARDFIR.bat` (pide elevación). Requiere Windows 10 o posterior para la
interfaz con color; PowerShell 2.0 como mínimo.

## Licencia

MIT para el código propio. Ver [LICENSE](LICENSE).
