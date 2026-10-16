# AMBARDFIR

Framework de adquisición forense para Windows, en batch y PowerShell, bilingüe (ES/EN).
Cubre RAM, discos físicos y lógicos, máquinas virtuales (VMware, VirtualBox, Hyper-V, QEMU),
contenedores Docker, dispositivos Android (ADB) y triaje con KAPE. Registra cadena de custodia,
hashes SHA-256 y un inventario de herramientas, siguiendo ISO/IEC 27037, NIST SP 800-86 y RFC 3227.

- Sitio del proyecto: https://euclides-angeles.pages.dev/ambar-forensics/
- Documentación técnica: https://euclides-angeles.pages.dev/ambar-forensics/Documentacion_Tecnica.es

## Qué hay en este repositorio

Solo el código propio. Las herramientas forenses de terceros **no se incluyen**: varias tienen
licencias que no permiten redistribuirlas (KAPE, FTK Imager, DumpIt, los binarios de VMware, el
Windows SDK), y las que sí lo permiten se dejan fuera igualmente para que cada una se obtenga de
su fuente oficial, en su versión vigente y con su propia licencia aceptada por quien la usa.

```
Windows/
  AMBARDFIR.bat                 Punto de entrada (se autoeleva)
  Sistema/lib/                  Scripts PowerShell del framework
  Sistema/herramientas/         Aquí van las herramientas de terceros (ver abajo)
    Utilidades/*.ps1            Motores propios: listado de discos de VM y evaluación de cifrado
```

## Herramientas de terceros: dónde descargarlas

Cada una va dentro de `Windows/Sistema/herramientas/`, en la ruta indicada. El framework arranca
aunque falte alguna: la pantalla de verificación marca lo que no encuentra y el módulo que la
necesita no se ofrece.

| Ruta | Herramienta | Descarga oficial | Licencia |
|---|---|---|---|
| `Adquisicion/Discos/dc3dd/dc3dd.exe` (+ DLL de Cygwin) | dc3dd | https://sourceforge.net/projects/dc3dd/ | GPL-3.0 |
| `Adquisicion/Discos/dd/dd.exe` | dd for Windows | http://www.chrysocome.net/dd | GPL |
| `Adquisicion/Discos/ewf/ewfacquire.exe` (+ `libewf.dll`, `zlib.dll`) | libewf | https://github.com/libyal/libewf/releases | LGPL-3.0 |
| `Adquisicion/Discos/ftk/ftkimager.exe` | FTK Imager CLI | https://www.exterro.com/digital-forensics-software/ftk-imager | Propietaria (Exterro), sin redistribución |
| `Hashes/HashMyFiles/hashmyfiles-x64/HashMyFiles.exe` y `x32/` | HashMyFiles | https://www.nirsoft.net/utils/hash_my_files.html | Freeware (NirSoft) |
| `platform-tools/adb.exe` (+ `AdbWinApi.dll`, `AdbWinUsbApi.dll`) | Android SDK Platform-Tools | https://developer.android.com/tools/releases/platform-tools | Términos del Android SDK |
| `Terminal/terminal-<versión>/OpenConsole.exe` (opcional) | Windows Terminal portable | https://github.com/microsoft/terminal/releases | MIT |
| `Triaje/kape/kape.exe` (+ `Targets/`, `Modules/`) | KAPE | https://www.kroll.com/en/services/cyber/incident-response-recovery/kroll-artifact-parser-and-extractor-kape | Propietaria (Kroll), requiere registro |
| `Utilidades/7zip/7zr.exe` | 7-Zip (versión reducida) | https://www.7-zip.org/download.html | LGPL-2.1 |
| `Virtualizacion/QEMU/qemu-img.exe` (+ sus DLL) | qemu-img | https://qemu.weilnetz.de/w64/ | GPL-2.0 |
| `Virtualizacion/VirtualBox/VBoxManage.exe` (opcional) | VirtualBox | https://www.virtualbox.org/wiki/Downloads | GPL-3.0 |
| `Virtualizacion/VMware/vmrun/vmrun.exe` y `vdiskmanager/bin/vmware-vdiskmanager.exe` | VMware Workstation | https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion | Propietaria (Broadcom) |
| `Volcados/RAM/comae/{x64,x86,ARM64}/DumpIt.exe` | Magnet DumpIt | https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/ | Propietaria (Magnet Forensics) |
| `Volcados/RAM/winpmem/winpmem_mini_x64_rc2.exe` y `winpmem_mini_x86.exe` | WinPmem | https://github.com/Velocidex/WinPmem/releases | Apache-2.0 |
| `Volcados/Virtual/vmsavedstate/vmsavedstatedumpprovider.dll` (x64) | VmSavedStateDumpProvider | https://developer.microsoft.com/windows/downloads/windows-sdk/ | Licencia del Windows SDK |
| `volatility3-develop/` (opcional, análisis) | Volatility 3 | https://github.com/volatilityfoundation/volatility3 | Volatility Software License |

Notas:

- VBoxManage, vmrun y vmware-vdiskmanager se buscan primero en la instalación del equipo y en el
  `PATH`; la copia dentro de `herramientas/` es el último recurso.
- `vmsavedstatedumpprovider.dll` está en `Windows Kits\10\bin\<versión>\x64\` tras instalar el
  Windows SDK. Si el SDK está instalado, el framework la encuentra sin copiarla.
- Al arrancar cada caso, el framework escribe `Herramientas_SHA256.txt` con la ruta, la versión y
  el SHA-256 de cada binario que va a usar, y marca como ausente lo que falte.

## Uso

Ejecutar `Windows\AMBARDFIR.bat` (pide elevación). Requiere Windows 10 o posterior para la
interfaz con color; PowerShell 2.0 como mínimo.

## Licencia

MIT para el código propio. Ver [LICENSE](LICENSE). Cada herramienta de terceros se rige por la
suya, indicada en la tabla.
