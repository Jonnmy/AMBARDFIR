# AMBARDFIR

**Ámbar** es un framework de adquisición forense para Windows, escrito en batch y PowerShell, con
interfaz de consola bilingüe (español / inglés). Reúne en un solo menú la adquisición de memoria,
discos, archivos, máquinas virtuales, contenedores y dispositivos Android, y documenta cada paso
para la cadena de custodia (ISO/IEC 27037, NIST SP 800-86, RFC 3227).

- Sitio del proyecto: https://euclides-angeles.pages.dev/ambar-forensics/
- Documentación técnica completa: https://euclides-angeles.pages.dev/ambar-forensics/Documentacion_Tecnica.es

## Qué hace

| Menú | Módulo | Herramientas que usa |
|---|---|---|
| 1 | Volcado de RAM del equipo | DumpIt, WinPmem |
| 2 | Triaje de artefactos | KAPE |
| 3 | Discos físicos, particiones lógicas, copia lógica y evaluación previa de cifrado | dc3dd, dd, ewfacquire, FTK Imager, robocopy, qemu-img |
| 4 | Máquinas virtuales: VMware, VirtualBox, Hyper-V y conversión QEMU | vmrun, vmware-vdiskmanager, VBoxManage, cmdlets de Hyper-V, qemu-img |
| 5 | Contenedores Docker | docker, 7zr |
| 6 | Android por ADB | adb, 7zr |
| 7 | Write blocker por software | `Set-Disk -IsReadOnly` |
| 8 | Registro de comandos ejecutados | — |
| 9 | Idioma de la interfaz | — |

En todos los módulos:

- **Integridad:** el hash SHA-256 (o MD5 / SHA1) lo calcula HashMyFiles, instalado dentro de la
  carpeta del framework. No se usa ningún hasher del equipo analizado. Si no se puede calcular,
  queda escrito el motivo.
- **Cadena de custodia:** cada comando externo queda en `Forensic_Commands.log`, con su versión,
  hora UTC, duración y código de salida. Cada caso tiene su diario y su inventario de herramientas
  (`Herramientas_SHA256.txt`).
- **Protección contra interrupciones:** un `CTRL+C` no mata una adquisición en curso. La congela y
  pregunta antes de abortar.

## Requisitos

- Windows 7 o posterior, x86 o x64. La interfaz con color necesita Windows 10 1511 o posterior. En
  ARM64 solo el volcado de RAM con DumpIt tiene binario nativo.
- PowerShell 2.0 o posterior. Algunas funciones piden más: el write blocker y la detección de
  discos usan el módulo Storage (Windows 8 o posterior), y Hyper-V usa su propio módulo.
- Permisos de administrador. El script pide elevación al arrancar; sin ella avisa y limita lo que
  ofrece.
- Opcional, según el módulo: Docker Desktop, VMware Workstation, VirtualBox o el rol Hyper-V
  instalados en el equipo.

## Instalación

1. Descarga este repositorio (botón **Code → Download ZIP**, o `git clone`).
2. Consigue las herramientas de terceros de sus fuentes oficiales (tabla de abajo) y colócalas en
   `Windows/Sistema/herramientas/`, en la ruta indicada para cada una. Los nombres de carpeta
   importan: el framework las busca ahí.
3. Ejecuta `Windows\AMBARDFIR.bat`. La pantalla de verificación del arranque muestra qué
   herramientas encontró y cuáles faltan. Si falta alguna, el framework arranca igual y solo deja
   de ofrecer el módulo que la necesita.

## Uso

Al arrancar se elige el idioma y se introducen el caso, la evidencia y el examinador. Por defecto
la evidencia se guarda dentro de la carpeta del proyecto:

```
Evidencias/<CASO>/
  Caso.txt                  ficha del caso
  Logs/                     diario y registro de comandos del caso
  <EVIDENCIA>/              lo adquirido para ese elemento
Logs/                       registro global de la sesión
```

En cada adquisición se puede elegir otro destino; lo recomendable es un disco externo distinto del
que se analiza. `Evidencias/` y `Logs/` están excluidas en `.gitignore`: una evidencia no debe
acabar nunca en un repositorio.

## Estructura del repositorio

```
Windows/
  AMBARDFIR.bat                          punto de entrada y todos los módulos
  Sistema/
    lib/
      launch_noctrlc.ps1                 relanzador que aísla la consola de CTRL+C
      forensic_wrapper.ps1               ejecuta cada herramienta y gestiona CTRL+C
      hv_savedstate_to_raw.ps1           convierte un estado guardado de Hyper-V a RAW
      console_font.ps1                   tamaño de letra y maximizado de la consola
    herramientas/
      Utilidades/
        Listar-DiscosVM.ps1              inventario de discos virtuales por VM
        PreAdquisicion-Cifrado.ps1       detección de cifrado antes de adquirir
      (resto de carpetas)                herramientas de terceros, NO incluidas
```

## Herramientas de terceros

Este repositorio contiene solo código propio. Las herramientas de terceros no se incluyen. Algunas
tienen licencias que no permiten redistribuirlas; para otras no se ha podido confirmar si se
permite. Además, así cada usuario obtiene la versión vigente desde la fuente oficial y acepta él
mismo la licencia correspondiente.

Todas las rutas son relativas a `Windows/Sistema/herramientas/`.

| Herramienta | Ruta en el proyecto | Fuente oficial | Licencia | Restricciones y notas |
|---|---|---|---|---|
| dc3dd | `Adquisicion/Discos/dc3dd/dc3dd.exe` + DLL de Cygwin (`cygwin1.dll`, `cygiconv-2.dll`, `cygintl-8.dll`, `cyggcc_s-seh-1.dll`) | https://sourceforge.net/projects/dc3dd/ | GPL-3.0 | Las DLL de Cygwin tienen su propia licencia. Los empaquetadores difieren entre "only" y "or later". |
| dd for Windows | `Adquisicion/Discos/dd/dd.exe` | http://www.chrysocome.net/dd | GPL-2.0 | Según el `Copying.txt` que la acompaña. |
| libewf (ewfacquire) | `Adquisicion/Discos/ewf/ewfacquire.exe` + `libewf.dll`, `zlib.dll` | https://github.com/libyal/libewf/releases | LGPL-3.0 o posterior | |
| FTK Imager (CLI) | `Adquisicion/Discos/ftk/ftkimager.exe` + sus DLL | https://www.exterro.com/digital-forensics-software/ftk-imager | Propietaria (Exterro) | No se ha podido confirmar si permite redistribuirla: descárgala de la fuente oficial y acepta su EULA. |
| HashMyFiles | `Hashes/HashMyFiles/hashmyfiles-x64/HashMyFiles.exe` y `Hashes/HashMyFiles/x32/HashMyFiles.exe` | https://www.nirsoft.net/utils/hash_my_files.html | Freeware (NirSoft) | Puede redistribuirse gratis y sin modificar, con todos sus archivos. Es el único motor de hash del framework. |
| Android SDK Platform-Tools | `platform-tools/adb.exe` + `AdbWinApi.dll`, `AdbWinUsbApi.dll` | https://developer.android.com/tools/releases/platform-tools | Términos del Android SDK | El paquete de Google se descarga aceptando sus términos; sus componentes de código abierto tienen licencias propias (Apache-2.0, entre otras). |
| Windows Terminal (opcional) | `Terminal/terminal-<versión>/OpenConsole.exe` | https://github.com/microsoft/terminal/releases | MIT | Solo para abrir el framework en una consola moderna. |
| KAPE | `Triaje/kape/kape.exe` + `Targets/`, `Modules/` | https://www.kroll.com/en/services/cyber/incident-response-recovery/kroll-artifact-parser-and-extractor-kape | EULA de Kroll | Gratis solo con restricciones. El EULA exige licencia Enterprise para uso comercial, profesional, en redes de terceros o en encargos remunerados. Revísalo antes de usarlo. |
| 7-Zip (`7zr.exe`) | `Utilidades/7zip/7zr.exe` | https://www.7-zip.org/download.html | GNU LGPL | Una redistribución binaria debe incluir la información de licencia de 7-Zip. |
| qemu-img | `Virtualizacion/QEMU/qemu-img.exe` + sus DLL | https://qemu.weilnetz.de/w64/ (compilaciones para Windows enlazadas desde qemu.org) | GPL-2.0 | |
| VirtualBox (opcional) | `Virtualizacion/VirtualBox/VBoxManage.exe` | https://www.virtualbox.org/wiki/Downloads | GPL-3.0 (paquete base, desde la 7.0) | El Extension Pack tiene otra licencia (PUEL) y el framework no lo usa. Se prefiere el VBoxManage instalado en el equipo. |
| VMware vmrun y vmware-vdiskmanager | `Virtualizacion/VMware/vmrun/vmrun.exe`, `Virtualizacion/VMware/vdiskmanager/bin/vmware-vdiskmanager.exe` | https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion | Propietaria (Broadcom) | Vienen con VMware Workstation, gratuito para uso personal y comercial desde noviembre de 2024. La descarga requiere una cuenta de Broadcom. Se prefiere la instalación del equipo. |
| Magnet DumpIt | `Volcados/RAM/comae/x64/DumpIt.exe` (también `x86/` y `ARM64/`) | https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/ | EULA de Magnet Forensics (Magnet Free Tools) | No se ha podido confirmar si permite redistribuirla: descárgala de la fuente oficial. |
| WinPmem | `Volcados/RAM/winpmem/winpmem_mini_x64_rc2.exe` y `winpmem_mini_x86.exe` | https://github.com/Velocidex/WinPmem/releases | Apache-2.0 | |
| VmSavedStateDumpProvider | `Volcados/Virtual/vmsavedstate/vmsavedstatedumpprovider.dll` (x64) | https://developer.microsoft.com/windows/downloads/windows-sdk/ | Licencia del Windows SDK | Solo se puede redistribuir si figura en el REDIST.TXT del SDK, y no se ha comprobado. Si el SDK está instalado, el framework la encuentra en `Windows Kits\10\bin\<versión>\x64\`. |
| Volatility 3 (opcional) | `volatility3-develop/` | https://github.com/volatilityfoundation/volatility3 | Volatility Software License 1.0 | Solo para analizar después lo adquirido; el framework no lo ejecuta. |

Componentes de Windows que se usan y no se distribuyen: robocopy, los módulos de PowerShell
Hyper-V, Storage y SecureBoot, y WMI. Docker y Hyper-V se usan solo si están instalados.

## Limitaciones conocidas

- El write blocker por software (`Set-Disk -IsReadOnly`) actúa cuando Windows ya montó el disco.
  No sustituye a un bloqueador por hardware.
- `dd` no lleva `conv=noerror,sync`: ante un sector ilegible se detiene. Para discos dañados usa
  dc3dd o ewfacquire.
- Un volcado de memoria de una VM en marcha es inconsistente por construcción (*smear*), y la
  conversión de Hyper-V a RAW lee la memoria como un bloque contiguo. Las dos cosas quedan
  declaradas junto a la evidencia.
- La comprobación de que el destino no está en el disco de origen compara letras de unidad: no
  detecta otra partición del mismo disco físico.
- Los `for /f` de cmd abren un `cmd` interno sin `/d`, así que el `AutoRun` del registro aún puede
  ejecutarse ahí. No se puede evitar desde un script.
- No hay pruebas automáticas de extremo a extremo: las adquisiciones reales necesitan hardware,
  máquinas virtuales y privilegios.

## Validación

Validaciones que se hacen sobre el código:

- Análisis estático de etiquetas: todo `goto` y `call` tiene destino y no hay etiquetas
  duplicadas.
- Finales de línea CRLF en el `.bat`, imprescindibles para cmd.
- Análisis sintáctico de todos los `.ps1` con el parser de PowerShell.
- Pruebas aisladas de las subrutinas de duración (`:TIMEDIFF`) y de saneado de nombres.

## Seguridad

- No subas evidencias, volcados ni registros de casos. `.gitignore` excluye `Evidencias/`,
  `Logs/` y los registros que generan las herramientas.
- Si encuentras un problema de seguridad, escribe a EuclidesJ.Angeles@protonmail.com en lugar de
  abrir un issue público.

## Licencia

El código de este repositorio se publica bajo licencia MIT (ver [LICENSE](LICENSE)), © 2026
Euclides Junior Ángeles Alcántara. La licencia cubre solo el código propio. Cada herramienta de
terceros se rige por la suya, indicada en la tabla anterior.
