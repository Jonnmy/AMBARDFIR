<#
===============================================================================
 AMBARDFIR - Enumeracion y CLASIFICACION de discos virtuales (Evaluacion Previa)
===============================================================================
 Lista los discos de VMware, VirtualBox e Hyper-V agrupados por maquina y
 clasificados por su ROL REAL dentro de la cadena de discos. Estrictamente de
 SOLO LECTURA: no se invoca ninguna herramienta que escriba en el origen.

 COMO SE LOCALIZA CADA UNO, Y POR QUE ASI
   VMware     : se leen los .vmx del inventario (%APPDATA%\VMware\inventory.vmls)
                y de las carpetas de maquinas, y se sacan las claves
                <bus><n>:<n>.fileName. Broadcom no documenta el formato del .vmx,
                asi que las claves se descubren leyendo, no se dan por supuestas.
   VirtualBox : se parsea VirtualBox.xml (registro global) y cada .vbox, unica
                via de SOLO LECTURA. Cualquier invocacion de VBoxManage arranca
                VBoxSVC, que puede reescribir VirtualBox.xml (en este equipo se
                comprobo: existe VirtualBox.xml-prev y 11 VBoxSVC.log rotados),
                y este modulo no puede permitirse alterar la evidencia.
   Hyper-V    : cmdlets oficiales del modulo Hyper-V (Get-VM, Get-VMHardDiskDrive,
                Get-VMSnapshot, Get-VHD). Msvm_VirtualHardDiskSettingData (usada
                en una version anterior) es una clase WMI SIN proveedor de
                instancias y enumerarla da SIEMPRE cero - no es un problema de
                permisos, es una clase equivocada. Validado el 2026-08-01 contra
                la cadena WMI manual y contra los .vmcx reales del store.
                Exige elevacion; sin ella se DICE que no se pudo consultar.

 COMO SE CLASIFICA CADA DISCO (nunca por el nombre del archivo ni por la carpeta)
   VMware     : campo parentCID del descriptor VMDK. ffffffff = base; cualquier
                otro valor = diferencial. La cadena se sube con parentFileNameHint.
   VirtualBox : ANIDAMIENTO de <HardDisk> dentro de <MediaRegistry>. Un HardDisk
                hijo de otro HardDisk es diferencial de su padre. Que este dentro
                de la carpeta "Snapshots\" NO se usa como criterio: un disco puede
                vivir ahi y ser base, y un diferencial puede vivir fuera.
   Hyper-V    : propiedad VhdType de Get-VHD (Fixed/Dynamic/Differencing) y
                ParentPath para subir la cadena. La extension .avhdx es solo
                indicio, no criterio.

 FASES SEPARADAS: los discos que pertenecen a una VM registrada y los discos
 HUERFANOS (existen en disco pero ninguna VM registrada los referencia) se
 emiten en grupos distintos y jamas se mezclan. Un huerfano es un indicio
 forense por si mismo (VM borrada conservando el disco, backup suelto, disco
 desconectado a proposito) y contaminar con el la lista de una VM real seria
 una afirmacion falsa sobre la composicion de esa maquina.

 DISCOS AUSENTES (ROL = "AUSENTE (...)"): cuando la configuracion (.vmx /
 .vbox / Get-VMHardDiskDrive) declara una ruta que ya no existe en el sistema
 de archivos - disco movido, renombrado, en medio desconectado o eliminado -
 se registra igual en vez de descartarse en silencio. Sin esto, una VM cuyo
 unico disco fue movido desaparecia del informe COMPLETO sin dejar rastro: el
 peor tipo de falso negativo, porque ni siquiera queda una nota que lo delate.
 Verificado con un caso real en este equipo: un medio del MediaRegistry
 GLOBAL de VirtualBox.xml (C:/npm/Evidencias/VBox_Disk_Export.vdi) ya no
 existe; antes de este cambio no aparecia en ningun lado de la salida.

 LIMITACION CONOCIDA (Get-ChildItem -Recurse y enlaces simbolicos): en
 Windows PowerShell 5.1, verificado empiricamente en este equipo, -Recurse
 (con o sin -Depth) NO atraviesa junctions ni symlinks de directorio. Si la
 carpeta de una VM o su carpeta de snapshots fue reubicada mediante un enlace
 simbolico, los discos huerfanos que vivan detras de ese enlace no se
 detectaran en el barrido. NO afecta a los discos PRINCIPALES de cada VM
 (esos se resuelven por ruta directa via XML/.vmx/API, no por recorrido
 recursivo) - solo al barrido de huerfanos, que es una capa defensiva
 adicional, no la fuente primaria de cada VM.

 CONTRATO DE SALIDA (el .bat lo trocea con "for /f delims=|")
   #PLAT|<plataforma>|<n_maquinas>|<n_discos>|<n_huerfanos>
   Contadores en campos separados, NO en una frase con separador visual
   incrustado: el .bat arma el "Maquinas: X | Discos: Y | ..." que se ve en
   pantalla; si esa frase se generara aqui con "|" como separador visual,
   el propio "|" se colaria como delimitador de campo y correria el resto.
   #VM|<nombre maquina>|<estado de registro>
   #D|<idx>|<ROL>|<formato>|<MB>|<observacion>|<ruta>
   #NOTA|<texto>
   #VACIO|<texto>
 Ningun campo puede ir vacio: "for /f" de cmd.exe COLAPSA los delimitadores
 consecutivos y correria todos los campos siguientes una posicion. Se rellena
 con "-", que el .bat ya interpreta como "sin dato".
===============================================================================
#>
[CmdletBinding()]
param([int]$Max = 60)

$ErrorActionPreference = 'SilentlyContinue'
Set-StrictMode -Version 2.0

# El .bat pone la consola en 65001 (UTF-8) antes de llamar a este script, asi
# que la salida se emite en UTF-8 SIN BOM: un BOM se colaria como basura en el
# primer campo de la primera linea al trocearla con "for /f". Sin fijarlo, los
# nombres con acento que vienen de la evidencia (p.ej. un snapshot llamado
# "Instantanea 1" con tilde) salian como "?" y el informe alteraba un dato del
# original, que es justo lo que no puede pasar.
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }

# Extensiones que SI son discos virtuales. Se filtra por esta lista explicita
# en vez de con -Include de Get-ChildItem: con -LiteralPath, -Include se ignora
# en silencio y el barrido devolvia .log, .sav, .vbox y hasta archivos sin
# extension como si fueran discos huerfanos.
$EXT_DISCO_HV  = @('.vhd', '.vhdx', '.avhd', '.avhdx', '.vhds')
$EXT_DISCO_VB  = @('.vdi', '.vmdk', '.vhd', '.vhdx', '.hdd', '.qcow2')

function Get-Discos {
    param([string]$Dir, [string[]]$Exts, [int]$Prof = 2)
    $sal = New-Object System.Collections.Generic.List[object]
    if (-not $Dir) { return $sal }
    if (-not (Test-Path -LiteralPath $Dir)) { return $sal }
    foreach ($f in @(Get-ChildItem -LiteralPath $Dir -File -Recurse -Depth $Prof -ErrorAction SilentlyContinue)) {
        if ($Exts -contains $f.Extension.ToLower()) { $sal.Add($f) }
    }
    return $sal
}

# Cada entrada: Plat, Grupo (nombre de VM, o '#HUERFANOS'), GrupoEstado, Rol,
# Fmt, MB, Obs, Ruta, Orden (para conservar base-antes-que-diferencial).
$res    = New-Object System.Collections.Generic.List[object]
$notas  = New-Object System.Collections.Generic.List[string]
# Rutas ya atribuidas a una VM registrada, por plataforma. Lo que NO esta aqui
# tras recorrer todas las VMs es, por definicion, huerfano.
$claim  = @{}
$orden  = 0

# Formula de clave compartida por las dos funciones de abajo: antes cada una
# la repetia por separado, y un cambio de formato en una sin la otra habria
# roto el reclamo en silencio (Test-Reclamado siempre "no reclamado").
function Get-ClaimKey {
    param([string]$Plat, [string]$Ruta)
    return $Plat + '|' + $Ruta.ToLower()
}
function Test-Reclamado {
    param([string]$Plat, [string]$Ruta)
    return $claim.ContainsKey((Get-ClaimKey $Plat $Ruta))
}
function Set-Reclamado {
    param([string]$Plat, [string]$Ruta)
    $claim[(Get-ClaimKey $Plat $Ruta)] = $true
}

# Formato abreviado que se muestra al operador, deducido SOLO de la extension
# (no requiere que el archivo exista: tambien se usa para las entradas AUSENTE).
function Get-DiscoFormato {
    param([string]$Ruta)
    $ext = ([IO.Path]::GetExtension($Ruta)).TrimStart('.').ToLower()
    switch ($ext) {
        'vmdk'  { 'vmdk' }
        'vdi'   { 'vdi' }
        'vhdx'  { 'vhdx' }
        'avhdx' { 'vhdx' }
        'vhd'   { 'vpc' }
        'avhd'  { 'vpc' }
        default { $ext }
    }
}

# Tamano en MB. Un VMDK partido en extents tiene un descriptor de texto de
# menos de 1 KB: mostrar "0 MB" haria pensar que el disco esta vacio, asi que
# se suman los extents que el propio descriptor declara, que es el tamano
# real ocupado.
function Get-DiscoSizeMB {
    param([string]$Ruta)
    $mb = 0
    try { $mb = [math]::Round((Get-Item -LiteralPath $Ruta).Length / 1MB) } catch { }
    if ($mb -eq 0 -and $Ruta -like '*.vmdk') {
        $dirv = Split-Path -Parent $Ruta
        $tot = 0
        try {
            foreach ($l in (Get-Content -LiteralPath $Ruta -ErrorAction Stop)) {
                if ($l -match '^\s*(RW|RDONLY|NOACCESS)\s+\d+\s+\S+\s+"([^"]+)"') {
                    $ex = $Matches[2]
                    if (-not [IO.Path]::IsPathRooted($ex)) { $ex = Join-Path $dirv $ex }
                    if (Test-Path -LiteralPath $ex) { $tot += (Get-Item -LiteralPath $ex).Length }
                }
            }
        } catch { }
        if ($tot -gt 0) { $mb = [math]::Round($tot / 1MB) }
    }
    return $mb
}

function Add-Disco {
    param(
        [string]$Plat, [string]$Grupo, [string]$GrupoEstado,
        [string]$Rol, [string]$Ruta, [string]$Obs = ''
    )
    if (-not $Ruta) { return }
    # Mismo disco, misma VM, ya listado (un .vmdk puede aparecer en varias
    # claves del .vmx; un padre puede alcanzarse desde dos ramas de snapshot).
    foreach ($x in $res) {
        if ($x.Plat -eq $Plat -and $x.Grupo -eq $Grupo -and $x.Ruta -eq $Ruta) { return }
    }
    $fmt = Get-DiscoFormato $Ruta
    # ANTES esto se descartaba en silencio si la ruta no existia. Un disco que
    # la configuracion (.vmx / .vbox / Get-VMHardDiskDrive) declara pero que ya
    # no esta ahi es EXACTAMENTE el caso "VM con archivos movidos": si se
    # descarta sin dejar rastro, una VM entera puede desaparecer del informe
    # sin que el operador tenga ninguna forma de saberlo - el peor tipo de
    # falso negativo, porque no hay ni una nota que lo delate. Se registra
    # igual, marcado AUSENTE, en la misma tabla que todo lo demas.
    if (-not (Test-Path -LiteralPath $Ruta)) {
        $obsFinal = if ($Obs) { $Obs + ' (la ruta declarada no existe)' } else { 'la configuracion declara esta ruta pero el archivo no existe aqui: disco movido, renombrado, en medio desconectado o eliminado' }
        $script:orden++
        $res.Add([pscustomobject]@{
            Plat = $Plat; Grupo = $Grupo; GrupoEstado = $GrupoEstado
            Rol = 'AUSENTE (' + $Rol + ')'; Fmt = $fmt; MB = 0
            Obs = $obsFinal; Ruta = $Ruta; Orden = $script:orden
        })
        return
    }
    $mb = Get-DiscoSizeMB $Ruta
    $script:orden++
    $res.Add([pscustomobject]@{
        Plat = $Plat; Grupo = $Grupo; GrupoEstado = $GrupoEstado
        Rol = $Rol; Fmt = $fmt; MB = $mb; Obs = $Obs; Ruta = $Ruta; Orden = $script:orden
    })
}

# --------------------------------------------------------------------------
# Recorre el arbol de <HardDisk> del MediaRegistry de un .vbox y llena $Mapa
# (uuid -> {Ruta, Prof}); Prof=0 es la raiz/base, cada nivel de anidamiento es
# un diferencial del padre. Definida aqui, a nivel de script, y no dentro del
# bucle que procesa cada .vbox: no depende de ningun estado de esa iteracion
# (todo le llega por parametro), asi que definirla dentro solo la redefinia
# en cada vuelta sin ninguna necesidad.
# --------------------------------------------------------------------------
function Read-VbHardDisk {
    param($Nodo, [int]$Prof, [string]$BaseDir, $Mapa)
    $u = $Nodo.GetAttribute('uuid')
    $lo = $Nodo.GetAttribute('location')
    if ($u -and $lo) {
        # location puede ser RELATIVA a la carpeta del .vbox. Resolverla es
        # obligatorio: sin esto la ruta no existe y el disco se descarta.
        if (-not [IO.Path]::IsPathRooted($lo)) { $lo = Join-Path $BaseDir $lo }
        $Mapa[$u] = [pscustomobject]@{ Ruta = $lo; Prof = $Prof }
    }
    foreach ($hijo in @($Nodo.SelectNodes("./*[local-name()='HardDisk']"))) {
        Read-VbHardDisk -Nodo $hijo -Prof ($Prof + 1) -BaseDir $BaseDir -Mapa $Mapa
    }
}

# --------------------------------------------------------------------------
# Lector de descriptor VMDK. Se abre con FileShare ReadWrite a proposito: si
# la VM esta encendida, VMware mantiene el archivo abierto y un Open exclusivo
# fallaria; ademas un descriptor monolitico lleva cabecera binaria delante del
# texto, por eso se leen bytes crudos y se interpretan como ASCII en vez de
# usar Get-Content.
# --------------------------------------------------------------------------
function Get-VmdkInfo {
    param([string]$Path)
    $r = [pscustomobject]@{ Leido = $false; EsBase = $true; ParentHint = '' }
    try {
        $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            $len = [Math]::Min(65536, $fs.Length)
            if ($len -le 0) { return $r }
            $buf = New-Object byte[] $len
            [void]$fs.Read($buf, 0, $len)
        } finally { $fs.Close() }
        $txt = [Text.Encoding]::ASCII.GetString($buf)
        $r.Leido = $true
        # parentCID = ffffffff  ->  disco base. Cualquier otro valor -> diferencial.
        if ($txt -match 'parentCID\s*=\s*([0-9a-fA-F]+)') {
            if ($Matches[1].ToLower() -ne 'ffffffff') { $r.EsBase = $false }
        }
        if ($txt -match 'parentFileNameHint\s*=\s*"([^"]+)"') { $r.ParentHint = $Matches[1] }
    } catch { }
    return $r
}

# --------------------------------------------------------------------------
# Extrae del .vmx el nombre para mostrar, si esta cifrada por VMware, y las
# rutas de disco que declara. Una sola lectura del archivo para las tres
# cosas (igual que antes de extraer esto a funcion): no se abre el .vmx dos
# veces por VM.
# --------------------------------------------------------------------------
function Get-VmxInfo {
    param([string]$VmxPath, [string]$Dir)
    $info = [pscustomobject]@{
        Nombre = [IO.Path]::GetFileNameWithoutExtension($VmxPath)
        Cifrada = $false
        Adjuntos = New-Object System.Collections.Generic.List[string]
    }
    foreach ($l in (Get-Content -LiteralPath $VmxPath)) {
        if ($l -match '^\s*encryption\.(keySafe|data)') { $info.Cifrada = $true }
        if ($l -match '^\s*displayName\s*=\s*"([^"]*)"') { $info.Nombre = $Matches[1] }
        if ($l -match '^\s*[a-z]+\d+:\d+\.fileName\s*=\s*"([^"]+\.vmdk)"') {
            $r = $Matches[1]
            if (-not [IO.Path]::IsPathRooted($r)) { $r = Join-Path $Dir $r }
            $info.Adjuntos.Add($r)
        }
    }
    return $info
}

# ============================================================== Hyper-V =====
# Requiere elevacion. Sin ella se DICE que no se pudo consultar, en vez de
# dejar la lista corta y que el operador crea que no hay maquinas Hyper-V.
$elevado = $false
try {
    $idw = [Security.Principal.WindowsIdentity]::GetCurrent()
    $elevado = (New-Object Security.Principal.WindowsPrincipal($idw)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }
if (-not $elevado) {
    $notas.Add('Hyper-V NO consultado: se requiere Administrador. Sin elevacion Get-VM devuelve "acceso denegado" (UAC filtering). La ausencia de discos Hyper-V en esta lista NO significa que no los haya.')
}

# Sube la cadena de un VHD/VHDX hasta su base leyendo ParentPath. El tope de 32
# saltos evita colgarse con una cadena corrupta o circular.
$script:hvPadreFaltante = ''
function Get-HvCadena {
    param([string]$Path)
    $chain = New-Object System.Collections.Generic.List[object]
    $script:hvPadreFaltante = ''
    $cur = $Path
    $guard = 0
    while ($cur -and $guard -lt 32) {
        $guard++
        $info = $null
        try { $info = Get-VHD -Path $cur -ErrorAction Stop }
        catch {
            # ParentPath del nodo anterior declara esta ruta, pero Get-VHD no
            # pudo abrirla (casi siempre porque ya no existe). ANTES esto
            # truncaba la cadena en silencio: se afirmaba una cadena completa
            # cuando en realidad estaba rota. El barrido de huerfanos ya
            # distinguia este caso ("PADRE AUSENTE"); aqui faltaba el mismo
            # criterio para una VM REGISTRADA, que es el caso mas grave.
            $script:hvPadreFaltante = $cur
            break
        }
        $par = ''
        try { if ($info.ParentPath) { $par = $info.ParentPath } } catch { }
        $chain.Add([pscustomobject]@{ Path = $cur; Tipo = [string]$info.VhdType; Padre = $par })
        if (-not $par) { break }
        $cur = $par
    }
    # OJO al devolver: PowerShell DESENROLLA las colecciones al salir de una
    # funcion, asi que este "return $chain" entrega
    #   0 elementos -> $null
    #   1 elemento  -> el objeto suelto, NO una lista
    #   2 o mas     -> Object[]
    # Con Set-StrictMode 2.0, pedir .Count sobre los dos primeros casos lanza
    # "The property 'Count' cannot be found on this object". Un disco base sin
    # checkpoints da una cadena de UN nodo -el caso mas comun de todos-, asi
    # que la excepcion saltaba en la primera VM, subia al try/catch que
    # envuelve TODA la enumeracion de Hyper-V y abortaba el modulo entero:
    # 0 maquinas y todos los discos del host reportados como huerfanos.
    # La normalizacion se hace en el SITIO DE LLAMADA con @(), que reagrupa
    # los tres casos en un array. NO usar aqui ",$chain": esa forma impide el
    # desenrollado y entonces el @() del llamador envuelve la lista ENTERA
    # como un unico elemento (Count=1 con dos nodos dentro). Comprobado: las
    # dos defensas juntas se anulan, hay que elegir una y es la de abajo.
    return $chain
}

$hvVmCount = 0
$hvDiscosCount = 0
$hvCarpetas = New-Object System.Collections.Generic.List[string]
# Solo se pone en $true si Get-VM termino sin lanzar excepcion. El barrido de
# huerfanos de mas abajo se condiciona a esto ademas de a $elevado: sin este
# flag, un Get-VM que falla (modulo Hyper-V ausente, PowerShell de 32 bits
# invocado desde un cmd de 32 bits -el proveedor Hyper-V solo existe en
# 64 bits-, un hipo de WMI) cae en el catch con 0 VMs, pero el barrido de
# huerfanos IGUAL encuentra los .vhdx del host y los reporta como huerfanos:
# exactamente "0 maquinas, todo huerfano" con Hyper-V Manager mostrando VMs
# reales. Caso real reproducido en produccion.
$hvEnumeracionOk = $false
if ($elevado) {
    try {
        Import-Module Hyper-V -ErrorAction Stop
        $vmsHv = @(Get-VM -ErrorAction Stop)
        $hvVmCount = $vmsHv.Count
        if ($hvVmCount -eq 0) {
            $notas.Add('Hyper-V consultado con privilegios: no hay maquinas virtuales registradas en el host')
        }
        foreach ($vm in $vmsHv) {
            $nomVm = [string]$vm.Name
            $estVm = 'REGISTRADA (' + [string]$vm.State + ', generacion ' + [string]$vm.Generation + ')'

            # --- discos conectados AHORA a la VM ---
            foreach ($d in @(Get-VMHardDiskDrive -VMName $nomVm -ErrorAction SilentlyContinue)) {
                if (-not $d.Path) { continue }
                # @() normaliza a array pase lo que pase con el desenrollado de
                # PowerShell: sin esto, .Count sobre una cadena de 0 o 1 nodo
                # lanza bajo Set-StrictMode 2.0 (ver comentario en Get-HvCadena).
                $cad = @(Get-HvCadena $d.Path)
                $hvCarpetas.Add((Split-Path -Parent $d.Path))
                if ($cad.Count -eq 0) {
                    # Get-VHD no pudo leerlo (disco bloqueado, formato raro). Se
                    # lista igualmente pero SIN afirmar su rol.
                    Add-Disco 'Hyper-V' $nomVm $estVm 'SIN CLASIFICAR' $d.Path 'Get-VHD no pudo leer el descriptor'
                    Set-Reclamado 'Hyper-V' $d.Path
                    $hvDiscosCount++
                    continue
                }
                for ($k = 0; $k -lt $cad.Count; $k++) {
                    $nodo = $cad[$k]
                    $esDif = ($nodo.Tipo -eq 'Differencing')
                    if ($k -eq 0) {
                        # El nodo 0 es el que la VM tiene REALMENTE conectado.
                        if ($esDif) {
                            $rol = 'CHECKPOINT ACTIVO'
                            $obs = 'la VM esta corriendo sobre este diferencial'
                            if ($cad.Count -gt 1) {
                                $obs += '; base de la cadena: ' + (Split-Path -Leaf $cad[$cad.Count - 1].Path)
                            }
                        } else {
                            $rol = 'BASE'
                            $obs = 'conectado a ' + [string]$d.ControllerType + ' ' + [string]$d.ControllerNumber + ':' + [string]$d.ControllerLocation
                        }
                    } else {
                        # Ancestros de la cadena: NO estan conectados, pero son
                        # parte de la maquina. Marcarlos huerfanos seria falso.
                        if ($esDif) {
                            $rol = 'DIFERENCIAL (en cadena)'
                            $obs = 'padre de ' + (Split-Path -Leaf $cad[$k - 1].Path)
                        } else {
                            $rol = 'BASE (padre de la cadena)'
                            $obs = 'lo referencia ' + (Split-Path -Leaf $cad[$k - 1].Path)
                        }
                    }
                    Add-Disco 'Hyper-V' $nomVm $estVm $rol $nodo.Path $obs
                    Set-Reclamado 'Hyper-V' $nodo.Path
                    $hvCarpetas.Add((Split-Path -Parent $nodo.Path))
                    $hvDiscosCount++
                }
                if ($script:hvPadreFaltante) {
                    # La cadena de $d.Path declara un padre que Get-VHD no
                    # pudo abrir: se registra igual (Add-Disco lo marca
                    # AUSENTE) en vez de dar la cadena por completa cuando no
                    # lo esta silenciosamente.
                    Add-Disco 'Hyper-V' $nomVm $estVm 'ancestro de la cadena' $script:hvPadreFaltante `
                        ('la cadena de ' + (Split-Path -Leaf $d.Path) + ' declara este padre, pero Get-VHD no pudo leerlo')
                    $hvDiscosCount++
                }
            }

            # --- discos de los CHECKPOINTS guardados de esta VM ---
            # Pertenecen a la maquina aunque no esten conectados ahora. Sin este
            # paso apareceria como huerfano el .avhdx de cada checkpoint.
            foreach ($sn in @(Get-VMSnapshot -VMName $nomVm -ErrorAction SilentlyContinue)) {
                foreach ($sd in @(Get-VMHardDiskDrive -VMSnapshot $sn -ErrorAction SilentlyContinue)) {
                    if (-not $sd.Path) { continue }
                    if (Test-Reclamado 'Hyper-V' $sd.Path) { continue }
                    Add-Disco 'Hyper-V' $nomVm $estVm 'CHECKPOINT' $sd.Path ('checkpoint "' + [string]$sn.Name + '"')
                    Set-Reclamado 'Hyper-V' $sd.Path
                    $hvCarpetas.Add((Split-Path -Parent $sd.Path))
                    $hvDiscosCount++
                }
            }
            # Simetria con la nota agregada de mas abajo, pero POR VM: la nota
            # agregada solo dispara si NINGUNA VM tiene discos; una VM
            # individual sin discos en un host con otras VMs que si los tienen
            # quedaba invisible sin ningun aviso especifico.
            $tieneDiscoEstaVm = $false
            foreach ($x in $res) { if ($x.Plat -eq 'Hyper-V' -and $x.Grupo -eq $nomVm) { $tieneDiscoEstaVm = $true; break } }
            if (-not $tieneDiscoEstaVm) {
                $notas.Add("Hyper-V / $nomVm : registrada, sin ningun disco duro virtual conectado ni en checkpoints (revise si usa pass-through)")
            }
        }
        if ($hvVmCount -gt 0 -and $hvDiscosCount -eq 0) {
            $notas.Add("Hyper-V: $hvVmCount maquina(s) registrada(s), ninguna con disco duro virtual conectado (revise si usan discos pass-through: la evidencia seria un disco FISICO)")
        }
        $hvEnumeracionOk = $true
    } catch {
        $notas.Add('Hyper-V NO consultado: ' + $_.Exception.Message.Split([char]10)[0] + ' (su ausencia en esta lista no significa que no haya maquinas, NI que los discos de abajo sean huerfanos: no se pudo verificar)')
    }
}

# --- Hyper-V: FASE SEPARADA de huerfanos -----------------------------------
# Se barren la carpeta de discos por defecto del host (leida de Get-VMHost, no
# asumida) y las carpetas donde viven los discos ya atribuidos. No se barre
# todo el volumen: eso lo decide el operador aparte si sospecha de otra ruta.
# Condicionado tambien a $hvEnumeracionOk: sin una enumeracion de VMs que
# haya funcionado, "huerfano" es una afirmacion que no se puede sostener -
# podria ser un disco de una VM real que Get-VM no logro listar.
if ($elevado -and -not $hvEnumeracionOk) {
    $notas.Add('Hyper-V: barrido de discos huerfanos OMITIDO porque la enumeracion de VMs (Get-VM) fallo. Sin saber que VMs hay, no se puede afirmar que un disco no pertenezca a ninguna.')
}
if ($elevado -and $hvEnumeracionOk) {
    $dirsHv = New-Object System.Collections.Generic.List[string]
    $hvDef = $null
    try { $hvDef = (Get-VMHost -ErrorAction Stop).VirtualHardDiskPath } catch { }
    if (-not $hvDef) { $hvDef = Join-Path $env:ProgramData 'Microsoft\Windows\Virtual Hard Disks' }
    $dirsHv.Add($hvDef)
    foreach ($c in $hvCarpetas) { if ($c) { $dirsHv.Add($c) } }
    $vistosDir = @{}
    foreach ($dir in $dirsHv) {
        if (-not $dir) { continue }
        $kd = $dir.ToLower()
        if ($vistosDir.ContainsKey($kd)) { continue }
        $vistosDir[$kd] = $true
        foreach ($f in (Get-Discos -Dir $dir -Exts $EXT_DISCO_HV)) {
            if (Test-Reclamado 'Hyper-V' $f.FullName) { continue }
            # Clasificar tambien el huerfano: un diferencial suelto arrastra una
            # cadena que puede estar incompleta, y eso cambia como se adquiere.
            $rolH = 'HUERFANO'
            $obsH = 'ninguna VM registrada lo referencia'
            try {
                $vi = Get-VHD -Path $f.FullName -ErrorAction Stop
                if ($vi.VhdType -eq 'Differencing') {
                    $rolH = 'HUERFANO DIFERENCIAL'
                    $pp = ''
                    try { if ($vi.ParentPath) { $pp = $vi.ParentPath } } catch { }
                    if ($pp) {
                        if (Test-Path -LiteralPath $pp) { $obsH = 'declara padre: ' + (Split-Path -Leaf $pp) }
                        else { $obsH = 'PADRE AUSENTE: ' + $pp + ' - la cadena esta rota' }
                    } else { $obsH = 'diferencial sin padre declarado' }
                }
            } catch { }
            Add-Disco 'Hyper-V' '#HUERFANOS' 'no pertenecen a ninguna VM registrada' $rolH $f.FullName $obsH
        }
    }
}

# =========================================================== VirtualBox =====
# 1) Resolver el directorio de configuracion SIN asumirlo: Oracle documenta
#    VBOX_USER_HOME como via oficial para reubicarlo.
$vbCfgDir = $null
try { if ($env:VBOX_USER_HOME) { $vbCfgDir = $env:VBOX_USER_HOME } } catch { }
if (-not $vbCfgDir) { $vbCfgDir = Join-Path $env:USERPROFILE '.VirtualBox' }
$vbGlobalXml = Join-Path $vbCfgDir 'VirtualBox.xml'

# 2) Leer el registro global: carpeta por defecto REAL y lista autorizada de VMs.
$vbDefFolder = $null
$vbRegistradas = @{}   # ruta .vbox en minusculas -> uuid
$vbMediosGlobales = New-Object System.Collections.Generic.List[string]
if (Test-Path -LiteralPath $vbGlobalXml) {
    $gx = $null
    try { [xml]$gx = Get-Content -LiteralPath $vbGlobalXml -Raw } catch { }
    if ($gx) {
        $sp = $gx.SelectSingleNode("//*[local-name()='SystemProperties']")
        if ($sp) {
            $dmf = $sp.GetAttribute('defaultMachineFolder')
            if ($dmf) { $vbDefFolder = $dmf }
        }
        foreach ($me in @($gx.SelectNodes("//*[local-name()='MachineEntry']"))) {
            $src = $me.GetAttribute('src')
            # Clave en minusculas para comparar sin depender de mayusculas;
            # Src conserva la ruta tal cual la escribio VirtualBox.
            if ($src) {
                $vbRegistradas[$src.ToLower()] = [pscustomobject]@{ Src = $src; Uuid = $me.GetAttribute('uuid') }
            }
        }
        # MediaRegistry GLOBAL: medios registrados que pueden vivir FUERA del
        # arbol de VMs (discos exportados, medios compartidos). Un barrido por
        # carpeta jamas los encontraria.
        foreach ($hd in @($gx.SelectNodes("//*[local-name()='MediaRegistry']//*[local-name()='HardDisk']"))) {
            $lo = $hd.GetAttribute('location')
            if ($lo) { $vbMediosGlobales.Add($lo) }
        }
    }
} else {
    $notas.Add('VirtualBox: no se encontro ' + $vbGlobalXml + ' - no se puede distinguir VM registrada de desregistrada. Se listan solo las halladas por barrido.')
}
if (-not $vbDefFolder) { $vbDefFolder = Join-Path $env:USERPROFILE 'VirtualBox VMs' }

# 3) Reunir los .vbox: los REGISTRADOS (ruta absoluta del registro, este donde
#    este) mas los hallados barriendo la carpeta por defecto.
# OJO: se conserva la ruta con sus MAYUSCULAS ORIGINALES. Normalizar a
# minusculas aqui contaminaba todo lo derivado: la carpeta base del .vbox se
# usa para resolver los "location" relativos del MediaRegistry, y las rutas de
# los discos acababan escritas en minusculas en el informe, que es alterar como
# se nombra la evidencia. La deduplicacion usa una clave aparte.
$vboxFiles = New-Object System.Collections.Generic.List[string]
foreach ($k in $vbRegistradas.Keys) { $vboxFiles.Add($vbRegistradas[$k].Src) }
if (Test-Path -LiteralPath $vbDefFolder) {
    foreach ($f in @(Get-ChildItem -LiteralPath $vbDefFolder -Filter *.vbox -Recurse -Depth 2 -File -ErrorAction SilentlyContinue)) {
        $vboxFiles.Add($f.FullName)
    }
}
$vbVistos = @{}
foreach ($vbRaw in $vboxFiles) {
    if (-not $vbRaw) { continue }
    $kv = $vbRaw.ToLower()
    if ($vbVistos.ContainsKey($kv)) { continue }
    $vbVistos[$kv] = $true
    # Resolver a la ruta real con mayusculas correctas
    $vbPath = $vbRaw
    try { $vbPath = (Get-Item -LiteralPath $vbRaw -ErrorAction Stop).FullName } catch { }
    if (-not (Test-Path -LiteralPath $vbPath)) {
        # Registrado pero el archivo ya no existe: eso es un hallazgo, no un error.
        $notas.Add('VirtualBox: la VM registrada ' + $vbRaw + ' aparece en VirtualBox.xml pero su .vbox NO existe en disco (VM movida o borrada sin desregistrar)')
        continue
    }

    $vx = $null
    try { [xml]$vx = Get-Content -LiteralPath $vbPath -Raw } catch { continue }
    $mNode = $vx.SelectSingleNode("//*[local-name()='Machine']")
    if (-not $mNode) { continue }
    $vbNom = $mNode.GetAttribute('name')
    if (-not $vbNom) { $vbNom = [IO.Path]::GetFileNameWithoutExtension($vbPath) }
    $vbDir = Split-Path -Parent $vbPath
    $curSnap = $mNode.GetAttribute('currentSnapshot')

    # Estado de registro: el cruce que da valor probatorio.
    if ($vbRegistradas.ContainsKey($kv)) {
        $vbEstado = 'REGISTRADA en VirtualBox.xml'
    } else {
        $vbEstado = 'NO REGISTRADA (existe en disco pero no esta en VirtualBox.xml)'
    }

    # --- Mapa de medios del .vbox, resolviendo el ANIDAMIENTO ---------------
    # uuid -> { Ruta absoluta, Profundidad (0 = base) }. Read-VbHardDisk esta
    # definida a nivel de script (mas arriba, junto a Get-VmdkInfo).
    $medios = @{}
    $mr = $vx.SelectSingleNode("//*[local-name()='MediaRegistry']/*[local-name()='HardDisks']")
    if ($mr) {
        foreach ($raiz in @($mr.SelectNodes("./*[local-name()='HardDisk']"))) {
            Read-VbHardDisk -Nodo $raiz -Prof 0 -BaseDir $vbDir -Mapa $medios
        }
    }

    # --- Que disco esta conectado AHORA -------------------------------------
    # Los StorageControllers que cuelgan DIRECTAMENTE de <Machine> describen el
    # estado actual. Los que cuelgan de un <Snapshot> describen ese snapshot.
    # AttachedDevice referencia por UUID (<Image uuid=.../>), NUNCA por ruta:
    # hay que resolverlo contra el MediaRegistry.
    # El XPath cubre las DOS disposiciones vistas: VirtualBox 7.x cuelga
    # <StorageControllers> de <Hardware>, y versiones antiguas lo colgaban
    # directamente de <Machine>. Buscar solo el segundo caso devolvia CERO
    # coincidencias y ningun disco quedaba marcado como conectado, con lo que
    # un diferencial en uso se rotulaba como simple "DIFERENCIAL".
    $XP_ADJ = "./*[local-name()='Hardware']//*[local-name()='AttachedDevice'] | ./*[local-name()='StorageControllers']//*[local-name()='AttachedDevice']"
    $adjuntosAhora = @{}
    foreach ($ad in @($mNode.SelectNodes($XP_ADJ))) {
        if ($ad.GetAttribute('type') -ne 'HardDisk') { continue }
        $img = $ad.SelectSingleNode("./*[local-name()='Image']")
        if ($img) {
            $iu = $img.GetAttribute('uuid')
            if ($iu) { $adjuntosAhora[$iu] = $true }
        }
    }
    # --- Que discos usa cada SNAPSHOT guardado -------------------------------
    $enSnapshot = @{}
    foreach ($snNode in @($mNode.SelectNodes(".//*[local-name()='Snapshot']"))) {
        $snNombre = $snNode.GetAttribute('name')
        # Se toma el <Hardware> PROPIO de este snapshot. Los snapshots anidados
        # cuelgan de <Snapshots>, que es hermano de <Hardware>, asi que no se
        # cuentan aqui: cada snapshot reclama solo sus discos, no los de sus hijos.
        foreach ($ad in @($snNode.SelectNodes($XP_ADJ))) {
            if ($ad.GetAttribute('type') -ne 'HardDisk') { continue }
            $img = $ad.SelectSingleNode("./*[local-name()='Image']")
            if ($img) {
                $iu = $img.GetAttribute('uuid')
                if ($iu -and -not $enSnapshot.ContainsKey($iu)) { $enSnapshot[$iu] = $snNombre }
            }
        }
    }

    # --- Emitir cada medio con su rol real -----------------------------------
    foreach ($u in $medios.Keys) {
        $m = $medios[$u]
        $rol = ''
        $obs = ''
        if ($m.Prof -eq 0) {
            $rol = 'BASE'
            if ($adjuntosAhora.ContainsKey($u)) { $obs = 'conectado a la maquina ahora mismo' }
            elseif ($medios.Count -gt 1) { $obs = 'raiz de la cadena de diferenciales' }
        } else {
            if ($adjuntosAhora.ContainsKey($u)) {
                $rol = 'SNAPSHOT ACTIVO'
                $obs = 'la VM esta corriendo sobre este diferencial'
                if ($curSnap) { $obs += '; currentSnapshot=' + $curSnap }
            } elseif ($enSnapshot.ContainsKey($u)) {
                $rol = 'SNAPSHOT'
                $obs = 'snapshot "' + $enSnapshot[$u] + '"'
            } else {
                $rol = 'DIFERENCIAL'
                $obs = 'diferencial en la cadena, no conectado ni asociado a un snapshot vigente'
            }
        }
        Add-Disco 'VirtualBox' $vbNom $vbEstado $rol $m.Ruta $obs
        Set-Reclamado 'VirtualBox' $m.Ruta
    }
    if ($medios.Count -eq 0) {
        # MediaRegistry sin ningun <HardDisk>: maquina genuinamente sin
        # discos (o el .vbox no declara ninguno). Sin esta nota la VM
        # simplemente no aparece en la salida, indistinguible de un error.
        $notas.Add("VirtualBox / $vbNom : $vbEstado, sin ningun disco duro en su MediaRegistry")
    }

    # --- Huerfanos DENTRO de la carpeta de esta VM ---------------------------
    # Un .vdi que esta en la carpeta de la maquina pero no figura en su
    # MediaRegistry: quedo de un snapshot borrado, se copio a mano, o la VM se
    # reconstruyo. No se le atribuye a la VM: va al grupo de huerfanos.
    foreach ($f in (Get-Discos -Dir $vbDir -Exts $EXT_DISCO_VB)) {
        if (Test-Reclamado 'VirtualBox' $f.FullName) { continue }
        Add-Disco 'VirtualBox' '#HUERFANOS' 'no figuran en el MediaRegistry de ninguna VM' 'HUERFANO' $f.FullName ('hallado en la carpeta de "' + $vbNom + '"')
    }
}
# Medios del registro GLOBAL que no pertenecen a ninguna VM
foreach ($lo in $vbMediosGlobales) {
    if (-not $lo) { continue }
    $loF = $lo
    if (-not [IO.Path]::IsPathRooted($loF)) { continue }
    if (Test-Reclamado 'VirtualBox' $loF) { continue }
    Add-Disco 'VirtualBox' '#HUERFANOS' 'no figuran en el MediaRegistry de ninguna VM' 'REGISTRADO SIN VM' $loF 'esta en el MediaRegistry global de VirtualBox.xml pero ninguna VM lo usa'
}

# =============================================================== VMware =====
# El inventario vive en el perfil del usuario. vmrun list NO sirve para
# enumerar: solo devuelve las maquinas ENCENDIDAS.
$vmxs = New-Object System.Collections.Generic.List[string]
$inv = Join-Path $env:APPDATA 'VMware\inventory.vmls'
if (Test-Path -LiteralPath $inv) {
    foreach ($l in (Get-Content -LiteralPath $inv)) {
        if ($l -match '\.config\s*=\s*"([^"]+\.vmx)"') { $vmxs.Add($Matches[1]) }
    }
}
# Carpeta por defecto elegida por el usuario, leida de preferences.ini en vez
# de asumir Documents\Virtual Machines.
$vmwPrefDir = $null
$vmwPrefs = Join-Path $env:APPDATA 'VMware\preferences.ini'
if (Test-Path -LiteralPath $vmwPrefs) {
    foreach ($l in (Get-Content -LiteralPath $vmwPrefs)) {
        if ($l -match '^\s*prefvmx\.defaultVMPath\s*=\s*"([^"]+)"') { $vmwPrefDir = $Matches[1] }
    }
}
$vmwRaices = New-Object System.Collections.Generic.List[string]
if ($vmwPrefDir) { $vmwRaices.Add($vmwPrefDir) }
$vmwRaices.Add((Join-Path $env:USERPROFILE 'Documents\Virtual Machines'))
$vmwRaices.Add((Join-Path $env:USERPROFILE 'Virtual Machines'))
foreach ($raiz in $vmwRaices) {
    if (Test-Path -LiteralPath $raiz) {
        # -Filter usa el matching de 8.3 del proveedor: "*.vmx" tambien devuelve
        # "*.vmxf" (el archivo de "team member" de VMware, XML, sin relacion con
        # los discos). Comprobado en este equipo. Se filtra la extension real
        # aparte para no procesar un .vmxf como si fuera la config de una VM.
        foreach ($f in @(Get-ChildItem -LiteralPath $raiz -Filter *.vmx -Recurse -Depth 2 -File -ErrorAction SilentlyContinue)) {
            if ($f.Extension.ToLower() -eq '.vmx') { $vmxs.Add($f.FullName) }
        }
    }
}
$vmwVistos = @{}
foreach ($vmx in $vmxs) {
    if (-not $vmx) { continue }
    if ($vmwVistos.ContainsKey($vmx.ToLower())) { continue }
    $vmwVistos[$vmx.ToLower()] = $true
    if (-not (Test-Path -LiteralPath $vmx)) {
        # Mismo caso que ya se cubre para VirtualBox (.vbox registrado pero
        # ausente): inventory.vmls referencia este .vmx, pero ya no esta en
        # esa ruta. Antes se descartaba en silencio; ahora se dice, igual que
        # en VirtualBox, en vez de dejar que la VM desaparezca sin dejar rastro.
        $notas.Add('VMware: se referencia ' + $vmx + ' (en inventory.vmls o hallado antes) pero el .vmx ya NO existe en esa ruta (VM movida o eliminada sin actualizar el inventario)')
        continue
    }
    $dir = Split-Path -Parent $vmx
    $vmxInfo = Get-VmxInfo -VmxPath $vmx -Dir $dir
    $nom = $vmxInfo.Nombre
    $adjuntos = $vmxInfo.Adjuntos
    $estVmw = 'en inventario de VMware'
    if ($vmxInfo.Cifrada) { $estVmw = 'VM CIFRADA por VMware (encryption.keySafe presente en el .vmx)' }

    foreach ($ad in $adjuntos) {
        # Subir la cadena con parentFileNameHint. El primero es el conectado.
        $cur = $ad
        $prof = 0
        $guard = 0
        while ($cur -and $guard -lt 32) {
            $guard++
            if (-not (Test-Path -LiteralPath $cur)) {
                # El .vmx (prof=0) o el parentFileNameHint de un descriptor
                # anterior (prof>0) declara esta ruta, pero ya no esta ahi.
                # ANTES esto rompia la cadena en silencio: la VM se quedaba con
                # menos discos de los que su propia configuracion declara, sin
                # ningun aviso. Add-Disco ya marca AUSENTE cualquier ruta que
                # no exista, asi que basta con dejar de saltarselo aqui.
                $rolAus = if ($prof -eq 0) { 'disco principal, referenciado por el .vmx' } else { 'ancestro de la cadena, referenciado por ' + (Split-Path -Leaf $ant) }
                Add-Disco 'VMware' $nom $estVmw $rolAus $cur ''
                Set-Reclamado 'VMware' $cur
                break
            }
            $vi = Get-VmdkInfo $cur
            if (-not $vi.Leido) {
                Add-Disco 'VMware' $nom $estVmw 'SIN CLASIFICAR' $cur 'no se pudo leer el descriptor VMDK'
                Set-Reclamado 'VMware' $cur
                break
            }
            if ($prof -eq 0) {
                if ($vi.EsBase) {
                    $rol = 'BASE'; $obs = 'conectado a la maquina ahora mismo'
                } else {
                    $rol = 'SNAPSHOT ACTIVO'; $obs = 'la VM esta corriendo sobre este diferencial'
                }
            } else {
                if ($vi.EsBase) {
                    $rol = 'BASE (padre de la cadena)'; $obs = 'lo referencia ' + (Split-Path -Leaf $ant)
                } else {
                    $rol = 'DIFERENCIAL (en cadena)'; $obs = 'padre de ' + (Split-Path -Leaf $ant)
                }
            }
            Add-Disco 'VMware' $nom $estVmw $rol $cur $obs
            Set-Reclamado 'VMware' $cur
            if ($vi.EsBase -or -not $vi.ParentHint) { break }
            $ant = $cur
            $nxt = $vi.ParentHint
            if (-not [IO.Path]::IsPathRooted($nxt)) { $nxt = Join-Path (Split-Path -Parent $cur) $nxt }
            $cur = $nxt
            $prof++
        }
    }

    # Descriptores de la carpeta que no estan en la cadena activa: snapshots de
    # otras ramas o restos. Se clasifican por parentCID, NO por el nombre
    # "-000001": ese sufijo es convencion, no garantia.
    foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter *.vmdk -File -ErrorAction SilentlyContinue)) {
        if ($f.Name -match '-s[0-9]+\.vmdk$' -or $f.Name -match '-flat\.vmdk$' -or $f.Name -match '-delta\.vmdk$') { continue }
        if (Test-Reclamado 'VMware' $f.FullName) { continue }
        $vi = Get-VmdkInfo $f.FullName
        if ($vi.Leido -and -not $vi.EsBase) {
            Add-Disco 'VMware' $nom $estVmw 'SNAPSHOT' $f.FullName 'diferencial no conectado (rama de snapshot no vigente)'
        } else {
            Add-Disco 'VMware' $nom $estVmw 'BASE (no conectado)' $f.FullName 'descriptor base presente pero no referenciado por el .vmx'
        }
        Set-Reclamado 'VMware' $f.FullName
    }
    if ($adjuntos.Count -eq 0) {
        # El .vmx no declara NINGUNA clave "<bus>N:N.fileName": maquina sin
        # discos virtuales (diskless, p.ej. arranque por red) o formato de
        # clave no reconocido. Sin esta nota la VM no aparece en absoluto en
        # la salida, indistinguible de que el modulo simplemente la paso por alto.
        $notas.Add("VMware / $nom : $estVmw, el .vmx no declara ningun disco (<bus>N:N.fileName)")
    }
}

# =============================================================== salida =====
# Orden de plataformas fijo (no alfabetico) para que el informe salga siempre
# igual: Hyper-V, VirtualBox, VMware.
$rank = @{ 'Hyper-V' = 1; 'VirtualBox' = 2; 'VMware' = 3 }
$i = 0
$cortado = $false
foreach ($plat in ($res | Select-Object -ExpandProperty Plat -Unique | Sort-Object { $rank[$_] })) {
    $delPlat = @($res | Where-Object { $_.Plat -eq $plat })
    if ($delPlat.Count -eq 0) { continue }
    $nVm = @($delPlat | Where-Object { $_.Grupo -ne '#HUERFANOS' } | Select-Object -ExpandProperty Grupo -Unique).Count
    $nHu = @($delPlat | Where-Object { $_.Grupo -eq '#HUERFANOS' }).Count
    # Contadores en campos separados, NO como una frase con "|" incrustado: el
    # .bat trocea por "|" y un separador visual dentro del texto le correria
    # los campos siguientes. El .bat arma el "Maquinas: X | Discos: Y | ..."
    # que se ve en pantalla; aqui solo se emiten los numeros crudos.
    '#PLAT|{0}|{1}|{2}|{3}' -f $plat, $nVm, $delPlat.Count, $nHu

    # VMs primero (alfabetico), el grupo de huerfanos SIEMPRE al final.
    $grupos = @($delPlat | Where-Object { $_.Grupo -ne '#HUERFANOS' } | Select-Object -ExpandProperty Grupo -Unique | Sort-Object)
    if ($nHu -gt 0) { $grupos += '#HUERFANOS' }
    foreach ($g in $grupos) {
        $items = @($delPlat | Where-Object { $_.Grupo -eq $g } | Sort-Object Orden)
        if ($items.Count -eq 0) { continue }
        $estado = $items[0].GrupoEstado
        if (-not $estado) { $estado = '-' }
        if ($g -eq '#HUERFANOS') {
            '#VM|DISCOS HUERFANOS|{0}' -f $estado
        } else {
            # El displayName de un .vmx es texto libre y puede llevar "|": correria
            # el estado a otro campo. Mismo criterio que Obs y Rol de abajo.
            '#VM|{0}|{1}' -f ($g -replace '\|', '/'), $estado
        }
        foreach ($d in $items) {
            $i++
            if ($i -gt $Max) { $cortado = $true; break }
            # NINGUN campo puede ir vacio ni contener "|": "for /f" de cmd.exe
            # COLAPSA los delimitadores consecutivos y correria todos los campos
            # siguientes una posicion, de modo que elegir ese disco por numero
            # devolveria una ruta equivocada o vacia.
            $obs = $d.Obs; if (-not $obs) { $obs = '-' }
            $rol = $d.Rol; if (-not $rol) { $rol = 'SIN CLASIFICAR' }
            $fmt = $d.Fmt; if (-not $fmt) { $fmt = '-' }
            $obs = $obs -replace '\|', '/'
            $rol = $rol -replace '\|', '/'
            '#D|{0}|{1}|{2}|{3}|{4}|{5}' -f $i, $rol, $fmt, $d.MB, $obs, $d.Ruta
        }
        if ($cortado) { break }
    }
    if ($cortado) { break }
}
if ($cortado) { $notas.Add("Listado truncado en $Max discos. Use la opcion de ruta manual para los que falten.") }
foreach ($n in $notas) { '#NOTA|' + $n }
if ($i -eq 0) { '#VACIO|No se localizo ningun disco virtual en el perfil del usuario actual' }
