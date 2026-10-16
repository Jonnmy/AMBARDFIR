<#
===============================================================================
 AMBARDFIR - Motor de Evaluacion Previa a la Adquisicion (Identificacion de cifrado)
===============================================================================

 ALCANCE NORMATIVO
   Este motor pertenece EXCLUSIVAMENTE a la fase de IDENTIFICACION de
   ISO/IEC 27037:2012 ("Guidelines for identification, collection, acquisition
   and preservation of digital evidence"), cuyo primer proceso es el
   reconocimiento de las fuentes potenciales de evidencia digital.

   NIST SP 800-86 define Examination como ejecutar herramientas sobre "the
   collected data". Todo lo que hace este motor opera sobre datos que AUN NO
   se han recolectado, por lo que NO constituye examen ni analisis.

 LO QUE ESTE MOTOR NO HACE, POR DISENO
   - No descifra nada.
   - No extrae ni deriva claves (ni VMK, ni FVEK, ni contrasenas).
   - No monta ningun sistema de archivos.
   - No recorre la MFT, ni el Registro, ni enumera programas instalados.
   - No lee archivos del invitado.
   - No escribe en el disco virtual ni en la configuracion del host o del guest.
   - No toma ninguna decision: solo emite recomendaciones para el perito.

 ALTERACION DE EVIDENCIA - declaracion honesta
   La unica alteracion posible es el sello de ULTIMO ACCESO del archivo
   contenedor en el sistema de archivos DEL HOST. Se midio en laboratorio que
   ese sello puede avanzar aun con la politica NTFS en "System Managed,
   Disabled"; puede tratarse de un valor en memoria no volcado todavia al MFT.
   El contenido y el sello de ESCRITURA no se modifican (verificado por SHA-256
   antes y despues). El motor registra la politica NTFS vigente para que quede
   constancia. No se suprime la actualizacion del sello: hacerlo exigiria pedir
   el derecho FILE_WRITE_ATTRIBUTES y podria generar entrada en el USN journal,
   dejando mas rastro que el problema que evita.

 POR QUE SE LEE UN PREFIJO Y NO SECTORES SUELTOS
   Se midio que "qemu-img dd" de esta distribucion IGNORA el parametro skip:
   con skip=1 o superior devuelve 0 bytes, y ocurre igual sobre RAW plano, asi
   que no es un problema del contenedor. La unica lectura fiable es un prefijo
   desde el offset 0, que despues se corta en memoria. Tambien se midio que el
   tamano de bloque domina el rendimiento: 601 MiB tardan 71 s con bs=512 y
   10 s con bs=1M (8 MB/s frente a 59 MB/s). Por eso se usa bs=1M y por eso la
   lectura profunda es una decision explicita del operador y no automatica.

 (c) 2026 Euclides Junior Angeles Alcantara
===============================================================================
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Host', 'Disco')]
    [string]$Modo,

    # --- Modo Disco ---
    [string]$Disco,
    [string]$Formato,
    [string]$QemuImg,
    # Cuantos MiB leer desde el offset 0. 2 MiB alcanzan MBR, GPT y la particion
    # que empiece en LBA 2048 (la ESP habitual, donde vive VeraCrypt EFI).
    # 0 = AUTOMATICO: se lee primero el minimo (la tabla de particiones SIEMPRE
    # cabe ahi: MBR en LBA 0, cabecera GPT en LBA 1, entradas en LBA 2), se mide
    # donde empieza la particion mas lejana y se relee solo lo necesario para
    # alcanzarla. Es una MEDICION, no una estimacion: el offset sale de la propia
    # tabla del disco. Se acota con -AutoMaxMiB para que un disco con una
    # particion muy adentro no dispare una lectura desmedida sin control.
    [int]$PrefijoMiB = 2,
    # Tope del modo automatico. A los ~59 MB/s medidos, 1024 MiB son unos 17 s.
    # Lo que quede fuera de este tope se sigue informando como NO INSPECCIONADA,
    # nunca como limpia, igual que en modo manual.
    [int]$AutoMaxMiB = 1024,
    [string]$TempDir,

    # Comun
    [string]$Informe,

    # Modo de comprobacion rapida para el flujo de adquisicion: NO escribe informe
    # ni resumen en pantalla. Ejecuta la deteccion y emite UNA sola linea a stdout,
    # legible por el .bat con un for /f:
    #   ENC=BitLocker | ENC=LUKS | ENC=CoreStorage | ENC=APFS | ENC=NONE | ENC=ERROR
    # Solo cuenta el cifrado DETERMINISTA (firma leida en su offset), nunca un
    # indicio, para no bloquear una adquisicion por una sospecha no confirmada.
    [switch]$QuickCheck
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# Acumuladores. HALLAZGOS son hechos observados; RECOMENDACIONES son sugerencias
# para el perito. Se mantienen SEPARADOS a proposito: un hallazgo es reproducible
# y una recomendacion es un juicio, y el informe no debe confundirlos.
$script:HALLAZGOS       = New-Object System.Collections.Generic.List[object]
$script:RECOMENDACIONES = New-Object System.Collections.Generic.List[object]
$script:LIMITACIONES    = New-Object System.Collections.Generic.List[string]

function Add-Hallazgo {
    param(
        [string]$Categoria,
        [string]$Sujeto,
        [string]$Detalle,
        # Certeza del hallazgo. DETERMINISTA = firma documentada leida en su
        # offset. INDICIO = correlacion, no prueba. NO_DETERMINADO = no se pudo
        # establecer, y se dice, en lugar de omitirlo.
        [ValidateSet('DETERMINISTA', 'INDICIO', 'NO_DETERMINADO')]
        [string]$Certeza,
        [string]$Base,
        [string]$Limitacion = '',
        # Marca explicita de "aqui hay cifrado". NO se deduce buscando palabras
        # en el texto del hallazgo: se probo contra una VM real y la etiqueta
        # descriptiva del GUID de particion, que dice "el que conserva
        # BitLocker", se detectaba a si misma y el modulo afirmaba haber hallado
        # cifrado en un disco NTFS sin cifrar. Un falso positivo de ese tipo es
        # el peor error posible en una fase que decide el orden de adquisicion.
        [switch]$EsCifrado
    )
    $script:HALLAZGOS.Add([pscustomobject]@{
        Categoria  = $Categoria
        Sujeto     = $Sujeto
        Detalle    = $Detalle
        Certeza    = $Certeza
        Base       = $Base
        Limitacion = $Limitacion
        EsCifrado  = [bool]$EsCifrado
    })
}

function Add-Recomendacion {
    param([string]$Accion, [string]$Motivo, [string]$Fundamento)
    $script:RECOMENDACIONES.Add([pscustomobject]@{
        Accion     = $Accion
        Motivo     = $Motivo
        Fundamento = $Fundamento
    })
}

function Add-Limitacion { param([string]$Texto) $script:LIMITACIONES.Add($Texto) }

# RESUMEN: lo unico que se pinta en pantalla. En campo se trabaja con prisa y
# la pregunta operativa es una sola -"esto esta cifrado o no"-, asi que la
# consola responde eso y nada mas. Toda la fundamentacion (base observada,
# limitaciones, certeza) sigue generandose igual y va al archivo de informe,
# que es donde tiene sentido leerla con calma.
#   Nivel: ok = sin cifrado | cifrado = hay cifrado | duda = no se pudo mirar
#          na = no aplica (particion que por definicion no lleva sistema de archivos)
$script:RESUMEN = New-Object System.Collections.Generic.List[object]
function Add-Resumen {
    param([string]$Etiqueta, [string]$Estado, [ValidateSet('ok','cifrado','duda','na')][string]$Nivel)
    $script:RESUMEN.Add([pscustomobject]@{ Etiqueta = $Etiqueta; Estado = $Estado; Nivel = $Nivel })
}

# ---------------------------------------------------------------------------
# Utilidades binarias
# ---------------------------------------------------------------------------

function Test-Bytes {
    # Compara $Patron dentro de $Buf a partir de $Offset. Devuelve $false si el
    # buffer es corto en lugar de lanzar: un disco truncado no debe abortar el
    # analisis entero, debe reportarse como no determinado.
    param([byte[]]$Buf, [int]$Offset, [byte[]]$Patron)
    if ($null -eq $Buf) { return $false }
    if ($Offset -lt 0 -or ($Offset + $Patron.Length) -gt $Buf.Length) { return $false }
    for ($i = 0; $i -lt $Patron.Length; $i++) {
        if ($Buf[$Offset + $i] -ne $Patron[$i]) { return $false }
    }
    return $true
}

function Get-AsciiZ {
    param([byte[]]$Buf, [int]$Offset, [int]$Max)
    if ($Offset -lt 0 -or ($Offset + $Max) -gt $Buf.Length) { return '' }
    $n = 0
    while ($n -lt $Max -and $Buf[$Offset + $n] -ne 0) { $n++ }
    if ($n -eq 0) { return '' }
    return [Text.Encoding]::ASCII.GetString($Buf, $Offset, $n)
}

function Get-U16LE { param([byte[]]$B, [int]$O) if (($O + 2) -gt $B.Length) { return -1 } return [BitConverter]::ToUInt16($B, $O) }
function Get-U32LE { param([byte[]]$B, [int]$O) if (($O + 4) -gt $B.Length) { return -1 } return [BitConverter]::ToUInt32($B, $O) }
function Get-U64LE { param([byte[]]$B, [int]$O) if (($O + 8) -gt $B.Length) { return [uint64]0 } return [BitConverter]::ToUInt64($B, $O) }

function Get-U16BE {
    # LUKS almacena sus enteros en network byte order. Olvidarlo es el error
    # clasico al parsear su cabecera.
    param([byte[]]$B, [int]$O)
    if (($O + 2) -gt $B.Length) { return -1 }
    return ([int]$B[$O] -shl 8) -bor [int]$B[$O + 1]
}

function Get-GuidMixed {
    # Los GUID en GPT y en la cabecera BitLocker van en formato mixto: los tres
    # primeros campos en little-endian y los dos ultimos en big-endian.
    param([byte[]]$B, [int]$O)
    if (($O + 16) -gt $B.Length) { return [Guid]::Empty }
    $t = New-Object byte[] 16
    [Array]::Copy($B, $O, $t, 0, 16)
    return New-Object Guid (,$t)
}

function Find-Ascii {
    # Busca una cadena ASCII dentro de un buffer. Devuelve el offset o -1.
    param([byte[]]$Buf, [string]$Texto, [int]$Desde = 0, [int]$Hasta = -1)
    $p = [Text.Encoding]::ASCII.GetBytes($Texto)
    if ($Hasta -lt 0 -or $Hasta -gt $Buf.Length) { $Hasta = $Buf.Length }
    $fin = $Hasta - $p.Length
    for ($i = $Desde; $i -le $fin; $i++) {
        $ok = $true
        for ($j = 0; $j -lt $p.Length; $j++) {
            if ($Buf[$i + $j] -ne $p[$j]) { $ok = $false; break }
        }
        if ($ok) { return $i }
    }
    return -1
}

# ---------------------------------------------------------------------------
# MODO HOST - Win32_EncryptableVolume
# ---------------------------------------------------------------------------

function Invoke-ModoHost {

    # Aqui se consultaba la politica NTFS de ultimo acceso con "fsutil behavior
    # query disableLastAccess" y se declaraba en el informe. Retirado por decision
    # del autor: el dato es correcto pero es ruido para el lector del expediente.
    # Se conserva la declaracion POR OPERACION en el modo Disco, que dice si esa
    # lectura concreta movio el sello, que es el hecho observado y no una
    # configuracion del sistema.

    $ns = 'Root\CIMV2\Security\MicrosoftVolumeEncryption'
    $vols = $null
    try {
        $vols = @(Get-CimInstance -Namespace $ns -ClassName Win32_EncryptableVolume -ErrorAction Stop)
    } catch {
        $m = $_.Exception.Message
        # "Access denied" aqui NO significa "no hay cifrado": significa que no
        # se pudo mirar. Confundir ambas cosas seria el peor fallo posible de
        # este modulo, asi que se distingue explicitamente.
        if ($m -match 'denied|denegado') {
            Add-Resumen -Etiqueta 'BitLocker' -Estado 'NO SE PUDO CONSULTAR (requiere Administrador)' -Nivel 'duda'
            Add-Hallazgo -Categoria 'Host' -Sujeto 'BitLocker' -Detalle 'NO SE PUDO CONSULTAR: acceso denegado' `
                -Certeza 'NO_DETERMINADO' -Base "Get-CimInstance -Namespace $ns -ClassName Win32_EncryptableVolume" `
                -Limitacion 'La clase exige privilegios de Administrador (verificado empiricamente). La ausencia de resultado NO equivale a ausencia de cifrado.'
            Add-Recomendacion -Accion 'Relanzar el framework como Administrador antes de decidir la estrategia' `
                -Motivo 'Sin elevacion no se puede distinguir un host sin cifrado de un host que no se pudo consultar' `
                -Fundamento 'Verificacion empirica: la clase devuelve Access denied sin elevacion'
        } else {
            Add-Resumen -Etiqueta 'BitLocker' -Estado ('NO SE PUDO CONSULTAR: ' + $m.Split([char]10)[0]) -Nivel 'duda'
            Add-Hallazgo -Categoria 'Host' -Sujeto 'BitLocker' -Detalle "NO SE PUDO CONSULTAR: $m" `
                -Certeza 'NO_DETERMINADO' -Base $ns
        }
        Add-Limitacion 'Win32_EncryptableVolume solo conoce BitLocker. Un host cifrado con VeraCrypt, LUKS o cualquier FDE de terceros NO aparece en esta consulta.'
        # Aunque no se haya podido leer el estado de cifrado, la enumeracion de
        # discos fisicos NO requiere elevacion y si funciona. Se ejecuta igual:
        # asi el operador ve al menos QUE discos hay, cuantas particiones tiene
        # cada uno y por que no se pudieron evaluar, en vez de una pantalla muda.
        $script:PORLETRA = @{}
        Get-EstadoPorDisco
        return
    }

    if ($vols.Count -eq 0) {
        Add-Hallazgo -Categoria 'Host' -Sujeto 'BitLocker' -Detalle 'Ningun volumen cifrable enumerado' `
            -Certeza 'DETERMINISTA' -Base 'Win32_EncryptableVolume (0 instancias)' `
            -Limitacion 'Solo cubre BitLocker. No descarta VeraCrypt ni otros FDE.'
    }

    # Tablas de la documentacion de Microsoft para Win32_EncryptableVolume.
    $mapProt = @{ 0 = 'DESPROTEGIDO (proteccion desactivada)'; 1 = 'PROTEGIDO'; 2 = 'DESCONOCIDO' }
    $mapConv = @{ 0 = 'Totalmente descifrado'; 1 = 'Totalmente cifrado'; 2 = 'Cifrado en curso';
                  3 = 'Descifrado en curso'; 4 = 'Cifrado en pausa'; 5 = 'Descifrado en pausa' }
    $mapEnc  = @{ 0 = 'Ninguno'; 1 = 'AES 128 con difusor'; 2 = 'AES 256 con difusor'; 3 = 'AES 128';
                  4 = 'AES 256'; 5 = 'Hardware'; 6 = 'XTS-AES 128'; 7 = 'XTS-AES 256' }
    $mapTipo = @{ 0 = 'Volumen del sistema operativo'; 1 = 'Volumen de datos fijo'; 2 = 'Volumen extraible' }
    $mapLock = @{ 0 = 'DESBLOQUEADO'; 1 = 'BLOQUEADO'; 2 = 'DESCONOCIDO' }

    # Indice por letra de unidad. Lo consume Get-EstadoPorDisco para responder la
    # pregunta que de verdad importa antes de imagenar: no "que volumenes hay
    # cifrados" sino "el disco que voy a adquirir, esta cifrado ENTERO".
    $script:PORLETRA = @{}

    $cifrados = 0
    foreach ($v in $vols) {
        $letra = if ($v.DriveLetter) { $v.DriveLetter } else { "(sin letra) $($v.DeviceID)" }

        $ps = [int]$v.ProtectionStatus
        $cs = -1
        try { $cs = [int]$v.ConversionStatus } catch { }
        $em = -1
        try { $em = [int]$v.EncryptionMethod } catch { }
        $vt = -1
        try { $vt = [int]$v.VolumeType } catch { }

        $txtProt = if ($mapProt.ContainsKey($ps)) { $mapProt[$ps] } else { "valor $ps" }
        $txtConv = if ($mapConv.ContainsKey($cs)) { $mapConv[$cs] } else { "valor $cs" }
        $txtEnc  = if ($mapEnc.ContainsKey($em))  { $mapEnc[$em] }  else { "valor $em" }
        $txtTipo = if ($mapTipo.ContainsKey($vt)) { $mapTipo[$vt] } else { "valor $vt" }

        # Estado de bloqueo: es un METODO, no una propiedad. Es el unico dato
        # que el host puede dar y que jamas se puede obtener leyendo el disco
        # de una VM, porque el desbloqueo vive en la RAM del invitado.
        $txtLock = 'no consultado'
        try {
            $r = Invoke-CimMethod -InputObject $v -MethodName GetLockStatus -ErrorAction Stop
            if ($r.ReturnValue -eq 0) {
                $ls = [int]$r.LockStatus
                $txtLock = if ($mapLock.ContainsKey($ls)) { $mapLock[$ls] } else { "valor $ls" }
            } else {
                $txtLock = "GetLockStatus devolvio 0x$('{0:X8}' -f $r.ReturnValue)"
            }
        } catch {
            $txtLock = 'no consultable: ' + $_.Exception.Message.Split([char]10)[0]
        }

        $pct = ''
        try { if ($null -ne $v.EncryptionPercentage) { $pct = "  Progreso: $($v.EncryptionPercentage)%" } } catch { }

        $det = "Proteccion: $txtProt | Conversion: $txtConv$pct | Metodo: $txtEnc | Bloqueo: $txtLock | Tipo: $txtTipo"
        Add-Hallazgo -Categoria 'Host' -Sujeto "Volumen $letra" -Detalle $det -Certeza 'DETERMINISTA' `
            -Base 'Win32_EncryptableVolume (ProtectionStatus, ConversionStatus, EncryptionMethod, GetLockStatus, VolumeType)'

        # Suspendido = proteccion 0 con datos aun cifrados (ConversionStatus > 0).
        # -1 es "no se pudo leer", no un estado de cifrado.
        $suspendido = ($ps -eq 0 -and $cs -gt 0)
        if ($v.DriveLetter) {
            # Protegido aqui significa "datos cifrados": un volumen suspendido lo
            # esta, y el veredicto por disco lo daba como SIN CIFRAR.
            $script:PORLETRA[[string]$v.DriveLetter] = [pscustomobject]@{
                Protegido = ($ps -eq 1 -or $suspendido); Metodo = $txtEnc; Bloqueo = $txtLock; Conversion = $txtConv
            }
        }

        # Veredicto de una linea para la consola.
        if ($ps -eq 1) {
            $eR = 'CIFRADO (' + $txtEnc + ')'
            if ($txtLock -eq 'BLOQUEADO') { $eR += ' - BLOQUEADO' }
            Add-Resumen -Etiqueta $letra -Estado $eR -Nivel 'cifrado'
        } elseif ($suspendido) {
            # Cifrado presente pero con la proteccion suspendida: NO es "sin
            # cifrado", los datos siguen cifrados. Se marca como cifrado.
            Add-Resumen -Etiqueta $letra -Estado 'CIFRADO - proteccion SUSPENDIDA' -Nivel 'cifrado'
        } elseif ($ps -eq 0 -and $cs -eq 0) {
            Add-Resumen -Etiqueta $letra -Estado 'Sin cifrado' -Nivel 'ok'
        } else {
            Add-Resumen -Etiqueta $letra -Estado 'Estado desconocido' -Nivel 'duda'
        }

        if ($ps -eq 1) { $cifrados++ }

        # BitLocker con proteccion desactivada pero volumen cifrado: es el
        # equivalente en el host de la "clear key" que se busca en disco. El
        # volumen es descifrable sin credenciales.
        if ($suspendido) {
            Add-Hallazgo -Categoria 'Host' -Sujeto "Volumen $letra - proteccion suspendida" `
                -Detalle 'El volumen conserva datos cifrados pero la proteccion esta DESACTIVADA' `
                -Certeza 'DETERMINISTA' -Base 'ProtectionStatus=0 con ConversionStatus distinto de 0' `
                -Limitacion 'Microsoft documenta que al suspender BitLocker la VMK queda cifrada con una clear key almacenada sin proteccion en el propio disco.'
            Add-Recomendacion -Accion "Documentar que el volumen $letra tiene la proteccion suspendida" `
                -Motivo 'Un volumen suspendido es descifrable sin credenciales; es un hecho relevante para la cadena de custodia' `
                -Fundamento 'Microsoft, BitLocker FAQ: "Suspend keeps the data encrypted but encrypts the BitLocker volume master key with a clear key"'
        }
    }

    if ($cifrados -gt 0) {
        Add-Recomendacion -Accion 'Adquirir la memoria RAM ANTES que el disco' `
            -Motivo "Se detectaron $cifrados volumen(es) con proteccion activa en el host" `
            -Fundamento 'SWGDE 17-F-002 v2.1: "To obtain encryption keys, examiners may need to capture memory prior to obtaining a disk image, and attempt to decrypt later" / NIST SP 800-86: orden de volatilidad'
        Add-Recomendacion -Accion 'Considerar exportar la clave de recuperacion antes de apagar' `
            -Motivo 'Una vez apagado el equipo, el volumen queda bloqueado y la clave ya no esta en memoria' `
            -Fundamento 'SWGDE 17-F-002 v2.1, adquisicion en vivo sobre sistemas cifrados'
    }

    Get-EstadoPorDisco

    Add-Limitacion 'Win32_EncryptableVolume solo conoce BitLocker. Un host cifrado con VeraCrypt, LUKS, DiskCryptor o cualquier FDE de terceros NO aparece en esta consulta, y su ausencia no debe leerse como ausencia de cifrado.'
}

function Get-EstadoPorDisco {
    <#
      Agrupa los volumenes por DISCO FISICO y emite un veredicto por disco.
      Motivo: se adquiere \\.\PhysicalDriveN, no una letra de unidad. Saber que
      C: esta cifrado no dice nada de si el disco que lo contiene lo esta ENTERO,
      y en el equipo de pruebas C: y D: resultaron estar en discos distintos
      mientras el periferico incautado era un tercero.

      Cadena de asociacion WMI, verificada en este equipo:
        Win32_DiskDrive -> Win32_DiskPartition -> Win32_LogicalDisk (letra)
      Coste medido del recorrido completo: 721 ms. Por eso se hace aqui, bajo
      demanda, y no en el arranque.

      LIMITE INSALVABLE POR ESTA VIA: una particion SIN letra de unidad no
      aparece en Win32_LogicalDisk y por tanto no tiene entrada en
      Win32_EncryptableVolume. En el disco de sistema de un Windows moderno eso
      son siempre al menos dos: la particion EFI y la de recuperacion. Nunca se
      afirma "disco entero cifrado" sin decir cuantas particiones no se pudieron
      evaluar: seria afirmar un hecho no observado.
    #>
    $discos = @()
    try { $discos = @(Get-CimInstance Win32_DiskDrive -ErrorAction Stop) } catch {
        Add-Hallazgo -Categoria 'Disco fisico' -Sujeto 'Enumeracion de discos' `
            -Detalle ('No consultable: ' + $_.Exception.Message.Split([char]10)[0]) `
            -Certeza 'NO_DETERMINADO' -Base 'Win32_DiskDrive'
        return
    }
    if ($discos.Count -eq 0) { return }

    foreach ($d in $discos) {
        $tam = 0
        try { if ($d.Size) { $tam = [double]$d.Size / 1GB } } catch { }
        $enc = "$($d.DeviceID)  $($d.Model)  $('{0:N1}' -f $tam) GB  [$($d.InterfaceType)]"
        # Version corta para la consola: se quita el prefijo "\\.\" y el modelo,
        # que en pantalla empujan el veredicto fuera de la vista. El disco se
        # identifica por su numero, que es lo que se teclea para adquirirlo.
        $encCorto = "$($d.DeviceID -replace '^\\\\\.\\', '')  ($('{0:N0}' -f $tam) GB)"

        $parts = @()
        try { $parts = @(Get-CimAssociatedInstance -InputObject $d -ResultClassName Win32_DiskPartition -ErrorAction Stop) } catch { }

        # Se cuentan por separado los volumenes CON LETRA y los que ademas se
        # pudieron EVALUAR. Confundirlos producia el peor error posible aqui:
        # con la consulta de cifrado fallida por falta de elevacion, los tres
        # discos de este equipo se reportaban como "SIN CIFRADO DETECTADO" y con
        # certeza DETERMINISTA, cuando lo cierto es que no se habia podido mirar.
        $conLetra = 0; $evaluables = 0; $protegidos = 0; $sinLetra = 0
        $detalle = New-Object System.Collections.Generic.List[string]

        foreach ($p in $parts) {
            $lds = @()
            try { $lds = @(Get-CimAssociatedInstance -InputObject $p -ResultClassName Win32_LogicalDisk -ErrorAction Stop) } catch { }
            if ($lds.Count -eq 0) {
                $sinLetra++
                $pt = 0
                try { if ($p.Size) { $pt = [double]$p.Size / 1GB } } catch { }
                $detalle.Add(("{0} ({1:N1} GB) SIN letra de unidad: NO EVALUABLE por esta via" -f $p.DeviceID, $pt))
                continue
            }
            foreach ($ld in $lds) {
                $conLetra++
                $L = [string]$ld.DeviceID
                if ($script:PORLETRA.ContainsKey($L)) {
                    $evaluables++
                    $e = $script:PORLETRA[$L]
                    if ($e.Protegido) { $protegidos++ }
                    $detalle.Add(("{0} {1} - {2} - {3}" -f $L, $(if ($e.Protegido) { 'CIFRADO' } else { 'SIN CIFRAR' }), $e.Metodo, $e.Bloqueo))
                } else {
                    $detalle.Add(("{0} sin entrada en Win32_EncryptableVolume: NO EVALUABLE" -f $L))
                }
            }
        }

        # Veredicto. La distincion entre "todos cifrados" y "todos los evaluables
        # cifrados" no es un matiz de redaccion: es la diferencia entre un hecho
        # observado y una extrapolacion.
        $noEval = ($conLetra - $evaluables) + $sinLetra
        if ($conLetra -eq 0 -and $sinLetra -eq 0) {
            $ver = 'SIN PARTICIONES VISIBLES'
            $cert = 'NO_DETERMINADO'
        } elseif ($evaluables -eq 0) {
            # Ni un solo volumen pudo evaluarse. Decir "sin cifrado" aqui seria
            # afirmar un hecho no observado.
            $ver = "NO EVALUABLE: ninguno de sus $($conLetra + $sinLetra) volumen/particion pudo consultarse. NO se afirma que este sin cifrar."
            $cert = 'NO_DETERMINADO'
        } elseif ($protegidos -eq 0) {
            $ver = "SIN CIFRADO en los $evaluables volumen(es) que SI se pudieron evaluar"
            $cert = if ($noEval -gt 0) { 'INDICIO' } else { 'DETERMINISTA' }
            if ($noEval -gt 0) { $ver += ", pero $noEval no se pudieron evaluar" }
        } elseif ($protegidos -lt $evaluables) {
            $ver = "PARCIALMENTE CIFRADO: $protegidos de $evaluables volumen(es) evaluado(s)"
            $cert = 'DETERMINISTA'
        } elseif ($noEval -gt 0) {
            $ver = "TODOS los volumenes evaluados estan CIFRADOS ($protegidos de $evaluables), pero $noEval particion(es) NO se pudieron evaluar"
            $cert = 'INDICIO'
        } else {
            $ver = "DISCO COMPLETO CIFRADO: sus $evaluables volumen(es) lo estan y no queda ninguna particion sin evaluar"
            $cert = 'DETERMINISTA'
        }

        # Linea de consola por DISCO FISICO: es lo que se adquiere realmente,
        # no la letra de unidad. Se conserva la distincion entre "sin cifrado"
        # y "sin cifrado en lo que se pudo mirar": callar las particiones no
        # evaluables daria una sensacion de seguridad que no se ha comprobado.
        if ($conLetra -eq 0 -and $sinLetra -eq 0) {
            Add-Resumen -Etiqueta $encCorto -Estado 'Sin particiones visibles' -Nivel 'duda'
        } elseif ($evaluables -eq 0) {
            Add-Resumen -Etiqueta $encCorto -Estado 'NO EVALUABLE (no se afirma que este sin cifrar)' -Nivel 'duda'
        } elseif ($protegidos -eq 0) {
            if ($noEval -gt 0) {
                Add-Resumen -Etiqueta $encCorto -Estado ("Sin cifrado ($noEval particion/es no evaluable/s)") -Nivel 'duda'
            } else {
                Add-Resumen -Etiqueta $encCorto -Estado 'Sin cifrado' -Nivel 'ok'
            }
        } elseif ($protegidos -lt $evaluables) {
            Add-Resumen -Etiqueta $encCorto -Estado ("PARCIALMENTE CIFRADO ($protegidos de $evaluables)") -Nivel 'cifrado'
        } else {
            $eD = 'CIFRADO'
            if ($noEval -gt 0) { $eD += " ($noEval particion/es no evaluable/s)" }
            Add-Resumen -Etiqueta $encCorto -Estado $eD -Nivel 'cifrado'
        }

        $lim = ''
        if ($sinLetra -gt 0) {
            $lim = "Las particiones sin letra de unidad no figuran en Win32_EncryptableVolume y no se pueden evaluar por esta via. En un disco de sistema Windows suelen ser la EFI y la de recuperacion, que BitLocker NO cifra por diseno porque el arranque necesita leerlas."
        }
        Add-Hallazgo -Categoria 'Disco fisico' -Sujeto $enc -Detalle ($ver + '  ||  ' + ($detalle -join '  ||  ')) `
            -Certeza $cert `
            -Base 'Win32_DiskDrive asociado a Win32_DiskPartition y a Win32_LogicalDisk, cruzado con Win32_EncryptableVolume por letra de unidad' `
            -Limitacion $lim

        if ($protegidos -gt 0 -and $protegidos -lt $evaluables) {
            Add-Recomendacion -Accion ("Decidir el alcance de la adquisicion de " + $d.DeviceID) `
                -Motivo 'El disco tiene volumenes cifrados y sin cifrar a la vez: una imagen fisica capturara ambos, unos legibles y otros no' `
                -Fundamento 'Verificado por asociacion WMI entre el disco fisico y sus volumenes'
        }
    }
}

# ---------------------------------------------------------------------------
# MODO DISCO - lectura de prefijo y firmas
# ---------------------------------------------------------------------------

function Read-Prefijo {
    # Extrae los primeros $MiB del disco virtual mediante qemu-img dd. Se usa
    # bs=1M por rendimiento (medido: 59 MB/s frente a 8 MB/s con bs=512) y
    # skip=0 SIEMPRE porque se comprobo que skip no funciona en esta version.
    param([string]$Img, [string]$Fmt, [int]$MiB, [string]$Qemu, [string]$Tmp)

    $out = Join-Path $Tmp ("ambar_pre_" + [Guid]::NewGuid().ToString('N').Substring(0, 12) + ".bin")
    $argumentos = @('dd', '-f', $Fmt, 'bs=1M', "count=$MiB", 'skip=0', "if=$Img", "of=$out")
    $salida = & $Qemu $argumentos 2>&1
    if (-not (Test-Path $out)) {
        throw ("qemu-img no produjo salida. " + (($salida | Out-String).Trim()))
    }
    $bytes = [IO.File]::ReadAllBytes($out)
    Remove-Item $out -Force -ErrorAction SilentlyContinue
    # La coma NO sobra. Con "return $bytes" PowerShell ENUMERA el array y el
    # llamador recibe un Object[] de bytes encajonados en lugar de un byte[].
    # A partir de ahi, cada funcion con parametro [byte[]] reconvierte el array
    # entero en cada llamada. Medido: con un prefijo de 8 MiB el analisis pasaba
    # de milisegundos a 104 segundos y 1,4 GB de memoria residente. El operador
    # coma unario devuelve el array como un unico objeto y lo evita.
    return ,$bytes
}

function Test-VeraCryptMBR {
    # El cifrado de sistema de VeraCrypt/TrueCrypt en modo MBR deja el nombre
    # del gestor de arranque en TEXTO CLARO en el sector 0. La documentacion
    # oficial de VeraCrypt afirma que sus volumenes no tienen firma, y eso es
    # cierto para volumenes de DATOS, pero no para el cifrado de sistema.
    # El modo silencioso solo suprime la impresion del mensaje: los bytes siguen.
    param([byte[]]$Sec0)
    foreach ($n in @('VeraCrypt Boot Loader', 'TrueCrypt Boot Loader')) {
        $off = Find-Ascii -Buf $Sec0 -Texto $n -Desde 0 -Hasta 512
        if ($off -ge 0) {
            $prod = $n.Split(' ')[0]
            # La version del gestor vive en el offset 430 como entero de 16 bits
            # big-endian, dentro de los 440 bytes de codigo de arranque.
            $ver = ''
            if ($Sec0.Length -ge 432) {
                $v = Get-U16BE -B $Sec0 -O 430
                if ($v -gt 0 -and $v -lt 0xFFFF) { $ver = ("  Version declarada: 0x{0:X4}" -f $v) }
            }
            Add-Hallazgo -Categoria 'Disco' -Sujeto "$prod - cifrado de sistema" `
                -Detalle "Gestor de arranque de $prod presente en el MBR (offset $off)$ver" `
                -Certeza 'DETERMINISTA' `
                -EsCifrado -Base "Cadena ASCII '$n' hallada en el sector 0" `
                -Limitacion 'Indica cifrado de sistema. NO detecta contenedores ni volumenes de datos de VeraCrypt, que por diseno carecen de firma.'
            return $true
        }
    }
    return $false
}

function Test-BitLockerVBR {
    # Tres variantes documentadas en la especificacion BDE de libyal. La
    # distincion entre BitLocker y BitLocker To Go NO esta en el valor del GUID
    # (es el mismo) sino en el OFFSET donde aparece, y en la firma del offset 3.
    param([byte[]]$Buf, [int]$Base, [string]$Etiqueta)

    if (($Base + 512) -gt $Buf.Length) { return $false }

    $EB52 = [byte[]](0xEB, 0x52, 0x90)
    $EB58 = [byte[]](0xEB, 0x58, 0x90)
    $FVE  = [Text.Encoding]::ASCII.GetBytes('-FVE-FS-')
    $MSW  = [Text.Encoding]::ASCII.GetBytes('MSWIN4.1')

    # 4967d63b-2e29-4ad8-8399-f6a339e3d001
    $idNormal = [byte[]](0x3b,0xd6,0x67,0x49,0x29,0x2e,0xd8,0x4a,0x83,0x99,0xf6,0xa3,0x39,0xe3,0xd0,0x01)
    # 92a84d3b-dd80-4d0e-9e4e-b1e3284eaed8  (modo "solo espacio usado")
    $idUDSO   = [byte[]](0x3b,0x4d,0xa8,0x92,0x80,0xdd,0x0e,0x4d,0x9e,0x4e,0xb1,0xe3,0x28,0x4e,0xae,0xd8)

    $variante = $null
    $offFVE   = -1   # offset del primer puntero a metadatos FVE
    $extra    = ''

    if (Test-Bytes -Buf $Buf -Offset $Base -Patron $EB52) {
        if (Test-Bytes -Buf $Buf -Offset ($Base + 3) -Patron $FVE) {
            $variante = 'BitLocker (Windows Vista)'
            # En Vista el puntero esta en 0x38 y es un NUMERO DE CLUSTER, no un
            # offset en bytes, asi que no se resuelve aqui.
            $extra = '  Los metadatos FVE de Vista se referencian por numero de cluster; no se resuelven en esta fase.'
        }
    } elseif (Test-Bytes -Buf $Buf -Offset $Base -Patron $EB58) {
        if (Test-Bytes -Buf $Buf -Offset ($Base + 0x0A0) -Patron $idNormal) {
            $variante = 'BitLocker (Windows 7 o posterior)'
            $offFVE = $Base + 0x0B0
        } elseif (Test-Bytes -Buf $Buf -Offset ($Base + 0x0A0) -Patron $idUDSO) {
            $variante = 'BitLocker (Windows 7+, modo Solo Espacio Usado)'
            $offFVE = $Base + 0x0B0
            $extra = '  Cifrado unicamente del espacio en uso: el espacio libre NO esta cifrado.'
        } elseif (Test-Bytes -Buf $Buf -Offset ($Base + 0x1A8) -Patron $idNormal) {
            $variante = 'BitLocker To Go'
            $offFVE = $Base + 0x1B8
        } elseif (Test-Bytes -Buf $Buf -Offset ($Base + 3) -Patron $MSW) {
            $variante = 'BitLocker To Go (firma FAT, identificador no reconocido)'
        } elseif (Test-Bytes -Buf $Buf -Offset ($Base + 3) -Patron $FVE) {
            $variante = 'BitLocker (identificador no reconocido)'
            $extra = '  La firma -FVE-FS- esta presente pero el GUID identificador no coincide con ninguno documentado.'
        }
    }

    if (-not $variante) { return $false }

    Add-Hallazgo -Categoria 'Disco' -Sujeto "$Etiqueta - $variante" `
        -Detalle ("Volumen cifrado con BitLocker.$extra") -Certeza 'DETERMINISTA' `
        -EsCifrado -Base 'Firma en el Volume Boot Record segun la especificacion BDE (libyal): bytes de arranque, firma en offset 0x03 e identificador GUID' `
        -Limitacion 'La presencia de cifrado es un hecho. El ESTADO DE BLOQUEO no es observable desde el disco: el desbloqueo ocurre en la memoria del invitado y no modifica un solo byte del volumen.'

    # Metadatos FVE: algoritmo y protectores. Estan en TEXTO CLARO; solo las
    # claves van envueltas en AES-CCM. Leerlos NO es extraer material criptografico.
    if ($offFVE -ge 0) { Read-MetadatosFVE -Buf $Buf -OffPuntero $offFVE -BaseVol $Base -Etiqueta $Etiqueta }

    return $true
}

function Read-MetadatosFVE {
    param([byte[]]$Buf, [int]$OffPuntero, [int]$BaseVol, [string]$Etiqueta)

    $rel = Get-U64LE -B $Buf -O $OffPuntero
    if ($rel -eq 0) { return }

    # El puntero es un offset EN BYTES relativo al inicio del volumen.
    $abs = [int64]$BaseVol + [int64]$rel
    if ($abs -lt 0 -or ($abs + 0x70) -gt $Buf.Length) {
        Add-Hallazgo -Categoria 'Disco' -Sujeto "$Etiqueta - metadatos FVE" `
            -Detalle ("Los metadatos FVE estan en el offset {0:N0} del volumen, fuera del prefijo leido" -f $rel) `
            -Certeza 'NO_DETERMINADO' -Base 'Puntero del VBR a los bloques de metadatos FVE' `
            -Limitacion 'Amplie el prefijo de lectura para determinar el algoritmo de cifrado y el tipo de protector.'
        return
    }

    if (-not (Test-Bytes -Buf $Buf -Offset ([int]$abs) -Patron ([Text.Encoding]::ASCII.GetBytes('-FVE-FS-')))) {
        Add-Hallazgo -Categoria 'Disco' -Sujeto "$Etiqueta - metadatos FVE" `
            -Detalle 'El bloque apuntado no lleva la firma -FVE-FS- esperada' -Certeza 'NO_DETERMINADO' `
            -Base 'Verificacion de firma del bloque de metadatos FVE'
        return
    }

    # Cabecera de metadatos: +0x40 del bloque. El metodo de cifrado esta en su
    # offset 0x24 (4 bytes); los 16 bits altos no estan documentados.
    $hdr = [int]$abs + 0x40
    $met = Get-U32LE -B $Buf -O ($hdr + 0x24)
    if ($met -ge 0) {
        # El cast a [int] NO sobra: BitConverter devuelve UInt32 y las claves de
        # la tabla son Int32. ContainsKey compara tipo ademas de valor, asi que
        # sin el cast un 0x8004 legitimo se reportaba como "no documentado".
        $m = [int]($met -band 0xFFFF)
        $mapa = @{
            0x8000 = 'AES-CBC 128 bits con difusor Elephant'
            0x8001 = 'AES-CBC 256 bits con difusor Elephant'
            0x8002 = 'AES-CBC 128 bits'
            0x8003 = 'AES-CBC 256 bits'
            0x8004 = 'AES-XTS 128 bits'
            0x8005 = 'AES-XTS 256 bits'
        }
        if ($mapa.ContainsKey($m)) {
            Add-Hallazgo -Categoria 'Disco' -Sujeto "$Etiqueta - algoritmo" -Detalle $mapa[$m] `
                -Certeza 'DETERMINISTA' `
                -Base ("Cabecera de metadatos FVE, offset 0x24, valor 0x{0:X4}" -f $m) `
                -Limitacion 'El algoritmo se lee en claro de los metadatos; NO implica acceso a ninguna clave.'
        } else {
            Add-Hallazgo -Categoria 'Disco' -Sujeto "$Etiqueta - algoritmo" `
                -Detalle ("Identificador no documentado: 0x{0:X4}" -f $m) -Certeza 'NO_DETERMINADO' `
                -Base 'Cabecera de metadatos FVE, offset 0x24'
        }
    }

    # Tamano aun cifrado (cabecera de bloque version 2, offset 0x10). BitLocker
    # descifra de atras hacia adelante, asi que este campo mide lo que QUEDA
    # cifrado, no el progreso del cifrado inicial.
    $ver = Get-U16LE -B $Buf -O ([int]$abs + 0x0A)
    if ($ver -eq 2) {
        $enc = Get-U64LE -B $Buf -O ([int]$abs + 0x10)
        if ($enc -gt 0) {
            Add-Hallazgo -Categoria 'Disco' -Sujeto "$Etiqueta - volumen aun cifrado" `
                -Detalle ("{0:N0} bytes ({1:N1} GiB) permanecen cifrados" -f $enc, ($enc / 1GB)) `
                -Certeza 'DETERMINISTA' -Base 'Cabecera de bloque FVE version 2, offset 0x10 (encrypted volume size)' `
                -Limitacion 'Este campo mide lo que falta por DESCIFRAR. No existe en disco un equivalente al Conversion Status del cifrado inicial.'
        }
    }

    Find-ClearKey -Buf $Buf -Abs ([int]$abs) -Etiqueta $Etiqueta
}

function Find-ClearKey {
    # Busca entradas VMK cuyo tipo de proteccion sea 0x0000 (clear key). Es el
    # hallazgo de mayor valor de todo el modulo: significa que el volumen es
    # descifrable SIN credenciales, y se sabe leyendo unicamente el disco.
    #
    # NOTA DE HONESTIDAD: el recorrido de entradas TLV de los metadatos FVE se
    # implementa de forma DEFENSIVA. Si la estructura no valida, se reporta
    # NO_DETERMINADO en lugar de adivinar. Un falso positivo aqui seria grave:
    # afirmaria que un volumen es accesible cuando no lo es.
    param([byte[]]$Buf, [int]$Abs, [string]$Etiqueta)

    $tamMeta = Get-U32LE -B $Buf -O ($Abs + 0x40)
    if ($tamMeta -le 0 -or $tamMeta -gt 0x10000) {
        Add-Hallazgo -Categoria 'Disco' -Sujeto "$Etiqueta - protectores" `
            -Detalle 'No se pudo delimitar el area de metadatos' -Certeza 'NO_DETERMINADO' `
            -Base 'Cabecera de metadatos FVE, campo de tamano'
        return
    }

    $ini = $Abs + 0x40 + 48          # primera entrada, tras la cabecera de 48 bytes
    $fin = [Math]::Min($Abs + 0x40 + $tamMeta, $Buf.Length)
    $p = $ini
    $vistos = 0
    $clear = 0
    $tipos = New-Object System.Collections.Generic.List[string]

    $mapProt = @{
        0x0000 = 'CLEAR KEY (VMK sin proteccion)'
        0x0100 = 'TPM'
        0x0200 = 'Clave de inicio (startup key)'
        0x0500 = 'TPM + PIN'
        0x0800 = 'Contrasena de recuperacion'
        0x2000 = 'Contrasena'
    }

    while (($p + 8) -le $fin -and $vistos -lt 64) {
        $tam = Get-U16LE -B $Buf -O $p
        if ($tam -lt 8 -or ($p + $tam) -gt $fin) { break }
        $valueType = Get-U16LE -B $Buf -O ($p + 4)

        # value type 0x0002 = VMK. Su dato empieza tras la cabecera de 8 bytes.
        if ($valueType -eq 0x0002 -and ($p + 8 + 0x1C) -le $fin) {
            # [int] por el mismo motivo que en el algoritmo: Get-U16LE devuelve
            # UInt16 y las claves de la tabla son Int32.
            $prot = [int](Get-U16LE -B $Buf -O ($p + 8 + 0x1A))
            $txt = if ($mapProt.ContainsKey($prot)) { $mapProt[$prot] } else { ("tipo 0x{0:X4}" -f $prot) }
            $tipos.Add($txt)
            if ($prot -eq 0x0000) { $clear++ }
        }
        $p += $tam
        $vistos++
    }

    if ($tipos.Count -eq 0) {
        Add-Hallazgo -Categoria 'Disco' -Sujeto "$Etiqueta - protectores" `
            -Detalle 'No se identifico ninguna entrada VMK interpretable' -Certeza 'NO_DETERMINADO' `
            -Base 'Recorrido defensivo de las entradas de metadatos FVE' `
            -Limitacion 'El recorrido se aborta ante cualquier inconsistencia estructural en lugar de inferir. Verifique con herramienta especializada si el dato es relevante para el caso.'
        return
    }

    Add-Hallazgo -Categoria 'Disco' -Sujeto "$Etiqueta - protectores" `
        -Detalle ('Protectores hallados: ' + ($tipos -join '; ')) -Certeza 'DETERMINISTA' `
        -Base 'Entradas VMK de los metadatos FVE, campo de tipo de proteccion en el offset 0x1A' `
        -Limitacion 'Se identifica el TIPO de protector. NO se lee, deriva ni extrae ninguna clave.'

    if ($clear -gt 0) {
        Add-Hallazgo -Categoria 'Disco' -Sujeto "$Etiqueta - CLEAR KEY DETECTADA" `
            -Detalle 'El volumen tiene una VMK protegida con clear key: es descifrable SIN credenciales' `
            -Certeza 'DETERMINISTA' `
            -Base 'Entrada VMK con tipo de proteccion 0x0000' `
            -Limitacion 'Corresponde a BitLocker SUSPENDIDO o a BitLocker preaprovisionado en espera de activacion. Ambos escenarios se ven identicos en disco y no deben reportarse indistintamente como "suspendido".'
        Add-Recomendacion -Accion "Hacer constar en el acta que $Etiqueta presenta una clear key" `
            -Motivo 'El volumen es descifrable sin credenciales, lo que condiciona toda la estrategia posterior' `
            -Fundamento 'Microsoft, BitLocker FAQ: "The clear key is a cryptographic key stored unencrypted and unprotected on the disk drive"'
    }
}

function Test-LUKS {
    param([byte[]]$Buf, [int]$Base, [string]$Etiqueta)
    $magic = [byte[]](0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE)
    if (-not (Test-Bytes -Buf $Buf -Offset $Base -Patron $magic)) { return $false }

    # LUKS guarda sus enteros en network byte order (big-endian).
    $ver = Get-U16BE -B $Buf -O ($Base + 6)
    if ($ver -eq 1) {
        $cn = Get-AsciiZ -Buf $Buf -Offset ($Base + 0x08) -Max 32
        $cm = Get-AsciiZ -Buf $Buf -Offset ($Base + 0x28) -Max 32
        $hs = Get-AsciiZ -Buf $Buf -Offset ($Base + 0x48) -Max 32
        $uu = Get-AsciiZ -Buf $Buf -Offset ($Base + 0xA8) -Max 40
        Add-Hallazgo -Categoria 'Disco' -Sujeto "$Etiqueta - LUKS1" `
            -Detalle "Cifrado LUKS version 1. Cifrador: $cn  Modo: $cm  Hash: $hs  UUID: $uu" `
            -Certeza 'DETERMINISTA' `
            -EsCifrado -Base 'Magic LUKS en offset 0 y campos cipherName/cipherMode/hashSpec en offsets 0x08/0x28/0x48' `
            -Limitacion 'La cabecera LUKS es publica por diseno: leer el cifrador NO implica acceso al material de clave, que esta protegido en los keyslots.'
    } elseif ($ver -eq 2) {
        Add-Hallazgo -Categoria 'Disco' -Sujeto "$Etiqueta - LUKS2" `
            -Detalle 'Cifrado LUKS version 2. Los parametros criptograficos residen en el area JSON del offset 0x1000.' `
            -Certeza 'DETERMINISTA' -EsCifrado -Base 'Magic LUKS en offset 0, campo de version = 2 (big-endian)' `
            -Limitacion 'No se parsea el area JSON en esta fase para mantener la lectura al minimo.'
    } else {
        Add-Hallazgo -Categoria 'Disco' -Sujeto "$Etiqueta - LUKS" `
            -Detalle "Magic LUKS presente con version no reconocida ($ver)" -Certeza 'INDICIO' `
            -Base 'Magic LUKS en offset 0'
    }
    return $true
}

function Test-CoreStorage {
    param([byte[]]$Buf, [int]$Base, [string]$Etiqueta)
    if (-not (Test-Bytes -Buf $Buf -Offset ($Base + 0x58) -Patron ([byte[]](0x43, 0x53)))) { return $false }
    $m = Get-U32LE -B $Buf -O ($Base + 0xAC)
    $txt = if ($m -eq 2) { 'AES-XTS' } elseif ($m -eq 0) { 'sin cifrado' } else { "identificador $m" }
    # Metodo 0 es CoreStorage SIN cifrar (Fusion Drive): marcarlo como cifrado era
    # un falso positivo que QuickCheck devolvia como ENC=CoreStorage.
    Add-Hallazgo -Categoria 'Disco' -Sujeto "$Etiqueta - Apple CoreStorage" `
        -Detalle "Volumen fisico CoreStorage. Metodo de cifrado: $txt" -Certeza 'DETERMINISTA' `
        -EsCifrado:($m -ne 0) -Base 'Firma "CS" en el offset 0x58 del primer sector y metodo de cifrado en el offset 0xAC' `
        -Limitacion 'CoreStorage se uso tambien SIN cifrado como gestor de volumenes logicos (Fusion Drive). Su presencia no implica FileVault por si sola.'
    return $true
}

function Test-APFS {
    param([byte[]]$Buf, [int]$Base, [string]$Etiqueta)
    if (-not (Test-Bytes -Buf $Buf -Offset ($Base + 0x20) -Patron ([Text.Encoding]::ASCII.GetBytes('NXSB')))) { return $false }
    $kb = Get-U64LE -B $Buf -O ($Base + 0x516)
    if ($kb -gt 0) {
        Add-Hallazgo -Categoria 'Disco' -Sujeto "$Etiqueta - APFS cifrado" `
            -Detalle "Contenedor APFS con key bag presente ($kb bloque/s): existen volumenes cifrados" `
            -Certeza 'INDICIO' `
            -EsCifrado -Base 'Superbloque de contenedor APFS (NXSB en offset 0x20), campo nx_keybag_blocks en offset 0x516' `
            -Limitacion 'El estado definitivo por volumen vive en el superbloque de volumen (APSB), al que solo se llega recorriendo el arbol B del contenedor. Eso excede la fase de identificacion y no se hace.'
    } else {
        Add-Hallazgo -Categoria 'Disco' -Sujeto "$Etiqueta - APFS" `
            -Detalle 'Contenedor APFS sin key bag en el superbloque: no se aprecian volumenes cifrados' `
            -Certeza 'INDICIO' -Base 'Superbloque de contenedor APFS, nx_keybag_blocks = 0'
    }
    return $true
}

function Test-Firmas {
    # Aplica en cascada todas las firmas conocidas sobre el inicio de un volumen.
    param([byte[]]$Buf, [int]$Base, [string]$Etiqueta)
    if (Test-BitLockerVBR  -Buf $Buf -Base $Base -Etiqueta $Etiqueta) { return $true }
    if (Test-LUKS          -Buf $Buf -Base $Base -Etiqueta $Etiqueta) { return $true }
    if (Test-CoreStorage   -Buf $Buf -Base $Base -Etiqueta $Etiqueta) { return $true }
    if (Test-APFS          -Buf $Buf -Base $Base -Etiqueta $Etiqueta) { return $true }

    # Sin firma de cifrado: se comprueba si hay una firma de sistema de archivos
    # reconocible. Su AUSENCIA en un volumen que deberia tenerla es el unico
    # indicio estructural de VeraCrypt, que por diseno no deja firma alguna.
    $fsCon = @{
        'NTFS'   = 3;  'MSDOS5.0' = 3;  'EXFAT'  = 3;  'FAT32' = 82;  'FAT16' = 54
    }
    foreach ($k in $fsCon.Keys) {
        if (Test-Bytes -Buf $Buf -Offset ($Base + $fsCon[$k]) -Patron ([Text.Encoding]::ASCII.GetBytes($k))) {
            Add-Hallazgo -Categoria 'Disco' -Sujeto $Etiqueta -Detalle "Sistema de archivos $k sin cifrado detectado" `
                -Certeza 'DETERMINISTA' -Base "Firma '$k' en el Volume Boot Record"
            return $true
        }
    }
    return $false
}

function Invoke-ModoDisco {

    if (-not (Test-Path -LiteralPath $Disco))   { throw "No existe el disco: $Disco" }
    if (-not (Test-Path -LiteralPath $QemuImg)) { throw "No existe qemu-img: $QemuImg" }
    if (-not $TempDir) { $TempDir = $env:TEMP }

    $fi = Get-Item -LiteralPath $Disco
    Add-Hallazgo -Categoria 'Disco' -Sujeto 'Contenedor analizado' `
        -Detalle ("{0}  ({1:N0} bytes en disco, formato declarado: {2})" -f $fi.FullName, $fi.Length, $Formato) `
        -Certeza 'DETERMINISTA' -Base 'Metadatos del sistema de archivos del host'

    # Sello de ultimo acceso ANTES de leer, para poder declarar el efecto real.
    $accAntes = [IO.File]::GetLastAccessTimeUtc($Disco)
    $wrtAntes = [IO.File]::GetLastWriteTimeUtc($Disco)

    # Modo AUTOMATICO: se arranca con el minimo imprescindible. La tabla de
    # particiones vive siempre dentro de esos 2 MiB (MBR en LBA 0, cabecera GPT
    # en LBA 1, entradas en LBA 2), asi que con esto ya se puede MEDIR donde
    # empieza cada particion y decidir despues, con el dato en la mano, cuanto
    # hace falta releer. No se adivina un tamano "que suele bastar".
    $prefijoAuto = ($PrefijoMiB -le 0)
    if ($prefijoAuto) { $PrefijoMiB = 2 }

    $sw = [Diagnostics.Stopwatch]::StartNew()
    $buf = Read-Prefijo -Img $Disco -Fmt $Formato -MiB $PrefijoMiB -Qemu $QemuImg -Tmp $TempDir
    $sw.Stop()

    $accDesp = [IO.File]::GetLastAccessTimeUtc($Disco)
    $wrtDesp = [IO.File]::GetLastWriteTimeUtc($Disco)

    Add-Hallazgo -Categoria 'Disco' -Sujeto 'Lectura realizada' `
        -Detalle ("Prefijo de {0} MiB leido en {1:N0} ms. Sello de ESCRITURA modificado: {2}. Sello de ULTIMO ACCESO modificado: {3}." -f `
            $PrefijoMiB, $sw.Elapsed.TotalMilliseconds, ($wrtAntes -ne $wrtDesp), ($accAntes -ne $accDesp)) `
        -Certeza 'DETERMINISTA' -Base 'qemu-img dd bs=1M skip=0, lectura de solo lectura' `
        -Limitacion 'El contenido del contenedor no se modifica. El sello de ultimo acceso del HOST puede avanzar; se declara aqui conforme al principio 2 de ACPO.'

    # --- Sector 0: VeraCrypt/TrueCrypt y tabla de particiones ---
    $sec0 = New-Object byte[] 512
    [Array]::Copy($buf, 0, $sec0, 0, [Math]::Min(512, $buf.Length))
    [void](Test-VeraCryptMBR -Sec0 $sec0)

    if (-not (Test-Bytes -Buf $sec0 -Offset 510 -Patron ([byte[]](0x55, 0xAA)))) {
        Add-Hallazgo -Categoria 'Disco' -Sujeto 'Tabla de particiones' `
            -Detalle 'El sector 0 no lleva la firma de arranque 0x55AA' -Certeza 'NO_DETERMINADO' `
            -Base 'Verificacion de la firma del sector 0' `
            -Limitacion 'Puede tratarse de un disco sin particionar, de un volumen suelto, o de un contenedor cifrado completo.'
    }

    $particiones = New-Object System.Collections.Generic.List[object]

    # --- GPT ---
    $esGPT = $false
    if ($buf.Length -ge 1024 -and (Test-Bytes -Buf $buf -Offset 512 -Patron ([Text.Encoding]::ASCII.GetBytes('EFI PART')))) {
        $esGPT = $true
        $lbaEnt = Get-U64LE -B $buf -O (512 + 0x48)
        $numEnt = Get-U32LE -B $buf -O (512 + 0x50)
        $tamEnt = Get-U32LE -B $buf -O (512 + 0x54)
        Add-Hallazgo -Categoria 'Disco' -Sujeto 'Esquema de particionado' `
            -Detalle ("GPT. Entradas: {0}, tamano de entrada: {1} bytes, tabla en LBA {2}" -f $numEnt, $tamEnt, $lbaEnt) `
            -Certeza 'DETERMINISTA' -Base 'Cabecera GPT ("EFI PART") en LBA 1'

        # GUID de tipo con significado forense. BitLocker NO tiene GUID propio:
        # conserva el de Basic Data Partition, por eso el GUID nunca puede
        # servir para detectarlo y hay que leer el VBR de cada particion.
        $guidConocidos = @{
            'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7' = 'Datos basicos de Microsoft (el que conserva BitLocker)'
            'c12a7328-f81f-11d2-ba4b-00a0c93ec93b' = 'Particion del sistema EFI (ESP)'
            'e3c9e316-0b5c-4db8-817d-f92df00215ae' = 'Reservada de Microsoft (MSR)'
            'de94bba4-06d1-4d40-a16a-bfd50179d6ac' = 'Entorno de recuperacion de Windows'
            'ca7d7ccb-63ed-4c53-861c-1742536059cc' = 'Linux LUKS'
            '7ffec5c9-2d00-49b7-8941-3ea10a5586b7' = 'Linux dm-crypt en claro'
            '0fc63daf-8483-4772-8e79-3d69d8477de4' = 'Sistema de archivos Linux'
            '53746f72-6167-11aa-aa11-00306543ecac' = 'Apple CoreStorage'
            '7c3457ef-0000-11aa-aa11-00306543ecac' = 'Apple APFS'
            '516e7cba-6ecf-11d6-8ff8-00022d09712b' = 'FreeBSD ZFS'
        }
        $cifradoPorGuid = @('ca7d7ccb-63ed-4c53-861c-1742536059cc', '7ffec5c9-2d00-49b7-8941-3ea10a5586b7')
        # Tipos que por definicion NO alojan un sistema de archivos. La MSR es
        # area de trabajo reservada de Windows y esta presente en cualquier
        # instalacion GPT: sin esta lista, cada disco Windows generaria un aviso
        # de "sin firma reconocible" que seria puro ruido.
        $sinFS = @('e3c9e316-0b5c-4db8-817d-f92df00215ae')

        $tabla = [int]$lbaEnt * 512
        $maxEnt = [Math]::Min($numEnt, 128)
        for ($i = 0; $i -lt $maxEnt; $i++) {
            $e = $tabla + ($i * $tamEnt)
            if (($e + 128) -gt $buf.Length) { break }
            $tg = Get-GuidMixed -B $buf -O $e
            if ($tg -eq [Guid]::Empty) { continue }
            $pri = Get-U64LE -B $buf -O ($e + 0x20)
            $ult = Get-U64LE -B $buf -O ($e + 0x28)
            $nom = ''
            try { $nom = ([Text.Encoding]::Unicode.GetString($buf, $e + 0x38, 72)).Trim([char]0) } catch { }
            $k = $tg.ToString().ToLower()
            $tipo = if ($guidConocidos.ContainsKey($k)) { $guidConocidos[$k] } else { "GUID $k" }
            $particiones.Add([pscustomobject]@{
                Indice = $i + 1; PrimerLBA = $pri; UltimoLBA = $ult; Tipo = $tipo; Nombre = $nom
                CifradoPorGuid = ($cifradoPorGuid -contains $k)
                SinSistemaArchivos = ($sinFS -contains $k)
            })
        }
    }

    # --- MBR clasico (solo si no hay GPT) ---
    if (-not $esGPT) {
        $tiposMBR = @{ 0x07 = 'NTFS/exFAT'; 0x0B = 'FAT32'; 0x0C = 'FAT32 LBA'; 0x83 = 'Linux'; 0x8E = 'Linux LVM'; 0xEE = 'GPT protectora' }
        for ($i = 0; $i -lt 4; $i++) {
            $e = 0x1BE + ($i * 16)
            $t = $sec0[$e + 4]
            if ($t -eq 0) { continue }
            $pri = Get-U32LE -B $sec0 -O ($e + 8)
            $cnt = Get-U32LE -B $sec0 -O ($e + 12)
            $tipo = if ($tiposMBR.ContainsKey([int]$t)) { $tiposMBR[[int]$t] } else { ("tipo 0x{0:X2}" -f $t) }
            $particiones.Add([pscustomobject]@{
                Indice = $i + 1; PrimerLBA = [uint64]$pri; UltimoLBA = [uint64]($pri + $cnt - 1)
                Tipo = $tipo; Nombre = ''; CifradoPorGuid = $false; SinSistemaArchivos = $false
            })
        }
        if ($particiones.Count -gt 0) {
            Add-Hallazgo -Categoria 'Disco' -Sujeto 'Esquema de particionado' -Detalle 'MBR clasico' `
                -Certeza 'DETERMINISTA' -Base 'Entradas de particion en el offset 0x1BE del sector 0'
        }
    }

    # --- Modo automatico: ampliar el prefijo a lo que la tabla exige ----------
    # Ya se conoce el offset REAL de cada particion, asi que el tamano necesario
    # es un dato medido, no una estimacion. Se relee una sola vez con el maximo
    # que haga falta, acotado por -AutoMaxMiB.
    if ($prefijoAuto -and $particiones.Count -gt 0) {
        # Se toma la particion mas lejana que TODAVIA CABE bajo el tope, no la
        # mas lejana a secas. Si una particion esta fuera de alcance (p.ej. una
        # de recuperacion a 163 GB del inicio), leer hasta el tope completo no
        # la alcanzaria igualmente: solo gastaria tiempo y espacio temporal sin
        # inspeccionar ni una particion mas. Medido en un disco real: con este
        # criterio se leen ~600 MiB en vez de los 1024 del tope, se inspeccionan
        # exactamente las mismas particiones, y se ahorran varios segundos.
        $necesarioBytes = [int64]0
        $fueraDeAlcance = 0
        $topeBytes = [int64]$AutoMaxMiB * 1MB
        foreach ($p in $particiones) {
            $fin = [int64]$p.PrimerLBA * 512 + 512
            if ($fin -gt $topeBytes) { $fueraDeAlcance++; continue }
            if ($fin -gt $necesarioBytes) { $necesarioBytes = $fin }
        }
        $necesarioMiB = [int][math]::Ceiling($necesarioBytes / 1MB)
        if ($necesarioMiB -lt 2) { $necesarioMiB = 2 }
        $topado = ($fueraDeAlcance -gt 0)

        if ($necesarioMiB -gt $PrefijoMiB) {
            $swA = [Diagnostics.Stopwatch]::StartNew()
            $buf = Read-Prefijo -Img $Disco -Fmt $Formato -MiB $necesarioMiB -Qemu $QemuImg -Tmp $TempDir
            $swA.Stop()
            $antes = $PrefijoMiB
            $PrefijoMiB = $necesarioMiB
            Add-Hallazgo -Categoria 'Disco' -Sujeto 'Prefijo ajustado automaticamente' `
                -Detalle ("Ampliado de {0} MiB a {1} MiB y releido en {2:N0} ms" -f $antes, $necesarioMiB, $swA.Elapsed.TotalMilliseconds) `
                -Certeza 'DETERMINISTA' `
                -Base 'El tamano sale del primer LBA de la particion mas lejana declarada en la tabla del propio disco, no de una estimacion' `
                -Limitacion 'La lectura sigue siendo de solo lectura y no modifica el contenedor.'
            if ($topado) {
                Add-Limitacion ("El ajuste automatico dejo $fueraDeAlcance particion(es) fuera de alcance: empiezan mas alla del tope de $AutoMaxMiB MiB. Se leyo solo hasta la ultima particion alcanzable; ampliar hasta el tope no habria alcanzado ninguna mas. Lo que queda fuera se informa como NO INSPECCIONADA, nunca como limpia.")
            }
        } else {
            Add-Hallazgo -Categoria 'Disco' -Sujeto 'Prefijo ajustado automaticamente' `
                -Detalle ("Bastan {0} MiB: ninguna particion declarada empieza mas alla" -f $PrefijoMiB) `
                -Certeza 'DETERMINISTA' `
                -Base 'Primer LBA de todas las particiones de la tabla, comparado con el prefijo ya leido'
        }
    }

    # --- Inspeccion de cada particion alcanzable dentro del prefijo ---
    $limiteBytes = [int64]$PrefijoMiB * 1MB
    $fuera = New-Object System.Collections.Generic.List[string]

    foreach ($p in $particiones) {
        $et = "Particion $($p.Indice) [$($p.Tipo)]"
        if ($p.Nombre) { $et += " '$($p.Nombre)'" }
        # Etiqueta corta para la consola: "Particion 3", sin el GUID descriptivo
        # completo, que en pantalla ocupa media linea y no aporta a la decision.
        $etCorta = "Particion $($p.Indice)"

        if ($p.CifradoPorGuid) {
            Add-Hallazgo -Categoria 'Disco' -Sujeto $et -Detalle 'El GUID de tipo declara cifrado' `
                -Certeza 'DETERMINISTA' -Base 'GUID de tipo de particion GPT' `
                -Limitacion 'En la practica muchas instalaciones con LUKS dejan el GUID generico de Linux, asi que su ausencia no descarta cifrado.'
        }

        $off = [int64]$p.PrimerLBA * 512
        if (($off + 512) -gt $limiteBytes -or ($off + 512) -gt $buf.Length) {
            $mib = [math]::Ceiling(($off + 512) / 1MB)
            $fuera.Add("$et empieza en el LBA $($p.PrimerLBA) (~$mib MiB)")
            Add-Resumen -Etiqueta $etCorta -Estado 'NO INSPECCIONADA (fuera del prefijo)' -Nivel 'duda'
            Add-Hallazgo -Categoria 'Disco' -Sujeto $et -Detalle 'NO INSPECCIONADA: comienza fuera del prefijo leido' `
                -Certeza 'NO_DETERMINADO' -Base ("Primer LBA {0}, equivalente a {1} MiB del inicio" -f $p.PrimerLBA, $mib) `
                -Limitacion "Para inspeccionarla hay que leer un prefijo de al menos $mib MiB. No se hace automaticamente porque el coste lo debe asumir el perito de forma consciente."
            continue
        }

        # Se anota cuantos hallazgos habia ANTES de la cascada de firmas para
        # saber despues QUE encontro exactamente: mirar la marca EsCifrado de
        # los hallazgos que ella misma acaba de anadir es fiable, mientras que
        # buscar palabras en el texto no lo es (la etiqueta del GUID de la
        # particion de datos dice "el que conserva BitLocker" y ya provoco una
        # vez ese falso positivo, segun consta en Add-Hallazgo).
        $nAntes = $script:HALLAZGOS.Count
        $hayFirma = Test-Firmas -Buf $buf -Base ([int]$off) -Etiqueta $et
        $nuevos = @()
        if ($script:HALLAZGOS.Count -gt $nAntes) {
            $nuevos = @($script:HALLAZGOS[$nAntes..($script:HALLAZGOS.Count - 1)])
        }
        $cifradoAqui = @($nuevos | Where-Object { $_.EsCifrado }).Count -gt 0

        if ($cifradoAqui) {
            # Se toma el detalle del hallazgo de cifrado, que ya nombra la
            # tecnologia concreta (BitLocker, LUKS, CoreStorage, APFS).
            $hc = @($nuevos | Where-Object { $_.EsCifrado })[0]
            Add-Resumen -Etiqueta $etCorta -Estado ('CIFRADO - ' + $hc.Detalle) -Nivel 'cifrado'
        } elseif ($p.CifradoPorGuid) {
            Add-Resumen -Etiqueta $etCorta -Estado 'CIFRADO segun el GUID de tipo' -Nivel 'cifrado'
        } elseif ($hayFirma) {
            # Firma de sistema de archivos, sin cifrado. Se extrae el nombre del
            # sistema de archivos del propio detalle para poder mostrar
            # "Particion 3 (NTFS)  Sin cifrado".
            $fs = ''
            foreach ($h in $nuevos) {
                if ($h.Detalle -match 'Sistema de archivos (\S+) sin cifrado') { $fs = $Matches[1]; break }
            }
            if ($fs) { $etCorta = "$etCorta ($fs)" }
            Add-Resumen -Etiqueta $etCorta -Estado 'Sin cifrado' -Nivel 'ok'
        } elseif ($p.SinSistemaArchivos) {
            Add-Resumen -Etiqueta $etCorta -Estado 'No aplica' -Nivel 'na'
        } else {
            Add-Resumen -Etiqueta $etCorta -Estado 'SIN FIRMA reconocible (revisar: posible VeraCrypt)' -Nivel 'duda'
        }

        if (-not $hayFirma) {
            # Hay tipos de particion que legitimamente NO llevan sistema de
            # archivos, y marcarlos como sospechosos generaria ruido en TODOS
            # los discos Windows: la MSR aparece en cualquier instalacion GPT.
            # Se comprobo contra una VM real, donde la MSR disparaba un aviso
            # de "examinar manualmente" que nunca habria estado justificado.
            if ($p.SinSistemaArchivos) {
                Add-Hallazgo -Categoria 'Disco' -Sujeto $et `
                    -Detalle 'Sin sistema de archivos, que es lo esperado para este tipo de particion' `
                    -Certeza 'DETERMINISTA' `
                    -Base 'Tipo de particion que por definicion no aloja un sistema de archivos'
            } else {
                Add-Hallazgo -Categoria 'Disco' -Sujeto $et `
                    -Detalle 'Sin firma de cifrado NI firma de sistema de archivos reconocible' -Certeza 'INDICIO' `
                    -Base 'Cascada de firmas documentadas aplicada al inicio de la particion' `
                    -Limitacion 'La ausencia de TODA firma donde deberia haber una es el unico indicio estructural de un volumen tipo VeraCrypt, que por diseno no deja firma. NO es prueba: tambien lo produce una particion sin formatear.'
                Add-Recomendacion -Accion "Examinar manualmente $et" `
                    -Motivo 'No hay firma de cifrado ni de sistema de archivos donde deberia haber una' `
                    -Fundamento 'VeraCrypt, documentacion oficial: los volumenes "have no signature or ID strings and until decrypted appear to consist solely of random data"'
            }
        }
    }

    if ($fuera.Count -gt 0) {
        Add-Limitacion ("NO se inspeccionaron " + $fuera.Count + " particion(es) por quedar fuera del prefijo de $PrefijoMiB MiB: " + ($fuera -join '; '))
        Add-Recomendacion -Accion 'Repetir con un prefijo mayor si necesita cubrir esas particiones' `
            -Motivo 'Hay particiones cuyo inicio no se alcanzo con el prefijo actual' `
            -Fundamento 'Medicion propia: la lectura rinde ~59 MB/s con bs=1M, de modo que 600 MiB tardan unos 10 s'
    }

    # Correlacion final: cifrado detectado implica recomendar memoria primero.
    $hayCifrado = @($script:HALLAZGOS | Where-Object { $_.EsCifrado -and $_.Certeza -eq 'DETERMINISTA' }).Count
    if ($hayCifrado -gt 0) {
        Add-Recomendacion -Accion 'Adquirir la memoria de la maquina virtual ANTES que el disco' `
            -Motivo 'Se detectaron firmas de cifrado en el disco virtual' `
            -Fundamento 'SWGDE 17-F-002 v2.1: "To obtain encryption keys, examiners may need to capture memory prior to obtaining a disk image, and attempt to decrypt later"'
        Add-Recomendacion -Accion 'NO apagar la maquina virtual antes de adquirir la memoria' `
            -Motivo 'Al apagarse, el material criptografico residente en la memoria del invitado desaparece' `
            -Fundamento 'NIST SP 800-86, orden de volatilidad: los datos volatiles se recolectan primero'
    }

    Add-Limitacion 'El estado de BLOQUEO de un volumen cifrado NO es observable desde el disco de una maquina virtual: el desbloqueo ocurre en la memoria del invitado y no modifica el contenedor. Un volumen montado y uno bloqueado son byte a byte identicos.'
    Add-Limitacion 'Este modulo NO detecta contenedores ni volumenes de datos de VeraCrypt, que carecen de firma por diseno declarado del fabricante.'
}

# ---------------------------------------------------------------------------
# Informe
# ---------------------------------------------------------------------------

function Write-Informe {
    $sb = New-Object Text.StringBuilder
    $n = { param($t) [void]$sb.AppendLine($t) }

    & $n ('=' * 78)
    & $n ' AMBARDFIR - EVALUACION PREVIA A LA ADQUISICION'
    & $n ' Fase de IDENTIFICACION (ISO/IEC 27037) - no constituye adquisicion,'
    & $n ' examen ni analisis forense'
    & $n ('=' * 78)
    & $n (' Generado (UTC) : ' + [DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss'))
    & $n (' Equipo         : ' + $env:COMPUTERNAME)
    & $n (' Modo           : ' + $Modo)
    & $n ('=' * 78)
    & $n ''
    & $n 'HALLAZGOS'
    & $n ('-' * 78)
    if ($script:HALLAZGOS.Count -eq 0) {
        & $n '  (ninguno)'
    } else {
        $i = 0
        foreach ($h in $script:HALLAZGOS) {
            $i++
            & $n ("  [{0:D2}] ({1}) {2}" -f $i, $h.Certeza, $h.Sujeto)
            & $n ("       {0}" -f $h.Detalle)
            & $n ("       Base observada: {0}" -f $h.Base)
            if ($h.Limitacion) { & $n ("       LIMITACION: {0}" -f $h.Limitacion) }
            & $n ''
        }
    }

    # La seccion solo se imprime si hay algo que recomendar. Un encabezado
    # seguido de "(ninguna)" ocupa cuatro lineas para no decir nada, y en un
    # informe que se lee en papel eso compite con lo que si importa.
    if ($script:RECOMENDACIONES.Count -gt 0) {
        & $n 'RECOMENDACIONES AL PERITO'
        & $n ('-' * 78)
        $i = 0
        foreach ($r in $script:RECOMENDACIONES) {
            $i++
            & $n ("  [{0:D2}] {1}" -f $i, $r.Accion)
            & $n ("       Motivo     : {0}" -f $r.Motivo)
            & $n ("       Fundamento : {0}" -f $r.Fundamento)
            & $n ''
        }
    }

    & $n 'LIMITACIONES DECLARADAS'
    & $n ('-' * 78)
    if ($script:LIMITACIONES.Count -eq 0) {
        & $n '  (ninguna)'
    } else {
        foreach ($l in $script:LIMITACIONES) { & $n ("  - {0}" -f $l) }
    }
    & $n ('=' * 78)

    # El informe completo YA NO se vuelca a la consola: va solo al archivo.
    # En campo se trabaja con prisa y nadie lee 60 lineas de fundamentacion en
    # pantalla; la consola muestra el resumen de Write-Resumen y el archivo
    # conserva intacto todo el detalle para cuando haga falta consultarlo.
    $txt = $sb.ToString()
    if ($Informe) {
        $dir = Split-Path -Parent $Informe
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        [IO.File]::WriteAllText($Informe, $txt, (New-Object Text.UTF8Encoding $false))
    }
}

function Write-Resumen {
    # Lo unico que ve el operador en pantalla: etiqueta y veredicto, alineados.
    $col = @{ ok = 'Green'; cifrado = 'Red'; duda = 'Yellow'; na = 'DarkGray' }

    Write-Host ''
    if ($script:RESUMEN.Count -eq 0) {
        Write-Host '  Sin resultados que mostrar.' -ForegroundColor Yellow
        Write-Host ''
        return
    }

    # Ancho de la primera columna segun la etiqueta mas larga, para que los
    # veredictos queden en vertical y se lean de un vistazo.
    $ancho = 0
    foreach ($r in $script:RESUMEN) { if ($r.Etiqueta.Length -gt $ancho) { $ancho = $r.Etiqueta.Length } }
    if ($ancho -gt 46) { $ancho = 46 }

    foreach ($r in $script:RESUMEN) {
        $lbl = $r.Etiqueta
        if ($lbl.Length -gt $ancho) { $lbl = $lbl.Substring(0, $ancho) }
        Write-Host ('  ' + $lbl.PadRight($ancho) + '  ') -NoNewline
        Write-Host $r.Estado -ForegroundColor $col[$r.Nivel]
    }

    # Veredicto global. "Sin cifrado detectado" y "no se pudo comprobar todo"
    # NO son lo mismo, y esa diferencia es justo la que hace que la prisa sea
    # peligrosa: se dicen por separado.
    $nCif  = @($script:RESUMEN | Where-Object { $_.Nivel -eq 'cifrado' }).Count
    $nDuda = @($script:RESUMEN | Where-Object { $_.Nivel -eq 'duda' }).Count
    $nOk   = @($script:RESUMEN | Where-Object { $_.Nivel -eq 'ok' }).Count
    Write-Host ''
    if ($nCif -gt 0) {
        Write-Host "  >> CIFRADO DETECTADO en $nCif elemento(s). Adquiera la RAM ANTES de apagar." -ForegroundColor Red
    } elseif ($nOk -eq 0 -and $nDuda -gt 0) {
        # Ni un solo elemento pudo comprobarse. Decir "sin cifrado en lo
        # comprobado" aqui sonaria tranquilizador cuando no se comprobo NADA:
        # es justo el mensaje que no debe darse con prisa encima.
        Write-Host '  >> NO SE PUDO COMPROBAR NADA. No se descarta cifrado.' -ForegroundColor Yellow
    } elseif ($nDuda -gt 0) {
        Write-Host "  >> Sin cifrado en lo comprobado, pero $nDuda elemento(s) NO se pudieron comprobar." -ForegroundColor Yellow
    } else {
        Write-Host '  >> SIN CIFRADO DETECTADO.' -ForegroundColor Green
    }
    Write-Host ''
}

# ---------------------------------------------------------------------------

try {
    if ($QuickCheck) {
        # Ejecuta la deteccion SIN emitir informe. Cualquier salida incidental de
        # la lectura (qemu-img) se descarta para que stdout lleve SOLO el token.
        switch ($Modo) {
            'Host'  { Invoke-ModoHost  | Out-Null }
            'Disco' { Invoke-ModoDisco | Out-Null }
        }
        # Solo cifrado DETERMINISTA: una firma leida en su offset, nunca un indicio.
        $cif = @($script:HALLAZGOS | Where-Object { $_.EsCifrado -and $_.Certeza -eq 'DETERMINISTA' })
        if ($cif.Count -gt 0) {
            $txt  = ($cif[0].Sujeto + ' ' + $cif[0].Detalle)
            $tech = 'Cifrado'
            if     ($txt -match 'BitLocker')   { $tech = 'BitLocker' }
            elseif ($txt -match 'LUKS')        { $tech = 'LUKS' }
            elseif ($txt -match 'CoreStorage') { $tech = 'CoreStorage' }
            elseif ($txt -match 'APFS')        { $tech = 'APFS' }
            elseif ($txt -match 'VeraCrypt')   { $tech = 'VeraCrypt' }
            Write-Output ('ENC=' + $tech)
        } else {
            Write-Output 'ENC=NONE'
        }
        exit 0
    }
    switch ($Modo) {
        'Host'    { Invoke-ModoHost }
        'Disco'   { Invoke-ModoDisco }
    }
    Write-Informe
    Write-Resumen
    exit 0
} catch {
    # En comprobacion rapida un fallo NO debe imprimir un volcado de error que el
    # .bat interpretaria como token: se emite ENC=ERROR y el llamador decide.
    if ($QuickCheck) { Write-Output 'ENC=ERROR'; exit 0 }
    Write-Output ''
    Write-Output ('ERROR: ' + $_.Exception.Message)
    Write-Output ('  en: ' + $_.InvocationInfo.PositionMessage)
    exit 1
}
