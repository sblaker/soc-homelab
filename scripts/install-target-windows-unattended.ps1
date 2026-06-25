<#
.SYNOPSIS
  Installa Windows 10 nella VM "target-windows" in modo COMPLETAMENTE automatico
  (unattended) e, opzionalmente, installa e arruola Wazuh Agent + Sysmon — senza un clic.

.DESCRIPTION
  Ricrea la VM target-windows e avvia l'installazione automatica di Windows tramite il
  supporto nativo di VirtualBox 7 (genera lui il file di risposta: partizioni, EULA,
  account locale, hostname, OOBE).

  Con -ProvisionAgent, inietta un comando di POST-INSTALL che gira come SYSTEM al termine
  del setup (niente UAC, niente automazione tastiera) e:
    - attende la rete
    - scarica e installa Wazuh Agent (arruolato su -Manager come "target-windows")
    - scarica e installa Sysmon con la config SwiftOnSecurity
    - aggiunge il canale Sysmon a ossec.conf e riavvia il servizio
  Log nel guest: C:\prov.log

  NB: questo e' l'approccio AFFIDABILE per provisioning headless. Le Guest Additions e
  VBoxManage guestcontrol si sono rivelate inaffidabili per il provisioning automatico
  (GA non sempre si installano via --install-additions); il post-install-command no.

.PARAMETER IsoPath        ISO di Windows 10 x64 (obbligatorio).
.PARAMETER ProvisionAgent Installa e arruola Wazuh Agent + Sysmon a fine setup.
.PARAMETER Manager        IP del Wazuh Manager (default 192.168.56.1).
.PARAMETER Gui            Avvia l'installazione in finestra invece che headless.

.EXAMPLE
  # VM Windows + Wazuh Agent + Sysmon, tutto automatico
  .\scripts\install-target-windows-unattended.ps1 -IsoPath "C:\ISOs\Win10.iso" -ProvisionAgent
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $IsoPath,
    [string] $VmName     = "target-windows",
    [string] $VmUser     = "labuser",
    [string] $VmPassword = "Passw0rd1!",
    [string] $Manager    = "192.168.56.1",
    [int]    $MemoryMB   = 3072,
    [int]    $Cpus       = 2,
    [int]    $DiskMB     = 51200,
    [switch] $ProvisionAgent,
    [switch] $Gui
)

$ErrorActionPreference = "Stop"

$VBoxManage = @(
    "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
    "C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $VBoxManage) { throw "VBoxManage non trovato." }
function VBox { & $VBoxManage @args }
if (-not (Test-Path $IsoPath)) { throw "ISO non trovata: $IsoPath" }

# --- Host-only adapter su 192.168.56.1 ---
$hostonlyName = $null; $cur = $null
foreach ($l in (VBox list hostonlyifs)) {
    if ($l -match '^Name:\s+(.+?)\s*$') { $cur = $Matches[1] }
    if ($l -match '^IPAddress:\s+192\.168\.56\.1\s*$') { $hostonlyName = $cur }
}
if (-not $hostonlyName) {
    $c = VBox hostonlyif create
    if ($c -match "Interface '(.+?)'") { $hostonlyName = $Matches[1] }
    VBox hostonlyif ipconfig "$hostonlyName" --ip 192.168.56.1 --netmask 255.255.255.0 | Out-Null
}

# --- Ricrea la VM ---
if ((VBox list vms) -match "`"$VmName`"") {
    try { VBox controlvm "$VmName" poweroff 2>$null } catch {}
    Start-Sleep -Seconds 2
    VBox unregistervm "$VmName" --delete | Out-Null
}
Write-Host "[1/3] Creo la VM '$VmName'..." -ForegroundColor Cyan
VBox createvm --name "$VmName" --ostype "Windows10_64" --register | Out-Null
$defFolder = ((VBox list systemproperties) -match '^Default machine folder:') -replace '^Default machine folder:\s+',''
$diskPath  = Join-Path (Join-Path $defFolder $VmName) "$VmName.vdi"
VBox modifyvm "$VmName" --memory $MemoryMB --cpus $Cpus --vram 128 --graphicscontroller vboxsvga `
    --ioapic on --rtcuseutc on --firmware bios --nic1 nat --nic2 hostonly --hostonlyadapter2 "$hostonlyName" `
    --audio-driver none | Out-Null
VBox createmedium disk --filename "$diskPath" --size $DiskMB --format VDI | Out-Null
VBox storagectl "$VmName" --name "SATA" --add sata --controller IntelAhci --portcount 2 --bootable on | Out-Null
VBox storageattach "$VmName" --storagectl "SATA" --port 0 --device 0 --type hdd --medium "$diskPath" | Out-Null

# --- Provisioning come post-install (SYSTEM) ---
$postArgs = @()
if ($ProvisionAgent) {
    Write-Host "[2/3] Preparo il provisioning (Wazuh Agent + Sysmon) come post-install SYSTEM..." -ForegroundColor Cyan
    $prov = @"
`$ErrorActionPreference="Continue";`$ProgressPreference="SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
Start-Transcript C:\prov.log -Append
for(`$i=0;`$i -lt 90;`$i++){ if(Test-Connection 8.8.8.8 -Count 1 -Quiet){break}; Start-Sleep 10 }
`$msi="`$env:TEMP\wa.msi"
Invoke-WebRequest "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi" -OutFile `$msi -UseBasicParsing
Start-Process msiexec -ArgumentList "/i ```"`$msi```" /q WAZUH_MANAGER=$Manager WAZUH_AGENT_NAME=$VmName" -Wait
`$t="C:\Tools\Sysmon";New-Item -ItemType Directory `$t -Force|Out-Null
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "`$t\s.zip" -UseBasicParsing
Expand-Archive "`$t\s.zip" `$t -Force
Invoke-WebRequest "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "`$t\c.xml" -UseBasicParsing
& "`$t\Sysmon64.exe" -accepteula -i "`$t\c.xml"
`$cf="C:\Program Files (x86)\ossec-agent\ossec.conf";`$c=Get-Content `$cf -Raw
if(`$c -notmatch "Sysmon/Operational"){`$blk="  <localfile><location>Microsoft-Windows-Sysmon/Operational</location><log_format>eventchannel</log_format></localfile>``r``n";`$idx=`$c.LastIndexOf("</ossec_config>");`$c=`$c.Substring(0,`$idx)+`$blk+`$c.Substring(`$idx);[IO.File]::WriteAllText(`$cf,`$c)}
Restart-Service WazuhSvc
Stop-Transcript
"@
    $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($prov))
    $postArgs = @("--post-install-command=powershell.exe -ExecutionPolicy Bypass -EncodedCommand $b64")
}

Write-Host "[3/3] Avvio installazione unattended ($(if($Gui){'gui'}else{'headless'}))..." -ForegroundColor Cyan
$startType = if ($Gui) { "gui" } else { "headless" }
VBox unattended install "$VmName" `
    --iso="$IsoPath" --user="$VmUser" --password="$VmPassword" --full-user-name="SOC Lab User" `
    --hostname="$VmName.lab" --locale="en_US" --country="US" --language="en-US" --time-zone="UTC" `
    --image-index=6 --install-additions @postArgs --start-vm="$startType"

Write-Host ""
Write-Host "Windows si installa da solo (~25-40 min)." -ForegroundColor Green
if ($ProvisionAgent) {
    Write-Host "Al termine, come SYSTEM: Wazuh Agent (Manager=$Manager) + Sysmon. Log guest: C:\prov.log" -ForegroundColor Green
    Write-Host "Assicurati che lo stack Wazuh sia attivo cosi' l'agente si arruola." -ForegroundColor Yellow
}
Write-Host "Account VM: $VmUser / $VmPassword" -ForegroundColor Gray
