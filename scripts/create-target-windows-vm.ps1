<#
.SYNOPSIS
  Crea la VM "target-windows" del SOC Home Lab in VirtualBox, in modo ripetibile.

.DESCRIPTION
  Provisioning automatico via VBoxManage:
    - VM Windows 10/11 64-bit, 3 GB RAM, 2 vCPU, disco 50 GB dinamico
    - NIC1 = NAT (internet), NIC2 = Host-Only (192.168.56.0/24, per parlare col Wazuh Manager)
    - Boot da DVD se viene fornita una ISO Windows
  Lo script e' IDEMPOTENTE: se la VM esiste gia' si ferma (usa -Force per ricrearla da zero).

  Una volta creata la VM:
    1. Avvia la VM e completa l'installazione di Windows (account locale, hostname target-windows)
    2. Installa Wazuh Agent (WAZUH_MANAGER=192.168.56.1) e Sysmon (config SwiftOnSecurity)
       -> vedi docs/agents-setup.md e docs/sysmon-setup.md

.PARAMETER IsoPath
  Percorso della ISO di Windows (Win10/11 Evaluation). Se omesso, la VM viene creata
  senza ISO e dovrai attaccarla manualmente (Settings -> Storage) prima di installare.

.PARAMETER VmName
  Nome della VM (default: target-windows).

.PARAMETER OsType
  Tipo OS VirtualBox: Windows10_64 (default) o Windows11_64.
  NB: Windows11_64 richiede EFI + Secure Boot + vTPM (configurati automaticamente).

.PARAMETER Force
  Se la VM esiste gia', la spegne ed elimina (con tutti i dischi) prima di ricrearla.

.EXAMPLE
  # Crea la VM e attacca la ISO scaricata
  .\scripts\create-target-windows-vm.ps1 -IsoPath "C:\Users\antol\Desktop\stuff\ISOs\Win10_Eval.iso"

.EXAMPLE
  # Solo la VM, ISO da attaccare dopo
  .\scripts\create-target-windows-vm.ps1
#>

[CmdletBinding()]
param(
    [string] $IsoPath,
    [string] $VmName  = "target-windows",
    [ValidateSet("Windows10_64", "Windows11_64")]
    [string] $OsType  = "Windows10_64",
    [int]    $MemoryMB = 3072,
    [int]    $Cpus     = 2,
    [int]    $DiskMB   = 51200,
    [switch] $Force
)

$ErrorActionPreference = "Stop"

# --- 1. Individua VBoxManage ---------------------------------------------------
$candidates = @(
    "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
    "C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe"
)
$VBoxManage = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $VBoxManage) {
    $cmd = Get-Command VBoxManage -ErrorAction SilentlyContinue
    if ($cmd) { $VBoxManage = $cmd.Source }
}
if (-not $VBoxManage) {
    throw "VBoxManage non trovato. Installa VirtualBox o aggiorna il PATH."
}
function VBox { & $VBoxManage @args }
Write-Host "VBoxManage: $VBoxManage" -ForegroundColor DarkGray
Write-Host "Versione VirtualBox: $(VBox --version)" -ForegroundColor DarkGray

# --- 2. Rete host-only ---------------------------------------------------------
# Recupera il nome dell'adattatore host-only (quello su 192.168.56.1).
$hostonlyName = $null
$ifs = VBox list hostonlyifs
$currentName = $null
foreach ($line in $ifs) {
    if ($line -match '^Name:\s+(.+?)\s*$')      { $currentName = $Matches[1] }
    if ($line -match '^IPAddress:\s+192\.168\.56\.1\s*$') { $hostonlyName = $currentName }
}
if (-not $hostonlyName) {
    # Nessun adattatore su 192.168.56.1: lo creo
    Write-Host "Nessun host-only su 192.168.56.1: lo creo..." -ForegroundColor Yellow
    $created = VBox hostonlyif create
    if ($created -match 'Interface\s+''(.+?)''') { $hostonlyName = $Matches[1] }
    VBox hostonlyif ipconfig "$hostonlyName" --ip 192.168.56.1 --netmask 255.255.255.0 | Out-Null
}
Write-Host "Host-Only adapter: $hostonlyName" -ForegroundColor DarkGray

# --- 3. Gestione VM esistente --------------------------------------------------
$existing = (VBox list vms) -match "`"$VmName`""
if ($existing) {
    if (-not $Force) {
        Write-Host "La VM '$VmName' esiste gia'. Usa -Force per ricrearla da zero." -ForegroundColor Yellow
        return
    }
    Write-Host "Rimuovo la VM esistente '$VmName' (-Force)..." -ForegroundColor Yellow
    try { VBox controlvm "$VmName" poweroff 2>$null } catch {}
    Start-Sleep -Seconds 2
    VBox unregistervm "$VmName" --delete | Out-Null
}

# --- 4. Crea e configura la VM -------------------------------------------------
Write-Host "[1/5] Creo la VM '$VmName' ($OsType)..." -ForegroundColor Cyan
VBox createvm --name "$VmName" --ostype $OsType --register | Out-Null

$defFolder = ((VBox list systemproperties) -match '^Default machine folder:' ) -replace '^Default machine folder:\s+', ''
$vmDir     = Join-Path $defFolder $VmName
$diskPath  = Join-Path $vmDir "$VmName.vdi"

$firmware = if ($OsType -eq "Windows11_64") { "efi" } else { "bios" }

Write-Host "[2/5] Configuro CPU/RAM/rete/firmware..." -ForegroundColor Cyan
VBox modifyvm "$VmName" `
    --memory $MemoryMB --cpus $Cpus `
    --vram 128 --graphicscontroller vboxsvga `
    --ioapic on --rtcuseutc on --firmware $firmware `
    --nic1 nat `
    --nic2 hostonly --hostonlyadapter2 "$hostonlyName" `
    --audio-driver none `
    --usbohci on | Out-Null

if ($OsType -eq "Windows11_64") {
    # Requisiti Windows 11: vTPM 2.0 + Secure Boot
    VBox modifyvm "$VmName" --tpm-type 2.0 | Out-Null
    Write-Host "      Windows 11: abilitati vTPM 2.0 + EFI" -ForegroundColor DarkGray
}

# --- 5. Disco + storage --------------------------------------------------------
Write-Host "[3/5] Creo il disco da $([math]::Round($DiskMB/1024)) GB..." -ForegroundColor Cyan
VBox createmedium disk --filename "$diskPath" --size $DiskMB --format VDI | Out-Null

VBox storagectl "$VmName" --name "SATA" --add sata --controller IntelAhci --portcount 2 --bootable on | Out-Null
VBox storageattach "$VmName" --storagectl "SATA" --port 0 --device 0 --type hdd --medium "$diskPath" | Out-Null

Write-Host "[4/5] Configuro il lettore DVD..." -ForegroundColor Cyan
if ($IsoPath -and (Test-Path $IsoPath)) {
    VBox storageattach "$VmName" --storagectl "SATA" --port 1 --device 0 --type dvddrive --medium "$IsoPath" | Out-Null
    VBox modifyvm "$VmName" --boot1 dvd --boot2 disk --boot3 none --boot4 none | Out-Null
    Write-Host "      ISO attaccata: $IsoPath" -ForegroundColor DarkGray
    $isoReady = $true
} else {
    # Lettore DVD vuoto, pronto per attaccare la ISO dopo
    VBox storageattach "$VmName" --storagectl "SATA" --port 1 --device 0 --type dvddrive --medium emptydrive | Out-Null
    VBox modifyvm "$VmName" --boot1 dvd --boot2 disk --boot3 none --boot4 none | Out-Null
    if ($IsoPath) { Write-Host "      ATTENZIONE: ISO non trovata in '$IsoPath' - lettore lasciato vuoto." -ForegroundColor Yellow }
    $isoReady = $false
}

Write-Host "[5/5] Fatto." -ForegroundColor Green

# --- Riepilogo -----------------------------------------------------------------
Write-Host ""
Write-Host "===========================================================" -ForegroundColor Green
Write-Host " VM '$VmName' creata" -ForegroundColor Green
Write-Host "   RAM: $MemoryMB MB | CPU: $Cpus | Disco: $diskPath" -ForegroundColor Gray
Write-Host "   NIC1: NAT | NIC2: Host-Only ($hostonlyName -> 192.168.56.x)" -ForegroundColor Gray
Write-Host "===========================================================" -ForegroundColor Green
Write-Host ""
if ($isoReady) {
    Write-Host "Prossimo passo: avvia la VM e installa Windows" -ForegroundColor Cyan
    Write-Host "  & '$VBoxManage' startvm '$VmName'" -ForegroundColor White
} else {
    Write-Host "Manca la ISO di Windows. Scaricala (Win10/11 Evaluation, gratis 90gg):" -ForegroundColor Yellow
    Write-Host "  https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise" -ForegroundColor White
    Write-Host "Poi ri-lancia con: -IsoPath 'C:\percorso\Windows.iso'  (aggiungi -Force per ricreare)" -ForegroundColor White
}
Write-Host ""
Write-Host "Dopo l'installazione di Windows, dentro la VM:" -ForegroundColor Cyan
Write-Host "  - Wazuh Agent  -> docs/agents-setup.md  (WAZUH_MANAGER=192.168.56.1)" -ForegroundColor Gray
Write-Host "  - Sysmon       -> docs/sysmon-setup.md" -ForegroundColor Gray
