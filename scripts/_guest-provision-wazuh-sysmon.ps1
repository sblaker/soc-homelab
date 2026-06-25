<#
  _guest-provision-wazuh-sysmon.ps1
  ESEGUITO DENTRO la VM target-windows (copiato e lanciato via VBoxManage guestcontrol).
  Installa Wazuh Agent + Sysmon (config SwiftOnSecurity) e arruola l'agente sul Manager.
  Il prefisso "_" indica che NON va eseguito sull'host.
#>
param(
  [string]$Manager   = "192.168.56.1",
  [string]$AgentName = "target-windows",
  [string]$WazuhMsi  = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi"
)
$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Log($m){ Write-Host ("[{0}] {1}" -f (Get-Date -Format HH:mm:ss), $m) }

# 1) Wazuh Agent ------------------------------------------------------------
Log "Scarico Wazuh Agent MSI..."
$msi = "$env:TEMP\wazuh-agent.msi"
Invoke-WebRequest -Uri $WazuhMsi -OutFile $msi -UseBasicParsing
Log "Installo agent (Manager=$Manager, Name=$AgentName)..."
$p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /q WAZUH_MANAGER=$Manager WAZUH_AGENT_NAME=$AgentName" -Wait -PassThru
Log "msiexec exit code: $($p.ExitCode)"

# 2) Sysmon + config SwiftOnSecurity ---------------------------------------
Log "Scarico Sysmon + config SwiftOnSecurity..."
$tools = "C:\Tools\Sysmon"
New-Item -ItemType Directory -Path $tools -Force | Out-Null
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$tools\Sysmon.zip" -UseBasicParsing
Expand-Archive "$tools\Sysmon.zip" -DestinationPath $tools -Force
Invoke-WebRequest "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$tools\sysmonconfig.xml" -UseBasicParsing
Log "Installo Sysmon..."
& "$tools\Sysmon64.exe" -accepteula -i "$tools\sysmonconfig.xml" | Out-Null

# 3) Aggiungi il canale Sysmon a ossec.conf --------------------------------
$conf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$content = Get-Content $conf -Raw
if ($content -notmatch "Sysmon/Operational") {
  Log "Aggiungo il canale Sysmon a ossec.conf..."
  $block = @"
  <!-- [LAB] Telemetria Sysmon -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
"@
  $idx = $content.LastIndexOf("</ossec_config>")
  $content = $content.Substring(0, $idx) + $block + "`r`n" + $content.Substring($idx)
  [System.IO.File]::WriteAllText($conf, $content, (New-Object System.Text.UTF8Encoding($false)))
} else {
  Log "ossec.conf contiene gia' il canale Sysmon."
}

# 4) (Ri)avvia i servizi ----------------------------------------------------
Log "Avvio/riavvio WazuhSvc..."
Restart-Service -Name WazuhSvc -ErrorAction SilentlyContinue
Start-Sleep -Seconds 4
Log "Stato servizi:"
Get-Service WazuhSvc, Sysmon64 -ErrorAction SilentlyContinue | Format-Table Name, Status -AutoSize | Out-String | Write-Host

Log "Provisioning completato. L'agente dovrebbe comparire nella Dashboard Wazuh come '$AgentName'."
