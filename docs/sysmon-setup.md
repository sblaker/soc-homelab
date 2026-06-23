# Setup Sysmon su target-windows

> Sysmon (System Monitor) di Sysinternals aggiunge telemetria kernel su Windows che i log nativi non forniscono. È essenziale per rilevare tecniche di attacco a livello di processo, rete e registro.

---

## 1. Download

| File | URL |
|---|---|
| Sysmon (binario) | [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| SwiftOnSecurity config | [https://github.com/SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) |

Su `target-windows`, apri PowerShell come amministratore:

```powershell
# Crea cartella di lavoro
New-Item -ItemType Directory -Path "C:\Tools\Sysmon" -Force | Out-Null
Set-Location "C:\Tools\Sysmon"

# Scarica Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive -Path "Sysmon.zip" -DestinationPath "." -Force

# Scarica la config SwiftOnSecurity
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
  -OutFile "sysmonconfig.xml"
```

---

## 2. Installazione

```powershell
# Installa Sysmon con la config SwiftOnSecurity
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Output atteso:
```
System Monitor v15.x - System activity monitor
...
Sysmon installed.
SysmonDrv installed.
Starting SysmonDrv.
SysmonDrv started.
Starting Sysmon.
Sysmon started.
```

### Verifica installazione

```powershell
# Il servizio deve essere in Running
Get-Service -Name Sysmon64

# Controlla che gli eventi appaiano nell'Event Log
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Format-Table TimeCreated, Id, Message -AutoSize
```

---

## 3. Event ID chiave

| Event ID | Nome evento | Rilevanza per detection |
|---|---|---|
| **1** | Process Create | Identifica processi avviati, include parent process, command line, hash |
| **3** | Network Connection | Connessioni TCP/UDP outbound con processo sorgente |
| **5** | Process Terminated | Utile per correlazione con Event ID 1 |
| **7** | Image Loaded | DLL caricate da un processo (rileva DLL hijacking) |
| **8** | CreateRemoteThread | Thread remoti (injection) |
| **10** | ProcessAccess | Accesso alla memoria di altri processi (LSASS dumping) |
| **11** | FileCreate | File creati/sovrascritti con processo responsabile |
| **12/13/14** | Registry Events | Creazione, modifica, eliminazione chiavi/valori registro |
| **15** | FileCreateStreamHash | Alternate Data Stream (ADS) |
| **22** | DNSEvent | Query DNS con processo responsabile |
| **25** | ProcessTampering | Manipolazione memoria processo |

---

## 4. Integrazione con Wazuh Agent

Il Wazuh Agent su Windows legge automaticamente il canale `Microsoft-Windows-Sysmon/Operational` se configurato in `ossec.conf`.

Apri `C:\Program Files (x86)\ossec-agent\ossec.conf` come amministratore e verifica/aggiungi nella sezione `<localfile>`:

```xml
<!-- Sysmon -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Riavvia l'agente:

```powershell
Restart-Service -Name WazuhSvc
```

### Verifica ricezione eventi Sysmon su Wazuh

Nella Dashboard Wazuh, cerca:

```
agent.name: "target-windows" AND data.win.system.channel: "Microsoft-Windows-Sysmon/Operational"
```

Oppure filtra per rule group `sysmon`.

---

## 5. Aggiornamento della config

Quando vuoi applicare una config aggiornata (es. hai modificato `sysmonconfig.xml`):

```powershell
# Aggiorna la config senza reinstallare
.\Sysmon64.exe -c sysmonconfig.xml
```

---

## 6. Disinstallazione (se necessario)

```powershell
.\Sysmon64.exe -u
```

---

## 7. Test rapido: verifica Event ID 1

Apri un cmd e lancia un processo qualsiasi, poi verifica che Sysmon l'abbia catturato:

```powershell
# Lancia un processo di test
Start-Process -FilePath "calc.exe"

# Cerca l'evento in Sysmon (Event ID 1 = Process Create)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" `
  | Where-Object { $_.Id -eq 1 -and $_.Message -match "calc" } `
  | Select-Object -First 1 `
  | Format-List TimeCreated, Message
```

---

## Snapshot consigliato

Dopo aver verificato che Sysmon funziona e gli eventi arrivano su Wazuh, fai uno snapshot della VM:

**VirtualBox → Machine → Take Snapshot → `Sysmon installed and verified`**

Questo è il punto di partenza per tutte le simulazioni di attacco successive.
