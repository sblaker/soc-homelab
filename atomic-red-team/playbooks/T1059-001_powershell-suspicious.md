# Playbook — T1059.001: PowerShell Suspicious Execution

## Metadati

| Campo | Valore |
|---|---|
| MITRE Technique | [T1059.001 — Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| Tactic | Execution |
| Platform | Windows |
| VM | `target-windows` |
| Prerequisiti | Sysmon installato, Wazuh Agent attivo |
| Detection rule | `custom_windows.xml` — Rule ID 100021 / `custom_mitre_mapped.xml` — Rule ID 100063 |
| Severity attesa | High (level 12) |

---

## Obiettivo

Simulare l'uso offensivo di PowerShell con flag tipici di attacchi reali (encoded command, bypass execution policy, download in-memory) per triggerare le regole 100021 e 100063.

---

## Prerequisiti

Su `target-windows`:
- Sysmon in esecuzione (`Get-Service Sysmon64` → Running)
- Wazuh Agent in esecuzione (`Get-Service WazuhSvc` → Running)
- Wazuh Agent configurato per leggere `Microsoft-Windows-Sysmon/Operational` (vedi [sysmon-setup.md](../../docs/sysmon-setup.md))
- PowerShell 5.1+ (già presente su Windows 10)

---

## Simulazione

### Test 1 — Encoded Command (T1027 + T1059.001)

Il flag `-EncodedCommand` (o `-enc`) è usato dagli attaccanti per offuscare il payload PowerShell. Qui usiamo un comando benigno codificato in Base64.

```powershell
# Comando da eseguire (benigno: scrive un file di testo)
$cmd = 'Write-Host "Atomic Red Team Test T1059.001"'

# Codifica in Base64 (come farebbe un attaccante)
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
Write-Host "Encoded: $encoded"

# Esegui con il flag -EncodedCommand (trigger della regola)
powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded
```

### Test 2 — Execution Policy Bypass + IEX

```powershell
# Bypass dell'execution policy + Invoke-Expression (IEX)
# Payload benigno: stampa variabili d'ambiente
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "IEX 'Write-Host $env:COMPUTERNAME'"
```

### Test 3 — Download cradle simulato (senza rete reale)

```powershell
# Simula un download cradle — pattern comunissimo in malware reali
# Punta a localhost per evitare traffico esterno
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `
  "(New-Object Net.WebClient).DownloadString('http://127.0.0.1/test')"
```

> Questo tenterà una connessione a localhost (fallirà con errore di connessione, ma il process creation event Sysmon viene generato ugualmente — è quello che triggera la regola).

### Test 4 — Atomic Red Team (se installato)

```powershell
# Richiede: Install-Module -Name invoke-atomicredteam
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T1059.001 -TestNumbers 1,2,3
```

---

## Alert atteso su Wazuh

Sysmon Event ID 1 (Process Create) con:
- `Image`: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- `CommandLine`: contiene `-enc` / `-EncodedCommand` / `iex` / `bypass`

Alert Wazuh atteso:

```
rule.id: 100021
rule.level: 12
rule.description: "PowerShell execution with suspicious arguments: ..."
rule.mitre.technique: ["T1059.001", "T1027"]
agent.name: target-windows
data.win.eventdata.image: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
data.win.eventdata.commandLine: "powershell.exe -NoProfile -EncodedCommand ..."
```

---

## Come verificare la detection

### 1. Dalla Dashboard Wazuh

```
agent.name: "target-windows" AND rule.id: 100021
```

oppure:

```
agent.name: "target-windows" AND rule.mitre.technique: T1059.001
```

### 2. Event Viewer su target-windows

Apri **Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational**  
Filtra per Event ID = 1 e cerca `powershell` nel campo `CommandLine`.

### 3. Query OpenSearch Dashboards

```
data.win.system.eventID: "1" AND data.win.eventdata.commandLine: *EncodedCommand*
```

---

## Verifica True Positive vs False Positive

| Indicatore | True Positive | False Positive |
|---|---|---|
| `-EncodedCommand` | Quasi sempre sospetto | Script legittimi raramente lo usano |
| `-WindowStyle Hidden` | Nasconde finestra — evasione | Raro in script admin legittimi |
| `IEX` / `DownloadString` | Tipico di dropper | Possibile in script sysadmin |
| Parent process | `winword.exe`, `excel.exe` | `powershell_ise.exe`, task schedulato noto |

---

## Cleanup

```powershell
# Nessuna persistenza creata in questi test — niente da pulire
# Verifica che non ci siano processi powershell in background
Get-Process powershell -ErrorAction SilentlyContinue | Stop-Process -Force
```

---

## Note operative

- Se la rule non scatta, verifica che Sysmon stia loggando il command line completo: Event ID 1 deve includere il campo `CommandLine`
- Nella config SwiftOnSecurity, il command line logging è abilitato per default — non dovrebbe richiedere modifiche
- Se gli eventi Sysmon arrivano in Dashboard ma la rule non triggera, controlla il `<field name>` esatto nel decoder: può variare tra versioni di Wazuh

---

## Write-up di riferimento

→ [detections/DET-002_powershell-suspicious.md](../../detections/DET-002_powershell-suspicious.md)
