# Playbook — T1053.005: Scheduled Task Persistence

## Metadati

| Campo | Valore |
|---|---|
| MITRE Technique | [T1053.005 — Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) |
| Tactic | Persistence, Privilege Escalation, Execution |
| Platform | Windows |
| VM | `target-windows` |
| Prerequisiti | Sysmon installato, Wazuh Agent attivo |
| Detection rule | `custom_windows.xml` — Rule ID 100026 / `custom_mitre_mapped.xml` — Rule ID 100070 |
| Severity attesa | High (level 10) |

---

## Obiettivo

Simulare la creazione di un Scheduled Task come meccanismo di persistenza — una delle tecniche più usate dal malware reale. Il test verifica che Wazuh rilevi la creazione del task via `schtasks.exe /create`.

---

## Prerequisiti

Su `target-windows` (PowerShell come amministratore):
- Sysmon in esecuzione
- Wazuh Agent in esecuzione
- Permessi amministrativi (alcuni task richiedono elevazione)

---

## Simulazione

### Test 1 — Task con payload PowerShell (via cmd)

```cmd
REM Crea un task che esegue PowerShell ogni minuto (payload benigno)
schtasks /create /tn "AtomicTest_T1053" /tr "powershell.exe -NoProfile -Command Write-Host 'T1053 Test'" /sc MINUTE /mo 1 /f
```

### Test 2 — Task con esecuzione al logon (persistenza)

```cmd
REM Task che si avvia al logon dell'utente corrente
schtasks /create /tn "AtomicTest_T1053_Logon" /tr "cmd.exe /c echo Persistence > C:\Temp\persist_test.txt" /sc ONLOGON /ru "%USERNAME%" /f
```

### Test 3 — Task nascosto in path di sistema (evasione)

```powershell
# Crea il task in una directory di sistema per mimetizzarsi
schtasks /create `
  /tn "Microsoft\Windows\AtomicTest_T1053_Hidden" `
  /tr "powershell.exe -WindowStyle Hidden -Command Start-Sleep 1" `
  /sc DAILY `
  /st 00:00 `
  /f
```

### Test 4 — Via Register-ScheduledTask (PowerShell nativo)

```powershell
# Approccio via API PowerShell — bypassa schtasks.exe ma Sysmon cattura il processo
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -Command 'Write-Host T1053'"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "AtomicTest_PS_T1053" -Action $action -Trigger $trigger -Force
```

### Test 5 — Atomic Red Team

```powershell
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T1053.005 -TestNumbers 1,4
```

---

## Alert atteso su Wazuh

Sysmon Event ID 1 per `schtasks.exe` con `/create` nel CommandLine:

```
rule.id: 100026
rule.level: 10
rule.description: "Scheduled task created: schtasks /create /tn AtomicTest_T1053 ..."
rule.mitre.technique: ["T1053", "T1053.005"]
agent.name: target-windows
data.win.eventdata.image: "C:\Windows\System32\schtasks.exe"
data.win.eventdata.commandLine: "schtasks /create /tn AtomicTest_T1053 ..."
```

---

## Come verificare la detection

### 1. Dalla Dashboard Wazuh

```
agent.name: "target-windows" AND rule.id: 100026
```

```
rule.mitre.technique: T1053.005
```

### 2. Verifica il task creato su target-windows

```powershell
# Lista tutti i task creati di recente
Get-ScheduledTask | Where-Object { $_.TaskName -like "AtomicTest*" }

# Dettaglio di un task specifico
Get-ScheduledTaskInfo -TaskName "AtomicTest_T1053"
```

### 3. Windows Event Log (nativo)

Apri **Event Viewer → Windows Logs → Security** e cerca Event ID `4698` (A scheduled task was created).

---

## Verifica True Positive vs False Positive

| Indicatore | True Positive | False Positive |
|---|---|---|
| Path task | `\Microsoft\Windows\` con nome custom insolito | Path noti del sistema (Windows Update, Defender) |
| Trigger | At logon, at startup | Orari specifici documentati |
| Payload | PowerShell, cmd con encoding | Eseguibili firmati e noti |
| Parent process | `cmd.exe`, `powershell.exe` interattivo | Installer, software noto |

---

## Cleanup

```powershell
# Rimuovi i task creati durante il test
schtasks /delete /tn "AtomicTest_T1053" /f
schtasks /delete /tn "AtomicTest_T1053_Logon" /f
schtasks /delete /tn "Microsoft\Windows\AtomicTest_T1053_Hidden" /f
Unregister-ScheduledTask -TaskName "AtomicTest_PS_T1053" -Confirm:$false

# Verifica che non rimangano
Get-ScheduledTask | Where-Object { $_.TaskName -like "AtomicTest*" }

# Rimuovi file di test
Remove-Item "C:\Temp\persist_test.txt" -ErrorAction SilentlyContinue
```

---

## Note operative

- `schtasks.exe /create` genera sempre un Sysmon Event ID 1 se Sysmon è attivo
- Il Test 4 (Register-ScheduledTask) può non triggerare la rule 100026 se non lancia `schtasks.exe` — in quel caso viene rilevato il processo `powershell.exe` con argomenti sospetti
- Windows Event ID 4698 (task created) richiede che l'audit delle policy sia abilitato: `auditpol /set /subcategory:"Other Object Access Events" /success:enable`
