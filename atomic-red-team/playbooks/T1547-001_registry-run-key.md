# Playbook — T1547.001: Registry Run Key Persistence

## Metadati

| Campo | Valore |
|---|---|
| MITRE Technique | [T1547.001 — Boot/Logon Autostart Execution: Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/) |
| Tactic | Persistence, Privilege Escalation |
| Platform | Windows |
| VM | `target-windows` |
| Prerequisiti | Sysmon installato (Event ID 13), Wazuh Agent attivo |
| Detection rule | `custom_windows.xml` — Rule ID 100022 / `custom_mitre_mapped.xml` — Rule ID 100080 |
| Severity attesa | High (level 12) |

---

## Obiettivo

Simulare l'aggiunta di un valore alle chiavi Run/RunOnce del registro di sistema — tecnica di persistenza usata dalla maggior parte dei malware Windows. La detection si basa su Sysmon Event ID 13 (Registry Value Set).

---

## Prerequisiti

Su `target-windows` (PowerShell come amministratore):
- Sysmon in esecuzione con config SwiftOnSecurity (che cattura Event ID 12/13/14)
- Wazuh Agent in esecuzione
- I Registry Events di Sysmon devono essere abilitati nella config (lo sono per default in SwiftOnSecurity)

---

## Chiavi Run target

| Chiave | Scope | Requires Admin |
|---|---|---|
| `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run` | Utente corrente | No |
| `HKLM:\Software\Microsoft\Windows\CurrentVersion\Run` | Tutti gli utenti | Sì |
| `HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce` | Utente, esegue una volta | No |
| `HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce` | Sistema, esegue una volta | Sì |

---

## Simulazione

### Test 1 — Run key utente corrente (HKCU, no admin)

```powershell
# Aggiunge un payload benigno alla Run key dell'utente corrente
# Trigger: Sysmon Event ID 13 su HKCU\...\Run
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $regPath -Name "AtomicTest_T1547" -Value "powershell.exe -NoProfile -WindowStyle Hidden -Command Write-Host 'T1547 Test'"

# Verifica
Get-ItemProperty -Path $regPath -Name "AtomicTest_T1547"
```

### Test 2 — Run key di sistema (HKLM, richiede admin)

```powershell
# Aggiunge alla Run key di sistema (scope: tutti gli utenti)
$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $regPath -Name "AtomicTest_T1547_System" -Value "cmd.exe /c echo Persistence"

Get-ItemProperty -Path $regPath -Name "AtomicTest_T1547_System"
```

### Test 3 — Via reg.exe (simula approccio da cmd/batch)

```cmd
REM Metodo comune usato da malware via cmd o batch script
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v AtomicTest_reg /t REG_SZ /d "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden" /f
```

### Test 4 — RunOnce (esecuzione singola al prossimo avvio)

```powershell
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
Set-ItemProperty -Path $regPath -Name "AtomicTest_RunOnce" -Value "calc.exe"
```

### Test 5 — Atomic Red Team

```powershell
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T1547.001 -TestNumbers 1,2
```

---

## Alert atteso su Wazuh

Sysmon Event ID 13 (Registry Value Set):

```
rule.id: 100022
rule.level: 12
rule.description: "Registry Run key modified for persistence: HKCU\Software\Microsoft\Windows\CurrentVersion\Run by powershell.exe"
rule.mitre.technique: ["T1547", "T1547.001"]
agent.name: target-windows
data.win.eventdata.targetObject: "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\AtomicTest_T1547"
data.win.eventdata.image: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
data.win.eventdata.details: "powershell.exe -NoProfile -WindowStyle Hidden ..."
```

---

## Come verificare la detection

### 1. Dalla Dashboard Wazuh

```
agent.name: "target-windows" AND rule.id: 100022
```

```
rule.mitre.technique: T1547.001
```

```
data.win.eventdata.targetObject: *CurrentVersion\\Run*
```

### 2. Event Viewer su target-windows

Apri **Event Viewer → Microsoft → Windows → Sysmon → Operational**  
Filtra per Event ID = 13 e cerca `Run` nel campo `TargetObject`.

### 3. Verifica diretta del registro

```powershell
# Mostra tutti i valori Run per utente corrente
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Mostra tutti i valori Run di sistema
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
```

---

## Verifica True Positive vs False Positive

| Indicatore | True Positive | False Positive |
|---|---|---|
| Valore aggiunto | PowerShell, cmd, script | Software legittimo installato (Spotify, Teams, ecc.) |
| Path eseguibile | `%TEMP%`, `%APPDATA%`, path non standard | `C:\Program Files\...` con firma valida |
| Processo scrivente | `powershell.exe`, `cmd.exe` interattivo | Installer firmato (`msiexec.exe`) |
| Orario | Fuori orario normale / durante test | Post-installazione software |

---

## Cleanup

```powershell
# Rimuovi i valori Run aggiunti durante il test
$hkcu = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$hklm = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
$runonce = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"

Remove-ItemProperty -Path $hkcu  -Name "AtomicTest_T1547"        -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $hklm  -Name "AtomicTest_T1547_System" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $hkcu  -Name "AtomicTest_reg"           -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $runonce -Name "AtomicTest_RunOnce"     -ErrorAction SilentlyContinue

# Verifica pulizia
Get-ItemProperty $hkcu  | Select-Object *Atomic*
Get-ItemProperty $hklm  | Select-Object *Atomic*
```

---

## Note operative

- Sysmon deve avere i Registry Events abilitati (`EventID 12, 13, 14`) nella config — SwiftOnSecurity li abilita per default
- Se la rule 100022 non scatta ma l'Event ID 13 è visibile in Event Viewer, il problema è nel decoder Wazuh o nella localfile config
- Alcuni software legittimi scrivono nelle Run keys durante l'installazione — aspettati qualche FP nell'ambiente iniziale; il tuning si fa escludendo i percorsi noti (`C:\Program Files\`) con `<list>` o `<if_not_matched>`
