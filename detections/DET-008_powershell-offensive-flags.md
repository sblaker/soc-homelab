# DET-008 — PowerShell con Flag Offensivi

## Sommario

Rileva l'esecuzione di `powershell.exe` con la combinazione di flag tipica dell'uso **offensivo**:
`-nop`/`-NoProfile` (ignora il profilo), `-w hidden`/`-WindowStyle Hidden` (finestra nascosta),
`-Exec Bypass` (bypass execution policy), `-enc`/`-EncodedCommand` (payload offuscato in Base64),
`IEX`/`DownloadString` (esecuzione/download in-memory). Sono i mattoni di dropper, stager C2 e script
di post-exploitation.

Detection **validata dal vivo** su `target-windows` (VM Windows 10 Pro, agent 002): catturata da
**Sysmon Event ID 1** e rilevata dalla regola custom **`100063` (level 12)**. Aggiorna/estende
[DET-002](DET-002_powershell-suspicious.md), che era stato catturato sull'host e non sulla VM.

---

## MITRE ATT&CK

- **Tactic**: Execution
- **Technique**: [T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- **Sub-technique**: [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- Correlata: [T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)

---

## Come è stato simulato

**VM**: `target-windows` (`192.168.56.103`)
**Privilegi**: utente standard (integrity **Medium** — non serve admin)
**Playbook**: [T1059-001_powershell-suspicious.md](../atomic-red-team/playbooks/T1059-001_powershell-suspicious.md)

Comando eseguito (da `cmd.exe`):

```cmd
powershell -nop -w hidden -c exit
```

> Il payload (`exit`) è **benigno**: a innescare la detection è la **combinazione di flag**
> (`-nop` + `-w hidden`), identica a quella di un loader reale. In un attacco vero al posto di `exit`
> ci sarebbe un `-EncodedCommand` con shellcode o un download cradle (`IEX (New-Object
> Net.WebClient).DownloadString('http://…')`).

---

## Alert generato da Wazuh

```json
{
  "timestamp": "2026-06-25T00:43:22.245+0000",
  "rule": {
    "id": "100063",
    "level": 12,
    "description": "[T1059.001] PowerShell with offensive flags: powershell  -nop -w hidden -c exit",
    "mitre": {
      "id": ["T1059", "T1059.001"],
      "tactic": ["Execution"],
      "technique": ["Command and Scripting Interpreter", "PowerShell"]
    },
    "groups": ["custom_mitre", "execution", "defense_evasion"],
    "firedtimes": 1
  },
  "agent": { "id": "002", "name": "target-windows", "ip": "192.168.56.103" },
  "manager": { "name": "wazuh.manager" },
  "decoder": { "name": "windows_eventchannel" },
  "id": "1782348202.4835509",
  "location": "EventChannel",
  "data": {
    "win": {
      "system": {
        "eventID": "1",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "target-windows",
        "eventRecordID": "1255"
      },
      "eventdata": {
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "originalFileName": "PowerShell.EXE",
        "commandLine": "powershell  -nop -w hidden -c exit",
        "processId": "1644",
        "parentImage": "C:\\Windows\\System32\\cmd.exe",
        "parentCommandLine": "\"C:\\Windows\\system32\\cmd.exe\"",
        "parentProcessId": "6432",
        "user": "TARGET-WINDOWS\\labuser",
        "integrityLevel": "Medium",
        "currentDirectory": "C:\\Users\\labuser\\",
        "hashes": "MD5=BCF01E61144D6D6325650134823198B8,SHA256=B4E7BC24BF3F5C3DA2EB6E9EC5EC10F90099DEFA91B820F2F3FC70DD9E4785C4,IMPHASH=88CB9A420410BDA787E305B65518A934",
        "fileVersion": "10.0.19041.2913 (WinBuild.160101.0800)"
      }
    }
  }
}
```

---

## Analisi e triage

`powershell.exe` (PID 1644), figlio di `cmd.exe` (PID 6432), avviato dall'utente `labuser` con
**integrity Medium** e i flag `-nop -w hidden`. La combinazione *no-profile + finestra nascosta* è
rara negli script di amministrazione legittimi e tipica del codice che vuole **eseguire senza essere
visto**.

| Campo | Valore | Perché è rilevante |
|---|---|---|
| `image` | `powershell.exe` | Interprete universale di post-exploitation |
| `commandLine` | `powershell  -nop -w hidden -c exit` | `-nop` + `-w hidden` = pattern offensivo |
| `parentImage` | `cmd.exe` | **Determinante per il triage** (vedi sotto) |
| `integrityLevel` | Medium | Non elevato — esecuzione user-level |
| `user` | `TARGET-WINDOWS\labuser` | Account standard |

**Il parent process è tutto** nel triage di PowerShell:
- Parent `winword.exe`/`excel.exe`/`outlook.exe` → **macro malevola** → quasi certamente True Positive.
- Parent `cmd.exe`/`explorer.exe`/`powershell_ise.exe` → potrebbe essere attività interattiva (come qui).
- Parent `wmiprvse.exe`/`services.exe` → possibile esecuzione remota / persistenza.

**Altre domande**: c'è un `-EncodedCommand`? Decodifica il Base64
(`[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("<b64>"))`). C'è una connessione di
rete subito dopo (Sysmon EID 3)? L'utente/orario sono attesi?

**Verdetto**: **True Positive** (test controllato). Il payload era benigno, ma la struttura è quella
di un loader reale.

### True Positive vs False Positive

| Indicatore | True Positive | False Positive |
|---|---|---|
| `-EncodedCommand` | Quasi sempre sospetto | Script legittimi raramente lo usano |
| `-w hidden` | Evasione visiva | Raro in script admin legittimi |
| `IEX`/`DownloadString` | Tipico di dropper | Possibile in script sysadmin |
| Parent process | `winword.exe`, `excel.exe` | `powershell_ise.exe`, task schedulato noto |

---

## Regola Wazuh utilizzata

**File**: `wazuh/rules/custom_mitre_mapped.xml` · **Rule ID**: `100063` · **Level**: 12 (High)

```xml
<rule id="100063" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(-enc|-nop|-windowstyle\s+hidden|iex|invoke-expression|downloadstring)</field>
  <description>[T1059.001] PowerShell with offensive flags: $(win.eventdata.commandLine)</description>
  <mitre><id>T1059</id><id>T1059.001</id></mitre>
  <group>execution,defense_evasion,</group>
</rule>
```

> Regola gemella `100021` (in `custom_windows.xml`) copre un set di flag più ampio
> (`-exec bypass`, `webclient`, ecc.). Sullo stesso evento può scattare una delle due.

---

## Indicatori (IOC)

| Tipo | Valore | Note |
|---|---|---|
| Processo | `…\v1.0\powershell.exe` (PID 1644) | Interprete |
| Parent | `cmd.exe` (PID 6432) | In attacco reale: Office = TP forte |
| Command line | `powershell  -nop -w hidden -c exit` | Flag offensivi |
| SHA256 | `B4E7BC24BF3F5C3DA2EB6E9EC5EC10F90099DEFA91B820F2F3FC70DD9E4785C4` | Hash di powershell.exe |
| User / Integrity | `TARGET-WINDOWS\labuser` / Medium | User-level |
| Timestamp | `2026-06-25 07:43:19Z` (Sysmon) → `00:43:22Z` (manager) | |

---

## Remediation

1. **PowerShell Script Block Logging** (Event ID 4104): cattura il codice **de-offuscato** a runtime
   — la difesa più utile contro `-EncodedCommand`.
2. **Constrained Language Mode** + **AMSI**: limita le funzionalità e fa scansionare gli script.
3. **Execution Policy** aziendale `AllSigned`/`RemoteSigned`.
4. **AppLocker / WDAC**: blocca l'esecuzione di script PowerShell non firmati.
5. **Tuning**: escludi i task/script firmati noti per ridurre i falsi positivi e tenere alto il segnale.

---

## Lezioni apprese

- La detection si basa sul **pattern dei flag**, non sul payload: funziona anche se il contenuto è
  offuscato o sconosciuto.
- Il **parent process** è il discriminante principale TP/FP per PowerShell — va sempre incluso
  nell'alert e nel triage.

---

→ Playbook: [T1059-001_powershell-suspicious.md](../atomic-red-team/playbooks/T1059-001_powershell-suspicious.md) · Report: [CASE-STUDIES.md](CASE-STUDIES.md)
