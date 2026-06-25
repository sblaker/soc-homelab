# DET-009 — Mimikatz Command-Line Keywords

## Sommario

Rileva le **keyword caratteristiche di Mimikatz** nella command line: `sekurlsa::logonpasswords`,
`lsadump::`, `privilege::debug`, `kerberos::`, `crypto::`, `Invoke-Mimikatz`, `DumpCreds`. Mimikatz è
**lo** strumento di credential dumping per eccellenza (furto di password in chiaro, hash NTLM, ticket
Kerberos, attacchi pass-the-hash/golden ticket). Questa regola intercetta l'**intento** non appena il
comando viene lanciato — anche prima che il dump abbia successo.

Detection **validata dal vivo** su `target-windows` (VM Windows 10 Pro, agent 002): catturata da
**Sysmon Event ID 1** e rilevata dalla regola custom **`100034` (level 15 — la severità più alta del
lab)**.

---

## MITRE ATT&CK

- **Tactic**: Credential Access
- **Technique**: [T1003 — OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- **Sub-technique**: [T1003.001 — LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

---

## Come è stato simulato

**VM**: `target-windows` (`192.168.56.103`)
**Privilegi**: utente standard (integrity **Medium** — per *innescare la detection* non serve admin)
**Playbook**: [T1003-001_lsass-dumping.md](../atomic-red-team/playbooks/T1003-001_lsass-dumping.md)

Comando eseguito (da `cmd.exe`):

```cmd
powershell logonpasswords
```

> La keyword `logonpasswords` (uno dei comandi più noti di Mimikatz, `sekurlsa::logonpasswords`) è
> sufficiente a far scattare la regola. Il comando **fallisce** (non è un cmdlet PowerShell valido),
> ma Sysmon registra comunque la **creazione del processo** con quella command line → la detection
> coglie l'**intento**. In un attacco reale la command line sarebbe
> `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"` o `Invoke-Mimikatz`.

---

## Alert generato da Wazuh

```json
{
  "timestamp": "2026-06-25T00:44:52.960+0000",
  "rule": {
    "id": "100034",
    "level": 15,
    "description": "[T1003] Mimikatz command-line keywords detected: powershell  logonpasswords",
    "mitre": {
      "id": ["T1003", "T1003.001"],
      "tactic": ["Credential Access"],
      "technique": ["OS Credential Dumping", "LSASS Memory"]
    },
    "groups": ["custom_windows", "sysmon", "credential_access"],
    "firedtimes": 1
  },
  "agent": { "id": "002", "name": "target-windows", "ip": "192.168.56.103" },
  "manager": { "name": "wazuh.manager" },
  "decoder": { "name": "windows_eventchannel" },
  "id": "1782348292.4843960",
  "location": "EventChannel",
  "data": {
    "win": {
      "system": {
        "eventID": "1",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "target-windows",
        "eventRecordID": "1265"
      },
      "eventdata": {
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "originalFileName": "PowerShell.EXE",
        "commandLine": "powershell  logonpasswords",
        "processId": "5448",
        "parentImage": "C:\\Windows\\System32\\cmd.exe",
        "parentCommandLine": "\"C:\\Windows\\system32\\cmd.exe\"",
        "parentProcessId": "6432",
        "user": "TARGET-WINDOWS\\labuser",
        "integrityLevel": "Medium",
        "currentDirectory": "C:\\Users\\labuser\\",
        "hashes": "MD5=BCF01E61144D6D6325650134823198B8,SHA256=B4E7BC24BF3F5C3DA2EB6E9EC5EC10F90099DEFA91B820F2F3FC70DD9E4785C4,IMPHASH=88CB9A420410BDA787E305B65518A934"
      }
    }
  }
}
```

---

## Analisi e triage

Un processo (`powershell.exe`, PID 5448, figlio di `cmd.exe`) è stato avviato con la command line che
contiene `logonpasswords`. La regola è **level 15** perché la presenza di keyword Mimikatz è un
segnale ad altissima confidenza: praticamente non esistono usi legittimi.

| Campo | Valore | Perché è rilevante |
|---|---|---|
| `commandLine` | `powershell  logonpasswords` | Keyword Mimikatz = credential dumping |
| `image` | `powershell.exe` | Vettore (qui); spesso `mimikatz.exe`, `rundll32`, processi rinominati |
| `parentImage` | `cmd.exe` | Lancio interattivo |
| `integrityLevel` | Medium | Il *dump reale* richiede High, ma la keyword si logga comunque |
| `user` | `TARGET-WINDOWS\labuser` | Account coinvolto |

**Domande guida**:
- È presente anche un **accesso a LSASS** (Sysmon EID 10 → regola `100025`) o un comando `comsvcs
  MiniDump` (`100033`)? La correlazione conferma il dump effettivo.
- Il binario è `mimikatz.exe` o un **eseguibile rinominato**? Controlla `OriginalFileName` e gli
  hash (un mimikatz rinominato mantiene l'`OriginalFileName`/IMPHASH originali).
- C'è stato **movimento laterale** o uso di credenziali subito dopo?

**Caveat (detection per keyword)**: è ad alto segnale ma **evadibile** con offuscamento (es.
`sek`+`urlsa`). Per questo va **complementata** con detection comportamentali (`100025` accesso LSASS,
`100033` pattern di dump) — difesa in profondità.

**Verdetto**: **True Positive** (test). In produzione la keyword `logonpasswords`/`sekurlsa::` è da
trattare come **incidente critico** immediato.

### True Positive vs False Positive

| Indicatore | True Positive | False Positive |
|---|---|---|
| `sekurlsa::`, `logonpasswords`, `lsadump::` | Quasi sempre Mimikatz | Estremamente raro |
| Binario | `mimikatz.exe`, exe rinominato, `Invoke-Mimikatz` | — |
| Contesto | Accesso LSASS correlato, lateral movement | Stringa in un documento/log di sicurezza (falso match) |

---

## Regola Wazuh utilizzata

**File**: `wazuh/rules/custom_windows.xml` · **Rule ID**: `100034` · **Level**: 15 (Critical)

```xml
<rule id="100034" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(sekurlsa::|logonpasswords|lsadump::|kerberos::|crypto::|privilege::debug|mimikatz|invoke-mimikatz|DumpCreds)</field>
  <description>[T1003] Mimikatz command-line keywords detected: $(win.eventdata.commandLine)</description>
  <mitre><id>T1003</id><id>T1003.001</id></mitre>
  <group>credential_access,</group>
</rule>
```

> Difesa in profondità: `100025` (EID 10 accesso LSASS) e `100033` (pattern `comsvcs MiniDump` /
> `procdump lsass`) coprono i metodi che evitano le keyword di Mimikatz.

---

## Indicatori (IOC)

| Tipo | Valore | Note |
|---|---|---|
| Processo | `…\v1.0\powershell.exe` (PID 5448) | Vettore della keyword |
| Parent | `cmd.exe` (PID 6432) | Lancio interattivo |
| Command line | `powershell  logonpasswords` | Keyword Mimikatz |
| SHA256 | `B4E7BC24BF3F5C3DA2EB6E9EC5EC10F90099DEFA91B820F2F3FC70DD9E4785C4` | Hash di powershell.exe |
| User / Integrity | `TARGET-WINDOWS\labuser` / Medium | |
| Timestamp | `2026-06-25 07:44:50Z` (Sysmon) → `00:44:52Z` (manager) | |

---

## Remediation

1. **Credential Guard** + **LSASS PPL** (`RunAsPPL=1`): rendono inefficaci i metodi di dump che
   Mimikatz usa. (Vedi anche [DET-006](DET-006_lsass-dumping.md).)
2. **AMSI + AV/EDR**: Mimikatz e `Invoke-Mimikatz` sono ampiamente firmati — mantieni le difese attive.
3. **ASR** "Block credential stealing from lsass.exe".
4. **Detection complementari** comportamentali (`100025`, `100033`) per coprire le varianti offuscate.
5. **Risposta**: incidente critico → isolamento host + **reset delle credenziali** degli account loggati.

---

## Lezioni apprese

- La **keyword detection** è ad altissimo segnale ma da sola **non basta** (evadibile): va sempre
  affiancata da detection **comportamentali** — è il principio della difesa in profondità.
- `level 15` riservato ai segnali quasi-certi (Mimikatz, defense evasion critica): aiuta a
  **prioritizzare** il triage quando arrivano molti alert insieme.

---

→ Playbook: [T1003-001_lsass-dumping.md](../atomic-red-team/playbooks/T1003-001_lsass-dumping.md) · Report: [CASE-STUDIES.md](CASE-STUDIES.md)
