# DET-009 — Mimikatz Command-Line Keywords

## Sommario

Rileva le **keyword caratteristiche di Mimikatz** nella command line: `sekurlsa::logonpasswords`,
`lsadump::`, `privilege::debug`, `kerberos::`, `crypto::`, `Invoke-Mimikatz`, `DumpCreds`. Mimikatz è
**lo** strumento di credential dumping per eccellenza (furto di password in chiaro, hash NTLM, ticket
Kerberos, attacchi pass-the-hash/golden ticket). Questa regola intercetta l'**intento** non appena il
comando viene lanciato — anche prima che il dump abbia successo.

Detection **validata due volte** su `target-windows` (VM Windows 10 Pro, agent 002):
- **Alert 1** — keyword test via `powershell logonpasswords` (process: `powershell.exe`, integrity Medium)
- **Alert 2** — **binario reale `mimikatz.exe`** (gentilkiwi), `privilege::debug` + `sekurlsa::logonpasswords`, integrity **High** — True Positive completo

Entrambi catturati da **Sysmon Event ID 1**, regola custom **`100034` (level 15)**.

---

## MITRE ATT&CK

- **Tactic**: Credential Access
- **Technique**: [T1003 — OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- **Sub-technique**: [T1003.001 — LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

---

## Come è stato simulato

**VM**: `target-windows` (`192.168.56.103`)
**Playbook**: [T1003-001_lsass-dumping.md](../atomic-red-team/playbooks/T1003-001_lsass-dumping.md)

### Test 1 — keyword detection (integrity Medium)

**Privilegi**: utente standard (non serve admin per innescare la regola)

```cmd
powershell logonpasswords
```

> La keyword `logonpasswords` è sufficiente a far scattare la regola. Il comando fallisce (non è un
> cmdlet PowerShell valido), ma Sysmon registra la creazione del processo → la detection coglie
> l'**intento**.

### Test 2 — binario reale Mimikatz (integrity High)

**Privilegi**: amministrativi (UAC elevato — necessari per il dump LSASS reale)

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

> Mimikatz 2.2.0 (gentilkiwi/Benjamin DELPY), scaricato da GitHub e lanciato da un cmd elevato.
> Windows Defender **disabilitato** sulla VM per permettere l'esecuzione del binario originale.
> `privilege::debug` richiede SeDebugPrivilege (solo admin), `sekurlsa::logonpasswords` dumpa le
> credenziali dalla memoria LSASS.

---

## Alert generato da Wazuh

### Alert 1 — keyword test (`powershell logonpasswords`)

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
  "data": {
    "win": {
      "system": { "eventID": "1", "channel": "Microsoft-Windows-Sysmon/Operational", "eventRecordID": "1265" },
      "eventdata": {
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "originalFileName": "PowerShell.EXE",
        "commandLine": "powershell  logonpasswords",
        "parentImage": "C:\\Windows\\System32\\cmd.exe",
        "user": "TARGET-WINDOWS\\labuser",
        "integrityLevel": "Medium",
        "hashes": "MD5=BCF01E61144D6D6325650134823198B8,SHA256=B4E7BC24BF3F5C3DA2EB6E9EC5EC10F90099DEFA91B820F2F3FC70DD9E4785C4,IMPHASH=88CB9A420410BDA787E305B65518A934"
      }
    }
  }
}
```

### Alert 2 — binario reale Mimikatz (`mimikatz.exe`)

```json
{
  "timestamp": "2026-06-25T12:19:03.179+0000",
  "rule": {
    "id": "100034",
    "level": 15,
    "description": "[T1003] Mimikatz command-line keywords detected: mimikatz.exe  \"privilege::debug\" \"sekurlsa::logonpasswords\" \"exit\"",
    "mitre": {
      "id": ["T1003", "T1003.001"],
      "tactic": ["Credential Access"],
      "technique": ["OS Credential Dumping", "LSASS Memory"]
    },
    "groups": ["custom_windows", "sysmon", "credential_access"],
    "firedtimes": 3
  },
  "agent": { "id": "002", "name": "target-windows", "ip": "192.168.56.103" },
  "data": {
    "win": {
      "system": { "eventID": "1", "channel": "Microsoft-Windows-Sysmon/Operational", "eventRecordID": "6424" },
      "eventdata": {
        "image": "C:\\Users\\labuser\\Desktop\\mimikatz\\x64\\mimikatz.exe",
        "originalFileName": "mimikatz.exe",
        "description": "mimikatz for Windows",
        "product": "mimikatz",
        "company": "gentilkiwi (Benjamin DELPY)",
        "fileVersion": "2.2.0.0",
        "commandLine": "mimikatz.exe  \"privilege::debug\" \"sekurlsa::logonpasswords\" \"exit\"",
        "parentImage": "C:\\Windows\\System32\\cmd.exe",
        "parentCommandLine": "\"C:\\Windows\\System32\\cmd.exe\" /C \"C:\\Users\\labuser\\Desktop\\run-mimi.bat\"",
        "user": "TARGET-WINDOWS\\labuser",
        "integrityLevel": "High",
        "currentDirectory": "C:\\Users\\labuser\\Desktop\\mimikatz\\x64\\",
        "hashes": "MD5=29EFD64DD3C7FE1E2B022B7AD73A1BA5,SHA256=61C0810A23580CF492A6BA4F7654566108331E7A4134C968C2D6A05261B2D8A1,IMPHASH=55EE500BB4BDFC49F27A98AE456D8EDF"
      }
    }
  }
}
```

---

## Analisi e triage

### Confronto Alert 1 vs Alert 2

| Campo | Alert 1 (keyword test) | Alert 2 (binario reale) | Perché conta |
|---|---|---|---|
| `image` | `powershell.exe` | **`mimikatz.exe`** | Alert 2: firma inequivocabile |
| `originalFileName` | `PowerShell.EXE` | **`mimikatz.exe`** | Resiste al rename del binario |
| `company` | `Microsoft Corporation` | **`gentilkiwi (Benjamin DELPY)`** | Autore di Mimikatz nel PE header |
| `commandLine` | `powershell logonpasswords` | **`mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"`** | Comandi reali |
| `integrityLevel` | Medium | **High** | Alert 2: elevato → dump LSASS possibile |
| `firedtimes` | 1 | 3 | Eseguito più volte nella stessa sessione |

**Entrambi gli alert sono True Positive.** L'Alert 1 cattura l'*intento* (utile anche senza admin);
l'Alert 2 cattura l'*esecuzione reale* con tutti i marker forensi del binario originale.

**Domande guida per il triage**:
- È presente anche un **accesso a LSASS** (Sysmon EID 10 → regola `100025`) subito dopo?
- Il binario ha `company: gentilkiwi` o `originalFileName: mimikatz.exe`? → incidente confermato.
- `integrityLevel: High` → il dump LSASS ha avuto successo con alta probabilità.
- C'è stato **movimento laterale** o uso di credenziali subito dopo?

**Caveat**: la regola è keyword-based, quindi evadibile con offuscamento (`sek`+`urlsa`). Va
complementata con detection comportamentali (`100025` accesso LSASS, `100033` dump via comsvcs).

**Verdetto**: **True Positive** in entrambi i casi. In produzione → **incidente critico immediato**.

### True Positive vs False Positive

| Indicatore | True Positive | False Positive |
|---|---|---|
| `company: gentilkiwi` / `originalFileName: mimikatz.exe` | Incidente confermato | Impossibile |
| `sekurlsa::`, `logonpasswords`, `lsadump::` | Quasi sempre Mimikatz | Estremamente raro |
| `integrityLevel: High` + keyword | Dump reale probabile | — |
| Contesto | Accesso LSASS correlato, lateral movement | Stringa in documento/log di sicurezza |

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

### Alert 1 — keyword test

| Tipo | Valore | Note |
|---|---|---|
| Processo | `…\v1.0\powershell.exe` (PID 5448) | Vettore della keyword |
| Command line | `powershell  logonpasswords` | Keyword Mimikatz |
| SHA256 | `B4E7BC24BF3F5C3DA2EB6E9EC5EC10F90099DEFA91B820F2F3FC70DD9E4785C4` | Hash powershell.exe |
| User / Integrity | `TARGET-WINDOWS\labuser` / Medium | |
| Timestamp | `2026-06-25 07:44:50Z` (Sysmon) | |

### Alert 2 — binario reale Mimikatz

| Tipo | Valore | Note |
|---|---|---|
| Processo | `…\Desktop\mimikatz\x64\mimikatz.exe` (PID 4876) | Binario originale |
| Parent | `cmd.exe /C run-mimi.bat` (PID 7404) | Eseguito da batch file |
| Command line | `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"` | Comandi reali |
| MD5 | `29EFD64DD3C7FE1E2B022B7AD73A1BA5` | Hash Mimikatz 2.2.0 |
| SHA256 | `61C0810A23580CF492A6BA4F7654566108331E7A4134C968C2D6A05261B2D8A1` | Da correlare su VirusTotal |
| IMPHASH | `55EE500BB4BDFC49F27A98AE456D8EDF` | Utile per rilevare varianti rinominate |
| User / Integrity | `TARGET-WINDOWS\labuser` / **High** | Elevato |
| Timestamp | `2026-06-25 12:18:26Z` (Sysmon) | |

---

## Remediation

1. **Credential Guard** + **LSASS PPL** (`RunAsPPL=1`): rendono inefficaci i metodi di dump che
   Mimikatz usa. (Vedi anche [DET-006](DET-006_lsass-dumping.md).)
2. **AMSI + AV/EDR attivi**: Mimikatz e `Invoke-Mimikatz` sono ampiamente firmati — in questo test
   Defender è stato disabilitato manualmente; in produzione non deve mai essere disabilitato.
3. **ASR** "Block credential stealing from lsass.exe".
4. **Detection complementari** comportamentali (`100025`, `100033`) per coprire le varianti offuscate.
5. **Risposta**: incidente critico → isolamento host + **reset delle credenziali** degli account loggati.

---

## Lezioni apprese

- La stessa regola rileva sia il **tentativo grezzo** (keyword in powershell, integrity Medium) che
  l'**attacco completo** (binario reale, integrity High) — dimostra la solidità della detection
  keyword-based anche quando il vettore cambia.
- `originalFileName` e `company` nel PE header di Mimikatz rimangono `gentilkiwi` anche se il file
  viene rinominato — Sysmon li legge dal binario, non dal nome del file.
- `level 15` riservato ai segnali quasi-certi: aiuta a prioritizzare il triage quando arrivano molti
  alert insieme.
- **Defender disabilitato** è necessario per eseguire il binario originale in lab; in produzione
  l'AV rappresenta un layer di difesa aggiuntivo (ma non sufficiente da solo contro varianti offuscate).

---

→ Playbook: [T1003-001_lsass-dumping.md](../atomic-red-team/playbooks/T1003-001_lsass-dumping.md) · Report: [CASE-STUDIES.md](CASE-STUDIES.md)
