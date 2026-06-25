# DET-007 — Ransomware: Shadow Copy Deletion (Inhibit System Recovery)

## Sommario

Rileva la **cancellazione delle Volume Shadow Copies** (le copie di ripristino di Windows), cioè il
passo che **quasi ogni ransomware** esegue **prima di cifrare** per impedire alla vittima di
recuperare i file. Catturare questo evento dà al SOC una finestra preziosa — di solito **pochi
minuti** — per isolare l'host *prima* dell'impatto.

Detection **validata dal vivo** su `target-windows` (VM Windows 10 Pro, agent 002): `vssadmin.exe`
ha cancellato tutte le shadow copy in modalità silenziosa, catturato da **Sysmon Event ID 1** e
rilevato dalla regola custom **`100030` (level 14)**.

---

## MITRE ATT&CK

- **Tactic**: Impact
- **Technique**: [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- Correlata nella catena ransomware: [T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)

---

## Come è stato simulato

**VM**: `target-windows` (`192.168.56.103`)
**Privilegi**: amministrativi (la cancellazione delle shadow copy richiede elevazione)
**Playbook**: [T1490_ransomware-behavior.md](../atomic-red-team/playbooks/T1490_ransomware-behavior.md)

Comando eseguito (da un `cmd.exe` elevato):

```cmd
vssadmin delete shadows /all /quiet
```

> Sui ransomware reali (Ryuk, LockBit, Conti) questo comando è spesso seguito da
> `wmic shadowcopy delete`, `bcdedit /set recoveryenabled no` e `wbadmin delete catalog`. La regola
> `100031` copre la variante `bcdedit`. Su una VM appena installata non esistono shadow copy da
> cancellare, ma **il comando — e quindi la detection — è identico**: la regola si basa sul
> *process create*, non sull'esito.

---

## Alert generato da Wazuh

```json
{
  "timestamp": "2026-06-25T00:51:29.878+0000",
  "rule": {
    "id": "100030",
    "level": 14,
    "description": "[T1490] Shadow copy/backup deletion (ransomware pre-encryption): vssadmin  delete shadows /all /quiet",
    "mitre": {
      "id": ["T1490"],
      "tactic": ["Impact"],
      "technique": ["Inhibit System Recovery"]
    },
    "groups": ["custom_windows", "sysmon", "impact", "ransomware"],
    "firedtimes": 1
  },
  "agent": { "id": "002", "name": "target-windows", "ip": "192.168.56.103" },
  "manager": { "name": "wazuh.manager" },
  "decoder": { "name": "windows_eventchannel" },
  "id": "1782348689.4863744",
  "location": "EventChannel",
  "data": {
    "win": {
      "system": {
        "eventID": "1",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "target-windows",
        "eventRecordID": "1286"
      },
      "eventdata": {
        "image": "C:\\Windows\\System32\\vssadmin.exe",
        "originalFileName": "VSSADMIN.EXE",
        "description": "Command Line Interface for Microsoft® Volume Shadow Copy Service",
        "commandLine": "vssadmin  delete shadows /all /quiet",
        "processId": "7164",
        "parentImage": "C:\\Windows\\System32\\cmd.exe",
        "parentCommandLine": "\"C:\\Windows\\system32\\cmd.exe\"",
        "parentProcessId": "6100",
        "user": "TARGET-WINDOWS\\labuser",
        "integrityLevel": "High",
        "currentDirectory": "C:\\Windows\\system32\\",
        "utcTime": "2026-06-25 07:51:26.668",
        "hashes": "MD5=B58073DB8892B67A672906C9358020EC,SHA256=8C1FABCC2196E4D096B7D155837C5F699AD7F55EDBF84571E4F8E03500B7A8B0,IMPHASH=C1EDC431CD345F0A0F32019895D13FCE",
        "fileVersion": "10.0.19041.1 (WinBuild.160101.0800)"
      }
    }
  }
}
```

---

## Analisi e triage

`vssadmin.exe` (PID 7164), figlio di `cmd.exe` (PID 6100), è stato eseguito con **integrity level
High** (elevato) dall'utente `labuser`, con argomenti `delete shadows /all /quiet`: cancella **tutte**
le copie shadow **senza conferma** (`/quiet`). È il manuale operativo del ransomware.

| Campo | Valore | Perché è rilevante |
|---|---|---|
| `image` | `vssadmin.exe` | Tool legittimo Windows, abusato per distruggere il recovery |
| `commandLine` | `vssadmin  delete shadows /all /quiet` | `delete shadows /all` = intento distruttivo; `/quiet` = nessuna conferma |
| `parentImage` | `cmd.exe` | Lancio interattivo/script — non manutenzione pianificata |
| `integrityLevel` | **High** | Esecuzione elevata (necessaria) |
| `user` | `TARGET-WINDOWS\labuser` | Account che ha eseguito l'azione |
| `SHA256` | `8C1FABCC…B7A8B0` | Hash di `vssadmin.exe` per correlazione |

**Domande guida per il triage**:
- È un'operazione **pianificata** e documentata (raro), o **interattiva** da `cmd`/`powershell`? La
  seconda è quasi sempre malevola.
- Ci sono **altri segnali della catena ransomware** subito prima/dopo? `bcdedit recoveryenabled no`
  (`100031`), creazione di file `.locked`/ransom note (`100032`), picco di scritture su file.
- Qual è il **parent del parent**? Risali la catena: macro Office → PowerShell → cmd → vssadmin è un
  pattern d'attacco completo.

**Verdetto**: **True Positive** (simulazione). In produzione → **massima priorità**: la cifratura
segue tipicamente in pochi minuti. **Isola l'host immediatamente.**

### True Positive vs False Positive

| Indicatore | True Positive | False Positive |
|---|---|---|
| `vssadmin delete shadows /all` | Quasi sempre malevolo su endpoint | Rarissimi job di manutenzione/backup documentati |
| Parent | `cmd`/`powershell` interattivo, dopo una macro | Software di backup firmato e noto |
| Contesto | Seguito da `bcdedit`, file `.locked` | Singola azione isolata documentata |
| Orario | Fuori orario / durante un incidente | Finestra di manutenzione nota |

---

## Regola Wazuh utilizzata

**File**: `wazuh/rules/custom_windows.xml` · **Rule ID**: `100030` · **Level**: 14 (Critical)

```xml
<rule id="100030" level="14">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)(vssadmin|wmic|wbadmin|diskshadow)\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(delete\s+shadows|shadowcopy\s+delete|delete\s+catalog|delete\s+systemstatebackup|resize\s+shadowstorage)</field>
  <description>[T1490] Shadow copy/backup deletion (ransomware pre-encryption): $(win.eventdata.commandLine)</description>
  <mitre><id>T1490</id></mitre>
  <group>impact,ransomware,</group>
</rule>
```

> Regole correlate: `100031` (bcdedit recovery disabilitato), `100032` (ransom note / file cifrati).

---

## Indicatori (IOC)

| Tipo | Valore | Note |
|---|---|---|
| Processo | `C:\Windows\System32\vssadmin.exe` (PID 7164) | Tool nativo abusato |
| Parent | `C:\Windows\System32\cmd.exe` (PID 6100) | Lancio interattivo, elevato |
| Command line | `vssadmin  delete shadows /all /quiet` | Cancellazione shadow copy silenziosa |
| User / Integrity | `TARGET-WINDOWS\labuser` / High | Esecuzione elevata |
| SHA256 (vssadmin) | `8C1FABCC2196E4D096B7D155837C5F699AD7F55EDBF84571E4F8E03500B7A8B0` | Da Sysmon EID 1 |
| Timestamp | `2026-06-25 07:51:26Z` (Sysmon) → `00:51:29Z` (manager) | Vedi nota NTP in [DET-006](DET-006_lsass-dumping.md) |

---

## Remediation

1. **Backup immutabili / offline (3-2-1)**: l'unica difesa reale contro la cifratura — i backup non
   devono essere cancellabili dall'host compromesso.
2. **Alert ad altissima priorità** su `vssadmin delete shadows` e `bcdedit recoveryenabled no` con
   **risposta automatica** (isolamento host) dove possibile.
3. **Controlled Folder Access** (Defender) per proteggere le cartelle utente dalla cifratura.
4. **Least privilege**: la cancellazione delle shadow copy richiede l'elevazione — riduci gli admin locali.
5. **Playbook di IR** pronto: all'alert T1490, isola, identifica il *patient zero* e il vettore iniziale.

---

## Lezioni apprese

- L'**Inhibit System Recovery** è un *early warning* d'oro: arriva **prima** della cifratura. Una
  detection ad alta priorità qui può salvare l'organizzazione.
- Anche qui vale il **living-off-the-land**: `vssadmin` è un tool Microsoft — si rileva il
  *comportamento* (`delete shadows /all`), non un binario malevolo.

---

→ Playbook: [T1490_ransomware-behavior.md](../atomic-red-team/playbooks/T1490_ransomware-behavior.md) · Report: [CASE-STUDIES.md](CASE-STUDIES.md)
