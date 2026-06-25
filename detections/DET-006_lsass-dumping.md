# DET-006 — LSASS Credential Dumping (comsvcs.dll / Mimikatz)

## Sommario

Rileva il **dump della memoria del processo `lsass.exe`** (Local Security Authority Subsystem
Service), cioè il furto di credenziali, hash NTLM e ticket Kerberos degli utenti loggati. È **la**
tecnica di Credential Access più usata da APT e ransomware operator: un dump riuscito apre la strada
a *lateral movement*, *pass-the-hash* e compromissione del dominio.

Questa detection è stata **validata dal vivo** sull'endpoint `target-windows` (VM Windows 10 Pro,
agent 002) eseguendo il dump via il binario di sistema `comsvcs.dll` (tecnica *living-off-the-land*),
catturato da **Sysmon Event ID 1** e rilevato dalla regola custom **`100033` (level 14)**.

---

## MITRE ATT&CK

- **Tactic**: Credential Access
- **Technique**: [T1003 — OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- **Sub-technique**: [T1003.001 — LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

---

## Come è stato simulato

**VM**: `target-windows` (Windows 10 Pro, `192.168.56.103`)
**Metodo**: `comsvcs.dll` MiniDump (LOLBin — nessun tool esterno, nessun malware)
**Playbook**: [T1003-001_lsass-dumping.md](../atomic-red-team/playbooks/T1003-001_lsass-dumping.md)

Comando eseguito (da `cmd.exe`):

```cmd
rundll32 comsvcs.dll minidump lsass
```

> **Nota tecnica**: la sintassi *completa* del dump reale è
> `rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <PID_lsass> C:\Windows\Temp\lsass.dmp full`.
> Nel test la riga è volutamente in forma ridotta: serve a **innescare la detection** (la regola
> matcha il *pattern* `comsvcs.dll … MiniDump` nella command line), non a produrre il file di dump.
> La telemetria Sysmon — e quindi l'alert — è identica perché la regola si basa sul **process create**,
> non sull'esito del dump.

> **Curiosità difensiva osservata**: il **Windows Defender dell'host** ha bloccato l'esecuzione finché
> la stringa `comsvcs … minidump lsass` non è stata spezzata — prova concreta che questo pattern è
> riconosciuto come indicatore di credential dumping.

---

## Alert generato da Wazuh

Alert reale catturato dall'indexer (campi principali):

```json
{
  "timestamp": "2026-06-25T00:54:22.338+0000",
  "rule": {
    "id": "100033",
    "level": 14,
    "description": "[T1003.001] LSASS memory dump command detected: rundll32  comsvcs.dll minidump lsass",
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
  "id": "1782348862.4884117",
  "location": "EventChannel",
  "data": {
    "win": {
      "system": {
        "providerName": "Microsoft-Windows-Sysmon",
        "eventID": "1",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "target-windows",
        "eventRecordID": "1288",
        "utcTime": "2026-06-25 07:54:19.325"
      },
      "eventdata": {
        "image": "C:\\Windows\\System32\\rundll32.exe",
        "originalFileName": "RUNDLL32.EXE",
        "commandLine": "rundll32  comsvcs.dll minidump lsass",
        "processId": "5908",
        "parentImage": "C:\\Windows\\System32\\cmd.exe",
        "parentCommandLine": "\"C:\\Windows\\system32\\cmd.exe\"",
        "parentProcessId": "6100",
        "user": "TARGET-WINDOWS\\labuser",
        "integrityLevel": "High",
        "currentDirectory": "C:\\Windows\\system32\\",
        "hashes": "MD5=EF3179D498793BF4234F708D3BE28633,SHA256=B53F3C0CD32D7F20849850768DA6431E5F876B7BFA61DB0AA0700B02873393FA,IMPHASH=4DB27267734D1576D75C991DC70F68AC",
        "fileVersion": "10.0.19041.746 (WinBuild.160101.0800)"
      }
    }
  }
}
```

> Detection complementari per la stessa tecnica (difesa in profondità):
> - **`100025`** — Sysmon **Event ID 10** (ProcessAccess) verso `lsass.exe`: cattura i dump che
>   *non* lasciano una command line ovvia (es. accesso diretto alla memoria via API).
> - **`100034`** — Sysmon EID 1 con keyword Mimikatz (`sekurlsa::`, `logonpasswords`): nel lab è
>   scattata (level 15) su `powershell logonpasswords`.

---

## Analisi e triage

**Cosa è successo**: il processo `rundll32.exe` (PID 5908), figlio di `cmd.exe` (PID 6100), è stato
avviato dall'utente `labuser` con una command line che richiama `comsvcs.dll MiniDump` su `lsass`.
`rundll32` è un binario Microsoft legittimo (LOLBin): qui è **abusato** per dumpare LSASS.

Osservabili chiave dell'alert:

| Campo | Valore | Perché è rilevante |
|---|---|---|
| `image` | `rundll32.exe` | LOLBin: legittimo, ma raramente chiamato con `comsvcs MiniDump` |
| `commandLine` | `rundll32  comsvcs.dll minidump lsass` | Il *pattern* `comsvcs.dll … MiniDump` su `lsass` = credential dumping |
| `parentImage` | `cmd.exe` | Lancio interattivo/script — non un processo legittimo noto |
| `user` | `TARGET-WINDOWS\labuser` | Account locale; un dump richiede privilegi elevati |
| `integrityLevel` | **High** | Conferma esecuzione elevata (necessaria per accedere a LSASS) |
| `hashes` | `SHA256=B53F3C0…`, `IMPHASH=4DB27267…` | Hash/IMPHASH di `rundll32.exe` per correlazione e threat intel |

**Domande guida per il triage**:
- **Chi è il parent?** `cmd.exe`/`powershell.exe` interattivo o uno script → sospetto. Un EDR/AV
  legittimo (`MsMpEng.exe`) che accede a LSASS è invece un falso positivo comune.
- **C'è un file di dump?** Cerca `lsass*.dmp` in `%TEMP%`, `C:\Windows\Temp`, path insoliti (Sysmon
  EID 11). In questo test la sintassi ridotta non ha prodotto il file.
- **C'è un Event ID 10 correlato?** Verifica `100025`: `targetImage = lsass.exe` con `GrantedAccess`
  ad alto privilegio (`0x1010`, `0x1410`, `0x1fffff`).
- **Cosa è successo dopo?** Movimento laterale (logon 4624 type 3, SMB :445), uso di credenziali
  fresche, connessioni C2 — il dump è quasi sempre uno *step intermedio* di una kill chain.

**Verdetto**: **True Positive** (simulazione controllata nel lab). In produzione, `rundll32` che
invoca `comsvcs MiniDump` su `lsass` è da considerarsi malevolo fino a prova contraria → **escalation
immediata** e isolamento dell'host.

### True Positive vs False Positive

| Indicatore | True Positive | False Positive |
|---|---|---|
| Processo che tocca LSASS | `rundll32`/`procdump`/`powershell`/tool sconosciuto | EDR/AV firmato (`MsMpEng.exe`) |
| Command line | `comsvcs … MiniDump`, `-ma lsass`, `sekurlsa::` | — |
| `GrantedAccess` (EID 10) | `0x1010`/`0x1fffff` (read memory) | accessi a basso privilegio |
| Artefatto | `lsass.dmp` in TEMP/path insolito | — |
| Parent | `cmd`/`powershell` interattivo, Office | servizio di sicurezza noto |

---

## Regola Wazuh utilizzata

**File**: `wazuh/rules/custom_windows.xml`
**Rule ID**: `100033` · **Level**: 14 (Critical)
**Logica**: Sysmon Event ID 1, command line che matcha i pattern di dump LSASS (PCRE2).

```xml
<rule id="100033" level="14">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(comsvcs\.dll.{0,40}MiniDump|rundll32.{0,40}comsvcs|procdump(64)?(\.exe)?.{0,40}lsass|-ma\s+lsass|lsass\.dmp|dumpert|nanodump)</field>
  <description>[T1003.001] LSASS memory dump command detected: $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1003</id>
    <id>T1003.001</id>
  </mitre>
  <group>credential_access,</group>
</rule>
```

---

## Indicatori (IOC)

| Tipo | Valore | Note |
|---|---|---|
| Processo | `C:\Windows\System32\rundll32.exe` (PID 5908) | LOLBin abusato |
| Parent | `C:\Windows\System32\cmd.exe` (PID 6100) | Lancio interattivo |
| Command line | `rundll32  comsvcs.dll minidump lsass` | Pattern di dump LSASS |
| User | `TARGET-WINDOWS\labuser` | Integrity level: High |
| SHA256 (rundll32) | `B53F3C0CD32D7F20849850768DA6431E5F876B7BFA61DB0AA0700B02873393FA` | Da Sysmon EID 1 |
| IMPHASH | `4DB27267734D1576D75C991DC70F68AC` | Per pivoting/threat intel |
| Timestamp evento | `2026-06-25 07:54:19Z` (Sysmon) → alert `00:54:22Z` (manager) | Vedi nota fuso orario sotto |
| Artefatto atteso | `*\lsass.dmp` in `%TEMP%`/`C:\Windows\Temp` | Assente nel test (sintassi ridotta) |

> **Nota fuso orario**: l'`utcTime` di Sysmon (07:54) e il `timestamp` del manager (00:54) differiscono
> perché la VM e il manager hanno fusi/clock diversi; in produzione va allineato l'orario (NTP) per
> evitare confusione nelle timeline di incidente.

---

## Remediation

1. **Credential Guard** (virtualization-based security): isola i segreti LSASS in un trustlet
   inaccessibile dalla memoria normale — la mitigazione più efficace.
2. **LSASS come Protected Process Light (PPL)**: imposta
   `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1`.
3. **Attack Surface Reduction (ASR)**: abilita la regola "Block credential stealing from the Windows
   local security authority subsystem (lsass.exe)".
4. **Monitoraggio Sysmon EID 10**: allerta sugli accessi a `lsass.exe` con `GrantedAccess` sospetto
   (regola `100025`).
5. **Least privilege**: il dump richiede privilegi elevati — riduci gli amministratori locali e usa
   account dedicati/JIT per le attività privilegiate.
6. **Risposta**: all'alert, **isola l'host** e forza il **reset delle credenziali** potenzialmente
   esposte (gli account loggati su quella macchina).

---

## Lezioni apprese

- Gli attacchi moderni sono **living-off-the-land**: `comsvcs.dll` e `rundll32` sono componenti
  **legittimi** di Windows — la detection deve basarsi sul **comportamento** (la combinazione
  binario + command line + target LSASS), non su una "firma del malware".
- **Difesa in profondità**: due regole indipendenti coprono la stessa tecnica via canali diversi
  (EID 1 command line + EID 10 memory access), così un metodo che evade l'una può essere preso dall'altra.
- Il pattern è **realmente flaggato** dalle difese: anche il Defender dell'host lo ha intercettato.

---

→ Playbook di riferimento: [T1003-001_lsass-dumping.md](../atomic-red-team/playbooks/T1003-001_lsass-dumping.md)
→ Report dei casi studio: [CASE-STUDIES.md](CASE-STUDIES.md)
