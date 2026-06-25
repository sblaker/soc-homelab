# DET-004 — Registry Run Key Persistence

## Sommario

Rileva la **scrittura di chiavi Run/RunOnce nel registro di Windows** per ottenere persistenza: ogni
valore aggiunto a `HKCU\...\CurrentVersion\Run` o `HKLM\...\CurrentVersion\Run` viene eseguito
automaticamente al prossimo logon dell'utente (o di qualsiasi utente per HKLM). È una delle tecniche
di persistenza più antiche e ancora ampiamente usata da malware, RAT e strumenti di post-exploitation.

Detection **validata dal vivo** su `target-windows` (VM Windows 10 Pro, agent 002): rilevata da
**Sysmon Event ID 13** (Registry Value Set), regola custom **`100022` (level 12)**.

> **Nota fix**: la regola 100022 era presente ma non scattava a causa di un problema di matching sul
> gruppo Wazuh (backslash doppi nel campo `targetObject`). Fixata agganciandola alla parent built-in
> `92300` con `<if_sid>92300</if_sid>` — validata il 2026-06-25.

---

## MITRE ATT&CK

- **Tactic**: Persistence · Privilege Escalation
- **Technique**: [T1547 — Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
- **Sub-technique**: [T1547.001 — Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

---

## Come è stato simulato

**VM**: `target-windows` (`192.168.56.103`)
**Privilegi**: utente standard (HKCU non richiede admin)
**Playbook**: [T1547-001_registry-run-key.md](../atomic-red-team/playbooks/T1547-001_registry-run-key.md)

Comando eseguito (da `cmd.exe`):

```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "LabPersistence" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
```

> In un attacco reale al posto di `calc.exe` ci sarebbe il percorso di un backdoor, stager C2
> (`beacon.exe`, `implant.ps1`), o un loader offuscato. La chiave `HKCU` non richiede admin e viene
> eseguita al login dell'utente corrente — sufficiente per mantenere la persistenza dopo un reboot.
> La variante `HKLM` persiste per tutti gli utenti ma richiede elevazione.

**Cleanup** (da eseguire dopo il test):
```cmd
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "LabPersistence" /f
```

---

## Alert generato da Wazuh

```json
{
  "timestamp": "2026-06-25T12:43:25.634+0000",
  "rule": {
    "id": "100022",
    "level": 12,
    "description": "[T1547.001] Registry Run key persistence: HKU\\S-1-5-21-220708368-3173257815-628008255-1000\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\LabPersistence set by C:\\Windows\\system32\\reg.exe",
    "mitre": {
      "id": ["T1547", "T1547.001"],
      "tactic": ["Persistence", "Privilege Escalation"],
      "technique": ["Boot or Logon Autostart Execution", "Registry Run Keys / Startup Folder"]
    },
    "groups": ["custom_windows", "sysmon", "persistence"],
    "firedtimes": 1
  },
  "agent": { "id": "002", "name": "target-windows", "ip": "192.168.56.103" },
  "manager": { "name": "wazuh.manager" },
  "decoder": { "name": "windows_eventchannel" },
  "data": {
    "win": {
      "system": {
        "eventID": "13",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "target-windows",
        "eventRecordID": "6528"
      },
      "eventdata": {
        "ruleName": "T1060,RunKey",
        "eventType": "SetValue",
        "image": "C:\\Windows\\system32\\reg.exe",
        "targetObject": "HKU\\S-1-5-21-220708368-3173257815-628008255-1000\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\LabPersistence",
        "details": "C:\\Windows\\System32\\calc.exe",
        "user": "TARGET-WINDOWS\\labuser",
        "utcTime": "2026-06-25 12:42:45.478",
        "processId": "2340"
      }
    }
  }
}
```

> **Nota**: Sysmon tagga automaticamente questo evento con `RuleName: T1060,RunKey` grazie alla config
> SwiftOnSecurity — un ulteriore layer di detection prima ancora delle nostre regole custom.

---

## Analisi e triage

Sysmon EID 13 registra ogni **scrittura di un valore nel registro**. In questo caso `reg.exe` ha
scritto `LabPersistence = C:\Windows\System32\calc.exe` nella chiave Run dell'utente `labuser`.

| Campo | Valore | Perché è rilevante |
|---|---|---|
| `eventID` | `13` (Registry Value Set) | Sysmon rileva la scrittura nel momento in cui avviene |
| `image` | `reg.exe` | Tool nativo — LOLBin. In attacchi avanzati: PowerShell, script, dropper |
| `targetObject` | `HKU\...\Run\LabPersistence` | Percorso completo con nome del valore — identifica la chiave esatta |
| `details` | `C:\Windows\System32\calc.exe` | Il valore scritto — in reale: path del malware |
| `ruleName` | `T1060,RunKey` | Tag automatico Sysmon (SwiftOnSecurity config) |
| `user` | `TARGET-WINDOWS\labuser` | HKCU → persiste solo per questo utente |

**Domande guida per il triage**:
- Il valore punta a un **eseguibile noto e firmato** o a un path insolito (`%APPDATA%`, `%TEMP%`, path con nomi casuali)?
- L'`image` è `reg.exe` o un **processo anomalo** (Word, browser, script)?
- C'è correlazione con una **creazione di file** (EID 11) o un **processo create** (EID 1) nelle secondi precedenti?
- La chiave è `HKCU` (un solo utente) o `HKLM` (tutti) → indica il livello di privilegio dell'attaccante.

**HKCU vs HKLM nel triage**:
- `HKCU` → nessun admin necessario, eseguito solo al login dell'utente coinvolto
- `HKLM` → admin necessario, eseguito per tutti gli utenti → impatto maggiore, più indicativo di accesso privilegiato

**Verdetto**: **True Positive** (test). La scrittura in `...\Run\` da parte di un processo non-admin
su HKCU è un segnale di persistenza ad alta confidenza se il valore non corrisponde a software legittimo.

### True Positive vs False Positive

| Indicatore | True Positive | False Positive |
|---|---|---|
| Path del valore | `%TEMP%`, `%APPDATA%`, path con nomi casuali | Percorso di applicazione nota e firmata |
| `image` che scrive | `reg.exe` da processo anomalo, dropper, script | Installer legittimo, software di configurazione |
| Nome del valore | Stringa casuale, nome generico (`update`, `helper`) | Nome software riconoscibile |
| Orario | Fuori orario, durante un incidente attivo | Durante un'installazione attesa |

---

## Regola Wazuh utilizzata

**File**: `wazuh/rules/custom_windows.xml` · **Rule ID**: `100022` · **Level**: 12 (High)

```xml
<rule id="100022" level="12">
  <if_sid>92300</if_sid>
  <description>[T1547.001] Registry Run key persistence: $(win.eventdata.targetObject) set by $(win.eventdata.image)</description>
  <mitre>
    <id>T1547</id>
    <id>T1547.001</id>
  </mitre>
  <group>persistence,</group>
</rule>
```

**Catena di regole**:
```
sysmon_event_13 (EID 13)
  └─ 92300 (level 0) — parent: targetObject contiene \CurrentVersion\Run
        ├─ 92302 (level 6, built-in) — image è reg.exe
        └─ 100022 (level 12, custom) — aggiunge MITRE T1547 + level elevato
```

> La regola non riduplica il match sul `targetObject` (già fatto dalla 92300) — si aggancia come
> figlio per elevare la severity e aggiungere i tag MITRE mancanti nella built-in.

---

## Indicatori (IOC)

| Tipo | Valore | Note |
|---|---|---|
| Chiave | `HKU\S-1-5-21-...\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\LabPersistence` | HKCU labuser |
| Valore | `C:\Windows\System32\calc.exe` | Payload benigno (test) |
| Processo | `reg.exe` (PID 2340) | Tool nativo usato per la scrittura |
| EID Sysmon | 13 (Registry Value Set) | Trigger della detection |
| Timestamp | `2026-06-25 12:42:45Z` (Sysmon) | |
| User | `TARGET-WINDOWS\labuser` | Account che ha scritto la chiave |

---

## Remediation

1. **Elimina la chiave**: `reg delete "HKCU\...\Run" /v "LabPersistence" /f`
2. **Monitora le Run keys** con Autoruns (Sysinternals) — mostra tutto ciò che parte al login.
3. **AppLocker / WDAC**: impedisce l'esecuzione di binari non firmati anche se aggiunti alla Run key.
4. **Least privilege**: ridurre gli admin locali non elimina HKCU (basta utente standard), ma limita HKLM.
5. **Audit delle Run keys** nei processi di incident response: sempre controllare `HKCU\...\Run` e `HKLM\...\Run` su host compromessi.

---

## Lezioni apprese

- **Sysmon EID 13 è potente**: cattura la modifica del registro nel momento esatto in cui avviene,
  con processo responsabile, valore scritto e utente — informazioni complete per il triage.
- **LOLBin**: `reg.exe` è un tool Microsoft firmato — la detection non si basa sul binario malevolo
  ma sul *comportamento* (scrivere in una Run key).
- **Bug fix documentato**: la regola era scritta correttamente ma non scattava per un problema di
  gruppo/regex. Il fix (`<if_sid>92300</if_sid>`) è un esempio reale di debug di regole Wazuh.

---

→ Playbook: [T1547-001_registry-run-key.md](../atomic-red-team/playbooks/T1547-001_registry-run-key.md) · Report: [CASE-STUDIES.md](CASE-STUDIES.md)
