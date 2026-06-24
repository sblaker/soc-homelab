# DET-002 — PowerShell Sospetto

## Sommario

Rileva l'esecuzione di PowerShell con flag tipici di utilizzo offensivo: `-EncodedCommand` (offuscamento del payload), `-WindowStyle Hidden` (evasione visiva), `-ExecutionPolicy Bypass` (bypass delle policy di sicurezza), `IEX`/`Invoke-Expression` (esecuzione di codice dinamico), `DownloadString` (download in-memory). Questi pattern sono caratteristici di dropper, C2 implant, e script di post-exploitation. La detection si basa su Sysmon Event ID 1 (Process Create) che cattura il command line completo.

---

## MITRE ATT&CK

- **Tactic**: Execution
- **Technique**: [T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- **Sub-technique**: [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- **Technique correlata**: [T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) (quando usato `-EncodedCommand`)

---

## Come è stato simulato

**VM**: `target-windows`  
**Tool**: PowerShell nativo (nessun tool esterno necessario)  
**Playbook**: [T1059-001_powershell-suspicious.md](../atomic-red-team/playbooks/T1059-001_powershell-suspicious.md)

Comandi usati:

```powershell
# EncodedCommand + NoProfile + Hidden + Bypass (pattern offensivo completo)
$encoded = [Convert]::ToBase64String(
    [System.Text.Encoding]::Unicode.GetBytes("Write-Host 'Atomic Red Team T1059.001 test'")
)
Start-Process powershell.exe -ArgumentList "-NoP -NonI -W Hidden -Exec Bypass -EncodedCommand $encoded" -Wait
```

---

## Alert generato da Wazuh

```json
{
  "timestamp": "2026-06-24T12:07:29.560+0000",
  "rule": {
    "level": 12,
    "description": "Powershell.exe spawned a powershell process which executed a base64 encoded command",
    "id": "92057",
    "mitre": {
      "id": ["T1059.001"],
      "tactic": ["Execution"],
      "technique": ["PowerShell"]
    },
    "firedtimes": 1,
    "mail": true,
    "groups": ["sysmon", "sysmon_eid1_detections", "windows"]
  },
  "agent": {
    "id": "002",
    "name": "target-windows",
    "ip": "127.0.0.1"
  },
  "manager": { "name": "wazuh.manager" },
  "id": "1782302849.3161471",
  "decoder": { "name": "windows_eventchannel" },
  "data": {
    "win": {
      "system": {
        "providerName": "Microsoft-Windows-Sysmon",
        "eventID": "1",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "Matebook"
      },
      "eventdata": {
        "utcTime": "2026-06-24 12:07:28.149",
        "processId": "30836",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "commandLine": "\"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAQQB0AG8AbQBpAGMAIABSAGUAZAAgAFQAZQBhAG0AIABUADEAMAA1ADkALgAwADAAMQAgAHQAZQBzAHQAJwA=",
        "user": "Matebook\\antol",
        "integrityLevel": "Medium",
        "hashes": "MD5=A97E6573B97B44C96122BFA543A82EA1,SHA256=0FF6F2C94BC7E2833A5F7E16DE1622E5DBA70396F31C7D5F56381870317E8C46",
        "parentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
      }
    }
  },
  "location": "EventChannel"
}
```

> Payload Base64 decodificato: `Write-Host 'Atomic Red Team T1059.001 test'` — in un attacco reale conterrebbe shellcode, download o esecuzione di stager C2.

---

## Analisi e triage

- **Process**: `powershell.exe` (PID 30836)
- **Flag rilevati**: `-NoP` `-NonI` `-W Hidden` `-Exec Bypass` `-EncodedCommand` — combinazione ad alto rischio
- **Parent process**: `powershell.exe` — in un attacco reale spesso è `winword.exe`, `excel.exe`, `mshta.exe`
- **User**: `Matebook\antol` — account standard (non SYSTEM)
- **Payload decodificato**: benigno nel test, ma la struttura è identica a un dropper reale
- **Network post-exec**: nessuna connessione uscente rilevata (payload inerte)

Domande guida per il triage:
- Qual è il parent process? (campo `data.win.eventdata.parentImage`)
  - Se è `winword.exe` o `excel.exe` → altissima probabilità di True Positive (macro malevola)
  - Se è `explorer.exe` o `powershell_ise.exe` → potrebbe essere attività admin legittima
- Il command line contiene un payload decodificabile? Decodifica il Base64:
  ```powershell
  [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("<base64_qui>"))
  ```
- C'è una connessione di rete successiva? (Sysmon Event ID 3 subito dopo il processo)
- L'utente che ha lanciato il processo è previsto per quell'orario?

---

## Regola Wazuh utilizzata

**File**: `wazuh/rules/custom_windows.xml`  
**Rule ID**: `100021`  
**Logica**: Sysmon Event ID 1, image = `powershell.exe`, commandLine contiene pattern offensivi (regex PCREv2)

```xml
<rule id="100021" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">
    (?i)(-enc|-encodedcommand|-nop|-noprofile|-windowstyle\s+hidden|-exec\s+bypass|iex|invoke-expression|downloadstring|webclient)
  </field>
  <description>PowerShell execution with suspicious arguments: $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1059.001</id>
    <id>T1027</id>
  </mitre>
</rule>
```

---

## Indicatori (IOC)

| Tipo | Valore | Note |
|---|---|---|
| Process | `powershell.exe` | |
| Parent process | `powershell.exe` | In attacco reale: `winword.exe`/`excel.exe` = TP |
| Command line | `-NoP -NonI -W Hidden -Exec Bypass -EncodedCommand` | 5 flag offensivi simultanei |
| Hash processo | `SHA256=0FF6F2C94BC7E2833A5F7E16DE1622E5DBA70396F31C7D5F56381870317E8C46` | Da Sysmon EID 1 |
| User | `Matebook\antol` | Account standard — non SYSTEM |
| Timestamp | `2026-06-24T12:07:28.149Z` | |
| Network conn post-exec | Nessuna | Payload inerte (lab test) |

---

## Remediation

1. **Isola il sistema** se il parent process era un'applicazione Office o il payload decodificato è malevolo
2. **Decodifica e analizza il payload** Base64 prima di procedere:
   ```powershell
   [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("<base64>"))
   ```
3. **Abilita PowerShell Constrained Language Mode** per limitare le funzionalità disponibili agli script:
   ```powershell
   # Imposta via Group Policy o direttamente
   [Environment]::SetEnvironmentVariable("__PSLockdownPolicy", "4", "Machine")
   ```
4. **Abilita PowerShell Script Block Logging** per catturare il codice deoffuscato a runtime:
   ```
   HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
   EnableScriptBlockLogging = 1
   ```
5. **Configura AMSI** (Antimalware Scan Interface) — Windows 10+ lo include, verifica che non sia disabilitato
6. **Rivedi le Execution Policy** aziendali: `AllSigned` o `RemoteSigned` riduce la superficie d'attacco
7. **Applica Application Control** (AppLocker / WDAC) per bloccare l'esecuzione di script PowerShell non firmati
