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
# Test 1 — Encoded Command
$cmd = 'Write-Host "Atomic Red Team Test T1059.001"'
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded

# Test 2 — Execution Policy Bypass + IEX
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "IEX 'Write-Host test'"
```

---

## Alert generato da Wazuh

```json
[inserire dal lab]
```

> Campi attesi: `rule.id: 100021`, `rule.level: 12`, `data.win.eventdata.image`, `data.win.eventdata.commandLine`, `rule.mitre.technique: ["T1059.001", "T1027"]`

---

## Analisi e triage

[inserire dal lab]

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
| Parent process | `[inserire dal lab]` | Se Office app → TP quasi certo |
| Command line | `[inserire dal lab]` | Flag specifici rilevati |
| Hash processo | `[inserire dal lab]` | SHA256 da Sysmon |
| User | `[inserire dal lab]` | Account che ha lanciato il processo |
| Timestamp | `[inserire dal lab]` | |
| Network conn post-exec | `[inserire dal lab]` | IP/porta se presente (Sysmon EID 3) |

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
