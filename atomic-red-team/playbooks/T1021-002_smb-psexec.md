# Playbook — T1021.002: SMB / PsExec Lateral Movement

## Metadati

| Campo | Valore |
|---|---|
| MITRE Technique | [T1021.002 — Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/) |
| Tactic | Lateral Movement |
| Platform | Windows |
| VM attaccante | `target-windows` (o host con PsExec) |
| VM bersaglio | `target-windows` (self) o secondo host Windows |
| Prerequisiti | Credenziali valide, SMB accessibile, Sysmon + Wazuh Agent |
| Detection rule | `custom_mitre_mapped.xml` — Rule ID 100091 (adattare) |
| Severity attesa | Medium-High (level 8-10) |

---

> **Nota**: questo playbook è opzionale e più complesso da replicare in un lab single-VM. La detection di PsExec richiede o due VM Windows o un test in loopback. Se hai solo `target-windows`, usa la modalità loopback descritta nel Test 1.

---

## Obiettivo

Simulare lateral movement via SMB/PsExec — tecnica usata da ransomware (Ryuk, LockBit) e APT per spostarsi lateralmente nella rete dopo aver ottenuto credenziali. Verifica che Wazuh rilevi la creazione del servizio remoto e il login di rete.

---

## Prerequisiti

```powershell
# Verifica che SMB sia accessibile
Get-SmbServerConfiguration | Select-Object EnableSMB2Protocol

# Verifica condivisioni admin disponibili
net share

# Scarica PsExec (Sysinternals)
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/PSTools.zip" -OutFile "$env:TEMP\PSTools.zip"
Expand-Archive "$env:TEMP\PSTools.zip" -DestinationPath "$env:TEMP\PSTools" -Force
```

---

## Simulazione

### Test 1 — PsExec in loopback (singola VM)

```powershell
# Esegui un comando benigno su localhost via PsExec (simula lateral movement)
# Richiede credenziali dell'utente corrente
$psexec = "$env:TEMP\PSTools\PsExec64.exe"

& $psexec \\127.0.0.1 -u $env:USERNAME -p "tuapassword" -accepteula cmd /c "whoami > C:\Temp\psexec_test.txt"
```

> Sostituisci `"tuapassword"` con la password dell'utente locale della VM.

### Test 2 — PsExec verso secondo host Windows

> Richiede una seconda VM Windows sulla stessa rete host-only.

```powershell
$psexec = "$env:TEMP\PSTools\PsExec64.exe"
$targetIP = "192.168.56.102"   # IP di target-windows-2 se disponibile

& $psexec \\$targetIP -u "Administrator" -p "password" -accepteula `
  powershell.exe -NoProfile -Command "Write-Host 'Lateral movement test'"
```

### Test 3 — Impacket psexec.py (da target-linux)

```bash
# Installa Impacket su target-linux
pip3 install impacket

# PsExec via Python verso target-windows
python3 /usr/local/bin/psexec.py labuser:password@192.168.56.102 cmd.exe
```

### Test 4 — Atomic Red Team

```powershell
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T1021.002 -TestNumbers 1
```

---

## Alert atteso su Wazuh

### Da Windows Event Log (Security)

**Event ID 4624** (Logon) con Logon Type 3 (Network):
```
rule.id: 60106
agent.name: target-windows
data.win.eventdata.logonType: "3"
data.win.eventdata.logonProcessName: "NtLmSsp" o "Kerberos"
data.win.eventdata.ipAddress: <IP attaccante>
```

**Event ID 7045** (New Service Installed) — PsExec installa un servizio temporaneo:
```
data.win.eventdata.serviceName: "PSEXESVC"
data.win.eventdata.serviceFileName: "%SystemRoot%\PSEXESVC.exe"
```

### Da Sysmon

**Event ID 3** (Network Connection) su SMB (porta 445):
```
data.win.eventdata.destinationPort: "445"
data.win.eventdata.image: "System"
```

---

## Come verificare la detection

### 1. Dalla Dashboard Wazuh

```
agent.name: "target-windows" AND data.win.eventdata.logonType: "3"
```

```
data.win.eventdata.serviceName: "PSEXESVC"
```

```
rule.mitre.technique: T1021.002
```

### 2. Event Viewer su target-windows (bersaglio)

- **Security Log** → Event ID 4624 (Logon Type 3) e 4648 (Explicit credential logon)
- **System Log** → Event ID 7045 (new service: PSEXESVC)

---

## Verifica True Positive vs False Positive

| Indicatore | True Positive | False Positive |
|---|---|---|
| Servizio PSEXESVC | Quasi sempre malevolo in prod | Legittimo se tool admin documentato |
| Logon Type 3 da IP esterno | Sospetto fuori orario | Admin remoto documentato |
| Connessione SMB porta 445 | Da workstation → server non noto | File server condivisi (noti) |
| Account usato | Account di servizio / admin generico | Account nominativo documentato |

---

## Cleanup

```powershell
# Rimuovi file di test
Remove-Item "C:\Temp\psexec_test.txt" -ErrorAction SilentlyContinue

# Il servizio PSEXESVC viene rimosso automaticamente da PsExec al termine
# Verifica che non rimanga
Get-Service PSEXESVC -ErrorAction SilentlyContinue

# Rimuovi PsTools se non più necessari
Remove-Item "$env:TEMP\PSTools" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\PSTools.zip" -ErrorAction SilentlyContinue
```

---

## Regola custom suggerita (da aggiungere a custom_windows.xml)

Se vuoi una detection dedicata per PSEXESVC:

```xml
<!-- T1021.002 — PsExec service installation -->
<rule id="100029" level="14">
  <if_sid>7</if_sid>
  <field name="win.system.eventID">^7045$</field>
  <field name="win.eventdata.serviceName" type="pcre2">(?i)PSEXESVC</field>
  <description>[T1021.002] PsExec service (PSEXESVC) installed - possible lateral movement</description>
  <mitre>
    <id>T1021</id>
    <id>T1021.002</id>
  </mitre>
  <group>lateral_movement,</group>
</rule>
```

---

## Note operative

- In un lab single-VM, il Test 1 (loopback) genera gli event ID corretti ma potrebbe non replicare tutti i comportamenti di rete
- PsExec apre una connessione SMB su porta 445 — assicurati che il firewall di Windows nella VM non la blocchi
- Impacket è un'alternativa open source più stealth (non installa PSEXESVC)
- Event ID 7045 è uno degli IoC più affidabili per PsExec — cerca sempre questo prima nelle investigazioni
