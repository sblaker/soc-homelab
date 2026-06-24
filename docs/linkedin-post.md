# Post LinkedIn — SOC Home Lab

---

Ho completato il mio **SOC Home Lab** e lo sto pubblicando come progetto portfolio Blue Team 🛡️

**Stack:**
- **Wazuh 4.9** (SIEM/XDR) su Docker Compose
- **Ubuntu Server 22.04** + **Windows 11** come endpoint monitorati
- **Sysmon v15.21** con config SwiftOnSecurity per telemetria avanzata
- Regole custom MITRE ATT&CK-mapped (IDs 100001–100096)

**Simulazioni eseguite con Atomic Red Team:**

🔴 **T1110.001 — SSH Brute Force**: 8 tentativi in 10 secondi → alert reale catturato (rule 5712, level 10)

🔴 **T1059.001 — PowerShell offensivo**: `-EncodedCommand -W Hidden -Exec Bypass` → alert Sysmon EID 1 catturato (rule 92057, level 12)

Ogni detection ha un write-up completo con JSON dell'alert, analisi IOC, triage guidato e remediation.

Obiettivo: dimostrare skill operative da **SOC Analyst L1** — detection engineering, alert triage e documentazione incidenti.

🔗 GitHub: https://github.com/sblaker/soc-homelab

#BlueTeam #SOC #Wazuh #SIEM #MITRE #CyberSecurity #DetectionEngineering #Sysmon #HomeLab #Portfolio
