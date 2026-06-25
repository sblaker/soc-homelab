# Detection Coverage Index

Ogni detection è documentata con: simulazione dell'attacco, alert catturato dal lab, analisi triage, regola Wazuh usata, IOC e remediation.

> 📑 **Report dei casi studio**: [CASE-STUDIES.md](CASE-STUDIES.md) — report in stile SOC che
> raccoglie 6 casi studio (brute force, PowerShell, LSASS/Mimikatz, ransomware, persistenza, kill
> chain) con contesto della minaccia, logica di detection, triage e remediation.

---

## Indice

| ID | Nome | Tecnica MITRE | Tactic | Severity | Stato |
|---|---|---|---|---|---|
| [DET-001](DET-001_ssh-brute-force.md) | SSH Brute Force | T1110.001 | Credential Access | High | ✅ |
| [DET-002](DET-002_powershell-suspicious.md) | PowerShell Sospetto (host) | T1059.001 | Execution | High | ✅ |
| DET-003 | Scheduled Task Persistence | T1053.005 | Persistence | High | 🔄 |
| DET-004 | Registry Run Key Persistence | T1547.001 | Persistence | High | 🔄 |
| DET-005 | SMB / PsExec Lateral Movement | T1021.002 | Lateral Movement | High | 🔄 |
| [DET-006](DET-006_lsass-dumping.md) | LSASS Credential Dumping | T1003.001 | Credential Access | Critical | ✅ |
| [DET-007](DET-007_ransomware-shadow-deletion.md) | Ransomware: Shadow Copy Deletion | T1490 | Impact | Critical | ✅ |
| [DET-008](DET-008_powershell-offensive-flags.md) | PowerShell Offensive Flags (VM) | T1059.001 | Execution | High | ✅ |
| [DET-009](DET-009_mimikatz-keywords.md) | Mimikatz Keywords | T1003.001 | Credential Access | Critical | ✅ |
| DET-010 | Office → Child Process Spawn | T1566.001 | Initial Access | Critical | 🔄 |

> **DET validati dal vivo sulla VM** (`target-windows`, agent 002): DET-006, 007, 008, 009 — con JSON
> reale dell'alert. Vedi [CASE-STUDIES.md](CASE-STUDIES.md) per il quadro d'insieme.

**Legenda**: ✅ Completato · 🔄 In corso · ⬜ Non iniziato

---

## Template

Per aggiungere una nuova detection, copia il template qui sotto e salvalo come `DET-XXX_nome-detection.md`.

```markdown
# DET-XXX — [Nome Detection]

## Sommario
Cosa rileva e perché è rilevante dal punto di vista difensivo.

## MITRE ATT&CK
- Tactic: ...
- Technique: T....
- Sub-technique: ...

## Come è stato simulato
Comandi usati, VM coinvolte, tool (Atomic Red Team / manuale).
Link al playbook: [atomic-red-team/playbooks/TXXX-XXX_nome.md](../atomic-red-team/playbooks/)

## Alert generato da Wazuh
[inserire JSON alert catturato dal lab]

## Analisi e triage
Cosa ho osservato, come ho confermato true positive vs false positive.

## Regola Wazuh utilizzata
File e rule ID.

## Indicatori (IOC)
IP, processi, chiavi di registro, path rilevanti.

## Remediation
Azioni consigliate per mitigare la tecnica rilevata.
```
