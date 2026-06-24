# DET-001 — SSH Brute Force

## Sommario

Rileva attacchi brute force verso il servizio SSH identificando più di 5 autenticazioni fallite dallo stesso indirizzo IP nell'arco di 60 secondi. È una delle tecniche di Credential Access più comuni, usata sia da scanner automatici (Shodan-driven bots) sia da attaccanti mirati. La detection è critica perché un brute force riuscito fornisce accesso shell diretto al sistema.

---

## MITRE ATT&CK

- **Tactic**: Credential Access
- **Technique**: [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- **Sub-technique**: [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

---

## Come è stato simulato

**VM**: `target-linux`  
**Tool**: `hydra` / loop manuale con `sshpass`  
**Playbook**: [T1110-001_ssh-brute-force.md](../atomic-red-team/playbooks/T1110-001_ssh-brute-force.md)

Comandi usati:

```bash
# 10 tentativi SSH con password errate verso localhost (utente inesistente)
for i in $(seq 1 10); do
  sshpass -p "wrongpass${i}" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 fakeuser@127.0.0.1 2>/dev/null
done
```

---

## Alert generato da Wazuh

```json
{
  "timestamp": "2026-06-24T11:58:40.097+0000",
  "rule": {
    "level": 10,
    "description": "sshd: brute force trying to get access to the system. Non existent user.",
    "id": "5712",
    "mitre": {
      "id": ["T1110"],
      "tactic": ["Credential Access"],
      "technique": ["Brute Force"]
    },
    "frequency": 8,
    "firedtimes": 1,
    "groups": ["syslog", "sshd", "authentication_failures"],
    "gdpr": ["IV_35.7.d", "IV_32.2"],
    "hipaa": ["164.312.b"],
    "nist_800_53": ["SI.4", "AU.14", "AC.7"],
    "pci_dss": ["11.4", "10.2.4", "10.2.5"]
  },
  "agent": {
    "id": "001",
    "name": "target-linux",
    "ip": "192.168.56.101"
  },
  "manager": { "name": "wazuh.manager" },
  "id": "1782302320.1384407",
  "full_log": "Jun 24 11:58:39 target-linux sshd[4830]: Failed password for invalid user fakeuser from 127.0.0.1 port 51938 ssh2",
  "previous_output": "Jun 24 11:58:37 target-linux sshd[4830]: Invalid user fakeuser from 127.0.0.1 port 51938\nJun 24 11:58:37 target-linux sshd[4826]: Failed password for invalid user fakeuser from 127.0.0.1 port 51922 ssh2\nJun 24 11:58:35 target-linux sshd[4826]: Invalid user fakeuser from 127.0.0.1 port 51922\nJun 24 11:58:35 target-linux sshd[4822]: Failed password for invalid user fakeuser from 127.0.0.1 port 51906 ssh2\nJun 24 11:58:33 target-linux sshd[4822]: Invalid user fakeuser from 127.0.0.1 port 51906\nJun 24 11:58:32 target-linux sshd[4818]: Failed password for invalid user fakeuser from 127.0.0.1 port 51898 ssh2",
  "predecoder": { "program_name": "sshd", "timestamp": "Jun 24 11:58:39", "hostname": "target-linux" },
  "decoder": { "parent": "sshd", "name": "sshd" },
  "data": { "srcip": "127.0.0.1", "srcuser": "fakeuser" },
  "location": "journald"
}
```

> Nota: la regola built-in `5712` (Wazuh) ha sparato per prima con frequenza 8 in ~10 s. La regola custom `100001` estende questa detection con soglia personalizzata e tag MITRE T1110.001.

---

## Analisi e triage

- **Sorgente**: `127.0.0.1` (loopback — in un attacco reale sarebbe l'IP esterno dell'attaccante)
- **Utente bersaglio**: `fakeuser` (utente inesistente — pattern tipico di scanner automatici)
- **Frequenza**: 8 failure in ~10 secondi — soglia brute force raggiunta
- **Esito**: nessun accesso riuscito (`Accepted` non presente nei log)
- **MITRE**: T1110 Credential Access → Brute Force

Domande guida per il triage:
- L'IP sorgente è noto? È nella lista degli admin autorizzati?
- Quanti tentativi in totale? Su quanti username diversi?
- Il brute force ha avuto successo? (cercare Event ID 5715 / rule 5715 subito dopo)
- L'IP sorgente ha fatto altri tentativi su altre porte o servizi?

---

## Regola Wazuh utilizzata

**File**: `wazuh/rules/custom_ssh.xml`  
**Rule ID**: `100001`  
**Logica**: `frequency=5`, `timeframe=60`, `<if_matched_sid>5760</if_matched_sid>`, `<same_source_ip />`

```xml
<rule id="100001" level="10" frequency="5" timeframe="60">
  <if_matched_sid>5760</if_matched_sid>
  <same_source_ip />
  <description>SSH Brute Force: 5+ authentication failures from $(srcip) in 60 seconds</description>
  <mitre>
    <id>T1110</id>
    <id>T1110.001</id>
  </mitre>
</rule>
```

---

## Indicatori (IOC)

| Tipo | Valore | Note |
|---|---|---|
| Source IP | `127.0.0.1` | Loopback (lab); in produzione = IP attaccante |
| Username target | `fakeuser` | Utente inesistente — scanner automatico |
| Timestamp prima failure | `2026-06-24T11:58:31+0000` | |
| Timestamp ultima failure | `2026-06-24T11:58:39+0000` | |
| N° tentativi totali | 8 in ~10 secondi | Frequenza molto alta |
| Successo? | `False` | Nessun `Accepted` nei log |

---

## Remediation

1. **Blocca l'IP sorgente** immediatamente con `ufw deny from <srcip>` o aggiornando le regole firewall
2. **Verifica se il brute force ha avuto successo**: controlla gli ultimi login riusciti con `last -n 20` e `grep "Accepted" /var/log/auth.log`
3. **Abilita fail2ban** per bannare automaticamente gli IP dopo N failure: `sudo apt install fail2ban`
4. **Disabilita login SSH con password** e usa solo chiavi SSH:
   ```bash
   # /etc/ssh/sshd_config
   PasswordAuthentication no
   PubkeyAuthentication yes
   ```
5. **Sposta SSH su porta non standard** (security through obscurity, riduce il rumore):
   ```bash
   # /etc/ssh/sshd_config
   Port 2222
   ```
6. **Abilita MFA per SSH** con Google Authenticator o simili per account privilegiati
