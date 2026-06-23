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
# Generazione wordlist di password errate
cat > /tmp/passwords.txt << 'EOF'
password123
admin
123456
letmein
qwerty
root
toor
Password1
EOF

# Brute force SSH verso localhost
hydra -l labuser -P /tmp/passwords.txt ssh://127.0.0.1 -t 4 -V
```

---

## Alert generato da Wazuh

```json
[inserire dal lab]
```

> Campi attesi: `rule.id: 100001`, `rule.level: 10`, `data.srcip`, `rule.mitre.technique: ["T1110", "T1110.001"]`

---

## Analisi e triage

[inserire dal lab]

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
| Source IP | `[inserire dal lab]` | IP da cui proviene il brute force |
| Username target | `labuser`, `root` | Utenti più tentati |
| Timestamp prima failure | `[inserire dal lab]` | |
| Timestamp ultima failure | `[inserire dal lab]` | |
| N° tentativi totali | `[inserire dal lab]` | |
| Successo? | `[inserire dal lab]` | True/False |

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
