# Playbook — T1110.001: SSH Brute Force

## Metadati

| Campo | Valore |
|---|---|
| MITRE Technique | [T1110.001 — Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |
| Tactic | Credential Access |
| Platform | Linux |
| VM attaccante | `target-linux` |
| VM bersaglio | `target-linux` (self) o secondo host SSH raggiungibile |
| Detection rule | `custom_ssh.xml` — Rule ID 100001, 100006 |
| Severity attesa | High (level 10) |

---

## Obiettivo

Simulare un attacco brute force via SSH con tool reali per verificare che le regole custom 100001 e 100006 generino alert su Wazuh entro il timeframe configurato (5 failure in 60 secondi).

---

## Prerequisiti

- `target-linux` accesa e agente Wazuh attivo (`systemctl status wazuh-agent`)
- SSH server attivo sulla VM bersaglio (`systemctl status ssh`)
- Tool `hydra` installato sulla VM attaccante (o `medusa` come alternativa)
- Wazuh Dashboard accessibile su `https://localhost` dal host

```bash
# Installa hydra su target-linux (VM attaccante)
sudo apt install -y hydra

# Verifica che SSH sia in ascolto sulla VM bersaglio
ss -tlnp | grep :22
```

---

## Simulazione

### Opzione A — Hydra (brute force con wordlist)

```bash
# Crea una wordlist di password errate (simulate)
cat > /tmp/passwords.txt << 'EOF'
password123
admin
123456
letmein
qwerty
root
toor
Password1
P@ssw0rd
welcome
EOF

# Lancia il brute force SSH verso localhost (o IP del bersaglio)
# -l: username target | -P: wordlist | -t: thread paralleli | -V: verbose
hydra -l labuser -P /tmp/passwords.txt ssh://127.0.0.1 -t 4 -V
```

> Sostituisci `127.0.0.1` con l'IP di un'altra VM se vuoi simulare attacco cross-host.

### Opzione B — Loop manuale con ssh (senza tool aggiuntivi)

```bash
# 6 tentativi falliti in rapida successione — sufficiente a triggerare rule 100001
for i in {1..6}; do
  sshpass -p "wrongpassword${i}" ssh -o StrictHostKeyChecking=no \
    -o ConnectTimeout=3 labuser@127.0.0.1 2>/dev/null
  echo "Attempt $i done"
done
```

```bash
# Installa sshpass se non presente
sudo apt install -y sshpass
```

### Opzione C — Atomic Red Team (se installato)

```powershell
# Da target-windows con Atomic Red Team installato
Invoke-AtomicTest T1110.001 -TestNumbers 1
```

---

## Alert atteso su Wazuh

Dopo 5+ failure dallo stesso IP in 60 secondi, la rule 100001 dovrebbe generare un alert con:

```
rule.id: 100001
rule.level: 10
rule.description: "SSH Brute Force: 5+ authentication failures from <srcip> in 60 seconds"
rule.mitre.technique: ["T1110", "T1110.001"]
agent.name: target-linux
data.srcip: 127.0.0.1
```

---

## Come verificare la detection

### 1. Dalla Dashboard Wazuh

Vai su **Security Events** e filtra:

```
rule.id: 100001 AND agent.name: "target-linux"
```

oppure cerca per MITRE:

```
rule.mitre.technique: T1110.001
```

### 2. Dai log del Manager (dal host)

```powershell
docker compose logs wazuh.manager | Select-String "100001"
```

### 3. Dal log dell'agente (dentro target-linux)

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.log | grep -A5 "100001"
```

---

## Verifica True Positive vs False Positive

| Indicatore | True Positive | False Positive |
|---|---|---|
| Frequenza | >5 failure in <60s | Singolo errore di digitazione |
| Source IP | IP esterno / non noto | IP interno noto (admin) |
| Username | Usernames casuali / enum | Username esistente e noto |
| Orario | Fuori orario lavorativo | Orario normale di lavoro |

---

## Cleanup

```bash
# Rimuovi file temporanei
rm -f /tmp/passwords.txt

# Verifica che non rimangano processi hydra in background
pkill hydra 2>/dev/null
```

---

## Note operative

- La rule 100001 si basa su `<if_matched_sid>5760</if_matched_sid>` — verifica che il decoder SSH di Wazuh stia parsando correttamente i log di `/var/log/auth.log`
- Se gli alert non arrivano, controlla: `sudo tail -f /var/log/auth.log` per vedere se i failure vengono loggati
- L'agente deve avere `/var/log/auth.log` nella propria configurazione `<localfile>`

---

## Write-up di riferimento

→ [detections/DET-001_ssh-brute-force.md](../../detections/DET-001_ssh-brute-force.md)
