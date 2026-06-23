# Enrollment Agenti Wazuh

> **Prerequisito**: Wazuh stack attivo su Docker (vedi [docker-setup.md](docker-setup.md)) e VM raggiungibili sul host (vedi [vm-setup.md](vm-setup.md)).

Il Manager è raggiungibile dall'interno delle VM all'IP `192.168.56.1` (IP del host sulla rete host-only).

---

## Agente su `target-linux`

### 1. Download e installazione

Accedi alla VM (via console VirtualBox o SSH da host: `ssh labuser@192.168.56.10x`).

```bash
# Aggiunge il repository Wazuh
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt update

# Installa l'agente puntando al Manager (IP host)
sudo WAZUH_MANAGER='192.168.56.1' apt install wazuh-agent -y
```

### 2. Avvio e abilitazione

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

# Verifica stato
sudo systemctl status wazuh-agent
```

### 3. Verifica enrollment

Sul host, controlla i log del Manager:

```powershell
docker compose logs -f wazuh.manager | Select-String "agent"
```

Oppure accedi alla Dashboard: **Agents → Active agents** — `target-linux` deve comparire in stato verde.

### 4. File di configurazione agente

```bash
# Config principale dell'agente
sudo nano /var/ossec/etc/ossec.conf
```

Verifica che `<address>` punti a `192.168.56.1`:

```xml
<client>
  <server>
    <address>192.168.56.1</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
</client>
```

---

## Agente su `target-windows`

### 1. Download MSI

Dalla Dashboard Wazuh: **Agents → Deploy new agent → Windows** → copia il comando PowerShell generato automaticamente con il tuo Manager IP.

Oppure scarica manualmente:

```powershell
# Su target-windows, esegui come amministratore
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi" `
  -OutFile "$env:TEMP\wazuh-agent.msi"
```

### 2. Installazione silenziosa

```powershell
# Installa con configurazione automatica del Manager
Start-Process msiexec.exe -ArgumentList @(
  "/i", "$env:TEMP\wazuh-agent.msi",
  "/q",
  "WAZUH_MANAGER=192.168.56.1",
  "WAZUH_AGENT_NAME=target-windows"
) -Wait

# Avvia il servizio
NET START WazuhSvc

# Verifica
Get-Service -Name WazuhSvc
```

### 3. Verifica enrollment

Stesso controllo: Dashboard → **Agents** → `target-windows` deve comparire attivo.

### 4. File di configurazione agente (Windows)

```
C:\Program Files (x86)\ossec-agent\ossec.conf
```

Apri con Notepad come amministratore e verifica:

```xml
<client>
  <server>
    <address>192.168.56.1</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
</client>
```

---

## Verifica eventi in arrivo

### Dalla Dashboard

1. Vai su **Modules → Security Events**
2. Filtra per agent name: `target-linux` o `target-windows`
3. Dovresti vedere eventi continui (autenticazioni, servizi, ecc.)

### Query di test (OpenSearch Dashboards)

Nel campo di ricerca della Dashboard, prova:

```
agent.name: "target-linux" AND rule.level: [3 TO 15]
```

```
agent.name: "target-windows" AND data.win.system.channel: "Microsoft-Windows-Sysmon/Operational"
```

---

## Aggiornare la lista file monitorati (Linux)

Per assicurarti che l'agente Linux monitori i file rilevanti, verifica la sezione `<syscheck>` in `ossec.conf`:

```xml
<syscheck>
  <frequency>300</frequency>
  <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
  <directories check_all="yes">/bin,/sbin</directories>
</syscheck>
```

Riavvia l'agente dopo ogni modifica:

```bash
sudo systemctl restart wazuh-agent
```

---

## Troubleshooting

| Problema | Verifica |
|---|---|
| Agente non compare in Dashboard | `sudo systemctl status wazuh-agent` — cerca errori di connessione |
| Connessione rifiutata a 1514 | Firewall sul host — vedi [vm-setup.md §5](vm-setup.md#5-connettività-critica-vm--wazuh-manager-su-docker) |
| Agente in stato "Disconnected" | Il Manager è fermo? `docker ps` — verifica che `wazuh.manager` sia `Up` |
| Log agente Linux | `sudo tail -f /var/ossec/logs/ossec.log` |
| Log agente Windows | `C:\Program Files (x86)\ossec-agent\ossec.log` |
