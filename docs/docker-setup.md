# Setup Docker Desktop + Wazuh

## 1. Installazione Docker Desktop

1. Scarica Docker Desktop per Windows da [https://www.docker.com/products/docker-desktop/](https://www.docker.com/products/docker-desktop/)
2. Esegui il installer (`Docker Desktop Installer.exe`) — richiede riavvio
3. Dopo il riavvio, verifica che Docker sia attivo:

```powershell
docker version
docker compose version
```

Output atteso: versione del client e del server senza errori.

> **Prerequisito WSL 2**: Docker Desktop su Windows 11 usa WSL 2 come backend. Durante l'installazione viene proposto automaticamente; accetta e lascia che installi la distribuzione Linux necessaria.

---

## 2. Configurazione risorse Docker Desktop

Apri **Docker Desktop → Settings → Resources** e imposta:

| Parametro | Valore consigliato | Motivo |
|---|---|---|
| CPUs | 4 | Wazuh indexer è CPU-intensive durante l'indicizzazione |
| Memory | **5 GB** | Manager + Indexer + Dashboard: ~3.5–4 GB under load |
| Swap | 1 GB | Buffer per picchi dell'indexer |
| Disk image size | Default (≥ 60 GB) | OpenSearch accumula dati nel tempo |

> **Importante**: non assegnare più di 5 GB a Docker. Con le VM VirtualBox attive, il sistema ha bisogno di ~7–8 GB per il host. Stare entro 5 GB evita swapping pesante.

Clicca **Apply & Restart**.

---

## 3. Clone del docker-compose ufficiale Wazuh

Wazuh fornisce un repository ufficiale con il `docker-compose.yml` già configurato.

```powershell
# Scegli una cartella di lavoro, es. Desktop
cd C:\Users\<TuoUtente>\Desktop\stuff\pi-guard

# Clona il repository Docker ufficiale di Wazuh
git clone https://github.com/wazuh/wazuh-docker.git --branch v4.9.2 --depth 1
```

> Source ufficiale: [https://github.com/wazuh/wazuh-docker](https://github.com/wazuh/wazuh-docker)  
> Usa il tag corrispondente alla versione che vuoi deployare (es. `v4.9.2`). Controlla i [release](https://github.com/wazuh/wazuh-docker/releases) per la versione più recente stabile.

Il file `docker-compose.yml` che usiamo nel lab (`wazuh/docker-compose.yml` in questa repo) è basato su quello ufficiale con l'aggiunta dei **volume mount per le regole custom** — vedi [Step 3](../wazuh/docker-compose.yml).

---

## 4. Avvio dello stack

```powershell
# Entra nella directory del progetto (dove sta il docker-compose.yml)
cd C:\Users\<TuoUtente>\Desktop\stuff\pi-guard\wazuh

# Genera i certificati SSL (necessario al primo avvio)
docker compose -f generate-indexer-certs.yml run --rm generator

# Avvia lo stack in background
docker compose up -d
```

Il primo avvio richiede **3–5 minuti** perché OpenSearch (l'indexer) deve inizializzare i propri indici.

---

## 5. Verifica che i container girino

```powershell
docker ps
```

Output atteso (tre container in stato `Up`):

```
CONTAINER ID   IMAGE                              STATUS         PORTS
xxxxxxxxxxxx   wazuh/wazuh-manager:4.9.2          Up 3 minutes   0.0.0.0:1514->1514/udp, 0.0.0.0:1515->1515/tcp, 0.0.0.0:514->514/udp, 55000/tcp
xxxxxxxxxxxx   wazuh/wazuh-indexer:4.9.2          Up 3 minutes   0.0.0.0:9200->9200/tcp
xxxxxxxxxxxx   wazuh/wazuh-dashboard:4.9.2        Up 3 minutes   0.0.0.0:443->5601/tcp
```

Se un container non parte, controlla i log (vedi §7).

---

## 6. Accesso alla Dashboard

Apri il browser sul host e vai su:

```
https://localhost
```

> Il certificato è self-signed: il browser mostrerà un avviso. Clicca **Avanzate → Procedi comunque**.

**Credenziali default**:

| Campo | Valore |
|---|---|
| Username | `admin` |
| Password | `SecretPassword` |

> **Cambia la password immediatamente** dopo il primo accesso: Dashboard → icona utente (in alto a destra) → Change password.

Al primo login potresti vedere "Wazuh is not ready yet" — attendi 1–2 minuti e ricarica la pagina. L'indexer deve completare l'inizializzazione degli indici.

---

## 7. Comandi utili

```powershell
# Stato dei container
docker ps

# Log di tutti i container (live, Ctrl+C per uscire)
docker compose logs -f

# Log del solo manager
docker compose logs -f wazuh.manager

# Log del solo indexer
docker compose logs -f wazuh.indexer

# Stop dello stack (dati preservati nei volumi)
docker compose down

# Stop + rimozione volumi (⚠ DISTRUTTIVO: cancella tutti gli alert)
docker compose down -v

# Restart di un singolo container
docker compose restart wazuh.manager

# Shell interattiva nel manager (per debug regole, config, ecc.)
docker exec -it <container_id_manager> /bin/bash
```

---

## Troubleshooting rapido

| Problema | Causa probabile | Soluzione |
|---|---|---|
| Dashboard non raggiungibile dopo 5 min | Indexer non ancora pronto | Attendi e ricarica; controlla `docker compose logs wazuh.indexer` |
| Container manager si riavvia in loop | RAM insufficiente | Riduci altre applicazioni; verifica limite memoria Docker |
| Porta 443 già in uso | IIS o altro servizio sul host | `netstat -ano \| findstr :443` → identifica e stoppa il conflitto |
| Agente non si connette | Firewall Windows bloccante | Apri le porte 1514/1515 su Windows Defender Firewall |
