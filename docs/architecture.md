# Architettura del Lab

## Diagramma

```
┌─────────────────────────────────────────────────────────────────┐
│                      HOST — Windows 11                          │
│                  i5-1135G7 · 16 GB RAM · SSD                   │
│                                                                 │
│  ┌──────────────────────────────────┐                           │
│  │        Docker Desktop            │                           │
│  │  ┌────────────────────────────┐  │                           │
│  │  │    Wazuh Stack             │  │                           │
│  │  │  ┌──────────────────────┐  │  │                           │
│  │  │  │   wazuh-manager      │  │  │◄── agenti inviano eventi  │
│  │  │  │   (porta 1514/1515)  │  │  │    su questa porta        │
│  │  │  └──────────┬───────────┘  │  │                           │
│  │  │             │ analisi +    │  │                           │
│  │  │             │ regole       │  │                           │
│  │  │  ┌──────────▼───────────┐  │  │                           │
│  │  │  │  wazuh-indexer       │  │  │                           │
│  │  │  │  (OpenSearch)        │  │  │                           │
│  │  │  └──────────┬───────────┘  │  │                           │
│  │  │             │ dati         │  │                           │
│  │  │  ┌──────────▼───────────┐  │  │                           │
│  │  │  │  wazuh-dashboard     │  │  │                           │
│  │  │  │  https://localhost   │◄─┼──┼── Browser del host        │
│  │  │  └──────────────────────┘  │  │                           │
│  │  └────────────────────────────┘  │                           │
│  └──────────────────────────────────┘                           │
│                                                                 │
│  ┌──────────────────────┐  ┌──────────────────────────────┐    │
│  │ VirtualBox           │  │ VirtualBox                   │    │
│  │ target-linux         │  │ target-windows               │    │
│  │ Ubuntu Server 22.04  │  │ Windows 10 Evaluation        │    │
│  │ 1.5 GB RAM           │  │ 3 GB RAM                     │    │
│  │ Wazuh Agent          │  │ Wazuh Agent + Sysmon         │    │
│  └──────────┬───────────┘  └──────────────┬───────────────┘    │
│             │                             │                     │
│             └─────────────┬───────────────┘                     │
│                           │ eventi → 192.168.56.1:1514          │
│                           ▼                                     │
│                    [wazuh-manager]                              │
└─────────────────────────────────────────────────────────────────┘
```

## Flusso degli eventi

```
Attività sulla VM
      │
      ▼
Wazuh Agent (VM)          ← raccoglie log di sistema, Sysmon, auth.log, ecc.
      │  TCP 1514/1515
      ▼
Wazuh Manager (Docker)    ← applica decoder e regole (standard + custom)
      │
      ▼
Wazuh Indexer             ← indicizza gli alert in OpenSearch
      │
      ▼
Wazuh Dashboard           ← visualizzazione alert, query, dashboard
      │
      ▼
Triage manuale            ← analisi da browser sul host Windows
      │
      ▼
Write-up in /detections/  ← documentazione MITRE-mapped
```

## Piano risorse RAM

| Componente | Tipo | RAM allocata |
|---|---|---|
| Wazuh stack | Docker | ~3.5–4 GB |
| `target-linux` | VirtualBox VM | 1.5 GB |
| `target-windows` | VirtualBox VM | 3 GB |
| Host (residuo) | — | ~7–8 GB |
| **Totale stimato** | | **~8.5 GB** |

> **Nota operativa**: non avviare entrambe le VM contemporaneamente se non necessario. La maggior parte delle detection richiede una sola VM alla volta, risparmiando ~1.5–3 GB.

## Networking

Le VM usano due adattatori di rete:

- **NAT**: per l'accesso a internet dalla VM (download pacchetti, aggiornamenti)
- **Host-only** (`vboxnet0`, range `192.168.56.0/24`): rete privata tra host e VM

Il Wazuh Manager gira su Docker sul host. L'IP del host sulla rete host-only è tipicamente `192.168.56.1`. Gli agenti nelle VM puntano a questo IP per inviare gli eventi.

```
target-linux  192.168.56.101 ──┐
                               ├──► 192.168.56.1 (host) → wazuh-manager (Docker)
target-windows 192.168.56.102 ─┘
```

Verifica la connettività prima di enrollare gli agenti:
```bash
# da target-linux
ping 192.168.56.1
nc -zv 192.168.56.1 1514
```

## Componenti chiave

### Wazuh Manager
Cuore del SIEM. Riceve gli eventi dagli agenti, applica i decoder per parsare il formato raw, poi esegue le regole (prima quelle built-in, poi le custom) per generare alert con livello di severity.

### Wazuh Indexer (OpenSearch)
Database degli alert. Permette query full-text e aggregazioni. La Dashboard lo usa come backend.

### Wazuh Dashboard
Interfaccia web basata su OpenSearch Dashboards. Permette di visualizzare alert in real time, costruire query Lucene/KQL, creare dashboard personalizzate.

### Sysmon (Windows)
System Monitor di Sysinternals. Intercetta eventi kernel e li scrive nell'Event Log Windows con dettaglio molto superiore ai log nativi. Event ID principali monitorati:

| Event ID | Evento |
|---|---|
| 1 | Process Create |
| 3 | Network Connection |
| 7 | Image Loaded |
| 11 | File Created |
| 13 | Registry Value Set |
| 22 | DNS Query |

### Atomic Red Team
Libreria di test atomici mappati su MITRE ATT&CK. Ogni test simula una specifica tecnica di attacco con comandi esatti, usati nei [playbook](../atomic-red-team/playbooks/) di questo lab.
