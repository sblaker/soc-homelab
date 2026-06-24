# Screenshots

Questa cartella contiene gli screenshot della dashboard Wazuh catturati durante il lab live.

## Screenshot richiesti

| File | URL | Descrizione |
|---|---|---|
| `dashboard-overview.png` | `https://localhost/app/wazuh#/overview` | Panoramica generale degli eventi |
| `agent-target-linux.png` | `https://localhost/app/wazuh#/agents/001` | Stato agent 001 (Ubuntu VM) |
| `agent-target-windows.png` | `https://localhost/app/wazuh#/agents/002` | Stato agent 002 (Windows + Sysmon) |
| `mitre-coverage.png` | `https://localhost/app/wazuh#/mitre-attack` | Mappa copertura MITRE ATT&CK |
| `saved-searches.png` | `https://localhost/app/dashboards#/list` | Dashboard salvate |

## Come aggiungerli (metodo rapido)

Esegui lo script PowerShell nella root del progetto:

```powershell
# Da PowerShell nella cartella "pi guard"
.\take-screenshots.ps1
```

Lo script apre ogni URL in Edge, attende il caricamento e salva gli screenshot in questa cartella.

## Metodo manuale

1. Apri `https://localhost` in Edge (login: admin / SecretPassword)
2. Naviga su ciascuna URL nella tabella sopra
3. Premi `Win + Shift + S` per lo Snipping Tool e salva il file con il nome esatto indicato nella tabella
4. Salva in questa cartella (`screenshots/`)
