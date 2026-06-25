# Scripts — automazione del lab

Script PowerShell (host Windows) per provisionare l'endpoint Windows del lab in modo
ripetibile, senza clic manuali. Richiedono **VirtualBox 7+** installato.

| Script | Cosa fa |
|---|---|
| `install-target-windows-unattended.ps1` | **Consigliato.** Crea la VM `target-windows` e installa Windows 10 in modo *unattended* (VirtualBox genera il file di risposta). Con `-ProvisionAgent` installa e arruola anche Wazuh Agent + Sysmon, come SYSTEM, a fine setup. |
| `create-target-windows-vm.ps1` | Crea solo lo *shell* della VM (rete, disco, ISO) per chi vuole installare Windows manualmente. |
| `_guest-provision-wazuh-sysmon.ps1` | Script che gira **dentro** la VM per installare Wazuh Agent + Sysmon (riferimento; la versione unattended lo inietta già via post-install). |

## Uso tipico

```powershell
# 1. Ottieni una ISO ufficiale di Windows 10 x64 (es. via Fido: https://github.com/pbatard/Fido)
# 2. VM + OS + Agent + Sysmon, tutto automatico (headless):
.\scripts\install-target-windows-unattended.ps1 `
  -IsoPath "C:\ISOs\Win10_x64.iso" -ProvisionAgent

# Account VM creato: labuser / Passw0rd1!  (override con -VmUser/-VmPassword)
# Manager di default: 192.168.56.1         (override con -Manager)
```

L'installazione gira da sola per ~25-40 min. Assicurati che lo stack Wazuh
([`../wazuh/`](../wazuh/)) sia attivo così l'agente si arruola appena pronto.

## Note operative

- **Risorse**: durante l'install conviene tenere fermo lo stack Wazuh (l'indexer OpenSearch è
  pesante su disco e può rallentare molto il setup). Riavvialo prima della fase di enrollment.
- **Firewall host**: le porte 1514/1515 del manager devono essere raggiungibili dalla VM
  (rete host-only). Docker Desktop di solito le espone già; in caso, apri le regole inbound.
- **Collisione di nome agente**: un solo agente per nome sul manager. Se esiste già un
  `target-windows` attivo (es. sull'host), rimuovilo prima (`manage_agents -r <id>` sul manager,
  o ferma il servizio sull'host) così la VM può registrarsi.
- **Guest Additions / guestcontrol**: non sono affidabili per il provisioning automatico headless
  in questo setup; per questo l'agente si installa via *post-install command* (SYSTEM), non via
  `guestcontrol`.
