# Setup VirtualBox + VM target

## 1. Download dei software necessari

| Software | URL | Note |
|---|---|---|
| VirtualBox | [https://www.virtualbox.org/wiki/Downloads](https://www.virtualbox.org/wiki/Downloads) | Versione per Windows host |
| VirtualBox Extension Pack | stessa pagina | Stesso numero di versione di VirtualBox |
| Ubuntu Server 22.04 LTS | [https://ubuntu.com/download/server](https://ubuntu.com/download/server) | ISO ~1.5 GB, scegli "Option 2" (manual install) |
| Windows 10 Evaluation | [https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise) | ISO 90 giorni, rinnovabile |

Installa VirtualBox ed Extension Pack prima di creare le VM.

---

## 2. Configurazione rete Host-Only

Prima di creare le VM, configura la rete host-only che userà il lab.

In VirtualBox: **File → Tools → Network Manager → Host-only Networks → Create**

Imposta:
- **IPv4 Address**: `192.168.56.1` (questo è l'IP del host su questa rete)
- **IPv4 Network Mask**: `255.255.255.0`
- **DHCP Server**: abilitato, range `192.168.56.100` – `192.168.56.200`

---

## 3. Creazione VM `target-linux`

### Impostazioni base

| Parametro | Valore |
|---|---|
| Nome | `target-linux` |
| Tipo | Linux |
| Versione | Ubuntu (64-bit) |
| RAM | **1536 MB** (1.5 GB) |
| CPU | 1 vCPU |
| Disco | 20 GB (dinamicamente allocato) |

### Rete — due adattatori

- **Adattatore 1**: NAT (per accesso internet dalla VM)
- **Adattatore 2**: Host-only Adapter → seleziona `vboxnet0` (o il nome creato al §2)

### Installazione Ubuntu Server

1. Allega l'ISO e avvia la VM
2. Nell'installer, scegli:
   - Language: English
   - No proxy, mirror default
   - Storage: "Use entire disk"
   - Hostname: `target-linux`
   - Username: `labuser` (o a piacere), imposta password
   - **Installa OpenSSH Server** quando richiesto (servirà per i test di brute force)
   - Non installare snap packages aggiuntivi
3. Al termine, rimuovi l'ISO e riavvia

### Configurazione post-installazione

```bash
# Aggiorna il sistema
sudo apt update && sudo apt upgrade -y

# Verifica che la rete host-only sia attiva (cerca enp0s8 o simile con IP 192.168.56.x)
ip addr show

# Se l'interfaccia host-only non ha IP, configura netplan
sudo nano /etc/netplan/00-installer-config.yaml
```

Aggiungi la seconda interfaccia se non è già presente:

```yaml
network:
  version: 2
  ethernets:
    enp0s3:        # NAT
      dhcp4: true
    enp0s8:        # Host-only
      dhcp4: true
```

```bash
sudo netplan apply
ip addr show enp0s8    # deve mostrare 192.168.56.x
```

---

## 4. Creazione VM `target-windows`

### Impostazioni base

| Parametro | Valore |
|---|---|
| Nome | `target-windows` |
| Tipo | Microsoft Windows |
| Versione | Windows 10 (64-bit) |
| RAM | **3072 MB** (3 GB) |
| CPU | 2 vCPU |
| Disco | 50 GB (dinamicamente allocato) |

### Rete — due adattatori

- **Adattatore 1**: NAT
- **Adattatore 2**: Host-only Adapter → `vboxnet0`

### Installazione Windows 10

1. Allega l'ISO di valutazione e avvia
2. Scegli "Windows 10 Enterprise Evaluation"
3. "Custom: Install Windows only"
4. Completa l'installazione con account locale (salta il login Microsoft)
5. Hostname: `target-windows`

### VirtualBox Guest Additions (opzionale ma utile)

In VirtualBox: **Devices → Insert Guest Additions CD image** → esegui l'installer dentro la VM. Migliora le performance e abilita clipboard condivisa.

### Configurazione rete host-only su Windows

1. Apri **Pannello di controllo → Centro connessioni di rete**
2. Verifica che l'adattatore Ethernet 2 (host-only) abbia IP nel range `192.168.56.x`
3. Se non ha IP: tasto destro → Proprietà → IPv4 → Ottieni automaticamente (DHCP)

---

## 5. Connettività critica: VM → Wazuh Manager su Docker

> Questo è il punto più delicato del setup. Le VM devono raggiungere il Wazuh Manager che gira su Docker sul host Windows.

### Come funziona il routing

Il Wazuh Manager è in un container Docker, ma le porte `1514` e `1515` sono esposte sull'host. L'IP del host sulla rete host-only è `192.168.56.1`. Quindi gli agenti nelle VM si collegano a `192.168.56.1:1514`.

### Verifica connettività da `target-linux`

```bash
# Ping al host
ping -c 3 192.168.56.1

# Verifica porta 1515 (enrollment agenti)
nc -zv 192.168.56.1 1515

# Verifica porta 1514 (comunicazione agenti)
nc -zv 192.168.56.1 1514
```

### Verifica connettività da `target-windows`

```powershell
# Ping al host
ping 192.168.56.1

# Test porta 1515
Test-NetConnection -ComputerName 192.168.56.1 -Port 1515

# Test porta 1514
Test-NetConnection -ComputerName 192.168.56.1 -Port 1514
```

### Se le porte non sono raggiungibili: Windows Defender Firewall

Su Windows 11 host, apri **Windows Defender Firewall con sicurezza avanzata** e crea due regole in entrata:

```powershell
# Esegui come amministratore sul host Windows
New-NetFirewallRule -DisplayName "Wazuh Agent 1514" -Direction Inbound -Protocol TCP -LocalPort 1514 -Action Allow
New-NetFirewallRule -DisplayName "Wazuh Agent 1515" -Direction Inbound -Protocol TCP -LocalPort 1515 -Action Allow
New-NetFirewallRule -DisplayName "Wazuh Agent 1514 UDP" -Direction Inbound -Protocol UDP -LocalPort 1514 -Action Allow
```

---

## 6. Snapshot iniziale

Prima di enrollare gli agenti, fai uno snapshot di ogni VM in stato "pulito":

In VirtualBox: seleziona la VM → **Machine → Take Snapshot** → nome: `Clean install`

Questo permette di tornare allo stato iniziale in caso di problemi.
