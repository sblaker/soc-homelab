# SOC Home Lab

![Wazuh](https://img.shields.io/badge/SIEM-Wazuh_4.9-blue?logo=wazuh)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-red)
![Docker](https://img.shields.io/badge/Stack-Docker_Compose-2496ED?logo=docker)
![Platform](https://img.shields.io/badge/Platform-Windows_11_Host-0078D4?logo=windows)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

A realistic SOC home lab built to demonstrate L1 Security Analyst skills: SIEM operations, detection engineering, alert triage, and MITRE ATT&CK-mapped incident documentation.

Built as a portfolio piece targeting Blue Team / Cybersecurity Analyst roles.

---

## Architecture

```
Host — Windows 11 (i5-1135G7 · 16 GB RAM)
│
├── Docker Desktop
│   └── Wazuh Stack (docker-compose)
│       ├── wazuh-manager     ← receives agent events, applies rules
│       ├── wazuh-indexer     ← OpenSearch, stores alerts
│       └── wazuh-dashboard   ← https://localhost (browser on host)
│
├── VirtualBox
│   ├── target-linux          Ubuntu Server 22.04 · 1.5 GB RAM · Wazuh Agent
│   └── target-windows        Windows 10 Eval · 3 GB RAM · Wazuh Agent + Sysmon
│
└── Browser (host) → Wazuh Dashboard → Alert triage → Write-up

Event flow:
  VM activity → Wazuh Agent → Manager (rules engine) → Indexer → Dashboard → Write-up
```

Full diagram and networking details: [docs/architecture.md](docs/architecture.md)

---

## Stack

| Component | Technology | Notes |
|---|---|---|
| SIEM | **Wazuh 4.9** | Docker Compose, single-node |
| Linux target | Ubuntu Server 22.04 | CLI only, Wazuh Agent |
| Windows target | Windows 10 Pro (VirtualBox VM) | Wazuh Agent + Sysmon (SwiftOnSecurity), unattended-provisioned |
| Attack simulation | **Atomic Red Team** | MITRE-mapped test cases |
| Detection rules | Custom Wazuh XML | ID range 100001–100099 |
| Endpoint telemetry | **Sysmon** | Event ID 1, 3, 7, 11, 13, 22 |
| Write-ups | Markdown | Per-detection, MITRE-mapped |

---

## Detection Coverage

| ID | Detection | MITRE Technique | Tactic | Severity | Status |
|---|---|---|---|---|---|
| [DET-001](detections/DET-001_ssh-brute-force.md) | SSH Brute Force | T1110.001 | Credential Access | High | ✅ |
| [DET-002](detections/DET-002_powershell-suspicious.md) | Suspicious PowerShell | T1059.001 | Execution | High | ✅ |
| DET-003 | Scheduled Task Persistence | T1053.005 | Persistence | High | 🔄 |
| DET-004 | Registry Run Key Persistence | T1547.001 | Persistence | High | 🔄 |
| DET-005 | SMB / PsExec Lateral Movement | T1021.002 | Lateral Movement | High | 🔄 |
| DET-006 | LSASS Memory Access | T1003.001 | Credential Access | Critical | 🔄 |
| DET-007 | Office → Child Process Spawn | T1566.001 | Initial Access | Critical | 🔄 |

### MITRE ATT&CK Coverage Map

| Tactic | Techniques Covered |
|---|---|
| Credential Access | T1110, T1110.001, T1110.003, T1003, T1003.001 |
| Execution | T1059, T1059.001, T1059.003, T1053, T1053.005 |
| Persistence | T1547, T1547.001, T1053, T1053.003 |
| Lateral Movement | T1021, T1021.001, T1021.002, T1021.004 |
| Defense Evasion | T1027, T1218, T1562, T1562.001, T1562.002 |
| Initial Access | T1566, T1566.001 |
| Command & Control | T1071, T1071.004, T1568 |

---

## Custom Detection Rules

Rules are in [`wazuh/rules/`](wazuh/rules/) and loaded into the Wazuh Manager via Docker volume mount.

| File | Coverage | Rule IDs |
|---|---|---|
| [custom_ssh.xml](wazuh/rules/custom_ssh.xml) | SSH brute force, user enumeration, sudo abuse | 100001–100006 |
| [custom_windows.xml](wazuh/rules/custom_windows.xml) | Sysmon-based: process injection, registry, file drops, LSASS | 100020–100028 |
| [custom_mitre_mapped.xml](wazuh/rules/custom_mitre_mapped.xml) | Full MITRE tag coverage: T1110, T1059, T1053, T1547, T1021, T1562 | 100060–100096 |

---

## Attack Simulations

Playbooks in [`atomic-red-team/playbooks/`](atomic-red-team/playbooks/) — each includes exact commands, expected Wazuh alert, and cleanup procedure.

| Playbook | Technique | Platform |
|---|---|---|
| [T1110-001 SSH Brute Force](atomic-red-team/playbooks/T1110-001_ssh-brute-force.md) | T1110.001 | Linux |
| [T1059-001 PowerShell](atomic-red-team/playbooks/T1059-001_powershell-suspicious.md) | T1059.001 | Windows |
| [T1053-005 Scheduled Task](atomic-red-team/playbooks/T1053-005_scheduled-task.md) | T1053.005 | Windows |
| [T1547-001 Registry Run Key](atomic-red-team/playbooks/T1547-001_registry-run-key.md) | T1547.001 | Windows |
| [T1021-002 SMB/PsExec](atomic-red-team/playbooks/T1021-002_smb-psexec.md) | T1021.002 | Windows |

---

## Screenshots

The Wazuh dashboard runs at `https://localhost` (Docker, single-node). To capture fresh
screenshots from a live deployment into [`screenshots/`](screenshots/), bring the stack up,
enroll the agents, then run [`take-screenshots.ps1`](take-screenshots.ps1) (overview, per-agent,
and MITRE ATT&CK coverage views).

> Screenshots are environment-specific and are not committed to keep the repo lean.

---

## Quick Start (Replication Guide)

> Full step-by-step guides in Italian are in [`docs/`](docs/).

### Prerequisites

- Windows 10/11 host, 16 GB RAM minimum
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) with WSL 2
- [VirtualBox](https://www.virtualbox.org/)
- Ubuntu Server 22.04 ISO + Windows 10 Evaluation ISO

### Steps

**1 — Start Wazuh (Docker)**

```powershell
cd wazuh
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
# Dashboard → https://localhost  (admin / SecretPassword)
```

Guide: [docs/docker-setup.md](docs/docker-setup.md)

**2 — Create VMs (VirtualBox)**

- `target-linux`: Ubuntu Server 22.04, 1.5 GB RAM, NAT + Host-only adapter
- `target-windows`: Windows 10, 3 GB RAM, NAT + Host-only adapter

The Windows VM can be built **fully unattended** (OS + Agent + Sysmon, zero clicks) — see
[Windows VM automation](#windows-vm-automation). Manual guide: [docs/vm-setup.md](docs/vm-setup.md)

**3 — Enroll Wazuh Agents**

Both VMs point to `192.168.56.1` (host IP on the host-only network, where Docker runs).

```bash
# target-linux
sudo WAZUH_MANAGER='192.168.56.1' apt install wazuh-agent -y
sudo systemctl enable --now wazuh-agent
```

Guide: [docs/agents-setup.md](docs/agents-setup.md)

**4 — Install Sysmon (Windows target)**

```powershell
# target-windows (admin PowerShell)
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Guide: [docs/sysmon-setup.md](docs/sysmon-setup.md)

**5 — Load custom rules**

Rules in `wazuh/rules/` are auto-mounted into the Manager container via the volume defined in `wazuh/docker-compose.yml`. Restart the manager after any rule change:

```powershell
docker compose restart wazuh.manager
```

**6 — Run a simulation and verify detection**

```bash
# target-linux — trigger SSH brute force detection
for i in {1..6}; do
  sshpass -p "wrong${i}" ssh -o StrictHostKeyChecking=no labuser@127.0.0.1 2>/dev/null
done
```

Then check Wazuh Dashboard: **Security Events** → filter `rule.id: 100001`

---

## Windows VM automation

Building the Windows endpoint by hand (download ISO, click through Setup, install the agent and
Sysmon) is slow and not reproducible. This lab automates it end-to-end with VirtualBox 7's native
unattended-install support — **one command, zero clicks**:

```powershell
# Fetch an official Windows 10 ISO URL (via Fido), then:
.\scripts\install-target-windows-unattended.ps1 `
  -IsoPath "C:\ISOs\Win10_x64.iso" -ProvisionAgent
```

What it does, unattended and headless:

1. Creates the `target-windows` VM (3 GB RAM, 2 vCPU, NAT + host-only `192.168.56.x`).
2. Installs Windows 10 Pro — VirtualBox generates the answer file (partitions, EULA, local
   account `labuser`, hostname, OOBE).
3. Runs a **post-install command as `SYSTEM`** (no UAC, no GUI automation) that waits for
   networking, then installs **Wazuh Agent** (enrolled to the manager as `target-windows`) and
   **Sysmon** (SwiftOnSecurity config), and wires the Sysmon channel into `ossec.conf`.

The agent comes up Active and streams Sysmon telemetry to the manager. Scripts:

| Script | Purpose |
|---|---|
| [scripts/create-target-windows-vm.ps1](scripts/create-target-windows-vm.ps1) | Create the VM shell (manual OS install) |
| [scripts/install-target-windows-unattended.ps1](scripts/install-target-windows-unattended.ps1) | Unattended OS install + optional agent/Sysmon provisioning |
| [scripts/_guest-provision-wazuh-sysmon.ps1](scripts/_guest-provision-wazuh-sysmon.ps1) | In-guest Agent + Sysmon install (reference) |

> **Note on agent naming**: only one agent may hold a given name on the manager. If a previous
> host-based agent named `target-windows` is still active, the VM's enrollment is rejected
> (`Duplicate name … rejecting enrollment`). Stop/remove the old agent (or rename one) so the VM
> can register.

---

## Repository Structure

```
soc-homelab/
├── docs/                         # Setup guides (Italian)
│   ├── architecture.md
│   ├── docker-setup.md
│   ├── vm-setup.md
│   ├── agents-setup.md
│   └── sysmon-setup.md
├── wazuh/                        # Self-contained: no need to clone wazuh-docker
│   ├── docker-compose.yml        # Wazuh 4.9 single-node + custom rules mount
│   ├── generate-indexer-certs.yml
│   ├── config/                   # Non-secret config (certs generated locally)
│   │   ├── certs.yml
│   │   ├── wazuh_cluster/wazuh_manager.conf   # adds <rule_dir> for custom rules
│   │   ├── wazuh_indexer/
│   │   └── wazuh_dashboard/
│   ├── rules/
│   │   ├── custom_ssh.xml        # SSH detection rules
│   │   ├── custom_windows.xml    # Sysmon-based Windows rules
│   │   └── custom_mitre_mapped.xml
│   └── decoders/                 # Custom decoders (if needed)
├── scripts/
│   └── create-target-windows-vm.ps1   # VirtualBox provisioning for target-windows
├── sysmon/
│   └── sysmon-config.xml         # SwiftOnSecurity config (add manually)
├── atomic-red-team/
│   └── playbooks/                # Attack simulation guides
├── detections/
│   ├── README.md                 # Coverage index + template
│   ├── DET-001_ssh-brute-force.md
│   └── DET-002_powershell-suspicious.md
└── screenshots/
```

---

## Resource Budget

| Component | Type | RAM |
|---|---|---|
| Wazuh stack | Docker | ~3.5–4 GB |
| target-linux | VirtualBox | 1.5 GB |
| target-windows | VirtualBox | 3 GB |
| Host headroom | — | ~7–8 GB |
| **Total** | | **~8.5 GB** |

> Run only one VM at a time when possible — saves 1.5–3 GB.

---

## Key Findings

Real alerts captured during attack simulations — JSON in [`detections/`](detections/).

### DET-001 — SSH Brute Force (T1110.001)

| Field | Value |
|---|---|
| Rule ID | `5712` (built-in) + `100001` (custom) |
| Level | 10 — High |
| Frequency | 8 authentication failures in ~10 s |
| Source IP | `127.0.0.1` (loopback in lab; would be attacker IP in production) |
| Target user | `fakeuser` (non-existent — typical of automated scanners) |
| Outcome | No successful login (`Accepted` not present) |
| MITRE | T1110 · T1110.001 — Credential Access / Brute Force |
| Timestamp | 2026-06-24T11:58:40Z |

### DET-002 — Suspicious PowerShell (T1059.001)

| Field | Value |
|---|---|
| Rule ID | `92057` (built-in) + `100021` (custom) |
| Level | 12 — High |
| Flags detected | `-NoP -NonI -W Hidden -Exec Bypass -EncodedCommand` |
| Parent process | `powershell.exe` (in real attack: `winword.exe` / `excel.exe`) |
| Payload | Base64 → `Write-Host 'Atomic Red Team T1059.001 test'` |
| Sysmon Event | EID 1 (Process Create) |
| MITRE | T1059.001 — Execution / PowerShell + T1027 — Obfuscation |
| Timestamp | 2026-06-24T12:07:29Z |

---

## Lab Results

| Agent | Name | Platform | Network | Status | Telemetry |
|---|---|---|---|---|---|
| 001 | target-linux | Ubuntu Server 22.04 (VirtualBox VM) | host-only `192.168.56.x` | ✅ Active | auth.log → SSH Brute Force (T1110.001) |
| 002 | target-windows | **Windows 10 Pro (VirtualBox VM)** | host-only `192.168.56.x` | ✅ Active | **Sysmon EID 1** → Process Create, custom rules loaded |

> The Windows endpoint is a real VirtualBox VM, provisioned **fully unattended** (OS install +
> Wazuh Agent + Sysmon) via the scripts in [`scripts/`](scripts/) — see
> [Windows VM automation](#windows-vm-automation). Agent `002` reports Windows 10 Pro and streams
> live Sysmon telemetry to the manager, where the custom detection ruleset is applied.

---

## Author

Portfolio project — Blue Team / SOC Analyst L1  
[GitHub](https://github.com/sblaker/soc-homelab)
