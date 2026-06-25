# SOC Home Lab — Detection Case Studies

A practitioner's report of attack techniques simulated in this lab and how they were detected,
triaged and mapped to MITRE ATT&CK. Every "attack" uses **benign or simulated payloads** executed
**only inside the isolated lab VMs** — this is detection engineering, not offensive tooling.

---

## Executive summary

This lab runs **Wazuh 4.9.2** (SIEM/XDR, Docker single-node) collecting telemetry from two
monitored endpoints — an Ubuntu Server VM (`target-linux`) and a Windows 10 Pro VM
(`target-windows`, with **Sysmon**). Attacks are reproduced with real techniques (and the
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) framework), detected by a set of
custom Wazuh rules (IDs `100001–100096`), then triaged and documented.

| Metric | Value |
|---|---|
| Monitored endpoints | 2 (Linux + Windows, host-only `192.168.56.0/24`) |
| Custom detection rules | 24 (SSH, Sysmon/Windows, MITRE-mapped) |
| MITRE tactics covered | 8 (Initial Access → Impact) |
| Case studies in this report | 6 |
| Telemetry | auth logs (Linux) · **Sysmon EID 1/3/10/11/13/22** (Windows) |

**Status legend:** ✅ *Validated* = alert captured from a live run · 🧪 *Designed* = rule built and
loaded, ready to validate with the linked playbook.

---

## Environment & data flow

```
Attack on VM ─► Wazuh Agent ─► Manager (decoders + rules) ─► Indexer (OpenSearch) ─► Dashboard ─► Triage ─► Write-up
```

- **Linux telemetry**: `/var/log/auth.log` (journald) — SSH, sudo, PAM.
- **Windows telemetry**: Sysmon `Microsoft-Windows-Sysmon/Operational` — process creation (EID 1),
  network (EID 3), LSASS access (EID 10), file create (EID 11), registry (EID 13), DNS (EID 22).
- Custom rules are mounted into the manager and loaded via `<rule_dir>etc/rules/custom_lab</rule_dir>`.

---

## Detection-engineering methodology

Each case study follows the loop a detection engineer actually runs:

1. **Threat context** — why an attacker uses the technique.
2. **Simulation** — the exact commands (benign/simulated), linked to a playbook.
3. **Detection logic** — the Wazuh rule and *why* it fires.
4. **What the analyst sees** — the alert and key observables.
5. **Triage** — the questions that separate true positive from false positive.
6. **IOCs & remediation** — what to hunt for and how to mitigate.

---

## Case Study 1 — SSH Brute Force ✅

| | |
|---|---|
| MITRE | T1110 · **T1110.001** (Credential Access / Password Guessing) |
| Endpoint | `target-linux` (Ubuntu Server 22.04) |
| Rule(s) | built-in `5712` + custom `100001` |
| Playbook | [T1110-001](../atomic-red-team/playbooks/T1110-001_ssh-brute-force.md) · Write-up: [DET-001](DET-001_ssh-brute-force.md) |

**Threat context.** Internet-facing SSH is hammered constantly by botnets and targeted attackers; a
single successful guess yields a shell. Detection hinges on the *rate* of failures, not a single one.

**Simulation.** A loop of failed logins against a non-existent user:
```bash
for i in $(seq 1 10); do sshpass -p "wrong${i}" ssh -o StrictHostKeyChecking=no fakeuser@127.0.0.1; done
```

**Detection logic.** Custom rule `100001` correlates the built-in *authentication failure* signature
across time: **5+ failures from the same source IP within 60 s** (`frequency=5 timeframe=60`,
`<same_source_ip/>`), tagged `T1110.001`.

**What the analyst saw (live capture).** 8 failures in ~10 s from `127.0.0.1` against user
`fakeuser`, no `Accepted` line → brute force **attempted and failed**, level 10. The non-existent
username is the fingerprint of an automated scanner.

**Triage.** Is the source IP known/allow-listed? How many usernames tried? Any subsequent
`Accepted`? (search for the success signature right after the burst).

**IOCs.** src IP, targeted usernames, failure rate, absence of a success event.

**Remediation.** `fail2ban`, key-only auth (`PasswordAuthentication no`), MFA for privileged
accounts, move SSH off :22 to cut scanner noise.

---

## Case Study 2 — Suspicious / Obfuscated PowerShell ✅

| | |
|---|---|
| MITRE | **T1059.001** (Execution / PowerShell) · T1027 (Obfuscation) |
| Endpoint | `target-windows` (Sysmon EID 1) |
| Rule(s) | custom `100021`, `100063` (+ built-in `91809`/`92057`) |
| Playbook | [T1059-001](../atomic-red-team/playbooks/T1059-001_powershell-suspicious.md) · Write-up: [DET-002](DET-002_powershell-suspicious.md) |

**Threat context.** PowerShell is the universal post-exploitation interpreter; attackers hide intent
with `-EncodedCommand` (Base64), `-WindowStyle Hidden`, `-ExecutionPolicy Bypass`, and in-memory
download cradles (`IEX`, `DownloadString`).

**Simulation.**
```powershell
$enc=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Host 'ART T1059.001 test'"))
powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand $enc
```

**Detection logic.** `100021/100063` match Sysmon EID 1 where `image` is `powershell.exe` and the
`commandLine` regex hits any offensive flag (`-enc`, `-nop`, `-w hidden`, `iex`, `downloadstring`…).

**What the analyst saw (live capture).** During this lab's own automated provisioning, an encoded
PowerShell command triggered rule **`100063` (level 12)** with the full `T1059.001` MITRE mapping —
a real demonstration that the rule fires on encoded-PowerShell telemetry. (The same pattern is what a
malicious dropper looks like; here the decoded payload was benign.)

**Triage.** *Parent process is everything*: `winword.exe`/`excel.exe` parent → almost certainly a
malicious macro (true positive); `powershell_ise.exe`/known scheduled task → likely admin activity.
Decode the Base64 to read the real payload; check for a follow-on network connection (Sysmon EID 3).

**IOCs.** Process hash, parent image, decoded command, user, integrity level.

**Remediation.** Constrained Language Mode, Script Block Logging, AMSI, AppLocker/WDAC, `RemoteSigned`
execution policy.

---

## Case Study 3 — LSASS Credential Dumping (Mimikatz & LOLBins) 🧪

| | |
|---|---|
| MITRE | T1003 · **T1003.001** (Credential Access / LSASS Memory) |
| Endpoint | `target-windows` (Sysmon EID 1 + EID 10) |
| Rule(s) | custom `100025` (EID 10 access), `100033` (dump command), `100034` (Mimikatz keywords) |
| Playbook | [T1003-001](../atomic-red-team/playbooks/T1003-001_lsass-dumping.md) |

**Threat context.** `lsass.exe` caches credentials, NTLM hashes and Kerberos tickets. Dumping it is
the single most common Credential Access step for both APTs and ransomware crews — it unlocks lateral
movement and domain compromise.

**Simulation (living-off-the-land, no external malware).**
```powershell
$lsass=(Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsass C:\Windows\Temp\lsass.dmp full
```
Alternative methods: ProcDump `-ma lsass`, or Mimikatz `sekurlsa::logonpasswords` (the classic).

**Detection logic.** Defense in depth across two Sysmon channels:
- `100033` — EID 1 command line matches dump patterns (`comsvcs … MiniDump`, `-ma lsass`, `procdump … lsass`).
- `100025` — EID 10 *ProcessAccess* where `targetImage` is `lsass.exe` (catches dumps that never spawn an obvious command).
- `100034` — EID 1 command line contains Mimikatz module keywords (`sekurlsa::`, `lsadump::`, `privilege::debug`).

**What the analyst would see.** Critical alert (level 14–15) naming the dumping tool and the access
to LSASS. A `lsass.dmp` artifact in a temp path corroborates exfiltration intent.

**Triage.** Which process accessed LSASS, with what `GrantedAccess` (`0x1010`/`0x1fffff` = read
memory)? Is it a known EDR/AV (`MsMpEng.exe`) or something unexpected? Was a `.dmp` written?

**IOCs.** Source process + hash, `GrantedAccess` mask, `lsass*.dmp` files, Mimikatz keywords.

**Remediation.** Credential Guard, LSASS as Protected Process Light (`RunAsPPL=1`), ASR rule
"Block credential stealing from lsass.exe", least-privilege on local admin.

---

## Case Study 4 — Ransomware Behavior 🧪

| | |
|---|---|
| MITRE | **T1490** (Inhibit System Recovery) · **T1486** (Data Encrypted for Impact) |
| Endpoint | `target-windows` (Sysmon EID 1 + EID 11) |
| Rule(s) | custom `100030` (shadow delete), `100031` (bcdedit), `100032` (ransom note/encrypted files) |
| Playbook | [T1490](../atomic-red-team/playbooks/T1490_ransomware-behavior.md) |

**Threat context.** Modern ransomware (Ryuk, LockBit, Conti) follows a near-identical pre-encryption
playbook: **destroy recovery options** (shadow copies, backups, boot recovery) so the victim cannot
roll back, then **encrypt** and drop a ransom note. Catching the recovery-inhibition step buys the
SOC precious minutes *before* encryption.

**Simulation (no real crypto — test files only).**
```cmd
vssadmin delete shadows /all /quiet
bcdedit /set {default} recoveryenabled no
```
```powershell
# simulate mass encryption on a sandbox folder + drop the note
Get-ChildItem C:\RansomLab -File | % { Rename-Item $_.FullName "$($_.FullName).locked" }
"YOUR FILES ARE ENCRYPTED (lab sim)" | Out-File C:\RansomLab\HOW_TO_DECRYPT.txt
```

**Detection logic.**
- `100030` — EID 1, `vssadmin/wmic/wbadmin/diskshadow` with `delete shadows` / `delete catalog`.
- `100031` — EID 1, `bcdedit` disabling recovery.
- `100032` — EID 11, files named like ransom notes or with `.locked/.encrypted/...` extensions.

**What the analyst would see.** Two near-simultaneous **critical** alerts (level 14) for recovery
inhibition, immediately followed by the ransom-note alert — a textbook ransomware timeline.

**Triage.** Shadow-copy deletion is *almost never* legitimate on a workstation. Identify the parent
process and isolate the host **immediately** — encryption typically follows within minutes.

**IOCs.** `vssadmin delete shadows`, `bcdedit recoveryenabled no`, `.locked` files, `HOW_TO_DECRYPT*`.

**Remediation.** Immutable/offline 3-2-1 backups, Controlled Folder Access, high-priority alerting on
T1490, rapid host isolation playbook, least privilege.

---

## Case Study 5 — Persistence: Scheduled Task & Registry Run Key 🧪

| | |
|---|---|
| MITRE | **T1053.005** (Scheduled Task) · **T1547.001** (Registry Run Keys) |
| Endpoint | `target-windows` (Sysmon EID 1 + EID 13) |
| Rule(s) | custom `100026`/`100070` (schtasks), `100022`/`100080` (Run key) |
| Playbooks | [T1053-005](../atomic-red-team/playbooks/T1053-005_scheduled-task.md) · [T1547-001](../atomic-red-team/playbooks/T1547-001_registry-run-key.md) |

**Threat context.** After initial access, attackers ensure they survive a reboot. The two most common
mechanisms on Windows are a scheduled task and a `CurrentVersion\Run` registry value.

**Simulation.**
```cmd
schtasks /create /tn "Updater" /tr "powershell -w hidden -c ..." /sc onlogon /f
```
```powershell
Set-ItemProperty "HKCU:\...\CurrentVersion\Run" -Name Updater -Value "powershell -w hidden ..."
```

**Detection logic.** `100026` matches `schtasks.exe /create` (EID 1); `100022` matches Sysmon EID 13
registry writes to `…\CurrentVersion\Run|RunOnce`. Both tagged with their sub-techniques.

**What the analyst would see.** A high-severity alert naming the task/registry value and the writing
process. The *value* (a hidden PowerShell one-liner) and *path* (TEMP/APPDATA) are the giveaways.

**Triage.** Legitimate software writes Run keys at install time (Spotify, Teams…) — tune by
excluding signed binaries under `C:\Program Files\`. A PowerShell/cmd value pointing at TEMP is the
true positive.

**IOCs.** Task name + action, registry value name + data, writing process.

**Remediation.** Application allow-listing, monitor autoruns, restrict who can create tasks.

---

## Case Study 6 — Full Attack Chain (kill chain) 🧪

| | |
|---|---|
| Scenario | One realistic intrusion, 7 ATT&CK tactics end-to-end |
| Endpoint | `target-windows` |
| Playbook | [ATTACK-CHAIN](../atomic-red-team/playbooks/ATTACK-CHAIN_full-intrusion.md) |

**Why it matters.** Individual detections are useful; **reconstructing a chain** is what a SOC analyst
actually does during an incident. This scenario stitches the techniques above into one story:

```
Initial Access → Execution → Discovery → Credential Access → Persistence → Defense Evasion → Impact
   T1566.001       T1059.001    T1087        T1003.001          T1547.001     T1562.001/T1070   T1490/T1486
   (100020)        (100021/63)  (built-in)   (100025/33)        (100022/80)   (100095/96)       (100030/32)
```

**Analyst workflow.** Filter all alerts for the host, sort by `timestamp`, and the kill chain
reconstructs itself; the Wazuh **MITRE ATT&CK** module lights up the tactics in sequence. The
playbook ships a triage table to record time, `rule.id`, tactic and TP/FP per stage.

**Skills demonstrated.** Recognizing 7 tactics in one incident, building an attack timeline from
alerts, linking each event to detection and remediation — i.e. thinking like an **incident
responder**, not just a rule author.

---

## MITRE ATT&CK coverage summary

| Tactic | Techniques | Case study |
|---|---|---|
| Initial Access | T1566.001 | 6 |
| Execution | T1059.001, T1059.003, T1053.005 | 2, 5, 6 |
| Persistence | T1547.001, T1053.005, T1053.003 | 5, 6 |
| Credential Access | T1110.001, T1003.001 | 1, 3, 6 |
| Defense Evasion | T1027, T1562.001, T1562.002, T1218 | 2, 6 |
| Lateral Movement | T1021.002, T1021.001 | (PsExec playbook) |
| Command & Control | T1071, T1568 | (LOLBin/DNS rules) |
| Impact | T1490, T1486 | 4, 6 |

---

## Conclusions — skills demonstrated

- **SIEM operations**: deploy and run Wazuh; ingest Linux auth logs and Windows Sysmon telemetry.
- **Detection engineering**: author, load and tune 24 custom rules with explicit MITRE mapping;
  defense-in-depth (e.g. LSASS detected via both command line *and* memory-access channels).
- **Alert triage**: structured TP/FP reasoning per technique, parent-process and rate analysis.
- **Adversary emulation**: safe, repeatable simulations (Atomic Red Team + hand-built playbooks).
- **Incident response thinking**: reconstruct a multi-stage kill chain into an ATT&CK timeline.

> Next step to deepen each case study: run the linked playbook inside `target-windows`, capture the
> real alert JSON from the dashboard, and fold it into a per-detection write-up (`DET-00X.md`).
