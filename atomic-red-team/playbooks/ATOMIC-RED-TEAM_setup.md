# Playbook — Atomic Red Team (framework)

## Cos'è

[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (Red Canary) è una libreria
open-source di **test atomici**: piccoli script che riproducono una **singola tecnica MITRE ATT&CK**
con comandi reali e documentati. È lo standard de-facto per il *detection engineering*: invece di
inventare i comandi a mano, lanci il test ufficiale e verifichi se la tua regola scatta.

Si usa tramite il modulo PowerShell **Invoke-AtomicRedTeam**.

> ⚠️ Eseguire **solo dentro le VM del lab** (`target-windows` / `target-linux`). Ogni test ha una
> procedura di cleanup; molti creano persistenza o file — non lanciarli su sistemi reali.

---

## Installazione (nella VM `target-windows`)

```powershell
# PowerShell come amministratore
# 1. Permetti l'esecuzione e installa il modulo + le cartelle dei test (atomics)
Set-ExecutionPolicy Bypass -Scope Process -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force

# 2. Importa il modulo
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

> Nota: l'installer scarica gli "atomics" in `C:\AtomicRedTeam\atomics`. Defender potrebbe flaggare
> alcuni test: per il lab puoi escludere la cartella o disattivare la real-time protection durante i test.

---

## Uso

```powershell
# Vedere i dettagli di una tecnica (cosa fa, prerequisiti)
Invoke-AtomicTest T1059.001 -ShowDetailsBrief

# Controllare/installare i prerequisiti di un test
Invoke-AtomicTest T1003.001 -GetPrereqs

# Eseguire test specifici
Invoke-AtomicTest T1059.001 -TestNumbers 1,2

# Eseguire TUTTI i test di una tecnica
Invoke-AtomicTest T1547.001

# Cleanup (sempre dopo!)
Invoke-AtomicTest T1547.001 -Cleanup
```

---

## Tecniche mappate alle regole del lab

Lancia questi e verifica gli alert custom su Wazuh (`agent.name: target-windows`):

| Tecnica Atomic | Cosa testa | Regola custom attesa |
|---|---|---|
| `T1059.001` | PowerShell offensivo (encoded, hidden) | 100021 / 100063 |
| `T1547.001` | Registry Run key persistence | 100022 / 100080 |
| `T1053.005` | Scheduled task | 100026 / 100070 |
| `T1003.001` | LSASS dumping | 100025 / 100033 |
| `T1490` | Shadow copy deletion | 100030 |
| `T1562.001` | Disable Windows Defender | 100095 |
| `T1070.001` | Clear Windows event logs | 100096 |
| `T1218` | LOLBins (mshta, regsvr32, rundll32) | 100024 |
| `T1566.001` | Office → child process | 100020 |

### Linux (`target-linux`)

```bash
# Installazione su Ubuntu
sudo pwsh -c "IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics"
# Esempi
Invoke-AtomicTest T1110.001   # SSH brute force  -> regola 100001
Invoke-AtomicTest T1053.003   # cron job         -> regola 100071
```

---

## Come verificare su Wazuh

Per ogni tecnica lanciata, sulla Dashboard:

```
agent.name: "target-windows" AND rule.mitre.technique: "<nome tecnica>"
```

oppure filtra per il `rule.id` custom corrispondente (tabella sopra). Confronta il `commandLine`
dell'alert con il comando lanciato da Atomic per confermare il match.

---

## Workflow consigliato (detection engineering)

1. **Lancia** il test atomico di una tecnica.
2. **Verifica** se scatta la regola custom attesa.
3. Se **non** scatta → controlla in `wazuh-logtest` quale regola matcha l'evento e affina il
   `<field>`/regex della regola custom.
4. **Cleanup** del test.
5. **Documenta** il risultato in un write-up `detections/DET-XXX.md` (alert JSON reale + analisi).

> Questo ciclo *attacco → detection → tuning → write-up* è esattamente il lavoro di un detection engineer.
