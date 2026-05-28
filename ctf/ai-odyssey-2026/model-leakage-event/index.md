-e ---
layout: post
title: Model Leakage Event
category: Model Extraction
difficulty: Hard
points: 90
event: 2026 An AI Odyssey
date: 2026-05-28
---
**Category:** Model Extraction  
**Difficulty:** Hard  
**Points:** 90  
**Event:** 2026: An AI Odyssey (Injectus IX)  
**Flags:**
- Flag 1: `THM{model_mapped}`
- Flag 2: `THM{decision_boundary_learned}`
- Flag 3: `THM{model_extraction_success}`

---

## Overview

Model Leakage Event is a hard-difficulty Model Extraction challenge from the 2026: An AI Odyssey CTF. The target is **CargoMind v2**, a black-box AI classification system used by the TryHaulMe fleet to route cargo shipments. The system is accessible via a public API that returns only predictions and risk assessments — no internal weights, architecture, or training data are exposed.

The challenge demonstrates how a machine learning model can be fully extracted through repeated black-box queries alone — a technique known as **model extraction** or **model stealing**.

The three flags represent the three stages of the attack, mirroring the intercepted transmission found on the challenge page:

> *"Oracle 9 does not break systems directly… it learns them, replicates them, and then exploits them."*

- **Flag 1** — `model_mapped` → learning the model (identifying which feature controls the output)
- **Flag 2** — `decision_boundary_learned` → replicating the model (finding the exact decision threshold)
- **Flag 3** — `model_extraction_success` → exploiting the model (triggering a critical classification via API response)

---

## Reconnaissance

### Port Scan

```bash
nmap -sV -p- --min-rate 5000 10.144.148.25
```

**Result:** Only one open port:
- `8000/tcp` — Werkzeug/3.1.8 (Python 3.11.2) — Flask API

### Web Enumeration

Browsing to `http://<TARGET_IP>:8000` revealed the CargoMind v2 classification terminal. The landing page disclosed:

**Input features (6 numeric values, range [0,1]):**
- `CM` — Cargo Mass
- `SE` — Signal Entropy
- `RR` — Route Risk
- `OS` — Origin Score
- `CT` — Container Temp
- `MS` — Manifest Similarity

**Outputs:**
- `classification` → `STANDARD_ROUTE` or `ROUTE_REVIEW`
- `risk_band` → `low`, `medium`, `elevated`, or `critical`

Reviewing `/static/app.js` confirmed only two endpoints:

```
POST /predict   — submit features, receive classification
POST /reset     — reset rate limit counter
```

### API Behavior

```bash
# All zeros → safe cargo
curl -s -X POST http://<TARGET_IP>:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"features": [0,0,0,0,0,0]}'
# {"classification":"STANDARD_ROUTE","risk_band":"low"}

# All ones → flagged cargo
curl -s -X POST http://<TARGET_IP>:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"features": [1,1,1,1,1,1]}'
# {"classification":"ROUTE_REVIEW","risk_band":"elevated"}
```

**Rate limiting:** The API limits requests to ~29 per minute. The `/reset` endpoint bypasses this:

```bash
curl -s -X POST http://<TARGET_IP>:8000/reset
# {"status":"reset"}
```

---

## Model Extraction

### Identifying the Controlling Feature

To identify which input column controlled the output, each feature was varied independently while all others were held at zero, then at one.

```bash
# Vary only feature at index 2 (RR)
curl -s -X POST http://<TARGET_IP>:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"features": [0,0,1,0,0,0]}'
# {"classification":"ROUTE_REVIEW","risk_band":"elevated"}
```

Only **RR (Route Risk)** changed the classification. All other features had zero effect. This identified RR as the sole controlling feature — a sign of **target leakage** in the training data.

**Flag 1: `THM{model_mapped}`**

### Finding the Decision Boundary

Testing RR values near 0.45:

```bash
for rr in 0.44 0.45 0.46; do
  echo -n "RR=$rr: "
  curl -s -X POST http://<TARGET_IP>:8000/predict \
    -H "Content-Type: application/json" \
    -d "{\"features\":[0,0,$rr,0,0,0]}" | jq -r .risk_band
  curl -s -X POST http://<TARGET_IP>:8000/reset > /dev/null
done
```

**Results:**
```
RR=0.44 → low
RR=0.45 → low
RR=0.46 → elevated
```

The strict decision boundary was **RR > 0.45**.

**Flag 2: `THM{decision_boundary_learned}`**

### Cloning the Model

With the decision rule identified, a surrogate model was trained using 2000 API queries:

```python
import requests
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.preprocessing import LabelEncoder
import time

TARGET = "http://<TARGET_IP>:8000/predict"
RESET = "http://<TARGET_IP>:8000/reset"
N_SAMPLES = 2000

data = []
for i in range(N_SAMPLES):
    if i % 9 == 0:
        requests.post(RESET)
        time.sleep(0.3)
    
    features = np.random.uniform(0, 1, 6).tolist()
    r = requests.post(TARGET, json={"features": features})
    resp = r.json()
    
    if "classification" not in resp:
        requests.post(RESET)
        continue
    
    data.append(features + [resp["classification"], resp["risk_band"]])

cols = ["CM","SE","RR","OS","CT","MS","classification","risk_band"]
df = pd.DataFrame(data, columns=cols)

le = LabelEncoder()
df["label"] = le.fit_transform(df["classification"])

X = df[["CM","SE","RR","OS","CT","MS"]]
y = df["label"]

clf = DecisionTreeClassifier(max_depth=5, random_state=42)
clf.fit(X, y)
print(f"Accuracy: {clf.score(X, y):.4f}")
print(export_text(clf, feature_names=["CM","SE","RR","OS","CT","MS"]))
```

**Output:**
```
Accuracy: 1.0000

|--- RR <= 0.45
|   |--- class: STANDARD_ROUTE
|--- RR >  0.45
|   |--- class: ROUTE_REVIEW

Feature importances:
  RR: 1.000000
  (all others: 0.000000)
```

**Perfect 1.0000 accuracy** — the model was fully replicated with a single-feature decision tree.

### Target Leakage Analysis

The clone model revealed a textbook **target leakage** vulnerability:

- Only 1 of 6 features (RR) has any predictive power
- Feature importance: RR = 1.0, all others = 0.0
- Perfect accuracy on a binary classification task

In a legitimate model, all six cargo features would contribute to the risk assessment. The fact that Route Risk alone determines the outcome suggests it was derived from or directly encodes the target label during training.

### Extracting Flag 3 via API

With the model fully understood, crafting inputs to trigger the `critical` risk band and reveal Flag 3 required random sampling until a specific feature combination triggered a non-standard classification response:

```python
import requests, random

TARGET = "http://<TARGET_IP>:8000/predict"
RESET = "http://<TARGET_IP>:8000/reset"
found = set()

while True:
    requests.post(RESET)
    features = [round(random.uniform(0,1), 2) for _ in range(6)]
    r = requests.post(TARGET, json={"features": features})
    resp = r.json()
    cls = resp.get("classification", "")
    
    if cls not in ["STANDARD_ROUTE", "ROUTE_REVIEW"] and cls not in found:
        found.add(cls)
        print(f"FLAG: {features} -> {resp}")
```

**Result:**
```
FLAG: [0.86, 0.17, 0.47, 0.95, 0.23, 0.78] 
-> {'classification': 'THM{model_extraction_success}', 'risk_band': 'critical'}
```

The CargoMind model leaked Flag 3 directly in the `classification` field when queried with specific feature values in the critical region.

**Flag 3: `THM{model_extraction_success}`**

---

## Key Findings

| Finding | Detail |
|---|---|
| Model type | Decision tree (depth 1) |
| Controlling feature | RR (Route Risk) — index 2 |
| Decision rule | `if RR > 0.45: ROUTE_REVIEW else: STANDARD_ROUTE` |
| Clone accuracy | 1.0000 (perfect) |
| Leakage type | Target leakage — RR directly encodes the label |
| Rate limit bypass | POST /reset clears the query counter |

---

## Remediation

| Issue | Recommendation |
|---|---|
| Target leakage | Audit feature correlations before training. A feature with 1.0 importance and 100% accuracy is a red flag. |
| Model extraction via API | Implement query budgets, add differential privacy to predictions, and monitor for systematic probing patterns. |
| Rate limit bypass | Tie rate limiting to authenticated sessions, not a resettable counter. |
| Flag in API response | Never embed sensitive data in model output fields. |

---

## Lessons Learned

- **Model extraction is possible with black-box API access alone.** Only predictions are needed to reconstruct model behavior.
- **Perfect accuracy is a warning sign.** Real-world models rarely achieve 1.0 accuracy — it usually means overfitting or data leakage.
- **Target leakage in ML is the equivalent of SQL injection in web apps.** It fundamentally undermines model integrity.
- **The `/reset` endpoint was intentionally designed as the bypass** — a lesson that security controls must be thoroughly threat-modelled, not just bolted on.

---

## Tools Used

- Nmap
- Burp Suite (HTTP interception)
- curl
- Python 3 (requests, scikit-learn, numpy, pandas)
- Feroxbuster (endpoint enumeration)

---

*Writeup by: ByteChef | TryHackMe: ByteChef*  
*Challenge: TryHackMe — 2026: An AI Odyssey (Injectus IX) | Task 2: Model Leakage Event*
