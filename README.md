# 4postle 🛡️

**End‑to‑End Web Vulnerability Scanner for Bug Bounty & Pentesting**

4postle is a full‑stack, modular web vulnerability scanning framework designed to discover **real, exploitable security issues** — not noisy false positives. It combines **passive + active reconnaissance**, **intelligent attack surface expansion**, **validated vulnerability detection**, and **professional reporting**, powered by **Kali Linux** and **ProjectDiscovery tooling**.

---

## 🚀 Features

* 🔍 **Full Recon Pipeline** – passive & active discovery
* 🧠 **Smart Vulnerability Detection** – context‑aware scanning
* ✅ **Validation First** – no unverified findings
* ⚙️ **Tool‑Driven** – ProjectDiscovery + Kali best‑in‑class tools
* 📊 **Frontend‑Friendly** – real‑time scan progress & exports
* 📝 **Bug‑Bounty Ready Reports** – HackerOne / Bugcrowd style

---

## 🧱 Architecture Overview

```
Frontend (Dashboard)
   │
   ▼
Backend Orchestrator
   │
   ├─ Recon Engine
   ├─ Surface Expansion Engine
   ├─ Vulnerability Engine
   ├─ Validation Engine
   └─ Reporting Engine
```

4postle runs each phase **sequentially**, adapting scans based on discovered technologies and scope rules.

---

## 🔎 Scanning Phases

### 1️⃣ Passive Reconnaissance (No Target Interaction)

**Goal:** Identify assets without touching the target directly.

**Tools:**

* subfinder
* amass (passive)
* assetfinder
* crt.sh
* gau / waybackurls
* httpx (tech detect)

**Output:**

* Subdomains
* IP ranges
* Technologies
* Historical endpoints

---

### 2️⃣ Active Reconnaissance (Low Noise)

**Goal:** Confirm live assets & exposed services.

**Tools:**

* httpx
* dnsx
* naabu (top ports)
* whatweb

**Output:**

* Live hosts
* Open ports
* Web services
* Security headers

---

### 3️⃣ Attack Surface Expansion

**Goal:** Discover hidden and forgotten entry points.

**Tools:**

* ffuf / dirsearch
* paramspider
* arjun
* linkfinder
* jsluice

**Output:**

* Parameters
* Admin panels
* APIs
* Sensitive paths

---

### 4️⃣ Vulnerability Scanning

**Goal:** Identify vulnerabilities with context.

**Covered Classes:**

* XSS (Reflected, Stored, DOM)
* SQLi / NoSQLi
* IDOR / BOLA
* SSRF
* CSRF
* LFI / RFI
* File Upload
* CORS
* Auth & Logic flaws

**Tools:**

* nuclei (custom + community)
* dalfox
* sqlmap (targeted)
* kxss
* corscanner
* jwt_tool

---

### 5️⃣ Validation Engine (Critical Phase)

**Goal:** Eliminate false positives.

Every finding must:

* Be reproducible
* Show impact
* Include proof (request/response)
* Be exploitable within scope

❌ Informational noise is discarded.

---

### 6️⃣ Risk Scoring

Findings are ranked using:

* Severity (Critical → Low)
* Exploitability
* Business impact
* Attack complexity

---

### 7️⃣ Reporting

**Output Formats:**

* JSON
* Markdown
* PDF

**Each report includes:**

* Vulnerability description
* Endpoint & parameter
* Proof of Concept (PoC)
* Impact
* Remediation
* OWASP / CWE references

---

## 🖥️ Frontend Capabilities

* Live scan phase tracking
* Tools currently running
* Discovered assets
* Confirmed vulnerabilities
* Severity charts
* Raw logs & HTTP requests
* Exportable reports

---

## ⚙️ Installation

### Requirements

* Kali Linux (recommended)
* Go ≥ 1.20
* Python ≥ 3.10
* Node.js (for frontend)

### Tool Setup

```
subfinder, httpx, nuclei, naabu, dnsx
ffuf, dalfox, sqlmap, amass
```

---

## 🧪 Usage

```
4postle scan --target https://example.com --scope scope.txt
```

Optional flags:

* `--passive-only`
* `--deep`
* `--stealth`
* `--export pdf`

---

## 🔐 Legal Notice

4postle is intended **only for authorized security testing**.

You must:

* Have explicit permission
* Respect scope boundaries
* Avoid denial‑of‑service attacks

The authors are **not responsible for misuse**.

---

## 🎯 Philosophy

> Fast scans don’t find bugs.
> **Smart scans get paid.**

4postle thinks like a **human bug hunter**, not a noisy scanner.

---

## 🤝 Contributing

Contributions welcome:

* Custom nuclei templates
* New detection modules
* Reporting improvements

---

## 📜 License

MIT License

---

**4postle – Recon. Validate. Exploit. Report.**
