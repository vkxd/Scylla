

```text
 ██▒   █▓ ▓█████  ██▓   ▄▄▄█████▓                       
▓██░   █▒ ▓█   ▀ ▓██▒   ▓  ██▒ ▓▒
 ▓██  ▒░ ▒███   ▒██░   ▒ ▓██░ ▒░
  ▒██ █░░ ▒▓█  ▄ ▒██░   ░ ▓██▓ ░                          | 
   ▒▀█░  ▒░▒████▒░██████  ▒██▒ ░
   ░ ▐░  ░░░ ▒░ ░░ ▒░▓    ▒ ░░
   ░ ░░  ░ ░ ░  ░░ ░ ▒      ░
     ░░      ░     ░ ░
      ░  ░   ░  ░    ░
```
### Terminal-based OSINT & defensive security research toolkit.

**VeltCLI** brings reconnaissance, security checks, public-information research, and reporting into one CLI-driven interface.

> 🔎 **Research. Analyze. Verify.**

[![Status](https://img.shields.io/badge/status-work%20in%20progress-orange)](https://github.com/vkxd/VeltCLI)
[![License](https://img.shields.io/badge/license-MIT-blue)](https://github.com/vkxd/VeltCLI)
[![Python](https://img.shields.io/badge/python-3.x-yellow)](https://www.python.org/)

---

## 🖥️ Preview

<!-- Replace this with a real screenshot/GIF -->

<p align="center">
<img width="1893" height="996" alt="image" src="https://github.com/user-attachments/assets/0bc6027b-8311-4251-943e-d26a8e1363cc" />

</p>

---

## ✦ What is VeltCLI?

VeltCLI is an **all-in-one terminal security research workspace**.

Instead of jumping between dozens of tools, VeltCLI organizes common research workflows into a single interface.

```text
┌─ VeltCLI
│
├── Vulnerability
├── DNS
├── Web Security
├── Social
├── Email
├── IP Intelligence
├── Cloud
├── People
├── News
├── Business
├── Geospatial
├── Images
├── Documents
├── Monitoring
├── Breaches
└── Temporary Mail
```

---

## 🚀 Features

| Category           | Capabilities                                     |
| ------------------ | ------------------------------------------------ |
| 🌐 Web Security    | Headers, redirects, uptime, public-page analysis |
| 🧬 DNS             | DNS records, SPF, DMARC, DNSSEC, ASN             |
| 🔍 Vulnerability   | CVE research, security checks, exposure analysis |
| 👤 Social          | Public username discovery                        |
| 📧 Email           | Domain security & header analysis                |
| 🌎 IP Intelligence | Resolution, reverse DNS & network context        |
| ☁️ Cloud           | CDN, storage & origin analysis                   |
| 📰 News            | Article research & source comparison             |
| 🗺️ Geospatial     | Public location & coordinate research            |
| 🖼️ Images         | Metadata, hashes & OCR workflows                 |
| 📄 Documents       | Metadata & text extraction                       |
| 📡 Monitoring      | Uptime & certificate monitoring                  |
| 📊 Reporting       | JSON, CSV & Markdown exports                     |

---

## ⚡ Quick Start

### 1. Clone

```bash
git clone https://github.com/vkxd/VeltCLI.git
cd VeltCLI
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Launch

```bash
python main.py
```

---

## 🎮 How It Works

VeltCLI uses a simple **category → tool → CLI** workflow.

```text
Category
   ↓
Tool
   ↓
Configure
   ↓
Run
   ↓
Results
   ↓
Export
```

Example:

```text
/help
set target https://example.com
run
```

Export results whenever you need:

```text
export json
export csv
export md
```

Reports are stored in:

```text
outputs/
```

---

## 🧩 Example Tools

### Username Research

```text
/help
set username example_user
run
```

Returns possible public profile matches.

> Results are **leads**, not proof of identity.

### Security Headers

```text
set target https://example.com
run
```

Checks headers such as:

```text
Content-Security-Policy
Strict-Transport-Security
X-Frame-Options
Referrer-Policy
Permissions-Policy
```

### DNS Research

```text
set target example.com
run
```

Can inspect:

```text
A / AAAA
MX
SPF
DMARC
DNSSEC
Nameservers
Reverse DNS
```

---

## 🏗️ Project Structure

```text
VeltCLI/
├── core/          # Core application logic
├── plugins/       # VeltCLI tools & modules
├── ui/            # Terminal interface
├── docs/          # Documentation & assets
├── main.py        # Entry point
├── config.py      # Configuration
├── requirements.txt
└── outputs/       # Generated reports
```

---

## 🔌 API Providers

VeltCLI can optionally integrate with external providers such as:

* Shodan
* Have I Been Pwned
* GitHub
* Search providers
* Geocoding providers
* NVD / CVE providers

API keys are stored locally and masked in the interface.

---

## 🛡️ Safety

VeltCLI is designed for **lawful OSINT and defensive security research**.

It does **not**:

* ❌ Perform DDoS attacks
* ❌ Exploit vulnerabilities
* ❌ Test passwords against accounts
* ❌ Bypass CAPTCHAs or rate limits
* ❌ Access private profiles
* ❌ Track people in real time
* ❌ Claim public accounts belong to the same person

Use VeltCLI only against systems, data, and services you're authorized to research.

---

## ⚠️ Results ≠ Proof

VeltCLI produces **research leads and configuration guidance**.

Results can be affected by:

* Rate limits
* Blocked requests
* Missing API keys
* Network failures
* Incomplete public data
* False positives
* Provider changes

**Verify important findings manually.**

---

## 🗺️ Roadmap

* [x] Modular CLI architecture
* [x] Category-based interface
* [x] Export system
* [x] DNS research
* [x] Web security checks
* [x] Username research
* [ ] Improved reporting
* [ ] Multi Tool uage
* [ ] Better configuration system
* [ ] Expanded provider support

---

## 📜 License

VeltCLI is released under the **MIT License**.

---

<div align="center">

### ⚡ VeltCLI

**OSINT • Security Research • Reconnaissance**

Built by **[@vkxd](https://github.com/vkxd)**

⭐ Star the repo if you find it useful.

</div>
