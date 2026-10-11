# ⚡ AttackDNA — CVE Attack Chain Visualizer

> **Transform any CVE into an interactive, visual attack chain — powered by AI.**

![AttackDNA Screenshot](docs/screenshot.png)

---

## 🧬 What Is an Attack Chain?

An **attack chain** (also called a **cyber kill chain**) is the sequence of steps an attacker follows to compromise a system — from initial reconnaissance through exploitation to data exfiltration or system impact.

Understanding the chain matters because:

- **Defenders** can identify where to break the chain with detection controls
- **Security teams** can prioritize patching based on how exploitable a CVE actually is  
- **Executives** can understand risk in plain language, not just CVSS numbers
- **Red teamers** can model realistic attack paths during engagements

AttackDNA takes a CVE ID, fetches real vulnerability data from the [National Vulnerability Database (NVD)](https://nvd.nist.gov/), and uses Claude AI to generate a realistic, multi-phase attack chain mapped to the [MITRE ATT&CK](https://attack.mitre.org/) framework.

---

## 🚀 Features

| Feature | Description |
|---|---|
| **CVE Lookup** | Fetches real-time data from NVD API v2.0 |
| **AI Attack Chain** | Claude generates realistic multi-phase attack chains with MITRE ATT&CK mapping |
| **Interactive Graph** | D3.js force-directed visualization with drag, zoom, and pan |
| **Attacker / Defender Toggle** | Switch views to see detection points highlighted in green |
| **Node Details** | Click any phase to see tools, techniques, and MITRE ATT&CK links |
| **Keyword Search** | Search NVD by keyword to find relevant CVEs |
| **CEO Summary** | One-liner explanation for non-technical stakeholders |
| **Mobile Responsive** | Works on phones and tablets |
| **Graceful Errors** | Clear error messages — never crashes |

---

## 📦 Installation

### Prerequisites

- Python 3.9+
- An [Anthropic API key](https://console.anthropic.com/) (for AI-powered analysis)

### Setup

```bash
# 1. Clone and enter the project
git clone https://github.com/your-username/AttackDNA.git
cd AttackDNA

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure API key
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

---

## ▶️ How to Run

```bash
# Start the server
python backend/app.py
```

Then open your browser to **http://localhost:5000**

That's it — two commands.

---

## 🔍 Example CVEs to Try

| CVE ID | What It Is |
|---|---|
| `CVE-2024-3400` | Palo Alto PAN-OS Command Injection (Critical) |
| `CVE-2021-44228` | Log4Shell — Apache Log4j RCE (Critical) |
| `CVE-2023-34362` | MOVEit Transfer SQL Injection (Critical) |
| `CVE-2024-21762` | Fortinet FortiOS Out-of-Bounds Write (Critical) |
| `CVE-2023-44228` | Apache ActiveMQ RCE |
| `CVE-2023-23397` | Microsoft Outlook Privilege Escalation |
| `CVE-2024-1709` | ConnectWise ScreenConnect Authentication Bypass |

---

## 🏗️ Architecture

```
AttackDNA/
├── backend/
│   └── app.py              # Flask API server
├── frontend/
│   └── index.html           # Single-file SPA (D3.js + vanilla JS)
├── requirements.txt         # Python dependencies
├── .env.example            # Environment variable template
└── README.md               # This file
```

### API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Serves the frontend |
| `/api/cve/<cve_id>` | GET | Full CVE analysis + attack chain |
| `/api/search?q=keyword` | GET | Search NVD for CVEs (top 5) |
| `/api/health` | GET | Health check |

### Data Flow

```
User → Search CVE-2024-3400
  → Backend fetches NVD API
  → Extracts: description, CVSS, CWE, affected products
  → Sends to Claude AI with red team prompt
  → Validates JSON response
  → Returns combined data
  → Frontend renders D3.js attack chain
```

---

## ⚠️ Disclaimer

> **This tool is for educational purposes and authorized security research only.**
>
> AttackDNA is designed to help security professionals understand vulnerabilities and their potential attack paths. The attack chain analysis is AI-generated and represents *possible* scenarios, not definitive threat intelligence.
>
> - Do **NOT** use this tool to plan or execute unauthorized attacks
> - Always follow responsible disclosure practices  
> - Ensure you have proper authorization before performing any security testing
> - The AI-generated content may contain inaccuracies — always verify with authoritative sources
>
> The authors assume no liability for misuse of this tool.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  Built with 🧬 by security engineers, for security engineers.
</p>
