# ࿋ Sharingan — AI-Assisted Red Team Framework

## 📌 Overview

**Sharingan** is an AI-assisted offensive security framework that automates reconnaissance, analysis, and attack suggestions while complementing manual penetration testing.

> ⚠️ Sharingan is not an autonomous hacking system.  
> Human validation is required at every stage.

---

## 🎯 Objectives

- Automate recon & scanning
- Provide AI-driven attack suggestions
- Map findings to standard frameworks
- Generate structured security reports

---

## ⚖️ Toolset Split

### ⚙️ Sharingan (Automated)

- Nmap, Amass, theHarvester, Shodan
- ffuf, Wappalyzer, Nikto
- John the Ripper
- AI: Ollama (local) / OpenAI (cloud)

👉 Used for speed, coverage, and pattern detection

---

### 🧠 Manual Tools

- Burp Suite
- Aircrack-ng
- Metasploit

👉 Required for:

- Business logic flaws
- Advanced exploitation
- Context-based attacks

---

## 🧠 AI Strategy (Hybrid)

- **Local AI** → fast, lightweight analysis
- **Cloud AI** → complex reasoning & scaling

---

## 📁 Project Structure

```
ai_red_team_tool/
│
├── main.py                  # Entry point
│
├── config/
│   └── settings.yaml        # API keys, tool configs
│
├── recon/                   # Reconnaissance modules
│   ├── nmap_scan.py
│   ├── amass_enum.py
│   ├── shodan_lookup.py
│   └── harvester.py
│
├── web/                     # Web scanning modules
│   ├── ffuf_scan.py
│   ├── wappalyzer_scan.py
│   └── nikto_scan.py
│
├── cracking/                # Password attacks
│   └── john_crack.py
│
├── wifi/                    # Wireless (manual-assisted)
│   └── aircrack_module.py
│
├── ai/                      # 🧠 Intelligence Layer
│   ├── local_ai.py          # Local model interface
│   ├── cloud_ai.py          # API-based AI
│   └── attack_decision_engine.py  # MITRE ATT&CK-based prioritization logic
│
├── core/                    # ⚙️ Core Components
│   ├── orchestrator.py      # Controls full workflow
│   ├── parser.py            # Converts outputs → JSON
│   └── utils.py             # Shared helpers
│
├── reports/                 # 📊 Reporting System
│   └── report_generator.py  # Builds final reports
│
├── data/
│   ├── raw/                 # Raw tool outputs
│   └── processed/           # Parsed structured data
│
└── knowledge_base/
  └── mitre_attack_knowledge_base.json  # MITRE ATT&CK mapping hub
```

---

## 📊 Reporting

Each report includes:

- Vulnerabilities found
- Mapping to **MITRE ATT&CK**
- Related exploit methods (e.g. Metasploit)
- Recommended attacks
- Remediation steps

---

## 📚 Standards & References

- NIST SP 800-115 – Technical Guide to Information Security Testing  
  https://csrc.nist.gov/publications/detail/sp/800-115/final

- PTES – Penetration Testing Execution Standard  
  http://www.pentest-standard.org

- OWASP Web Security Testing Guide  
  https://owasp.org/www-project-web-security-testing-guide/

- MITRE ATT&CK Framework (classification reference)  
  https://attack.mitre.org

- NIST AI Risk Management Framework  
  https://www.nist.gov/itl/ai-risk-management-framework

---

## 🤝 Acknowledgments

- Open-source security community
- Contributors to tools like Nmap, Metasploit, and ffuf
- AI platforms enabling intelligent automation

---

## 📬 Contact

**Maintainer**: Yasseene  
**GitHub**: [@mUchiha26](https://github.com/mUchiha26)  
For collaboration or questions, open an issue or contact via GitHub

---

## ⚠️ Disclaimer

For educational and authorized testing only. Unauthorized use is prohibited.

---

## ࿋ Final Note

Sharingan combines:

> 🤖 Automation + 🧠 Human expertise = Effective Red Teaming
