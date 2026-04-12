# Sharingan Report — `192.168.1.5`
**Generated:** 20260412_121452

---

## Rule-Based Findings

### [CRITICAL] `445/tcp`
- **Category:** smb
- **MITRE:** [T1021](https://attack.mitre.org/techniques/T1021)
- **Attacks:** eternalblue, pass_the_hash, null_session
- **Tools:** metasploit, crackmapexec

### [CRITICAL] `3306/tcp`
- **Category:** database
- **MITRE:** [T1190](https://attack.mitre.org/techniques/T1190)
- **Attacks:** default_creds, unauthenticated_access
- **Tools:** nmap, metasploit

### [HIGH] `80/tcp`
- **Category:** web_server
- **MITRE:** [T1190](https://attack.mitre.org/techniques/T1190)
- **Attacks:** directory_fuzzing, cve_scan, sqli, xss
- **Tools:** nikto, ffuf, burpsuite

### [HIGH] `8080/tcp`
- **Category:** web_server
- **MITRE:** [T1190](https://attack.mitre.org/techniques/T1190)
- **Attacks:** directory_fuzzing, cve_scan, sqli, xss
- **Tools:** nikto, ffuf, burpsuite

### [MEDIUM] `21/tcp`
- **Category:** file_server
- **MITRE:** [T1078](https://attack.mitre.org/techniques/T1078)
- **Attacks:** anonymous_login, brute_force
- **Tools:** hydra, ftp

### [MEDIUM] `22/tcp`
- **Category:** ssh
- **MITRE:** [T1021](https://attack.mitre.org/techniques/T1021)
- **Attacks:** brute_force, key_theft, default_creds
- **Tools:** hydra, ssh-audit

### [LOW] `631/tcp`
- **Category:** general
- **MITRE:** [T1595](https://attack.mitre.org/techniques/T1595)
- **Attacks:** port_scan, web_fingerprint
- **Tools:** nmap, whatweb

## AI Analysis (Mistral)

ERROR: Ollama timed out
