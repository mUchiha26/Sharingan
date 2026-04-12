import json
import os

def classify_subdomain(subdomain: str) -> str:
    name = subdomain.lower()
    if any(k in name for k in ["mail", "smtp", "imap", "mx"]):       return "mail_server"
    elif any(k in name for k in ["vpn", "remote", "access"]):         return "vpn_gateway"
    elif any(k in name for k in ["dev", "staging", "test", "beta"]):  return "dev_environment"
    elif any(k in name for k in ["admin", "panel", "dashboard"]):     return "admin_panel"
    elif any(k in name for k in ["api", "rest", "graphql"]):          return "api_endpoint"
    elif any(k in name for k in ["ftp", "sftp", "files"]):            return "file_server"
    elif any(k in name for k in ["db", "database", "mysql"]):         return "database"
    else:                                                               return "general"

def classify_port(port: dict) -> str:
    service = port.get("service", "").lower()
    p = port.get("port", "")
    if service in ["http", "https"] or p in ["80", "443", "8080", "8443"]: return "web_server"
    elif service == "ftp"  or p == "21":   return "file_server"
    elif service == "ssh"  or p == "22":   return "ssh"
    elif service in ["smb", "microsoft-ds"] or p in ["445", "139"]:        return "smb"
    elif service in ["mysql", "postgresql"] or p in ["3306", "5432"]:      return "database"
    elif service in ["smtp", "imap"] or p in ["25", "143"]:                return "mail_server"
    elif service == "rdp"    or p == "3389": return "rdp"
    elif service == "telnet" or p == "23":   return "telnet"
    else: return "general"

def parse_amass(amass_result: dict) -> list:
    return [{"type": "subdomain", "value": s, "category": classify_subdomain(s), "target": amass_result["target"]}
            for s in amass_result.get("subdomains", [])]

def parse_nmap(nmap_result: dict) -> list:
    return [{"type": "port", "value": f"{p['port']}/{p['protocol']}", "service": p["service"],
             "version": p["version"], "category": classify_port(p), "target": nmap_result["target"]}
            for p in nmap_result.get("ports", [])]

def save_parsed(data: list, filename: str, output_dir: str = "data/processed"):
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[*] Parsed data saved → {path}")
    return path

def parse_harvester(harvester_result: dict) -> list:
    """Convert harvester results into findings list for AI analysis."""
    findings = []
    target = harvester_result.get("target", "unknown")

    for email in harvester_result.get("emails", []):
        findings.append({
            "type":     "email",
            "value":    email,
            "category": "mail_server",
            "target":   target
        })

    for host in harvester_result.get("hosts", []):
        findings.append({
            "type":     "subdomain",
            "value":    host,
            "category": classify_subdomain(host),
            "target":   target
        })

    for ip in harvester_result.get("ips", []):
        findings.append({
            "type":     "ip",
            "value":    ip,
            "category": "general",
            "target":   target
        })

    return findings
