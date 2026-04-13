from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.core.attack_decision_engine import DEFAULT_ATTACK_KB_PATH, prioritize_findings


_DEFAULT_KB_PATH = DEFAULT_ATTACK_KB_PATH


def classify_subdomain(subdomain: str) -> str:
    name = subdomain.lower()
    if any(k in name for k in ["mail", "smtp", "imap", "mx"]):
        return "mail_server"
    if any(k in name for k in ["vpn", "remote", "access"]):
        return "vpn_gateway"
    if any(k in name for k in ["dev", "staging", "test", "beta"]):
        return "dev_environment"
    if any(k in name for k in ["admin", "panel", "dashboard"]):
        return "admin_panel"
    if any(k in name for k in ["api", "rest", "graphql"]):
        return "api_endpoint"
    if any(k in name for k in ["ftp", "sftp", "files"]):
        return "file_server"
    if any(k in name for k in ["db", "database", "mysql"]):
        return "database"
    return "general"


def classify_port(port: dict[str, Any]) -> str:
    service = str(port.get("service", "")).lower()
    port_number = str(port.get("port", ""))

    if service in ["http", "https"] or port_number in ["80", "443", "8080", "8443"]:
        return "web_server"
    if service == "ftp" or port_number == "21":
        return "file_server"
    if service == "ssh" or port_number == "22":
        return "ssh"
    if service in ["smb", "microsoft-ds"] or port_number in ["445", "139"]:
        return "smb"
    if service in ["mysql", "postgresql"] or port_number in ["3306", "5432"]:
        return "database"
    if service in ["smtp", "imap"] or port_number in ["25", "143"]:
        return "mail_server"
    if service == "rdp" or port_number == "3389":
        return "rdp"
    if service == "telnet" or port_number == "23":
        return "telnet"
    return "general"


def parse_amass(amass_result: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "type": "subdomain",
            "value": subdomain,
            "category": classify_subdomain(subdomain),
            "target": amass_result.get("target", "unknown"),
        }
        for subdomain in amass_result.get("subdomains", [])
    ]


def parse_nmap(nmap_result: Any) -> list[dict[str, Any]]:
    if isinstance(nmap_result, dict):
        target = nmap_result.get("target", "unknown")
        ports = nmap_result.get("ports", []) or nmap_result.get("open_ports", [])
    else:
        target = getattr(nmap_result, "target", "unknown")
        ports = getattr(nmap_result, "open_ports", [])

    findings: list[dict[str, Any]] = []
    for port in ports:
        port_num = str(port.get("port", ""))
        protocol = str(port.get("protocol", "tcp"))
        findings.append(
            {
                "type": "port",
                "value": f"{port_num}/{protocol}",
                "service": str(port.get("service", "")),
                "version": str(port.get("version", "")),
                "category": classify_port(port),
                "target": target,
            }
        )
    return findings


def parse_harvester(harvester_result: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    target = harvester_result.get("target", "unknown")

    for email in harvester_result.get("emails", []):
        findings.append({"type": "email", "value": email, "category": "mail_server", "target": target})

    for host in harvester_result.get("hosts", []):
        findings.append(
            {"type": "subdomain", "value": host, "category": classify_subdomain(host), "target": target}
        )

    for ip_addr in harvester_result.get("ips", []):
        findings.append({"type": "ip", "value": ip_addr, "category": "general", "target": target})

    return findings


def save_parsed(data: list[dict[str, Any]], filename: str, output_dir: str = "data/processed") -> str:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / filename
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return str(path)


def enrich_with_kb(findings: list[dict[str, Any]], kb_path: Path = _DEFAULT_KB_PATH) -> list[dict[str, Any]]:
    return prioritize_findings(findings, kb_path)


def to_report_findings(enriched_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    report_findings: list[dict[str, Any]] = []
    for finding in enriched_findings:
        report_findings.append(
            {
                "title": f"{finding.get('category', 'general').replace('_', ' ').title()} detected",
                "mitre": finding.get("mitre", "T1595"),
                "description": (
                    f"{finding.get('type', 'item')} {finding.get('value', 'unknown')} on "
                    f"{finding.get('target', 'unknown')} (severity: {finding.get('severity', 'low')})."
                ),
            }
        )
    return report_findings
