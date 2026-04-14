"""Implement AI provider calls through an Ollama-compatible OpenAI client."""

from typing import Any

from openai import OpenAI
from src.ai.base_provider import BaseAIProvider


class OllamaClient(BaseAIProvider):
    def __init__(
        self,
        base_url: str = "http://localhost:11434/v1",
        model: str = "qwen3.5-9b-unredacted:latest",
        timeout: int = 120,
    ):
        self.client = OpenAI(base_url=base_url, api_key="ollama", timeout=timeout)
        self.model = model
        self.base_url = base_url
        self.timeout = timeout

    def is_available(self) -> bool:
        try:
            self.client.models.list()
            return True
        except Exception:
            return False

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system_prompt},
                      {"role": "user", "content": user_prompt}]
        )
        return resp.choices[0].message.content or ""

    def build_recon_prompt(self, findings: list[dict[str, Any]]) -> str:
        """Build a pentester-focused analysis prompt from recon findings.

        Suitable for tool output analysis and attack planning.
        """
        lines = [
            "You are an expert penetration tester with deep knowledge of network security,",
            "MITRE ATT&CK tactics, and exploitation techniques.",
            "",
            "Analyze these recon findings and provide:",
            "1. Most critical attack path to attempt first and why",
            "2. Step-by-step attack plan for the top 3 findings",
            "3. CVEs likely to apply based on services and versions",
            "4. Exact Metasploit modules or tools to use if applicable",
            "5. High-value targets for credential harvesting or lateral movement",
            "",
            "FINDINGS:",
        ]

        for finding in findings:
            f_type = finding.get("type", "unknown")
            value = finding.get("value", "")
            category = finding.get("category", "general")

            if f_type == "port":
                service = finding.get("service", "unknown")
                version = finding.get("version", "")
                severity = finding.get("severity", "unknown")
                lines.append(
                    f"- Port {value} | Service: {service} {version} | "
                    f"Category: {category} | Severity: {severity}"
                )
            elif f_type == "subdomain":
                lines.append(f"- Subdomain: {value} | Category: {category}")
            elif f_type == "email":
                lines.append(f"- Email: {value} (potential spear-phishing or password spray target)")
            elif f_type == "ip":
                lines.append(f"- IP: {value} (potential lateral movement target)")
            else:
                lines.append(f"- {f_type}: {value} (Category: {category})")

        lines.append("")
        lines.append(
            "Be specific, technical, and actionable. "
            "Prioritize findings by exploitability and business impact."
        )
        lines.append("Keep response under 400 words.")
        return "\n".join(lines)