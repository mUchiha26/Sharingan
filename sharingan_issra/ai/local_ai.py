import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5:0.5b"

def ask_ollama(prompt: str) -> str:
    payload = {"model": MODEL, "prompt": prompt, "stream": False}
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=300)
        response.raise_for_status()
        return response.json().get("response", "").strip()
    except requests.exceptions.ConnectionError:
        return "ERROR: Ollama not running. Run: ollama serve"
    except requests.exceptions.Timeout:
        return "ERROR: Ollama timed out"
    except Exception as e:
        return f"ERROR: {str(e)}"

def build_prompt(findings: list) -> str:
    lines = [
        "You are an expert penetration tester.",
        "Analyze these recon findings and provide:",
        "1. Most critical attack to attempt first and why",
        "2. Step-by-step attack plan for the top 3 findings",
        "3. CVEs likely to apply based on services and versions",
        "4. Exact Metasploit modules to use if applicable",
        "5. If emails found — phishing or password spray opportunities",
        "\nFINDINGS:"
    ]
    for f in findings:
        if f["type"] == "port":
            lines.append(f"- Port {f['value']} | Service: {f['service']} {f.get('version','')} | Risk: {f['category']}")
        elif f["type"] == "subdomain":
            lines.append(f"- Subdomain: {f['value']} | Type: {f['category']}")
        elif f["type"] == "email":
            lines.append(f"- Email found: {f['value']} (potential phishing/spray target)")
        elif f["type"] == "ip":
            lines.append(f"- IP discovered: {f['value']}")
    lines.append("\nBe specific, technical, and actionable. Keep response under 300 words.")
    return "\n".join(lines)
