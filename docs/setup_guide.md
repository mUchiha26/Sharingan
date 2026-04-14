# 🛠️ Sharingan Full Setup Guide

## Prerequisites

### System Dependencies

You'll need standard penetration testing tools installed at the OS level.

**Ubuntu/Debian:**

```bash
sudo apt update && sudo apt install -y \
  nmap aircrack-ng amass theharvester \
  build-essential libpango-1.0-0 libcairo2 \
  python3-dev python3-venv
```

**macOS (with Homebrew):**

```bash
brew install nmap aircrack-ng amass theharvester
```

### Python Environment

**Python 3.10+** is required.

Install **Poetry** (the Python package manager):

```bash
curl -sSL https://install.python-poetry.org | python3 -
export PATH="$HOME/.local/bin:$PATH"

# Verify installation
poetry --version  # Should show 1.8.0+
```

### AI Backend (Optional but Recommended)

#### Option 1: Local AI (Recommended for Privacy)

Install **Ollama** and pull the Qwen model:

```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull qwen2.5:7b        # ~3.6 GB, runs on CPU/GPU
ollama serve                  # Start the server (runs at http://localhost:11434)
```

#### Option 2: Cloud AI (For Complex Analysis)

Get an API key from [OpenRouter.ai](https://openrouter.ai/):

1. Create account
2. Navigate to API Keys
3. Copy your API key
4. Save it to `.env` (see Configure Environment below)

---

## Installation Steps

### 1. Clone Repository

```bash
git clone https://github.com/mUchiha26/Sharingan.git
cd Sharingan
```

### 2. Install Python Dependencies

```bash
poetry install
```

This creates an isolated virtual environment and installs all dependencies from `pyproject.toml`.

### 3. Configure Environment

Copy the template:

```bash
cp .env.example .env
```

Edit with your settings (optional for local-only mode):

```bash
nano .env
```

**Example `.env` content:**

```
# AI Configuration (optional)
OPENROUTER_API_KEY=sk-or-...        # Leave blank for local-only mode
OLLAMA_BASE_URL=http://localhost:11434/v1

# Logging
SHARINGAN_LOG_LEVEL=INFO

# Scope (optional)
AUTHORIZED_TARGETS=127.0.0.1,10.0.0.0/24
```

### 4. Verify Installation

Test that the CLI works:

```bash
poetry run python -m src.main --help
```

Run a safe local test (shows configuration):

```bash
poetry run python -m src.main --config
```

---

## Configuration Reference

### Configuration Files

| File               | Purpose                        | Committed?                  |
| ------------------ | ------------------------------ | --------------------------- |
| `config/base.yaml` | Framework defaults & structure | ✅ Yes                      |
| `.env`             | Secrets & runtime overrides    | ❌ No (add to `.gitignore`) |
| `.env.example`     | Template for `.env`            | ✅ Yes                      |

### config/base.yaml Structure

**Core Settings:**

```yaml
core:
  name: "Sharingan"
  log_level: "INFO" # DEBUG, INFO, WARNING, ERROR
  authorized_targets: # CRITICAL: Only these can be scanned
    - "127.0.0.1"
    - "10.0.0.0/24"
  enforce_scope: true # Reject targets outside authorized list
```

**Nmap Configuration:**

```yaml
tools:
  nmap:
    allowed_args: # Whitelist of safe nmap flags
      - "-sV" # Service version detection
      - "-T3" # Timing template
      - "-p-" # All ports
      - "-O" # OS detection
    disallowed_args: # Blocked dangerous flags
      - "--script=exploit"
      - "-sS" # SYN scan (sometimes requires root)
    timeout: 300 # Seconds
```

**AI Configuration:**

```yaml
ai:
  provider: "ollama" # "ollama" or "openrouter"
  base_url: "http://localhost:11434/v1"
  model: "qwen2.5:7b"
  max_tokens: 2048
  temperature: 0.3 # Lower = more deterministic
  timeout: 120 # Seconds
```

**Report Settings:**

```yaml
reports:
  output_dir: "./reports"
  formats: # Enable/disable output formats
    - "json"
    - "pdf"
  include:
    - "summary"
    - "detailed_findings"
    - "attack_paths"
    - "remediation"
```

**Security Settings:**

```yaml
security:
  rate_limit: 10 # Max requests per second
  enforce_scope: true # Strict target validation
  audit_file: "./data/audit/audit.jsonl"
```

### Environment Variables

| Variable               | Purpose                             | Required | Default                     |
| ---------------------- | ----------------------------------- | -------- | --------------------------- |
| `OPENROUTER_API_KEY`   | Cloud AI authentication             | No       | `""`                        |
| `OLLAMA_BASE_URL`      | Local AI endpoint                   | No       | `http://localhost:11434/v1` |
| `SHARINGAN_LOG_LEVEL`  | Logging verbosity                   | No       | `INFO`                      |
| `AUTHORIZED_TARGETS`   | Override scopes from config         | No       | From `config/base.yaml`     |
| `DEV_SKIP_SCOPE_CHECK` | Bypass scope enforcement (dev only) | No       | `0`                         |

---

## Running Sharingan

### Interactive Mode (Recommended for Beginners)

```bash
poetry run python -m src.main <target>
# Example:
poetry run python -m src.main scanme.nmap.org
```

### Config-Driven Mode (For Automation)

```bash
poetry run python -m src.main --config
# Uses target from config/base.yaml
```

### CLI Tool Selection

```bash
# Nmap scan only
poetry run python -m scripts.run_scan --tool nmap --target 127.0.0.1

# Aircrack-ng analysis
poetry run python -m scripts.run_scan --tool aircrack --target capture.cap --wordlist rockyou.txt
```

---

## Docker Setup (Production/Isolated)

### Build Docker Image

```bash
docker build -t sharingan:latest .
```

### Run Container with Persistence

```bash
docker run -it --rm \
  -v $(pwd)/config:/app/config:ro \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/data:/app/data \
  -e OPENROUTER_API_KEY=${OPENROUTER_API_KEY:-} \
  sharingan:latest --help
```

### Run a Scan in Docker

```bash
docker run -it --rm \
  -v $(pwd)/config:/app/config:ro \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/data:/app/data \
  sharingan:latest -m src.main 10.0.0.5
```

---

## Troubleshooting

### Error: `poetry: command not found`

Poetry isn't in your PATH. Add it:

```bash
export PATH="$HOME/.local/bin:$PATH"
# Add to ~/.bashrc or ~/.zshrc for permanent addition
```

### Error: `nmap not found`

Re-install nmap from source or OS package manager:

```bash
sudo apt install nmap          # Debian/Ubuntu
brew install nmap              # macOS
```

### Error: `ImportError: No module named 'nmap'`

The Python `nmap` package isn't installed. Use Poetry:

```bash
poetry install
```

If poetry still fails, you might have a stale virtual environment:

```bash
poetry env remove $(poetry env list | awk '{print $1}')
poetry install
```

### Error: `Ollama connection refused`

Ollama isn't running. Start it in a separate terminal:

```bash
ollama serve
```

It will start at `http://localhost:11434` by default.

### Error: Target outside authorized scope

You tried to scan a target not in `config/base.yaml` or `.env`. Either:

1. Add it to `authorized_targets` in the config
2. Override via environment: `export AUTHORIZED_TARGETS="10.0.0.5"`
3. Disable (dev only): `export DEV_SKIP_SCOPE_CHECK=1`

### Error: PDF reports fail to generate

WeasyPrint requires system libraries. Install them:

```bash
sudo apt install libpango-1.0-0 libcairo2 libgdk-pixbuf-2.0-0
```

### Error: Import errors after directory rename

Clear Python cache:

```bash
find . -type d -name __pycache__ -exec rm -rf {} +
find . -name "*.pyc" -delete

# Reinstall in dev mode:
poetry install
```

---

## Next Steps After Setup

✅ Run `poetry run pytest -q` to verify tests pass  
✅ Review `config/base.yaml` and update `authorized_targets`  
✅ Test AI integration: `poetry run python -m src.main --config`  
✅ Explore [testing_guide.md](testing_guide.md) for extending the framework  
✅ Read [TECHNICAL_ARCHITECTURE.md](design/TECHNICAL_ARCHITECTURE.md) for deep architecture understanding

---

## Need Help?

- **Issues**: [GitHub Issues](https://github.com/mUchiha26/Sharingan/issues)
- **Discussions**: [GitHub Discussions](https://github.com/mUchiha26/Sharingan/discussions)
- **Code**: [GitHub Repository](https://github.com/mUchiha26/Sharingan)
