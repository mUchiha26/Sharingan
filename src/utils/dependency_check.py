"""
Dependency health checks for Sharingan.

Provides graceful fallbacks and clear error messages when required
system tools or Python packages are missing.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from src.core.logger import get_logger, audit_log

logger = get_logger(__name__)


class DependencyStatus:
    """Result of a dependency check."""
    def __init__(
        self,
        name: str,
        present: bool,
        version: Optional[str] = None,
        error: Optional[str] = None,
        recommendation: Optional[str] = None,
    ):
        self.name = name
        self.present = present
        self.version = version
        self.error = error
        self.recommendation = recommendation
    
    def __repr__(self) -> str:
        status = "✓" if self.present else "✗"
        version_str = f" v{self.version}" if self.version else ""
        return f"{status} {self.name}{version_str}"


def check_python_package(package: str, import_name: Optional[str] = None) -> DependencyStatus:
    """Check if a Python package is installed and importable."""
    import_name = import_name or package
    
    try:
        __import__(import_name)
        # Try to get version
        module = sys.modules[import_name]
        version = getattr(module, '__version__', None)
        return DependencyStatus(package, True, version=version)
    except ImportError as e:
        return DependencyStatus(
            package, 
            False, 
            error=str(e),
            recommendation=f"Install with: pip install {package}"
        )


def check_system_binary(binary: str, version_flag: str = "--version") -> DependencyStatus:
    """Check if a system binary is available and executable."""
    binary_path = shutil.which(binary)
    
    if not binary_path:
        return DependencyStatus(
            binary,
            False,
            recommendation=f"Install {binary} via your system package manager"
        )
    
    # Try to get version
    try:
        result = subprocess.run(
            [binary_path, version_flag],
            capture_output=True,
            text=True,
            timeout=10,
            check=False  # Don't raise on non-zero exit
        )
        # Extract version from first line of output
        version_line = result.stdout.strip().split('\n')[0] if result.stdout else None
        version = version_line.split()[-1] if version_line else None
        return DependencyStatus(binary, True, version=version)
    except subprocess.TimeoutExpired:
        return DependencyStatus(binary, True, version="unknown")
    except Exception as e:
        return DependencyStatus(binary, True, version="unknown", error=str(e))


def check_nmap_setup() -> Tuple[bool, List[DependencyStatus]]:
    """
    Comprehensive check for nmap functionality.
    
    Returns:
        (is_functional: bool, list of status checks)
    """
    checks = []
    
    # Check binary
    binary_check = check_system_binary("nmap")
    checks.append(binary_check)
    
    if not binary_check.present:
        return False, checks
    
    # Check Python wrapper
    wrapper_check = check_python_package("python-nmap", "nmap")
    checks.append(wrapper_check)
    
    # Test actual functionality with a non-privileged localhost scan.
    # Use -sT to avoid requiring root privileges.
    if wrapper_check.present:
        try:
            import nmap
            nm = nmap.PortScanner()
            # Non-root localhost check with short timeout
            nm.scan(hosts="127.0.0.1", arguments="-sT -Pn -p 22 --max-retries 1 --host-timeout 10s")
            checks.append(DependencyStatus("nmap_functional", True))
            return True, checks
        except Exception as e:
            checks.append(
                DependencyStatus(
                    "nmap_functional",
                    False,
                    error=str(e),
                    recommendation="Run with --check-deps --verbose for details",
                )
            )
            return False, checks
    
    return binary_check.present, checks


def check_ollama_connection(base_url: str = "http://localhost:11434") -> DependencyStatus:
    """Check if Ollama API is reachable."""
    import urllib.request
    import json
    
    try:
        with urllib.request.urlopen(f"{base_url}/api/tags", timeout=5) as response:
            data = json.loads(response.read().decode())
            models = [m['name'] for m in data.get('models', [])]
            return DependencyStatus(
                "ollama_api", 
                True, 
                version=f"{len(models)} models available"
            )
    except Exception as e:
        return DependencyStatus(
            "ollama_api",
            False,
            error=str(e),
            recommendation="Start Ollama: ollama serve"
        )


def run_full_dependency_check(config: Optional[Dict] = None) -> Dict[str, DependencyStatus]:
    """
    Run comprehensive dependency checks based on configuration.
    
    Args:
        config: Optional config dict to check only enabled features
    
    Returns:
        Dict of dependency name -> DependencyStatus
    """
    results = {}
    
    # Core Python dependencies
    core_deps = ["yaml", "pydantic"]
    for dep in core_deps:
        results[f"python:{dep}"] = check_python_package(dep)
    
    # Tool dependencies (check if enabled in config)
    if not config or config.get('tools', {}).get('nmap'):
        nmap_ok, nmap_checks = check_nmap_setup()
        for check in nmap_checks:
            results[f"tool:{check.name}"] = check
    
    # AI dependencies
    if not config or config.get('ai', {}).get('enable'):
        provider = (config or {}).get('ai', {}).get('provider', 'ollama')
        if provider == 'ollama':
            base_url = (config or {}).get('ai', {}).get('ollama', {}).get('base_url', 'http://localhost:11434')
            results["ai:ollama"] = check_ollama_connection(base_url)
        elif provider == 'openrouter':
            # Just check if API key is set (can't test without making call)
            api_key = os.getenv('OPENROUTER_API_KEY')
            results["ai:openrouter_key"] = DependencyStatus(
                "openrouter_api_key",
                bool(api_key),
                recommendation="Set OPENROUTER_API_KEY environment variable"
            )
    
    return results


def print_dependency_report(results: Dict[str, DependencyStatus], verbose: bool = False) -> bool:
    """
    Print a human-readable dependency report.
    
    Returns:
        True if all critical dependencies are satisfied
    """
    import sys
    
    critical = [k for k in results if k.startswith(('python:yaml', 'python:pydantic', 'tool:nmap'))]
    all_ok = all(results[k].present for k in critical)
    
    print("\n🔍 Sharingan Dependency Report")
    print("=" * 50)
    
    # Group by category
    categories = {
        "Core Python": [k for k in results if k.startswith("python:")],
        "Tools": [k for k in results if k.startswith("tool:")],
        "AI Providers": [k for k in results if k.startswith("ai:")],
    }
    
    for category, keys in categories.items():
        if not keys:
            continue
        print(f"\n{category}:")
        for key in keys:
            status = results[key]
            symbol = "✓" if status.present else "✗"
            print(f"  {symbol} {status}")
            if verbose and not status.present and status.recommendation:
                print(f"      → {status.recommendation}")
    
    print("\n" + "=" * 50)
    if all_ok:
        print("✅ All critical dependencies satisfied")
        return True
    else:
        missing = [k for k in critical if not results[k].present]
        print(f"❌ {len(missing)} critical dependency(ies) missing:")
        for k in missing:
            rec = results[k].recommendation or "See documentation"
            print(f"   • {k}: {rec}")
        print("\n💡 Run with --check-deps --verbose for detailed recommendations")
        return False


def main():
    """CLI entry point for dependency checking."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Check Sharingan dependencies")
    parser.add_argument('--verbose', '-v', action='store_true', help="Show detailed recommendations")
    parser.add_argument('--config', '-c', help="Path to config file for context-aware checks")
    args = parser.parse_args()
    
    # Load config if provided
    config = None
    if args.config:
        try:
            from src.core.config_loader import load_config
            cfg = load_config(args.config)
            config = cfg.model_dump(mode='json')
        except Exception as e:
            logger.warning(f"Could not load config {args.config}: {e}")
    
    results = run_full_dependency_check(config)
    success = print_dependency_report(results, verbose=args.verbose)
    
    # Log audit event
    audit_log(logger, "dependency_check", 
              passed=sum(1 for r in results.values() if r.present),
              failed=sum(1 for r in results.values() if not r.present))
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()