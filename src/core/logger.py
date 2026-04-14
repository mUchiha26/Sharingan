"""
Unified logging interface for Sharingan.

Supports both stdlib logging and structlog (if available) with consistent
formatting, audit logging, and secret redaction.
"""
import logging
import os
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional, Union

# Try to import structlog for structured logging (optional dependency)
try:
    import structlog
    from structlog.typing import WrappedLogger
    
    STRUCTLOG_AVAILABLE = True
except ImportError:
    STRUCTLOG_AVAILABLE = False
    # Type checking only - provides hints when structlog is available
    if TYPE_CHECKING:
        import structlog  # type: ignore


# Secrets patterns to redact from logs
SECRET_PATTERNS = [
    (re.compile(r'(api[_-]?key|apikey|token|secret|password)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', re.I), r'\1=***REDACTED***'),
    (re.compile(r'sk-[a-zA-Z0-9]{20,}'), '***REDACTED***'),  # OpenAI-style keys
    (re.compile(r'gh[pousr]_[a-zA-Z0-9]{36,}'), '***REDACTED***'),  # GitHub tokens
]


def _redact_secrets(message: str) -> str:
    """Redact potential secrets from log messages."""
    for pattern, replacement in SECRET_PATTERNS:
        message = pattern.sub(replacement, message)
    return message


def _get_log_level(level: Union[str, int]) -> int:
    """Convert level string/name to logging constant."""
    if isinstance(level, int):
        return level
    level_map = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL,
    }
    return level_map.get(level.upper(), logging.INFO)


def setup_logging(
    level: Union[str, int] = "INFO",
    log_file: Optional[Union[str, Path]] = None,
    use_structlog: bool = False,
) -> None:
    """
    Configure global logging settings.
    
    Args:
        level: Logging level (string name or int constant)
        log_file: Optional file path to write logs to
        use_structlog: Force structlog if available (default: auto-detect)
    """
    numeric_level = _get_log_level(level)
    
    # Root logger configuration
    root = logging.getLogger()
    root.setLevel(numeric_level)
    
    # Clear existing handlers to avoid duplicates
    root.handlers.clear()
    
    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(numeric_level)
    console_formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console.setFormatter(console_formatter)
    root.addHandler(console)
    
    # Optional file handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path, mode='a', encoding='utf-8')
        file_handler.setLevel(numeric_level)
        file_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        root.addHandler(file_handler)
    
    # Configure structlog if requested and available
    if use_structlog and STRUCTLOG_AVAILABLE:
        if structlog is not None:
            structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )


def get_logger(
    name: Optional[str] = None,
    level: Optional[Union[str, int]] = None,
) -> logging.Logger:
    """
    Get a logger instance with consistent configuration.
    
    Args:
        name: Logger name (defaults to calling module)
        level: Optional level override for this logger only
    
    Returns:
        Configured logging.Logger instance
    """
    logger_name = name or __name__.rsplit('.', 1)[0]
    logger = logging.getLogger(logger_name)
    
    if level is not None:
        logger.setLevel(_get_log_level(level))
    
    return logger


def audit_log(
    logger: logging.Logger,
    event: str,
    level: str = "INFO",
    redact: bool = True,
    **fields: Any,
) -> None:
    """
    Log an audit event with structured fields.
    
    Args:
        logger: Logger instance to use
        event: Event name/description
        level: Log level (default: INFO)
        redact: Whether to redact secrets from fields (default: True)
        **fields: Additional key-value pairs to include
    """
    # Build message
    field_str = " ".join(f"{k}={v}" for k, v in fields.items())
    message = f"{event} {field_str}".strip()
    
    # Redact secrets if enabled
    if redact:
        message = _redact_secrets(message)
        fields = {k: _redact_secrets(str(v)) if isinstance(v, str) else v 
                  for k, v in fields.items()}
    
    # Log with appropriate level
    log_method = getattr(logger, level.lower(), logger.info)
    log_method(message, extra={"audit_event": event, **fields})


class SharinganLogger:
    """
    High-level logger wrapper for Sharingan components.
    
    Usage:
        logger = SharinganLogger(__name__)
        logger.info("Starting scan", target="127.0.0.1")
        logger.audit("tool_executed", tool="nmap", args="-sV")
    """
    
    def __init__(
        self,
        name: str,
        level: Union[str, int] = "INFO",
        audit_file: Optional[Union[str, Path]] = None,
    ):
        self.logger = get_logger(name, level)
        self.audit_file = Path(audit_file) if audit_file else None
        self.audit_handler: Optional[logging.FileHandler] = None
        
        # Setup audit file handler if specified
        if self.audit_file:
            self.audit_file.parent.mkdir(parents=True, exist_ok=True)
            self.audit_handler = logging.FileHandler(
                self.audit_file, mode='a', encoding='utf-8'
            )
            self.audit_handler.setFormatter(
                logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%dT%H:%M:%S')
            )
            self.audit_handler.setLevel(logging.INFO)
            self.logger.addHandler(self.audit_handler)
    
    def _log(self, level: str, message: str, **kwargs) -> None:
        """Internal logging method with redaction."""
        if kwargs:
            message = f"{message} " + " ".join(f"{k}={v}" for k, v in kwargs.items())
        message = _redact_secrets(message.strip())
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        log_method(message)
    
    def debug(self, message: str, **kwargs) -> None:
        self._log("DEBUG", message, **kwargs)
    
    def info(self, message: str, **kwargs) -> None:
        self._log("INFO", message, **kwargs)
    
    def warning(self, message: str, **kwargs) -> None:
        self._log("WARNING", message, **kwargs)
    
    def error(self, message: str, **kwargs) -> None:
        self._log("ERROR", message, **kwargs)
    
    def critical(self, message: str, **kwargs) -> None:
        self._log("CRITICAL", message, **kwargs)
    
    def audit(self, event: str, **fields) -> None:
        """Log audit event to both main log and audit file if configured."""
        audit_log(self.logger, event, **fields)
        if self.audit_handler:
            field_str = " ".join(
                f"{k}={_redact_secrets(str(v)) if isinstance(v, str) else v}"
                for k, v in fields.items()
            )
            record = self.logger.makeRecord(
                self.logger.name,
                logging.INFO,
                fn="",
                lno=0,
                msg=f"{event} {field_str}".strip(),
                args=(),
                exc_info=None,
            )
            self.audit_handler.handle(record)


# Convenience function for module-level loggers
def get_sharingan_logger(
    name: str,
    level: str = "INFO",
    audit_file: Optional[str] = None,
) -> SharinganLogger:
    """Get a SharinganLogger instance with audit file support."""
    return SharinganLogger(name=name, level=level, audit_file=audit_file)