"""
Logging configuration for the network traffic analyzer.

Provides structured logging with:
- Console output with colors
- File output with rotation
- JSON logging support
"""

import logging
import logging.handlers
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


# ANSI color codes for console output
class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colored output for console."""
    
    LEVEL_COLORS = {
        logging.DEBUG: Colors.CYAN,
        logging.INFO: Colors.GREEN,
        logging.WARNING: Colors.YELLOW,
        logging.ERROR: Colors.RED,
        logging.CRITICAL: Colors.RED + Colors.BOLD,
    }
    
    def format(self, record: logging.LogRecord) -> str:
        # Get the color for this log level
        color = self.LEVEL_COLORS.get(record.levelno, Colors.WHITE)
        
        # Format the message
        record.levelname = f"{color}{record.levelname}{Colors.RESET}"
        record.name = f"{Colors.BLUE}{record.name}{Colors.RESET}"
        
        return super().format(record)


def setup_logging(
    level: str = "INFO",
    log_dir: Optional[Path] = None,
    log_file: str = "nta.log",
    console: bool = True,
    file_logging: bool = True,
    max_bytes: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5,
) -> logging.Logger:
    """
    Set up logging for the network traffic analyzer.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir: Directory for log files
        log_file: Name of the log file
        console: Enable console output
        file_logging: Enable file output
        max_bytes: Maximum log file size before rotation
        backup_count: Number of backup files to keep
        
    Returns:
        logging.Logger: Configured root logger
    """
    # Get numeric level
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    # Get the root logger for the analyzer package
    logger = logging.getLogger("analyzer")
    logger.setLevel(numeric_level)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Console handler
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(numeric_level)
        
        # Use colored formatter if terminal supports it
        if sys.stdout.isatty():
            console_format = "%(asctime)s │ %(levelname)s │ %(name)s │ %(message)s"
            console_formatter = ColoredFormatter(console_format, datefmt="%H:%M:%S")
        else:
            console_format = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
            console_formatter = logging.Formatter(console_format, datefmt="%H:%M:%S")
        
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    # File handler with rotation
    if file_logging and log_dir:
        log_dir = Path(log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / log_file
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
        file_handler.setLevel(numeric_level)
        
        file_format = "%(asctime)s | %(levelname)s | %(name)s | %(funcName)s:%(lineno)d | %(message)s"
        file_formatter = logging.Formatter(file_format)
        file_handler.setFormatter(file_formatter)
        
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a specific module.
    
    Args:
        name: Module name (e.g., "analyzer.capture")
        
    Returns:
        logging.Logger: Logger instance
    """
    return logging.getLogger(name)


class AlertLogger:
    """
    Specialized logger for alerts with structured output.
    """
    
    def __init__(self, log_dir: Optional[Path] = None, output_format: str = "both"):
        """
        Initialize alert logger.
        
        Args:
            log_dir: Directory for alert log files
            output_format: "json", "text", or "both"
        """
        self.log_dir = Path(log_dir) if log_dir else None
        self.output_format = output_format
        self.logger = get_logger("analyzer.alerts")
        
        if self.log_dir:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            
            # Text alert log
            if output_format in ("text", "both"):
                self._setup_text_handler()
            
            # JSON alert log  
            if output_format in ("json", "both"):
                self._setup_json_handler()
    
    def _setup_text_handler(self) -> None:
        """Set up text format alert log file."""
        text_path = self.log_dir / "alerts.log"
        handler = logging.FileHandler(text_path, mode="a")
        handler.setFormatter(logging.Formatter("%(message)s"))
        handler.setLevel(logging.INFO)
        self.text_handler = handler
        self.logger.addHandler(handler)
    
    def _setup_json_handler(self) -> None:
        """Set up JSON format alert log file."""
        json_path = self.log_dir / "alerts.jsonl"
        self.json_path = json_path
    
    def log_alert(self, alert) -> None:
        """
        Log an alert to configured outputs.
        
        Args:
            alert: Alert object to log
        """
        # Log to text format
        if self.output_format in ("text", "both"):
            self.logger.info(alert.to_log_line())
        
        # Log to JSON format
        if self.output_format in ("json", "both") and self.log_dir:
            with open(self.json_path, "a") as f:
                f.write(alert.to_json() + "\n")
