"""
Configuration management for the network traffic analyzer.

Supports:
- YAML configuration files
- Environment variables
- CLI argument overrides
- Default values
"""

import os
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Any, Optional
import json

# Try to import YAML support
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


# Default configuration values
DEFAULT_CONFIG = {
    "interface": None,  # Auto-detect or user-specified
    "window_size": 5,  # Window duration in seconds
    "capture_filter": None,  # BPF filter string
    "output_dir": "data",  # Base output directory
    "log_level": "INFO",
    "max_packets": None,  # None = unlimited
    "pcap_file": None,  # For offline replay
    
    # Detection thresholds
    "thresholds": {
        "syn_flood": {
            "count": 100,  # SYN packets per window
            "rate": 50,  # SYN packets per second
        },
        "port_scan": {
            "ports": 15,  # Unique destination ports per source IP
            "rate": 10,  # Port access rate per second
        },
        "protocol_shift": {
            "change_percent": 25,  # Protocol distribution change threshold
        },
        "traffic_anomaly": {
            "rate_multiplier": 3.0,  # Traffic rate vs baseline multiplier
            "size_deviation": 2.0,  # Packet size standard deviations
        },
    },
    
    # Alert configuration
    "alerts": {
        "suppression_window": 60,  # Seconds to suppress duplicate alerts
        "output_format": "both",  # "json", "text", or "both"
        "console_output": True,
        "file_output": True,
    },
    
    # Baseline configuration
    "baseline": {
        "min_windows": 10,  # Minimum windows to build baseline
        "profile": "default",  # Baseline profile name
    },
    
    # Enabled detectors
    "detectors": [
        "syn_flood",
        "port_scan",
        "protocol_shift",
        "traffic_anomaly",
    ],
    
    # Report configuration
    "reports": {
        "format": "markdown",  # "markdown", "json", "csv"
        "include_raw_data": False,
        "top_talkers_count": 10,
    },
}


@dataclass
class ThresholdConfig:
    """Detection threshold configuration."""
    syn_flood_count: int = 100
    syn_flood_rate: float = 50.0
    port_scan_ports: int = 15
    port_scan_rate: float = 10.0
    protocol_shift_percent: float = 25.0
    traffic_rate_multiplier: float = 3.0
    traffic_size_deviation: float = 2.0


@dataclass  
class AlertConfig:
    """Alert output configuration."""
    suppression_window: int = 60
    output_format: str = "both"
    console_output: bool = True
    file_output: bool = True


@dataclass
class BaselineConfig:
    """Baseline learning configuration."""
    min_windows: int = 10
    profile: str = "default"


@dataclass
class ReportConfig:
    """Report generation configuration."""
    format: str = "markdown"
    include_raw_data: bool = False
    top_talkers_count: int = 10


@dataclass
class Config:
    """
    Main configuration container for the network traffic analyzer.
    
    Attributes:
        interface: Network interface to capture from
        window_size: Time window duration in seconds
        capture_filter: BPF filter string for packet capture
        output_dir: Base directory for output files
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        max_packets: Maximum packets to capture (None = unlimited)
        pcap_file: Path to PCAP file for offline replay
        thresholds: Detection threshold configuration
        alerts: Alert output configuration
        baseline: Baseline learning configuration
        detectors: List of enabled detector names
        reports: Report generation configuration
    """
    interface: Optional[str] = None
    window_size: int = 5
    capture_filter: Optional[str] = None
    output_dir: str = "data"
    log_level: str = "INFO"
    max_packets: Optional[int] = None
    pcap_file: Optional[str] = None
    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    baseline: BaselineConfig = field(default_factory=BaselineConfig)
    detectors: List[str] = field(default_factory=lambda: [
        "syn_flood", "port_scan", "protocol_shift", "traffic_anomaly"
    ])
    reports: ReportConfig = field(default_factory=ReportConfig)
    
    def get_data_path(self, subdir: str = "") -> Path:
        """Get path within output directory."""
        path = Path(self.output_dir)
        if subdir:
            path = path / subdir
        path.mkdir(parents=True, exist_ok=True)
        return path
    
    def get_logs_path(self) -> Path:
        """Get logs directory path."""
        return self.get_data_path("logs")
    
    def get_reports_path(self) -> Path:
        """Get reports directory path."""
        return self.get_data_path("reports")
    
    def get_baselines_path(self) -> Path:
        """Get baselines directory path."""
        return self.get_data_path("baselines")
    
    def get_sessions_path(self) -> Path:
        """Get sessions directory path."""
        return self.get_data_path("sessions")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "interface": self.interface,
            "window_size": self.window_size,
            "capture_filter": self.capture_filter,
            "output_dir": self.output_dir,
            "log_level": self.log_level,
            "max_packets": self.max_packets,
            "pcap_file": self.pcap_file,
            "thresholds": {
                "syn_flood": {
                    "count": self.thresholds.syn_flood_count,
                    "rate": self.thresholds.syn_flood_rate,
                },
                "port_scan": {
                    "ports": self.thresholds.port_scan_ports,
                    "rate": self.thresholds.port_scan_rate,
                },
                "protocol_shift": {
                    "change_percent": self.thresholds.protocol_shift_percent,
                },
                "traffic_anomaly": {
                    "rate_multiplier": self.thresholds.traffic_rate_multiplier,
                    "size_deviation": self.thresholds.traffic_size_deviation,
                },
            },
            "alerts": {
                "suppression_window": self.alerts.suppression_window,
                "output_format": self.alerts.output_format,
                "console_output": self.alerts.console_output,
                "file_output": self.alerts.file_output,
            },
            "baseline": {
                "min_windows": self.baseline.min_windows,
                "profile": self.baseline.profile,
            },
            "detectors": self.detectors,
            "reports": {
                "format": self.reports.format,
                "include_raw_data": self.reports.include_raw_data,
                "top_talkers_count": self.reports.top_talkers_count,
            },
        }
    
    def to_json(self) -> str:
        """Convert configuration to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    def to_yaml(self) -> str:
        """Convert configuration to YAML string."""
        if YAML_AVAILABLE:
            return yaml.dump(self.to_dict(), default_flow_style=False)
        return self.to_json()


def load_config(
    config_file: Optional[str] = None,
    cli_overrides: Optional[Dict[str, Any]] = None
) -> Config:
    """
    Load configuration from multiple sources with priority:
    1. CLI arguments (highest)
    2. Environment variables
    3. Config file
    4. Default values (lowest)
    
    Args:
        config_file: Path to configuration file (YAML or JSON)
        cli_overrides: Dictionary of CLI argument overrides
        
    Returns:
        Config: Loaded and merged configuration
    """
    config = Config()
    
    # Load from config file if provided
    if config_file and Path(config_file).exists():
        config = _load_config_file(config_file, config)
    else:
        # Try default config locations
        for path in _get_default_config_paths():
            if path.exists():
                config = _load_config_file(str(path), config)
                break
    
    # Apply environment variable overrides
    config = _apply_env_overrides(config)
    
    # Apply CLI overrides
    if cli_overrides:
        config = _apply_cli_overrides(config, cli_overrides)
    
    return config


def _get_default_config_paths() -> List[Path]:
    """Get list of default config file paths to check."""
    paths = []
    
    # Local project config
    paths.append(Path("nta.config.yaml"))
    paths.append(Path("nta.config.json"))
    paths.append(Path(".nta.yaml"))
    
    # User config directory
    if os.name == "nt":  # Windows
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            paths.append(Path(appdata) / "nta" / "config.yaml")
    else:  # Linux/Mac
        home = Path.home()
        paths.append(home / ".config" / "nta" / "config.yaml")
        paths.append(home / ".nta.yaml")
    
    return paths


def _load_config_file(config_file: str, config: Config) -> Config:
    """Load configuration from a file."""
    path = Path(config_file)
    
    try:
        with open(path, "r") as f:
            if path.suffix in (".yaml", ".yml"):
                if not YAML_AVAILABLE:
                    logging.warning("YAML support not available, skipping config file")
                    return config
                data = yaml.safe_load(f)
            else:
                data = json.load(f)
        
        if data:
            return _dict_to_config(data)
    except Exception as e:
        logging.warning(f"Failed to load config file {config_file}: {e}")
    
    return config


def _apply_env_overrides(config: Config) -> Config:
    """Apply environment variable overrides."""
    env_mapping = {
        "NTA_INTERFACE": "interface",
        "NTA_WINDOW_SIZE": ("window_size", int),
        "NTA_OUTPUT_DIR": "output_dir",
        "NTA_LOG_LEVEL": "log_level",
        "NTA_MAX_PACKETS": ("max_packets", int),
        "NTA_PCAP_FILE": "pcap_file",
    }
    
    for env_var, config_attr in env_mapping.items():
        value = os.environ.get(env_var)
        if value is not None:
            if isinstance(config_attr, tuple):
                attr_name, converter = config_attr
                value = converter(value)
            else:
                attr_name = config_attr
            setattr(config, attr_name, value)
    
    return config


def _apply_cli_overrides(config: Config, overrides: Dict[str, Any]) -> Config:
    """Apply CLI argument overrides."""
    for key, value in overrides.items():
        if value is not None and hasattr(config, key):
            setattr(config, key, value)
    return config


def _dict_to_config(data: Dict[str, Any]) -> Config:
    """Convert dictionary to Config object."""
    config = Config()
    
    # Simple attributes
    for attr in ["interface", "window_size", "capture_filter", "output_dir", 
                 "log_level", "max_packets", "pcap_file", "detectors"]:
        if attr in data:
            setattr(config, attr, data[attr])
    
    # Threshold configuration
    if "thresholds" in data:
        t = data["thresholds"]
        if "syn_flood" in t:
            config.thresholds.syn_flood_count = t["syn_flood"].get("count", 100)
            config.thresholds.syn_flood_rate = t["syn_flood"].get("rate", 50.0)
        if "port_scan" in t:
            config.thresholds.port_scan_ports = t["port_scan"].get("ports", 15)
            config.thresholds.port_scan_rate = t["port_scan"].get("rate", 10.0)
        if "protocol_shift" in t:
            config.thresholds.protocol_shift_percent = t["protocol_shift"].get("change_percent", 25.0)
        if "traffic_anomaly" in t:
            config.thresholds.traffic_rate_multiplier = t["traffic_anomaly"].get("rate_multiplier", 3.0)
            config.thresholds.traffic_size_deviation = t["traffic_anomaly"].get("size_deviation", 2.0)
    
    # Alert configuration
    if "alerts" in data:
        a = data["alerts"]
        config.alerts.suppression_window = a.get("suppression_window", 60)
        config.alerts.output_format = a.get("output_format", "both")
        config.alerts.console_output = a.get("console_output", True)
        config.alerts.file_output = a.get("file_output", True)
    
    # Baseline configuration
    if "baseline" in data:
        b = data["baseline"]
        config.baseline.min_windows = b.get("min_windows", 10)
        config.baseline.profile = b.get("profile", "default")
    
    # Report configuration
    if "reports" in data:
        r = data["reports"]
        config.reports.format = r.get("format", "markdown")
        config.reports.include_raw_data = r.get("include_raw_data", False)
        config.reports.top_talkers_count = r.get("top_talkers_count", 10)
    
    return config


def create_default_config(output_path: str = "nta.config.yaml") -> None:
    """Create a default configuration file."""
    config = Config()
    path = Path(output_path)
    
    with open(path, "w") as f:
        if path.suffix in (".yaml", ".yml") and YAML_AVAILABLE:
            yaml.dump(config.to_dict(), f, default_flow_style=False)
        else:
            json.dump(config.to_dict(), f, indent=2)
    
    print(f"Created default configuration at {output_path}")
