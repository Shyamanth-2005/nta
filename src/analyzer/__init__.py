"""
Network Traffic Analyzer - A real-time network monitoring and anomaly detection system.

This package provides tools for:
- Live packet capture and PCAP replay
- Traffic feature extraction and windowed aggregation
- Rule-based anomaly detection (SYN flood, port scan, protocol shifts)
- Baseline learning and comparison
- Report generation and alerting

Usage:
    # As CLI tool
    nta interfaces
    nta monitor eth0
    nta baseline train
    nta report latest
    
    # As library
    from analyzer import Monitor, Detector
"""

__version__ = "0.1.0"
__author__ = "Network Traffic Analyzer Team"
__license__ = "MIT"

from analyzer.models import PacketEvent, WindowSummary, Alert, AlertSeverity
from analyzer.config import Config, load_config

__all__ = [
    "__version__",
    "PacketEvent",
    "WindowSummary", 
    "Alert",
    "AlertSeverity",
    "Config",
    "load_config",
]
