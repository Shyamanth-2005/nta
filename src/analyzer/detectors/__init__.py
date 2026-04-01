"""
Detection engine and detector registry.

Manages anomaly detectors and coordinates detection across window summaries.
"""

from analyzer.detectors.base import BaseDetector, DetectorRegistry, DetectionEngine
from analyzer.detectors.syn_flood import SYNFloodDetector
from analyzer.detectors.port_scan import PortScanDetector
from analyzer.detectors.protocol_shift import ProtocolShiftDetector
from analyzer.detectors.traffic_anomaly import TrafficAnomalyDetector

__all__ = [
    "BaseDetector",
    "DetectorRegistry",
    "DetectionEngine",
    "SYNFloodDetector",
    "PortScanDetector",
    "ProtocolShiftDetector",
    "TrafficAnomalyDetector",
]

# Register built-in detectors
DetectorRegistry.register("syn_flood", SYNFloodDetector)
DetectorRegistry.register("port_scan", PortScanDetector)
DetectorRegistry.register("protocol_shift", ProtocolShiftDetector)
DetectorRegistry.register("traffic_anomaly", TrafficAnomalyDetector)
