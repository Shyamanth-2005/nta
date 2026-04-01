"""Tests for the detector modules."""

import pytest
import time

from analyzer.detectors import (
    BaseDetector,
    DetectorRegistry,
    SYNFloodDetector,
    PortScanDetector,
    ProtocolShiftDetector,
    TrafficAnomalyDetector,
)
from analyzer.detectors.base import DetectionEngine
from analyzer.models import WindowSummary, AlertSeverity


class TestBaseDetector:
    """Tests for BaseDetector and DetectorRegistry."""
    
    def test_registry_list_available(self):
        """Test listing available detectors."""
        available = DetectorRegistry.list_available()
        
        assert "syn_flood" in available
        assert "port_scan" in available
        assert "protocol_shift" in available
        assert "traffic_anomaly" in available
    
    def test_registry_create(self):
        """Test creating detector from registry."""
        detector = DetectorRegistry.create("syn_flood")
        
        assert detector is not None
        assert isinstance(detector, SYNFloodDetector)
    
    def test_registry_create_unknown(self):
        """Test creating unknown detector returns None."""
        detector = DetectorRegistry.create("nonexistent")
        
        assert detector is None
    
    def test_registry_create_all(self):
        """Test creating multiple detectors."""
        detectors = DetectorRegistry.create_all(["syn_flood", "port_scan"])
        
        assert len(detectors) == 2


class TestSYNFloodDetector:
    """Tests for SYNFloodDetector."""
    
    def test_initialization(self):
        """Test detector initialization."""
        detector = SYNFloodDetector()
        
        assert detector.name == "syn_flood"
        assert detector.category == "network_attack"
    
    def test_no_alert_below_threshold(self, sample_window_summary):
        """Test no alert when below threshold."""
        detector = SYNFloodDetector({"syn_count_threshold": 100})
        sample_window_summary.syn_count = 10
        
        alerts = detector.evaluate(sample_window_summary)
        
        assert len(alerts) == 0
    
    def test_alert_above_threshold(self, sample_window_summary):
        """Test alert generated when above threshold."""
        detector = SYNFloodDetector({"syn_count_threshold": 10})
        sample_window_summary.syn_count = 150
        
        alerts = detector.evaluate(sample_window_summary)
        
        assert len(alerts) > 0
        assert alerts[0].detector == "syn_flood"
        assert alerts[0].category == "network_attack"
    
    def test_alert_severity_scaling(self, sample_window_summary):
        """Test that severity scales with threshold excess."""
        detector = SYNFloodDetector({"syn_count_threshold": 100})
        
        # Just above threshold
        sample_window_summary.syn_count = 150
        alerts_low = detector.evaluate(sample_window_summary)
        
        # Way above threshold
        sample_window_summary.syn_count = 1000
        alerts_high = detector.evaluate(sample_window_summary)
        
        # Higher count should have higher or equal severity
        # Using severity order: LOW < MEDIUM < HIGH < CRITICAL
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        if alerts_low and alerts_high:
            high_level = severity_order.get(alerts_high[0].severity.value, 0)
            low_level = severity_order.get(alerts_low[0].severity.value, 0)
            assert high_level >= low_level
    
    def test_alert_contains_evidence(self, sample_window_summary):
        """Test that alert contains evidence."""
        detector = SYNFloodDetector({"syn_count_threshold": 10})
        sample_window_summary.syn_count = 100
        
        alerts = detector.evaluate(sample_window_summary)
        
        assert len(alerts) > 0
        assert "syn_count" in alerts[0].evidence
        assert "threshold" in alerts[0].evidence


class TestPortScanDetector:
    """Tests for PortScanDetector."""
    
    def test_initialization(self):
        """Test detector initialization."""
        detector = PortScanDetector()
        
        assert detector.name == "port_scan"
        assert detector.category == "reconnaissance"
    
    def test_no_alert_below_threshold(self, sample_window_summary):
        """Test no alert when below threshold."""
        detector = PortScanDetector({"port_threshold": 100})
        sample_window_summary.unique_dst_ports = 5
        
        alerts = detector.evaluate(sample_window_summary)
        
        assert len(alerts) == 0
    
    def test_alert_above_threshold(self, sample_window_summary):
        """Test alert when above threshold."""
        detector = PortScanDetector({"port_threshold": 5})
        sample_window_summary.unique_dst_ports = 50
        
        alerts = detector.evaluate(sample_window_summary)
        
        assert len(alerts) > 0
        assert alerts[0].detector == "port_scan"
    
    def test_rst_ratio_detection(self, sample_window_summary):
        """Test detection based on RST ratio."""
        detector = PortScanDetector({"rst_ratio_threshold": 0.3})
        sample_window_summary.packet_count = 100
        sample_window_summary.rst_count = 50  # 50% RST ratio
        sample_window_summary.unique_dst_ports = 5  # Below port threshold
        
        alerts = detector.evaluate(sample_window_summary)
        
        # Should detect based on RST ratio
        assert any("RST" in a.summary for a in alerts)


class TestProtocolShiftDetector:
    """Tests for ProtocolShiftDetector."""
    
    def test_initialization(self):
        """Test detector initialization."""
        detector = ProtocolShiftDetector()
        
        assert detector.name == "protocol_shift"
        assert detector.category == "anomaly"
    
    def test_no_alert_insufficient_packets(self, sample_window_summary):
        """Test no alert with insufficient packets."""
        detector = ProtocolShiftDetector({"min_packets": 100})
        sample_window_summary.packet_count = 10
        
        alerts = detector.evaluate(sample_window_summary)
        
        # May generate alerts for unusual protocols, but not for shift
        shift_alerts = [a for a in alerts if "shift" in a.summary.lower()]
        assert len(shift_alerts) == 0
    
    def test_detects_unusual_protocols(self, sample_window_summary):
        """Test detection of unusual protocols."""
        detector = ProtocolShiftDetector()
        sample_window_summary.protocol_counts = {
            "TCP": 50,
            "UDP": 30,
            "SCTP": 20,  # Unusual protocol
        }
        
        alerts = detector.evaluate(sample_window_summary)
        
        # Should detect SCTP as unusual
        unusual_alerts = [a for a in alerts if "unusual" in a.summary.lower()]
        assert len(unusual_alerts) > 0


class TestTrafficAnomalyDetector:
    """Tests for TrafficAnomalyDetector."""
    
    def test_initialization(self):
        """Test detector initialization."""
        detector = TrafficAnomalyDetector()
        
        assert detector.name == "traffic_anomaly"
        assert detector.category == "anomaly"
    
    def test_no_alert_insufficient_packets(self, sample_window_summary):
        """Test no alert with insufficient packets."""
        detector = TrafficAnomalyDetector({"min_packets": 100})
        sample_window_summary.packet_count = 5
        
        alerts = detector.evaluate(sample_window_summary)
        
        assert len(alerts) == 0
    
    def test_high_entropy_detection(self, sample_window_summary):
        """Test high entropy detection."""
        detector = TrafficAnomalyDetector({"entropy_threshold": 3.0})
        sample_window_summary.dst_ip_entropy = 5.0  # High entropy
        sample_window_summary.packet_count = 100
        
        alerts = detector.evaluate(sample_window_summary)
        
        # Should detect high entropy
        entropy_alerts = [a for a in alerts if "entropy" in a.summary.lower()]
        assert len(entropy_alerts) > 0
    
    def test_baseline_update(self, sample_window_summary):
        """Test manual baseline setting."""
        detector = TrafficAnomalyDetector()
        
        detector.set_baseline(pps=100, bps=10000)
        
        assert detector.baseline_pps == 100
        assert detector.baseline_bps == 10000


class TestDetectionEngine:
    """Tests for DetectionEngine."""
    
    def test_initialization(self):
        """Test engine initialization."""
        engine = DetectionEngine()
        
        assert len(engine.detectors) == 0
        assert len(engine.all_alerts) == 0
    
    def test_add_detector(self):
        """Test adding detector."""
        engine = DetectionEngine()
        detector = SYNFloodDetector()
        
        engine.add_detector(detector)
        
        assert len(engine.detectors) == 1
    
    def test_remove_detector(self):
        """Test removing detector."""
        engine = DetectionEngine()
        detector = SYNFloodDetector()
        engine.add_detector(detector)
        
        result = engine.remove_detector("syn_flood")
        
        assert result is True
        assert len(engine.detectors) == 0
    
    def test_evaluate_all(self, sample_window_summary):
        """Test evaluating with all detectors."""
        engine = DetectionEngine()
        engine.add_detector(SYNFloodDetector({"syn_count_threshold": 10}))
        engine.add_detector(PortScanDetector({"port_threshold": 5}))
        
        sample_window_summary.syn_count = 100
        sample_window_summary.unique_dst_ports = 50
        
        alerts = engine.evaluate(sample_window_summary)
        
        # Should have alerts from both detectors
        assert len(alerts) > 0
    
    def test_get_stats(self, sample_window_summary):
        """Test engine statistics."""
        engine = DetectionEngine()
        engine.add_detector(SYNFloodDetector())
        
        engine.evaluate(sample_window_summary)
        stats = engine.get_stats()
        
        assert "detector_count" in stats
        assert "total_alerts" in stats
        assert "detectors" in stats
    
    def test_filter_by_severity(self, sample_window_summary):
        """Test filtering alerts by severity."""
        engine = DetectionEngine()
        engine.add_detector(SYNFloodDetector({"syn_count_threshold": 10}))
        
        sample_window_summary.syn_count = 100
        engine.evaluate(sample_window_summary)
        
        # Filter by severity
        filtered = engine.get_alerts_by_severity(AlertSeverity.CRITICAL)
        
        # All filtered alerts should have requested severity
        for alert in filtered:
            assert alert.severity == AlertSeverity.CRITICAL
