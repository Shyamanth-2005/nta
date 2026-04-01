"""
SYN Flood detector.

Detects potential SYN flood attacks by monitoring:
- High volume of SYN packets
- SYN-to-ACK ratio imbalance
- SYN packets from single source
"""

import logging
from typing import List, Dict, Any, Optional

from analyzer.models import WindowSummary, Alert, AlertSeverity
from analyzer.detectors.base import BaseDetector

logger = logging.getLogger("analyzer.detectors.syn_flood")


class SYNFloodDetector(BaseDetector):
    """
    Detects SYN flood attacks.
    
    SYN floods are detected when:
    - Total SYN count exceeds threshold
    - SYN rate (per second) exceeds threshold
    - SYN-to-ACK ratio is abnormally high
    """
    
    name = "syn_flood"
    category = "network_attack"
    description = "Detects TCP SYN flood attacks"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize SYN flood detector.
        
        Config options:
            syn_count_threshold: Max SYN packets per window (default: 100)
            syn_rate_threshold: Max SYN packets per second (default: 50)
            syn_ack_ratio_threshold: Max SYN/ACK ratio (default: 3.0)
        """
        super().__init__(config)
        
        self.syn_count_threshold = self.config.get("syn_count_threshold", 100)
        self.syn_rate_threshold = self.config.get("syn_rate_threshold", 50.0)
        self.syn_ack_ratio_threshold = self.config.get("syn_ack_ratio_threshold", 3.0)
    
    def evaluate(self, window: WindowSummary) -> List[Alert]:
        """
        Evaluate window for SYN flood indicators.
        
        Args:
            window: Aggregated window statistics
            
        Returns:
            List[Alert]: Generated alerts
        """
        alerts = []
        
        syn_count = window.syn_count
        ack_count = window.ack_count
        duration = window.duration
        
        if duration <= 0:
            return alerts
        
        syn_rate = syn_count / duration
        syn_ack_ratio = syn_count / max(1, ack_count)
        
        # Check SYN count threshold
        if syn_count >= self.syn_count_threshold:
            severity = self._calculate_severity(syn_count, self.syn_count_threshold)
            
            alert = self.create_alert(
                severity=severity,
                summary=f"High SYN packet volume detected: {syn_count} SYN packets in {duration:.1f}s",
                evidence={
                    "syn_count": syn_count,
                    "threshold": self.syn_count_threshold,
                    "syn_rate": round(syn_rate, 2),
                    "ack_count": ack_count,
                    "syn_ack_ratio": round(syn_ack_ratio, 2),
                    "duration_seconds": round(duration, 2),
                },
                window=window,
                interpretation="Possible SYN flood attack. High volume of TCP connection initiation requests may indicate a denial-of-service attempt or aggressive scanning.",
            )
            alerts.append(alert)
            logger.warning(f"SYN flood alert: {syn_count} SYNs detected")
        
        # Check SYN rate threshold
        elif syn_rate >= self.syn_rate_threshold:
            severity = self._calculate_severity(syn_rate, self.syn_rate_threshold)
            
            alert = self.create_alert(
                severity=severity,
                summary=f"High SYN packet rate: {syn_rate:.1f} SYN/s",
                evidence={
                    "syn_rate": round(syn_rate, 2),
                    "threshold": self.syn_rate_threshold,
                    "syn_count": syn_count,
                    "duration_seconds": round(duration, 2),
                },
                window=window,
                interpretation="High rate of SYN packets may indicate a SYN flood attack in progress.",
            )
            alerts.append(alert)
        
        # Check SYN/ACK ratio (only if we have meaningful traffic)
        if syn_count > 10 and syn_ack_ratio >= self.syn_ack_ratio_threshold:
            alert = self.create_alert(
                severity=AlertSeverity.MEDIUM,
                summary=f"Abnormal SYN/ACK ratio: {syn_ack_ratio:.1f}:1",
                evidence={
                    "syn_count": syn_count,
                    "ack_count": ack_count,
                    "ratio": round(syn_ack_ratio, 2),
                    "threshold": self.syn_ack_ratio_threshold,
                },
                window=window,
                interpretation="High SYN-to-ACK ratio suggests many connection attempts are not being completed, which is characteristic of SYN flood attacks.",
            )
            alerts.append(alert)
        
        return alerts
    
    def _calculate_severity(self, value: float, threshold: float) -> AlertSeverity:
        """Calculate alert severity based on how much threshold is exceeded."""
        ratio = value / threshold
        
        if ratio >= 5:
            return AlertSeverity.CRITICAL
        elif ratio >= 3:
            return AlertSeverity.HIGH
        elif ratio >= 2:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
