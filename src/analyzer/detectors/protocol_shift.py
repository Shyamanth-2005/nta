"""
Protocol Shift detector.

Detects significant changes in protocol distribution that may indicate:
- Network misconfiguration
- Malware communication
- Data exfiltration
- Protocol-based attacks
"""

import logging
from typing import List, Dict, Any, Optional

from analyzer.models import WindowSummary, Alert, AlertSeverity
from analyzer.detectors.base import BaseDetector

logger = logging.getLogger("analyzer.detectors.protocol_shift")


class ProtocolShiftDetector(BaseDetector):
    """
    Detects significant changes in protocol distribution.
    
    Protocol shifts are detected when:
    - Protocol mix changes significantly from baseline/expected
    - Unusual protocols appear
    - Expected protocols disappear
    """
    
    name = "protocol_shift"
    category = "anomaly"
    description = "Detects changes in protocol distribution"
    
    # Expected protocol distribution (can be updated with baseline)
    DEFAULT_EXPECTED = {
        "TCP": 0.70,   # 70% TCP expected
        "UDP": 0.25,   # 25% UDP expected
        "ICMP": 0.05,  # 5% ICMP expected
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize protocol shift detector.
        
        Config options:
            change_threshold: Percentage change to trigger alert (default: 25)
            expected_distribution: Expected protocol percentages
            min_packets: Minimum packets for analysis (default: 50)
        """
        super().__init__(config)
        
        self.change_threshold = self.config.get("change_threshold", 25.0)
        self.expected = self.config.get("expected_distribution", self.DEFAULT_EXPECTED.copy())
        self.min_packets = self.config.get("min_packets", 50)
        
        # Track previous window for comparison
        self.previous_distribution: Optional[Dict[str, float]] = None
    
    def evaluate(self, window: WindowSummary) -> List[Alert]:
        """
        Evaluate window for protocol distribution changes.
        
        Args:
            window: Aggregated window statistics
            
        Returns:
            List[Alert]: Generated alerts
        """
        alerts = []
        
        if window.packet_count < self.min_packets:
            return alerts
        
        # Calculate current protocol distribution
        current_dist = self._calculate_distribution(window.protocol_counts, window.packet_count)
        
        # Compare with previous window
        if self.previous_distribution:
            shift_alerts = self._detect_shift(current_dist, self.previous_distribution, window)
            alerts.extend(shift_alerts)
        
        # Compare with expected baseline
        baseline_alerts = self._detect_baseline_deviation(current_dist, window)
        alerts.extend(baseline_alerts)
        
        # Detect unusual protocols
        unusual_alerts = self._detect_unusual_protocols(window.protocol_counts, window)
        alerts.extend(unusual_alerts)
        
        # Store for next comparison
        self.previous_distribution = current_dist
        
        return alerts
    
    def _calculate_distribution(self, protocol_counts: Dict[str, int], total: int) -> Dict[str, float]:
        """Calculate percentage distribution of protocols."""
        if total == 0:
            return {}
        return {proto: (count / total) * 100 for proto, count in protocol_counts.items()}
    
    def _detect_shift(
        self, 
        current: Dict[str, float], 
        previous: Dict[str, float],
        window: WindowSummary
    ) -> List[Alert]:
        """Detect shifts between consecutive windows."""
        alerts = []
        
        all_protocols = set(current.keys()) | set(previous.keys())
        significant_changes = []
        
        for proto in all_protocols:
            curr_pct = current.get(proto, 0)
            prev_pct = previous.get(proto, 0)
            change = abs(curr_pct - prev_pct)
            
            if change >= self.change_threshold:
                significant_changes.append({
                    "protocol": proto,
                    "previous_percent": round(prev_pct, 1),
                    "current_percent": round(curr_pct, 1),
                    "change": round(change, 1),
                    "direction": "increased" if curr_pct > prev_pct else "decreased",
                })
        
        if significant_changes:
            severity = AlertSeverity.MEDIUM
            if any(c["change"] >= 50 for c in significant_changes):
                severity = AlertSeverity.HIGH
            
            changes_summary = ", ".join(
                f"{c['protocol']} {c['direction']} by {c['change']}%"
                for c in significant_changes[:3]
            )
            
            alert = self.create_alert(
                severity=severity,
                summary=f"Protocol distribution shift: {changes_summary}",
                evidence={
                    "changes": significant_changes,
                    "current_distribution": {k: round(v, 1) for k, v in current.items()},
                    "previous_distribution": {k: round(v, 1) for k, v in previous.items()},
                    "threshold": self.change_threshold,
                },
                window=window,
                interpretation="Significant change in protocol mix may indicate new services, network issues, or potential security concerns.",
            )
            alerts.append(alert)
        
        return alerts
    
    def _detect_baseline_deviation(
        self, 
        current: Dict[str, float],
        window: WindowSummary
    ) -> List[Alert]:
        """Detect deviation from expected baseline."""
        alerts = []
        
        deviations = []
        for proto, expected_pct in self.expected.items():
            current_pct = current.get(proto, 0) / 100  # Convert to fraction
            deviation = abs(current_pct - expected_pct) * 100  # Percentage points
            
            if deviation >= self.change_threshold:
                deviations.append({
                    "protocol": proto,
                    "expected_percent": round(expected_pct * 100, 1),
                    "actual_percent": round(current_pct * 100, 1),
                    "deviation": round(deviation, 1),
                })
        
        if deviations:
            alert = self.create_alert(
                severity=AlertSeverity.LOW,
                summary=f"Protocol distribution differs from baseline for {len(deviations)} protocol(s)",
                evidence={
                    "deviations": deviations,
                    "current_distribution": {k: round(v, 1) for k, v in current.items()},
                    "expected_distribution": {k: round(v * 100, 1) for k, v in self.expected.items()},
                },
                window=window,
                interpretation="Protocol distribution varies from expected baseline. This may be normal traffic variation or indicate network changes.",
            )
            alerts.append(alert)
        
        return alerts
    
    def _detect_unusual_protocols(
        self,
        protocol_counts: Dict[str, int],
        window: WindowSummary
    ) -> List[Alert]:
        """Detect presence of unusual protocols."""
        alerts = []
        
        known_protocols = {"TCP", "UDP", "ICMP", "ARP", "ICMPv6", "GRE", "ESP"}
        unusual = set(protocol_counts.keys()) - known_protocols
        
        if unusual:
            unusual_counts = {proto: protocol_counts[proto] for proto in unusual}
            
            alert = self.create_alert(
                severity=AlertSeverity.LOW,
                summary=f"Unusual protocol(s) detected: {', '.join(unusual)}",
                evidence={
                    "unusual_protocols": unusual_counts,
                    "all_protocols": protocol_counts,
                    "packet_count": window.packet_count,
                },
                window=window,
                interpretation="Detected protocols that are not commonly seen. May be legitimate specialized traffic or potentially suspicious communication.",
            )
            alerts.append(alert)
        
        return alerts
    
    def update_baseline(self, distribution: Dict[str, float]) -> None:
        """
        Update expected baseline distribution.
        
        Args:
            distribution: New expected distribution (fractions, not percentages)
        """
        self.expected = distribution.copy()
        logger.info(f"Updated baseline distribution: {self.expected}")
