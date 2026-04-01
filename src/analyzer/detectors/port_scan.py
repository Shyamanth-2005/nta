"""
Port Scan detector.

Detects port scanning activity by monitoring:
- Vertical scans: Single source accessing many ports on one target
- Horizontal scans: Single source accessing same port on many targets
- High destination port diversity
"""

import logging
from typing import List, Dict, Any, Optional

from analyzer.models import WindowSummary, Alert, AlertSeverity
from analyzer.detectors.base import BaseDetector

logger = logging.getLogger("analyzer.detectors.port_scan")


class PortScanDetector(BaseDetector):
    """
    Detects port scanning activity.
    
    Port scans are detected when:
    - A source IP accesses many unique destination ports (vertical scan)
    - High ratio of unique ports to total packets
    - RST packets indicate refused connections
    """
    
    name = "port_scan"
    category = "reconnaissance"
    description = "Detects port scanning activity"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize port scan detector.
        
        Config options:
            port_threshold: Max unique ports per source (default: 15)
            port_rate_threshold: Max new ports per second (default: 10)
            rst_ratio_threshold: RST/total ratio indicating scan (default: 0.5)
        """
        super().__init__(config)
        
        self.port_threshold = self.config.get("port_threshold", 15)
        self.port_rate_threshold = self.config.get("port_rate_threshold", 10.0)
        self.rst_ratio_threshold = self.config.get("rst_ratio_threshold", 0.5)
    
    def evaluate(self, window: WindowSummary) -> List[Alert]:
        """
        Evaluate window for port scan indicators.
        
        Args:
            window: Aggregated window statistics
            
        Returns:
            List[Alert]: Generated alerts
        """
        alerts = []
        
        unique_ports = window.unique_dst_ports
        packet_count = window.packet_count
        rst_count = window.rst_count
        duration = window.duration
        
        if duration <= 0 or packet_count == 0:
            return alerts
        
        port_rate = unique_ports / duration
        rst_ratio = rst_count / max(1, packet_count)
        
        # Check unique ports threshold
        if unique_ports >= self.port_threshold:
            severity = self._calculate_severity(unique_ports, self.port_threshold)
            
            alert = self.create_alert(
                severity=severity,
                summary=f"Possible port scan: {unique_ports} unique destination ports accessed",
                evidence={
                    "unique_dst_ports": unique_ports,
                    "threshold": self.port_threshold,
                    "port_rate": round(port_rate, 2),
                    "packet_count": packet_count,
                    "rst_count": rst_count,
                    "rst_ratio": round(rst_ratio, 3),
                    "unique_src_ips": window.unique_src_ips,
                    "duration_seconds": round(duration, 2),
                },
                window=window,
                interpretation="High number of unique destination ports being accessed may indicate port scanning reconnaissance activity. Check the source IPs for potential attackers.",
            )
            alerts.append(alert)
            logger.warning(f"Port scan alert: {unique_ports} unique ports")
        
        # Check port rate threshold
        elif port_rate >= self.port_rate_threshold:
            alert = self.create_alert(
                severity=AlertSeverity.MEDIUM,
                summary=f"High port access rate: {port_rate:.1f} ports/s",
                evidence={
                    "port_rate": round(port_rate, 2),
                    "threshold": self.port_rate_threshold,
                    "unique_dst_ports": unique_ports,
                    "duration_seconds": round(duration, 2),
                },
                window=window,
                interpretation="Rapid access to different ports may indicate automated port scanning.",
            )
            alerts.append(alert)
        
        # Check RST ratio (high RSTs can indicate port scan with closed ports)
        if packet_count > 20 and rst_ratio >= self.rst_ratio_threshold:
            alert = self.create_alert(
                severity=AlertSeverity.MEDIUM,
                summary=f"High RST ratio ({rst_ratio:.1%}) may indicate port scan",
                evidence={
                    "rst_count": rst_count,
                    "packet_count": packet_count,
                    "rst_ratio": round(rst_ratio, 3),
                    "threshold": self.rst_ratio_threshold,
                    "unique_dst_ports": unique_ports,
                },
                window=window,
                interpretation="High ratio of RST (reset) packets suggests many connection attempts to closed ports, which is characteristic of port scanning.",
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
