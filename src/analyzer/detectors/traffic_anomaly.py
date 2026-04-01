"""
Traffic Anomaly detector.

Detects general traffic anomalies by monitoring:
- Traffic rate deviations
- Packet size anomalies
- Entropy-based anomalies
- Volume spikes
"""

import logging
from typing import List, Dict, Any, Optional
import math

from analyzer.models import WindowSummary, Alert, AlertSeverity
from analyzer.detectors.base import BaseDetector

logger = logging.getLogger("analyzer.detectors.traffic_anomaly")


class TrafficAnomalyDetector(BaseDetector):
    """
    Detects general traffic anomalies.
    
    Anomalies are detected based on:
    - Deviation from baseline traffic rates
    - Unusual packet size distributions
    - Entropy-based analysis
    """
    
    name = "traffic_anomaly"
    category = "anomaly"
    description = "Detects general traffic anomalies"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize traffic anomaly detector.
        
        Config options:
            rate_multiplier: Factor for rate spike detection (default: 3.0)
            size_deviation_threshold: Std devs for size anomaly (default: 2.0)
            entropy_threshold: Destination entropy threshold (default: 4.0)
            min_packets: Minimum packets for analysis (default: 20)
        """
        super().__init__(config)
        
        self.rate_multiplier = self.config.get("rate_multiplier", 3.0)
        self.size_deviation_threshold = self.config.get("size_deviation_threshold", 2.0)
        self.entropy_threshold = self.config.get("entropy_threshold", 4.0)
        self.min_packets = self.config.get("min_packets", 20)
        
        # Baseline statistics (can be learned)
        self.baseline_pps: Optional[float] = None  # packets per second
        self.baseline_bps: Optional[float] = None  # bytes per second
        self.baseline_mean_size: Optional[float] = None
        self.baseline_size_std: Optional[float] = None
        
        # Moving averages for baseline tracking
        self.pps_history: List[float] = []
        self.bps_history: List[float] = []
        self.size_history: List[float] = []
        self.history_size = 20  # Windows to track
    
    def evaluate(self, window: WindowSummary) -> List[Alert]:
        """
        Evaluate window for traffic anomalies.
        
        Args:
            window: Aggregated window statistics
            
        Returns:
            List[Alert]: Generated alerts
        """
        alerts = []
        
        if window.packet_count < self.min_packets:
            self._update_history(window)
            return alerts
        
        # Check for rate spikes
        rate_alerts = self._detect_rate_anomalies(window)
        alerts.extend(rate_alerts)
        
        # Check for size anomalies
        size_alerts = self._detect_size_anomalies(window)
        alerts.extend(size_alerts)
        
        # Check for entropy anomalies
        entropy_alerts = self._detect_entropy_anomalies(window)
        alerts.extend(entropy_alerts)
        
        # Update baseline history
        self._update_history(window)
        
        return alerts
    
    def _detect_rate_anomalies(self, window: WindowSummary) -> List[Alert]:
        """Detect traffic rate anomalies."""
        alerts = []
        
        # Calculate baseline from history if not set
        if self.baseline_pps is None and len(self.pps_history) >= 5:
            self.baseline_pps = sum(self.pps_history) / len(self.pps_history)
        
        if self.baseline_bps is None and len(self.bps_history) >= 5:
            self.baseline_bps = sum(self.bps_history) / len(self.bps_history)
        
        # Check packets per second
        if self.baseline_pps and self.baseline_pps > 0:
            pps_ratio = window.packets_per_second / self.baseline_pps
            
            if pps_ratio >= self.rate_multiplier:
                severity = self._rate_severity(pps_ratio)
                
                alert = self.create_alert(
                    severity=severity,
                    summary=f"Traffic rate spike: {window.packets_per_second:.1f} pps ({pps_ratio:.1f}x baseline)",
                    evidence={
                        "current_pps": round(window.packets_per_second, 2),
                        "baseline_pps": round(self.baseline_pps, 2),
                        "ratio": round(pps_ratio, 2),
                        "threshold_multiplier": self.rate_multiplier,
                        "packet_count": window.packet_count,
                        "byte_count": window.byte_count,
                    },
                    window=window,
                    interpretation="Significant increase in packet rate may indicate flooding, burst traffic, or network issues.",
                )
                alerts.append(alert)
                logger.warning(f"Traffic spike: {pps_ratio:.1f}x baseline")
        
        # Check bytes per second
        if self.baseline_bps and self.baseline_bps > 0:
            bps_ratio = window.bytes_per_second / self.baseline_bps
            
            if bps_ratio >= self.rate_multiplier:
                severity = self._rate_severity(bps_ratio)
                
                alert = self.create_alert(
                    severity=severity,
                    summary=f"Bandwidth spike: {self._format_bytes(window.bytes_per_second)}/s ({bps_ratio:.1f}x baseline)",
                    evidence={
                        "current_bps": round(window.bytes_per_second, 2),
                        "baseline_bps": round(self.baseline_bps, 2),
                        "ratio": round(bps_ratio, 2),
                        "threshold_multiplier": self.rate_multiplier,
                    },
                    window=window,
                    interpretation="Significant increase in bandwidth usage may indicate data transfer, streaming, or potential data exfiltration.",
                )
                alerts.append(alert)
        
        return alerts
    
    def _detect_size_anomalies(self, window: WindowSummary) -> List[Alert]:
        """Detect packet size anomalies."""
        alerts = []
        
        # Calculate baseline from history
        if self.baseline_mean_size is None and len(self.size_history) >= 5:
            self.baseline_mean_size = sum(self.size_history) / len(self.size_history)
            if len(self.size_history) > 1:
                variance = sum((x - self.baseline_mean_size)**2 for x in self.size_history) / (len(self.size_history) - 1)
                self.baseline_size_std = math.sqrt(variance) if variance > 0 else 1.0
            else:
                self.baseline_size_std = 1.0
        
        if self.baseline_mean_size and self.baseline_size_std:
            deviation = abs(window.mean_packet_size - self.baseline_mean_size) / max(1, self.baseline_size_std)
            
            if deviation >= self.size_deviation_threshold:
                direction = "larger" if window.mean_packet_size > self.baseline_mean_size else "smaller"
                
                alert = self.create_alert(
                    severity=AlertSeverity.LOW,
                    summary=f"Packet size anomaly: {direction} than usual ({window.mean_packet_size:.0f} vs {self.baseline_mean_size:.0f} bytes)",
                    evidence={
                        "mean_packet_size": round(window.mean_packet_size, 1),
                        "baseline_mean": round(self.baseline_mean_size, 1),
                        "baseline_std": round(self.baseline_size_std, 1),
                        "deviation_sigma": round(deviation, 2),
                        "min_size": window.min_packet_size,
                        "max_size": window.max_packet_size,
                    },
                    window=window,
                    interpretation=f"Packets are {direction} than typical. May indicate different traffic type or protocol behavior.",
                )
                alerts.append(alert)
        
        return alerts
    
    def _detect_entropy_anomalies(self, window: WindowSummary) -> List[Alert]:
        """Detect entropy-based anomalies."""
        alerts = []
        
        # High destination IP entropy can indicate scanning or DDoS
        if window.dst_ip_entropy >= self.entropy_threshold:
            alert = self.create_alert(
                severity=AlertSeverity.MEDIUM,
                summary=f"High destination entropy: {window.dst_ip_entropy:.2f} bits",
                evidence={
                    "dst_ip_entropy": round(window.dst_ip_entropy, 3),
                    "threshold": self.entropy_threshold,
                    "unique_dst_ips": window.unique_dst_ips,
                    "unique_src_ips": window.unique_src_ips,
                    "packet_count": window.packet_count,
                },
                window=window,
                interpretation="High entropy in destination IPs suggests traffic is spread across many destinations, which may indicate scanning or distributed communication.",
            )
            alerts.append(alert)
        
        # Very low entropy (all to one destination) with high volume can be suspicious
        if window.packet_count > 100 and window.unique_dst_ips == 1:
            alert = self.create_alert(
                severity=AlertSeverity.LOW,
                summary=f"All traffic to single destination ({window.packet_count} packets)",
                evidence={
                    "packet_count": window.packet_count,
                    "unique_dst_ips": 1,
                    "unique_src_ips": window.unique_src_ips,
                    "dst_ip_entropy": window.dst_ip_entropy,
                },
                window=window,
                interpretation="All traffic directed to a single destination may be normal (e.g., streaming) or could indicate focused attack.",
            )
            alerts.append(alert)
        
        return alerts
    
    def _update_history(self, window: WindowSummary) -> None:
        """Update baseline history with current window."""
        self.pps_history.append(window.packets_per_second)
        self.bps_history.append(window.bytes_per_second)
        self.size_history.append(window.mean_packet_size)
        
        # Keep history bounded
        if len(self.pps_history) > self.history_size:
            self.pps_history.pop(0)
        if len(self.bps_history) > self.history_size:
            self.bps_history.pop(0)
        if len(self.size_history) > self.history_size:
            self.size_history.pop(0)
    
    def _rate_severity(self, ratio: float) -> AlertSeverity:
        """Determine severity based on rate ratio."""
        if ratio >= 10:
            return AlertSeverity.CRITICAL
        elif ratio >= 5:
            return AlertSeverity.HIGH
        elif ratio >= 3:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
    
    def _format_bytes(self, bytes_val: float) -> str:
        """Format bytes to human-readable string."""
        for unit in ["B", "KB", "MB", "GB"]:
            if bytes_val < 1024:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f} TB"
    
    def set_baseline(
        self,
        pps: Optional[float] = None,
        bps: Optional[float] = None,
        mean_size: Optional[float] = None,
        size_std: Optional[float] = None,
    ) -> None:
        """
        Manually set baseline values.
        
        Args:
            pps: Baseline packets per second
            bps: Baseline bytes per second
            mean_size: Baseline mean packet size
            size_std: Baseline packet size standard deviation
        """
        if pps is not None:
            self.baseline_pps = pps
        if bps is not None:
            self.baseline_bps = bps
        if mean_size is not None:
            self.baseline_mean_size = mean_size
        if size_std is not None:
            self.baseline_size_std = size_std
        
        logger.info(f"Baseline updated: pps={self.baseline_pps}, bps={self.baseline_bps}")
