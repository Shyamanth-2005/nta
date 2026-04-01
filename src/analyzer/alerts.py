"""
Alert management and output.

Handles:
- Alert deduplication and suppression
- Multi-format output (console, file, JSON)
- Alert history and statistics
"""

import logging
import time
import json
from collections import defaultdict
from pathlib import Path
from typing import List, Dict, Optional, Callable, Any
from threading import Lock

from analyzer.models import Alert, AlertSeverity

logger = logging.getLogger("analyzer.alerts")


class AlertManager:
    """
    Manages alert generation, deduplication, and output.
    """
    
    def __init__(
        self,
        output_dir: Optional[Path] = None,
        console_output: bool = True,
        file_output: bool = True,
        output_format: str = "both",  # "json", "text", or "both"
        suppression_window: int = 60,  # seconds
        on_alert: Optional[Callable[[Alert], None]] = None,
    ):
        """
        Initialize alert manager.
        
        Args:
            output_dir: Directory for alert log files
            console_output: Enable console output
            file_output: Enable file output
            output_format: "json", "text", or "both"
            suppression_window: Seconds to suppress duplicate alerts
            on_alert: Callback for each alert
        """
        self.output_dir = Path(output_dir) if output_dir else None
        self.console_output = console_output
        self.file_output = file_output
        self.output_format = output_format
        self.suppression_window = suppression_window
        self.on_alert = on_alert
        
        # Alert storage
        self.alerts: List[Alert] = []
        self._lock = Lock()
        
        # Suppression tracking: (detector, category) -> last_alert_time
        self._suppression_map: Dict[tuple, float] = defaultdict(float)
        
        # Statistics
        self.alerts_total = 0
        self.alerts_suppressed = 0
        
        # Set up output files
        if self.output_dir and self.file_output:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            self._text_file = self.output_dir / "alerts.log"
            self._json_file = self.output_dir / "alerts.jsonl"
    
    def add_alert(self, alert: Alert) -> bool:
        """
        Add an alert, applying suppression rules.
        
        Args:
            alert: Alert to add
            
        Returns:
            bool: True if alert was added (not suppressed)
        """
        with self._lock:
            self.alerts_total += 1
            
            # Check suppression
            suppression_key = (alert.detector, alert.category)
            last_time = self._suppression_map[suppression_key]
            current_time = time.time()
            
            if current_time - last_time < self.suppression_window:
                # Suppress this alert
                self.alerts_suppressed += 1
                alert.suppressed = True
                logger.debug(f"Alert suppressed: {alert.detector}")
                return False
            
            # Update suppression time
            self._suppression_map[suppression_key] = current_time
            
            # Store alert
            self.alerts.append(alert)
            
            # Output alert
            self._output_alert(alert)
            
            # Call callback
            if self.on_alert:
                try:
                    self.on_alert(alert)
                except Exception as e:
                    logger.error(f"Alert callback error: {e}")
            
            return True
    
    def add_alerts(self, alerts: List[Alert]) -> int:
        """
        Add multiple alerts.
        
        Args:
            alerts: List of alerts to add
            
        Returns:
            int: Number of alerts actually added (not suppressed)
        """
        added = 0
        for alert in alerts:
            if self.add_alert(alert):
                added += 1
        return added
    
    def _output_alert(self, alert: Alert) -> None:
        """Output alert to configured destinations."""
        # Console output
        if self.console_output:
            self._print_alert(alert)
        
        # File output
        if self.file_output and self.output_dir:
            if self.output_format in ("text", "both"):
                self._write_text_alert(alert)
            if self.output_format in ("json", "both"):
                self._write_json_alert(alert)
    
    def _print_alert(self, alert: Alert) -> None:
        """Print alert to console with formatting."""
        severity_colors = {
            AlertSeverity.LOW: "\033[94m",      # Blue
            AlertSeverity.MEDIUM: "\033[93m",   # Yellow
            AlertSeverity.HIGH: "\033[91m",     # Red
            AlertSeverity.CRITICAL: "\033[95m", # Magenta
        }
        reset = "\033[0m"
        
        color = severity_colors.get(alert.severity, "")
        severity_str = f"[{alert.severity.value.upper()}]"
        
        print(f"\n{color}{'='*60}")
        print(f"⚠️  ALERT: {alert.summary}")
        print(f"{'='*60}{reset}")
        print(f"  Severity:   {severity_str}")
        print(f"  Detector:   {alert.detector}")
        print(f"  Category:   {alert.category}")
        print(f"  Time:       {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(alert.timestamp))}")
        
        if alert.evidence:
            print(f"  Evidence:")
            for key, value in list(alert.evidence.items())[:5]:
                print(f"    - {key}: {value}")
        
        if alert.interpretation:
            print(f"  Interpretation: {alert.interpretation[:100]}...")
        
        print()
    
    def _write_text_alert(self, alert: Alert) -> None:
        """Write alert to text log file."""
        try:
            with open(self._text_file, "a") as f:
                f.write(alert.to_log_line() + "\n")
                if alert.evidence:
                    for key, value in alert.evidence.items():
                        f.write(f"    {key}: {value}\n")
                f.write("\n")
        except Exception as e:
            logger.error(f"Failed to write text alert: {e}")
    
    def _write_json_alert(self, alert: Alert) -> None:
        """Write alert to JSONL file."""
        try:
            with open(self._json_file, "a") as f:
                f.write(alert.to_json() + "\n")
        except Exception as e:
            logger.error(f"Failed to write JSON alert: {e}")
    
    def get_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        detector: Optional[str] = None,
        category: Optional[str] = None,
        since: Optional[float] = None,
    ) -> List[Alert]:
        """
        Get alerts with optional filtering.
        
        Args:
            severity: Filter by severity
            detector: Filter by detector name
            category: Filter by category
            since: Filter by timestamp (alerts after this time)
            
        Returns:
            List[Alert]: Filtered alerts
        """
        with self._lock:
            filtered = self.alerts.copy()
        
        if severity:
            filtered = [a for a in filtered if a.severity == severity]
        if detector:
            filtered = [a for a in filtered if a.detector == detector]
        if category:
            filtered = [a for a in filtered if a.category == category]
        if since:
            filtered = [a for a in filtered if a.timestamp >= since]
        
        return filtered
    
    def get_stats(self) -> Dict[str, Any]:
        """Get alert statistics."""
        with self._lock:
            by_severity = defaultdict(int)
            by_detector = defaultdict(int)
            by_category = defaultdict(int)
            
            for alert in self.alerts:
                by_severity[alert.severity.value] += 1
                by_detector[alert.detector] += 1
                by_category[alert.category] += 1
            
            return {
                "total_generated": self.alerts_total,
                "total_stored": len(self.alerts),
                "total_suppressed": self.alerts_suppressed,
                "by_severity": dict(by_severity),
                "by_detector": dict(by_detector),
                "by_category": dict(by_category),
            }
    
    def get_recent(self, count: int = 10) -> List[Alert]:
        """Get most recent alerts."""
        with self._lock:
            return self.alerts[-count:]
    
    def clear(self) -> None:
        """Clear all alerts and reset statistics."""
        with self._lock:
            self.alerts.clear()
            self._suppression_map.clear()
            self.alerts_total = 0
            self.alerts_suppressed = 0
    
    def export_json(self, filepath: str) -> None:
        """Export all alerts to JSON file."""
        with self._lock:
            alerts_data = [a.to_dict() for a in self.alerts]
        
        with open(filepath, "w") as f:
            json.dump(alerts_data, f, indent=2)
        
        logger.info(f"Exported {len(alerts_data)} alerts to {filepath}")
    
    def get_timeline(self) -> List[Dict[str, Any]]:
        """Get alerts as timeline entries."""
        with self._lock:
            return [
                {
                    "timestamp": alert.timestamp,
                    "time_str": time.strftime("%H:%M:%S", time.localtime(alert.timestamp)),
                    "severity": alert.severity.value,
                    "detector": alert.detector,
                    "summary": alert.summary,
                }
                for alert in self.alerts
            ]
