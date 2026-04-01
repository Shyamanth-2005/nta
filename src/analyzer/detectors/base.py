"""
Base detector interface and registry.

All detectors must implement the BaseDetector interface.
"""

import logging
import uuid
import time
from abc import ABC, abstractmethod
from typing import List, Dict, Type, Optional, Any

from analyzer.models import WindowSummary, Alert, AlertSeverity

logger = logging.getLogger("analyzer.detectors")


class BaseDetector(ABC):
    """
    Abstract base class for all detectors.
    
    Each detector analyzes window summaries and produces alerts
    when anomalies are detected.
    """
    
    name: str = "base"
    category: str = "unknown"
    description: str = "Base detector"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize detector.
        
        Args:
            config: Detector-specific configuration
        """
        self.config = config or {}
        self.enabled = True
        self.alerts_generated = 0
        self.windows_analyzed = 0
    
    @abstractmethod
    def evaluate(self, window: WindowSummary) -> List[Alert]:
        """
        Evaluate a window summary for anomalies.
        
        Args:
            window: Aggregated window statistics
            
        Returns:
            List[Alert]: Generated alerts (empty if none)
        """
        pass
    
    def create_alert(
        self,
        severity: AlertSeverity,
        summary: str,
        evidence: Dict[str, Any],
        window: WindowSummary,
        interpretation: str = "",
    ) -> Alert:
        """
        Create an alert with standard fields populated.
        
        Args:
            severity: Alert severity level
            summary: Human-readable summary
            evidence: Supporting data
            window: Window that triggered the alert
            interpretation: Recommended interpretation
            
        Returns:
            Alert: Constructed alert object
        """
        self.alerts_generated += 1
        
        return Alert(
            alert_id=f"{self.name}-{uuid.uuid4().hex[:8]}",
            timestamp=time.time(),
            severity=severity,
            category=self.category,
            detector=self.name,
            summary=summary,
            evidence=evidence,
            window_start=window.window_start,
            window_end=window.window_end,
            interpretation=interpretation,
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics."""
        return {
            "name": self.name,
            "enabled": self.enabled,
            "alerts_generated": self.alerts_generated,
            "windows_analyzed": self.windows_analyzed,
        }
    
    def reset_stats(self) -> None:
        """Reset detector statistics."""
        self.alerts_generated = 0
        self.windows_analyzed = 0


class DetectorRegistry:
    """
    Registry for detector types.
    
    Allows dynamic registration and instantiation of detectors.
    """
    
    _detectors: Dict[str, Type[BaseDetector]] = {}
    
    @classmethod
    def register(cls, name: str, detector_class: Type[BaseDetector]) -> None:
        """
        Register a detector class.
        
        Args:
            name: Detector name for lookup
            detector_class: Detector class to register
        """
        cls._detectors[name] = detector_class
        logger.debug(f"Registered detector: {name}")
    
    @classmethod
    def get(cls, name: str) -> Optional[Type[BaseDetector]]:
        """
        Get a detector class by name.
        
        Args:
            name: Detector name
            
        Returns:
            Optional[Type[BaseDetector]]: Detector class or None
        """
        return cls._detectors.get(name)
    
    @classmethod
    def create(cls, name: str, config: Optional[Dict[str, Any]] = None) -> Optional[BaseDetector]:
        """
        Create a detector instance.
        
        Args:
            name: Detector name
            config: Detector configuration
            
        Returns:
            Optional[BaseDetector]: Detector instance or None
        """
        detector_class = cls.get(name)
        if detector_class:
            return detector_class(config)
        logger.warning(f"Unknown detector: {name}")
        return None
    
    @classmethod
    def list_available(cls) -> List[str]:
        """Get list of registered detector names."""
        return list(cls._detectors.keys())
    
    @classmethod
    def create_all(cls, names: List[str], config: Optional[Dict[str, Any]] = None) -> List[BaseDetector]:
        """
        Create multiple detector instances.
        
        Args:
            names: List of detector names
            config: Shared configuration
            
        Returns:
            List[BaseDetector]: Created detector instances
        """
        detectors = []
        for name in names:
            detector = cls.create(name, config)
            if detector:
                detectors.append(detector)
        return detectors


class DetectionEngine:
    """
    Coordinates multiple detectors for anomaly detection.
    """
    
    def __init__(self, detectors: Optional[List[BaseDetector]] = None):
        """
        Initialize detection engine.
        
        Args:
            detectors: List of detector instances
        """
        self.detectors = detectors or []
        self.all_alerts: List[Alert] = []
    
    def add_detector(self, detector: BaseDetector) -> None:
        """Add a detector to the engine."""
        self.detectors.append(detector)
    
    def remove_detector(self, name: str) -> bool:
        """Remove a detector by name."""
        for i, detector in enumerate(self.detectors):
            if detector.name == name:
                self.detectors.pop(i)
                return True
        return False
    
    def evaluate(self, window: WindowSummary) -> List[Alert]:
        """
        Run all enabled detectors on a window.
        
        Args:
            window: Window summary to analyze
            
        Returns:
            List[Alert]: All generated alerts
        """
        alerts = []
        
        for detector in self.detectors:
            if not detector.enabled:
                continue
            
            try:
                detector.windows_analyzed += 1
                detector_alerts = detector.evaluate(window)
                alerts.extend(detector_alerts)
            except Exception as e:
                logger.error(f"Detector {detector.name} error: {e}")
        
        self.all_alerts.extend(alerts)
        return alerts
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return {
            "detector_count": len(self.detectors),
            "total_alerts": len(self.all_alerts),
            "detectors": [d.get_stats() for d in self.detectors],
        }
    
    def get_alerts_by_severity(self, severity: AlertSeverity) -> List[Alert]:
        """Get alerts filtered by severity."""
        return [a for a in self.all_alerts if a.severity == severity]
    
    def get_alerts_by_detector(self, detector_name: str) -> List[Alert]:
        """Get alerts filtered by detector."""
        return [a for a in self.all_alerts if a.detector == detector_name]
    
    def clear_alerts(self) -> None:
        """Clear all stored alerts."""
        self.all_alerts.clear()
