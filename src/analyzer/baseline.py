"""
Baseline training and comparison.

Provides:
- Baseline learning from normal traffic
- Baseline storage and loading
- Statistical comparison with live traffic
"""

import logging
import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Dict, Optional, Any
import math

from analyzer.models import WindowSummary

logger = logging.getLogger("analyzer.baseline")


@dataclass
class BaselineStatistics:
    """
    Statistical baseline for normal traffic behavior.
    
    Stores mean and standard deviation for key metrics.
    """
    # Traffic rates
    mean_pps: float = 0.0
    std_pps: float = 0.0
    mean_bps: float = 0.0
    std_bps: float = 0.0
    
    # Packet sizes
    mean_packet_size: float = 0.0
    std_packet_size: float = 0.0
    
    # Protocol distribution
    protocol_distribution: Dict[str, float] = field(default_factory=dict)
    
    # Connection patterns
    mean_unique_src_ips: float = 0.0
    std_unique_src_ips: float = 0.0
    mean_unique_dst_ips: float = 0.0
    std_unique_dst_ips: float = 0.0
    mean_unique_dst_ports: float = 0.0
    std_unique_dst_ports: float = 0.0
    
    # TCP flags
    mean_syn_count: float = 0.0
    std_syn_count: float = 0.0
    
    # Entropy
    mean_dst_ip_entropy: float = 0.0
    std_dst_ip_entropy: float = 0.0
    
    # Metadata
    window_count: int = 0
    created_at: float = 0.0
    profile_name: str = "default"
    interface: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BaselineStatistics":
        """Create from dictionary."""
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> "BaselineStatistics":
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))


class BaselineBuilder:
    """
    Builds baseline statistics from window summaries.
    """
    
    def __init__(self, min_windows: int = 10):
        """
        Initialize baseline builder.
        
        Args:
            min_windows: Minimum windows required for valid baseline
        """
        self.min_windows = min_windows
        self.windows: List[WindowSummary] = []
    
    def add_window(self, window: WindowSummary) -> None:
        """Add a window to the baseline training set."""
        self.windows.append(window)
    
    def add_windows(self, windows: List[WindowSummary]) -> None:
        """Add multiple windows to the training set."""
        self.windows.extend(windows)
    
    @property
    def window_count(self) -> int:
        """Number of windows collected."""
        return len(self.windows)
    
    @property
    def is_ready(self) -> bool:
        """Check if enough windows have been collected."""
        return len(self.windows) >= self.min_windows
    
    def build(self, profile_name: str = "default", interface: str = "") -> Optional[BaselineStatistics]:
        """
        Build baseline statistics from collected windows.
        
        Args:
            profile_name: Name for this baseline profile
            interface: Network interface name
            
        Returns:
            Optional[BaselineStatistics]: Computed baseline or None if insufficient data
        """
        if not self.is_ready:
            logger.warning(f"Insufficient windows for baseline: {len(self.windows)}/{self.min_windows}")
            return None
        
        logger.info(f"Building baseline from {len(self.windows)} windows")
        
        # Extract metrics from windows
        pps_values = [w.packets_per_second for w in self.windows]
        bps_values = [w.bytes_per_second for w in self.windows]
        size_values = [w.mean_packet_size for w in self.windows]
        src_ip_values = [w.unique_src_ips for w in self.windows]
        dst_ip_values = [w.unique_dst_ips for w in self.windows]
        dst_port_values = [w.unique_dst_ports for w in self.windows]
        syn_values = [w.syn_count for w in self.windows]
        entropy_values = [w.dst_ip_entropy for w in self.windows]
        
        # Calculate protocol distribution
        total_packets = sum(w.packet_count for w in self.windows)
        protocol_totals: Dict[str, int] = {}
        for w in self.windows:
            for proto, count in w.protocol_counts.items():
                protocol_totals[proto] = protocol_totals.get(proto, 0) + count
        
        protocol_dist = {
            proto: count / total_packets
            for proto, count in protocol_totals.items()
        } if total_packets > 0 else {}
        
        # Build baseline
        baseline = BaselineStatistics(
            mean_pps=self._mean(pps_values),
            std_pps=self._std(pps_values),
            mean_bps=self._mean(bps_values),
            std_bps=self._std(bps_values),
            mean_packet_size=self._mean(size_values),
            std_packet_size=self._std(size_values),
            protocol_distribution=protocol_dist,
            mean_unique_src_ips=self._mean(src_ip_values),
            std_unique_src_ips=self._std(src_ip_values),
            mean_unique_dst_ips=self._mean(dst_ip_values),
            std_unique_dst_ips=self._std(dst_ip_values),
            mean_unique_dst_ports=self._mean(dst_port_values),
            std_unique_dst_ports=self._std(dst_port_values),
            mean_syn_count=self._mean(syn_values),
            std_syn_count=self._std(syn_values),
            mean_dst_ip_entropy=self._mean(entropy_values),
            std_dst_ip_entropy=self._std(entropy_values),
            window_count=len(self.windows),
            created_at=time.time(),
            profile_name=profile_name,
            interface=interface,
        )
        
        return baseline
    
    def _mean(self, values: List[float]) -> float:
        """Calculate mean of values."""
        if not values:
            return 0.0
        return sum(values) / len(values)
    
    def _std(self, values: List[float]) -> float:
        """Calculate standard deviation of values."""
        if len(values) < 2:
            return 0.0
        mean = self._mean(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return math.sqrt(variance)
    
    def reset(self) -> None:
        """Clear collected windows."""
        self.windows.clear()


class BaselineManager:
    """
    Manages baseline profiles (storage, loading, comparison).
    """
    
    def __init__(self, baselines_dir: Path):
        """
        Initialize baseline manager.
        
        Args:
            baselines_dir: Directory for storing baseline files
        """
        self.baselines_dir = Path(baselines_dir)
        self.baselines_dir.mkdir(parents=True, exist_ok=True)
        
        self.current_baseline: Optional[BaselineStatistics] = None
        self.builder = BaselineBuilder()
    
    def save_baseline(self, baseline: BaselineStatistics, name: Optional[str] = None) -> Path:
        """
        Save baseline to file.
        
        Args:
            baseline: Baseline statistics to save
            name: Optional custom name (uses profile_name if not provided)
            
        Returns:
            Path: Path to saved baseline file
        """
        filename = f"{name or baseline.profile_name}.json"
        filepath = self.baselines_dir / filename
        
        with open(filepath, "w") as f:
            f.write(baseline.to_json())
        
        logger.info(f"Saved baseline to {filepath}")
        return filepath
    
    def load_baseline(self, name: str) -> Optional[BaselineStatistics]:
        """
        Load baseline from file.
        
        Args:
            name: Baseline profile name
            
        Returns:
            Optional[BaselineStatistics]: Loaded baseline or None
        """
        filepath = self.baselines_dir / f"{name}.json"
        
        if not filepath.exists():
            logger.warning(f"Baseline not found: {filepath}")
            return None
        
        try:
            with open(filepath, "r") as f:
                baseline = BaselineStatistics.from_json(f.read())
            
            logger.info(f"Loaded baseline from {filepath}")
            return baseline
        except Exception as e:
            logger.error(f"Failed to load baseline: {e}")
            return None
    
    def list_baselines(self) -> List[str]:
        """Get list of available baseline profiles."""
        return [
            f.stem for f in self.baselines_dir.glob("*.json")
        ]
    
    def delete_baseline(self, name: str) -> bool:
        """Delete a baseline profile."""
        filepath = self.baselines_dir / f"{name}.json"
        if filepath.exists():
            filepath.unlink()
            logger.info(f"Deleted baseline: {name}")
            return True
        return False
    
    def set_current(self, name: str) -> bool:
        """
        Set the current active baseline.
        
        Args:
            name: Baseline profile name
            
        Returns:
            bool: True if baseline was loaded successfully
        """
        baseline = self.load_baseline(name)
        if baseline:
            self.current_baseline = baseline
            return True
        return False
    
    def compare_window(self, window: WindowSummary) -> Dict[str, Any]:
        """
        Compare a window against the current baseline.
        
        Args:
            window: Window summary to compare
            
        Returns:
            Dict with comparison results (deviations, anomalies)
        """
        if not self.current_baseline:
            return {"error": "No baseline loaded"}
        
        b = self.current_baseline
        
        # Calculate z-scores for key metrics
        def z_score(value: float, mean: float, std: float) -> float:
            if std == 0:
                return 0.0
            return (value - mean) / std
        
        deviations = {
            "pps": {
                "value": window.packets_per_second,
                "mean": b.mean_pps,
                "std": b.std_pps,
                "z_score": z_score(window.packets_per_second, b.mean_pps, b.std_pps),
            },
            "bps": {
                "value": window.bytes_per_second,
                "mean": b.mean_bps,
                "std": b.std_bps,
                "z_score": z_score(window.bytes_per_second, b.mean_bps, b.std_bps),
            },
            "packet_size": {
                "value": window.mean_packet_size,
                "mean": b.mean_packet_size,
                "std": b.std_packet_size,
                "z_score": z_score(window.mean_packet_size, b.mean_packet_size, b.std_packet_size),
            },
            "syn_count": {
                "value": window.syn_count,
                "mean": b.mean_syn_count,
                "std": b.std_syn_count,
                "z_score": z_score(window.syn_count, b.mean_syn_count, b.std_syn_count),
            },
            "entropy": {
                "value": window.dst_ip_entropy,
                "mean": b.mean_dst_ip_entropy,
                "std": b.std_dst_ip_entropy,
                "z_score": z_score(window.dst_ip_entropy, b.mean_dst_ip_entropy, b.std_dst_ip_entropy),
            },
        }
        
        # Identify anomalies (z-score > 2)
        anomalies = [
            metric for metric, data in deviations.items()
            if abs(data["z_score"]) > 2
        ]
        
        return {
            "baseline_profile": b.profile_name,
            "deviations": deviations,
            "anomalies": anomalies,
            "anomaly_count": len(anomalies),
        }
    
    def start_training(self, min_windows: int = 10) -> None:
        """Start collecting windows for baseline training."""
        self.builder = BaselineBuilder(min_windows=min_windows)
        logger.info(f"Started baseline training (min_windows={min_windows})")
    
    def add_training_window(self, window: WindowSummary) -> bool:
        """
        Add window to training set.
        
        Returns:
            bool: True if baseline is ready to build
        """
        self.builder.add_window(window)
        return self.builder.is_ready
    
    def complete_training(self, profile_name: str, interface: str = "") -> Optional[BaselineStatistics]:
        """
        Complete training and build baseline.
        
        Args:
            profile_name: Name for the baseline profile
            interface: Network interface name
            
        Returns:
            Optional[BaselineStatistics]: Built baseline or None
        """
        baseline = self.builder.build(profile_name, interface)
        
        if baseline:
            self.save_baseline(baseline)
            self.current_baseline = baseline
            self.builder.reset()
        
        return baseline
