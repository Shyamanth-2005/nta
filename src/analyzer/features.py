"""
Feature extraction from packets and windows.

Computes statistical features for anomaly detection:
- Traffic rates and volumes
- Protocol distributions
- Entropy calculations
- Inter-arrival time statistics
"""

import logging
import math
from collections import defaultdict
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass

from analyzer.models import PacketEvent, WindowSummary

logger = logging.getLogger("analyzer.features")


def calculate_entropy(distribution: Dict[str, int]) -> float:
    """
    Calculate Shannon entropy of a distribution.
    
    Args:
        distribution: Dictionary mapping items to counts
        
    Returns:
        float: Entropy value (0 = uniform, higher = more diverse)
    """
    total = sum(distribution.values())
    if total == 0:
        return 0.0
    
    entropy = 0.0
    for count in distribution.values():
        if count > 0:
            prob = count / total
            entropy -= prob * math.log2(prob)
    
    return entropy


def calculate_variance(values: List[float]) -> Tuple[float, float]:
    """
    Calculate mean and variance of a list of values.
    
    Args:
        values: List of numeric values
        
    Returns:
        Tuple[float, float]: (mean, variance)
    """
    if not values:
        return 0.0, 0.0
    
    n = len(values)
    mean = sum(values) / n
    
    if n < 2:
        return mean, 0.0
    
    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
    return mean, variance


class FeatureExtractor:
    """
    Extracts features from packets for window aggregation.
    """
    
    def __init__(self):
        """Initialize feature extractor."""
        self.reset()
    
    def reset(self) -> None:
        """Reset all accumulated state."""
        self.packet_sizes: List[int] = []
        self.timestamps: List[float] = []
        self.src_ips: Dict[str, int] = defaultdict(int)
        self.dst_ips: Dict[str, int] = defaultdict(int)
        self.dst_ports: Dict[int, int] = defaultdict(int)
        self.protocols: Dict[str, int] = defaultdict(int)
        self.syn_count = 0
        self.ack_count = 0
        self.rst_count = 0
        self.byte_count = 0
        self.packet_count = 0
    
    def add_packet(self, event: PacketEvent) -> None:
        """
        Add a packet event to the feature accumulator.
        
        Args:
            event: Parsed packet event
        """
        self.packet_count += 1
        self.byte_count += event.packet_size
        self.packet_sizes.append(event.packet_size)
        self.timestamps.append(event.timestamp)
        
        # Track IP addresses
        self.src_ips[event.src_ip] += 1
        self.dst_ips[event.dst_ip] += 1
        
        # Track destination ports
        if event.dst_port is not None:
            self.dst_ports[event.dst_port] += 1
        
        # Track protocols
        self.protocols[event.protocol] += 1
        
        # Track TCP flags
        if event.tcp_flags:
            flags = event.tcp_flags.upper()
            if "SYN" in flags and "ACK" not in flags:
                self.syn_count += 1
            if "ACK" in flags:
                self.ack_count += 1
            if "RST" in flags:
                self.rst_count += 1
    
    def compute_window_summary(
        self, 
        window_start: float, 
        window_end: float,
        top_n: int = 10
    ) -> WindowSummary:
        """
        Compute window summary from accumulated packets.
        
        Args:
            window_start: Window start timestamp
            window_end: Window end timestamp
            top_n: Number of top talkers to include
            
        Returns:
            WindowSummary: Computed window statistics
        """
        duration = window_end - window_start
        if duration <= 0:
            duration = 1.0
        
        # Packet size statistics
        mean_size, size_variance = calculate_variance(self.packet_sizes)
        min_size = min(self.packet_sizes) if self.packet_sizes else 0
        max_size = max(self.packet_sizes) if self.packet_sizes else 0
        
        # Inter-arrival time statistics
        inter_arrivals = []
        if len(self.timestamps) > 1:
            sorted_ts = sorted(self.timestamps)
            inter_arrivals = [
                sorted_ts[i+1] - sorted_ts[i] 
                for i in range(len(sorted_ts) - 1)
            ]
        mean_inter, inter_var = calculate_variance(inter_arrivals)
        
        # Destination IP entropy
        dst_ip_entropy = calculate_entropy(self.dst_ips)
        
        # Top talkers (source IPs by packet count)
        top_talkers = sorted(
            self.src_ips.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:top_n]
        
        return WindowSummary(
            window_start=window_start,
            window_end=window_end,
            packet_count=self.packet_count,
            byte_count=self.byte_count,
            packets_per_second=self.packet_count / duration,
            bytes_per_second=self.byte_count / duration,
            unique_src_ips=len(self.src_ips),
            unique_dst_ips=len(self.dst_ips),
            unique_dst_ports=len(self.dst_ports),
            protocol_counts=dict(self.protocols),
            mean_packet_size=mean_size,
            packet_size_variance=size_variance,
            min_packet_size=min_size,
            max_packet_size=max_size,
            mean_inter_arrival=mean_inter,
            inter_arrival_variance=inter_var,
            syn_count=self.syn_count,
            ack_count=self.ack_count,
            rst_count=self.rst_count,
            dst_ip_entropy=dst_ip_entropy,
            top_talkers=top_talkers,
        )
    
    def get_src_ip_port_counts(self) -> Dict[str, Dict[str, int]]:
        """
        Get port access counts per source IP.
        
        Returns:
            Dict mapping source IP to {port: count}
        """
        # This is tracked separately for port scan detection
        return {}


@dataclass
class PortScanTracker:
    """Tracks port access patterns for scan detection."""
    
    def __init__(self):
        self.src_to_ports: Dict[str, set] = defaultdict(set)
        self.src_to_dsts: Dict[str, set] = defaultdict(set)
    
    def add_packet(self, event: PacketEvent) -> None:
        """Track port access from packet."""
        if event.dst_port is not None:
            self.src_to_ports[event.src_ip].add(event.dst_port)
        self.src_to_dsts[event.src_ip].add(event.dst_ip)
    
    def get_vertical_scan_candidates(self, threshold: int = 15) -> List[Tuple[str, int]]:
        """
        Get source IPs with many unique destination ports (vertical scan).
        
        Args:
            threshold: Minimum unique ports to flag
            
        Returns:
            List of (src_ip, port_count) tuples above threshold
        """
        return [
            (ip, len(ports))
            for ip, ports in self.src_to_ports.items()
            if len(ports) >= threshold
        ]
    
    def get_horizontal_scan_candidates(self, threshold: int = 10) -> List[Tuple[str, int]]:
        """
        Get source IPs accessing many unique destinations (horizontal scan).
        
        Args:
            threshold: Minimum unique destinations to flag
            
        Returns:
            List of (src_ip, dst_count) tuples above threshold
        """
        return [
            (ip, len(dsts))
            for ip, dsts in self.src_to_dsts.items()
            if len(dsts) >= threshold
        ]
    
    def reset(self) -> None:
        """Clear all tracking data."""
        self.src_to_ports.clear()
        self.src_to_dsts.clear()


class SYNTracker:
    """Tracks SYN packets for flood detection."""
    
    def __init__(self):
        self.syn_counts: Dict[str, int] = defaultdict(int)
    
    def add_syn(self, src_ip: str) -> None:
        """Record a SYN packet from source IP."""
        self.syn_counts[src_ip] += 1
    
    def get_flood_candidates(self, threshold: int = 100) -> List[Tuple[str, int]]:
        """
        Get source IPs with high SYN counts (flood candidates).
        
        Args:
            threshold: Minimum SYN count to flag
            
        Returns:
            List of (src_ip, syn_count) tuples above threshold
        """
        return [
            (ip, count)
            for ip, count in self.syn_counts.items()
            if count >= threshold
        ]
    
    def reset(self) -> None:
        """Clear all tracking data."""
        self.syn_counts.clear()
