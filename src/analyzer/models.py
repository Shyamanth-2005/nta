"""
Data models for the network traffic analyzer.

Defines core data structures:
- PacketEvent: Normalized packet representation
- WindowSummary: Aggregated window statistics
- Alert: Detection alert with evidence
- AlertSeverity: Alert severity levels
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
import json


class AlertSeverity(Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    def __str__(self) -> str:
        return self.value


@dataclass
class PacketEvent:
    """
    Normalized packet event extracted from raw packet capture.
    
    Attributes:
        timestamp: When the packet was captured
        interface: Network interface that captured the packet
        src_ip: Source IP address
        dst_ip: Destination IP address
        protocol: Protocol name (TCP, UDP, ICMP, etc.)
        packet_size: Size of the packet in bytes
        src_port: Source port (if applicable)
        dst_port: Destination port (if applicable)
        tcp_flags: TCP flags as string (if TCP packet)
        direction: Inbound/outbound/unknown
    """
    timestamp: float
    interface: str
    src_ip: str
    dst_ip: str
    protocol: str
    packet_size: int
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    direction: str = "unknown"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "timestamp": self.timestamp,
            "interface": self.interface,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "packet_size": self.packet_size,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "tcp_flags": self.tcp_flags,
            "direction": self.direction,
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PacketEvent":
        """Create PacketEvent from dictionary."""
        return cls(**data)


@dataclass
class WindowSummary:
    """
    Aggregated statistics for a time window.
    
    Attributes:
        window_start: Start time of the window
        window_end: End time of the window
        packet_count: Total packets in window
        byte_count: Total bytes in window
        packets_per_second: Packet rate
        bytes_per_second: Byte rate
        unique_src_ips: Count of unique source IPs
        unique_dst_ips: Count of unique destination IPs
        unique_dst_ports: Count of unique destination ports
        protocol_counts: Count per protocol
        mean_packet_size: Average packet size
        packet_size_variance: Variance of packet sizes
        min_packet_size: Minimum packet size
        max_packet_size: Maximum packet size
        mean_inter_arrival: Average time between packets
        inter_arrival_variance: Variance of inter-arrival times
        syn_count: TCP SYN packet count
        ack_count: TCP ACK packet count
        rst_count: TCP RST packet count
        dst_ip_entropy: Entropy of destination IP distribution
        top_talkers: Top source IPs by packet count
    """
    window_start: float
    window_end: float
    packet_count: int = 0
    byte_count: int = 0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    unique_dst_ports: int = 0
    protocol_counts: Dict[str, int] = field(default_factory=dict)
    mean_packet_size: float = 0.0
    packet_size_variance: float = 0.0
    min_packet_size: int = 0
    max_packet_size: int = 0
    mean_inter_arrival: float = 0.0
    inter_arrival_variance: float = 0.0
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    dst_ip_entropy: float = 0.0
    top_talkers: List[tuple] = field(default_factory=list)
    
    @property
    def duration(self) -> float:
        """Window duration in seconds."""
        return self.window_end - self.window_start
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "window_start": self.window_start,
            "window_end": self.window_end,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "packets_per_second": self.packets_per_second,
            "bytes_per_second": self.bytes_per_second,
            "unique_src_ips": self.unique_src_ips,
            "unique_dst_ips": self.unique_dst_ips,
            "unique_dst_ports": self.unique_dst_ports,
            "protocol_counts": self.protocol_counts,
            "mean_packet_size": self.mean_packet_size,
            "packet_size_variance": self.packet_size_variance,
            "min_packet_size": self.min_packet_size,
            "max_packet_size": self.max_packet_size,
            "mean_inter_arrival": self.mean_inter_arrival,
            "inter_arrival_variance": self.inter_arrival_variance,
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "rst_count": self.rst_count,
            "dst_ip_entropy": self.dst_ip_entropy,
            "top_talkers": self.top_talkers,
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WindowSummary":
        """Create WindowSummary from dictionary."""
        return cls(**data)


@dataclass
class Alert:
    """
    Detection alert with evidence and context.
    
    Attributes:
        alert_id: Unique identifier for the alert
        timestamp: When the alert was generated
        severity: Alert severity level
        category: Alert category (e.g., "network_attack", "anomaly")
        detector: Name of the detector that generated the alert
        summary: Human-readable summary
        evidence: Supporting data for the alert
        window_start: Start of the window that triggered the alert
        window_end: End of the window that triggered the alert
        interpretation: Recommended interpretation/action
        suppressed: Whether alert was suppressed (deduplication)
    """
    alert_id: str
    timestamp: float
    severity: AlertSeverity
    category: str
    detector: str
    summary: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    window_start: Optional[float] = None
    window_end: Optional[float] = None
    interpretation: str = ""
    suppressed: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "timestamp_human": datetime.fromtimestamp(self.timestamp).isoformat(),
            "severity": str(self.severity),
            "category": self.category,
            "detector": self.detector,
            "summary": self.summary,
            "evidence": self.evidence,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "interpretation": self.interpretation,
            "suppressed": self.suppressed,
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())
    
    def to_log_line(self) -> str:
        """Format as human-readable log line."""
        ts = datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        return f"[{ts}] [{self.severity.value.upper()}] [{self.detector}] {self.summary}"
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Alert":
        """Create Alert from dictionary."""
        data = data.copy()
        data.pop("timestamp_human", None)
        if isinstance(data.get("severity"), str):
            data["severity"] = AlertSeverity(data["severity"])
        return cls(**data)


@dataclass
class SessionMetadata:
    """
    Metadata about a monitoring session.
    
    Attributes:
        session_id: Unique session identifier
        start_time: When monitoring started
        end_time: When monitoring ended (if finished)
        interface: Network interface being monitored
        mode: Capture mode (live, pcap)
        config: Configuration used
        packet_count: Total packets processed
        alert_count: Total alerts generated
        window_count: Number of windows processed
    """
    session_id: str
    start_time: float
    interface: str
    mode: str = "live"
    end_time: Optional[float] = None
    config: Dict[str, Any] = field(default_factory=dict)
    packet_count: int = 0
    alert_count: int = 0
    window_count: int = 0
    
    @property
    def duration(self) -> Optional[float]:
        """Session duration in seconds."""
        if self.end_time:
            return self.end_time - self.start_time
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "session_id": self.session_id,
            "start_time": self.start_time,
            "start_time_human": datetime.fromtimestamp(self.start_time).isoformat(),
            "end_time": self.end_time,
            "end_time_human": datetime.fromtimestamp(self.end_time).isoformat() if self.end_time else None,
            "duration_seconds": self.duration,
            "interface": self.interface,
            "mode": self.mode,
            "config": self.config,
            "packet_count": self.packet_count,
            "alert_count": self.alert_count,
            "window_count": self.window_count,
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())
