"""Pytest configuration and shared fixtures."""

import pytest
import time
from pathlib import Path
from typing import List

from analyzer.models import PacketEvent, WindowSummary, Alert, AlertSeverity
from analyzer.config import Config


@pytest.fixture
def sample_config() -> Config:
    """Create a sample configuration for testing."""
    return Config(
        interface="test0",
        window_size=5,
        output_dir="test_data",
        log_level="DEBUG",
    )


@pytest.fixture
def sample_packet_event() -> PacketEvent:
    """Create a sample packet event."""
    return PacketEvent(
        timestamp=time.time(),
        interface="test0",
        src_ip="192.168.1.100",
        dst_ip="192.168.1.1",
        protocol="TCP",
        packet_size=100,
        src_port=12345,
        dst_port=80,
        tcp_flags="SYN",
        direction="outbound",
    )


@pytest.fixture
def sample_packet_events() -> List[PacketEvent]:
    """Create a list of sample packet events."""
    base_time = time.time()
    events = []
    
    # Normal TCP traffic
    for i in range(50):
        events.append(PacketEvent(
            timestamp=base_time + i * 0.1,
            interface="test0",
            src_ip=f"192.168.1.{100 + i % 5}",
            dst_ip="192.168.1.1",
            protocol="TCP",
            packet_size=100 + i * 10,
            src_port=10000 + i,
            dst_port=80,
            tcp_flags="ACK",
        ))
    
    # Some UDP traffic
    for i in range(20):
        events.append(PacketEvent(
            timestamp=base_time + 5 + i * 0.1,
            interface="test0",
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            protocol="UDP",
            packet_size=60,
            src_port=50000,
            dst_port=53,
        ))
    
    # Some SYN packets
    for i in range(10):
        events.append(PacketEvent(
            timestamp=base_time + 7 + i * 0.05,
            interface="test0",
            src_ip="192.168.1.200",
            dst_ip="192.168.1.1",
            protocol="TCP",
            packet_size=60,
            src_port=20000 + i,
            dst_port=80 + i,
            tcp_flags="SYN",
        ))
    
    return events


@pytest.fixture
def sample_window_summary() -> WindowSummary:
    """Create a sample window summary."""
    return WindowSummary(
        window_start=time.time() - 5,
        window_end=time.time(),
        packet_count=100,
        byte_count=10000,
        packets_per_second=20.0,
        bytes_per_second=2000.0,
        unique_src_ips=5,
        unique_dst_ips=3,
        unique_dst_ports=10,
        protocol_counts={"TCP": 70, "UDP": 25, "ICMP": 5},
        mean_packet_size=100.0,
        packet_size_variance=25.0,
        min_packet_size=60,
        max_packet_size=1500,
        mean_inter_arrival=0.05,
        inter_arrival_variance=0.001,
        syn_count=15,
        ack_count=50,
        rst_count=2,
        dst_ip_entropy=1.5,
        top_talkers=[("192.168.1.100", 30), ("192.168.1.101", 25)],
    )


@pytest.fixture
def sample_alert() -> Alert:
    """Create a sample alert."""
    return Alert(
        alert_id="test-12345678",
        timestamp=time.time(),
        severity=AlertSeverity.MEDIUM,
        category="network_attack",
        detector="syn_flood",
        summary="High SYN packet volume detected: 150 SYN packets in 5.0s",
        evidence={
            "syn_count": 150,
            "threshold": 100,
            "syn_rate": 30.0,
        },
        window_start=time.time() - 5,
        window_end=time.time(),
        interpretation="Possible SYN flood attack.",
    )


@pytest.fixture
def tmp_data_dir(tmp_path: Path) -> Path:
    """Create temporary data directory structure."""
    data_dir = tmp_path / "data"
    (data_dir / "logs").mkdir(parents=True)
    (data_dir / "reports").mkdir(parents=True)
    (data_dir / "baselines").mkdir(parents=True)
    (data_dir / "sessions").mkdir(parents=True)
    return data_dir
