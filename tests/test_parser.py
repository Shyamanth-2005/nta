"""Tests for the packet parser module."""

import pytest
import time
from unittest.mock import Mock, MagicMock

from analyzer.parser import (
    parse_packet,
    parse_tcp_flags,
    get_protocol_name,
    is_syn_packet,
    is_ack_packet,
    is_rst_packet,
    PacketParser,
)
from analyzer.models import PacketEvent


class TestParseTcpFlags:
    """Tests for TCP flag parsing."""
    
    def test_syn_flag(self):
        """Test SYN flag detection."""
        assert parse_tcp_flags(0x02) == "SYN"
    
    def test_ack_flag(self):
        """Test ACK flag detection."""
        assert parse_tcp_flags(0x10) == "ACK"
    
    def test_syn_ack_flags(self):
        """Test SYN+ACK flag detection."""
        result = parse_tcp_flags(0x12)
        assert "SYN" in result
        assert "ACK" in result
    
    def test_rst_flag(self):
        """Test RST flag detection."""
        assert parse_tcp_flags(0x04) == "RST"
    
    def test_fin_flag(self):
        """Test FIN flag detection."""
        assert parse_tcp_flags(0x01) == "FIN"
    
    def test_multiple_flags(self):
        """Test multiple flags."""
        result = parse_tcp_flags(0x18)  # PSH + ACK
        assert "PSH" in result
        assert "ACK" in result
    
    def test_no_flags(self):
        """Test no flags set."""
        assert parse_tcp_flags(0x00) == "NONE"


class TestGetProtocolName:
    """Tests for protocol name lookup."""
    
    def test_tcp_protocol(self):
        """Test TCP protocol number."""
        assert get_protocol_name(6) == "TCP"
    
    def test_udp_protocol(self):
        """Test UDP protocol number."""
        assert get_protocol_name(17) == "UDP"
    
    def test_icmp_protocol(self):
        """Test ICMP protocol number."""
        assert get_protocol_name(1) == "ICMP"
    
    def test_unknown_protocol(self):
        """Test unknown protocol number."""
        result = get_protocol_name(255)
        assert "255" in result


class TestIsSynPacket:
    """Tests for SYN packet detection."""
    
    def test_syn_packet(self, sample_packet_event):
        """Test detection of SYN packet."""
        sample_packet_event.protocol = "TCP"
        sample_packet_event.tcp_flags = "SYN"
        assert is_syn_packet(sample_packet_event) is True
    
    def test_syn_ack_packet(self, sample_packet_event):
        """Test SYN+ACK is not detected as SYN-only."""
        sample_packet_event.protocol = "TCP"
        sample_packet_event.tcp_flags = "SYN,ACK"
        assert is_syn_packet(sample_packet_event) is False
    
    def test_non_tcp_packet(self, sample_packet_event):
        """Test non-TCP packet is not SYN."""
        sample_packet_event.protocol = "UDP"
        sample_packet_event.tcp_flags = None
        assert is_syn_packet(sample_packet_event) is False


class TestIsAckPacket:
    """Tests for ACK packet detection."""
    
    def test_ack_packet(self, sample_packet_event):
        """Test detection of ACK packet."""
        sample_packet_event.protocol = "TCP"
        sample_packet_event.tcp_flags = "ACK"
        assert is_ack_packet(sample_packet_event) is True
    
    def test_syn_ack_packet(self, sample_packet_event):
        """Test SYN+ACK contains ACK."""
        sample_packet_event.protocol = "TCP"
        sample_packet_event.tcp_flags = "SYN,ACK"
        assert is_ack_packet(sample_packet_event) is True


class TestIsRstPacket:
    """Tests for RST packet detection."""
    
    def test_rst_packet(self, sample_packet_event):
        """Test detection of RST packet."""
        sample_packet_event.protocol = "TCP"
        sample_packet_event.tcp_flags = "RST"
        assert is_rst_packet(sample_packet_event) is True


class TestPacketParser:
    """Tests for PacketParser class."""
    
    def test_parser_initialization(self):
        """Test parser initialization."""
        parser = PacketParser(interface="eth0")
        assert parser.interface == "eth0"
        assert parser.packets_parsed == 0
    
    def test_parser_stats(self):
        """Test parser statistics."""
        parser = PacketParser()
        stats = parser.get_stats()
        
        assert "packets_parsed" in stats
        assert "packets_dropped" in stats
        assert "parse_errors" in stats
    
    def test_reset_stats(self):
        """Test statistics reset."""
        parser = PacketParser()
        parser.packets_parsed = 100
        parser.packets_dropped = 10
        
        parser.reset_stats()
        
        assert parser.packets_parsed == 0
        assert parser.packets_dropped == 0
