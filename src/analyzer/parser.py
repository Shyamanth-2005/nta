"""
Packet parsing and normalization.

Converts raw Scapy packets to normalized PacketEvent objects.
"""

import logging
import time
from typing import Optional, Generator, Any

from scapy.all import Packet, IP, TCP, UDP, ICMP, Ether, ARP

from analyzer.models import PacketEvent

logger = logging.getLogger("analyzer.parser")


# Protocol number to name mapping
PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}


# TCP flag constants
TCP_FLAGS = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x40: "ECE",
    0x80: "CWR",
}


def parse_tcp_flags(flags: int) -> str:
    """
    Parse TCP flags integer to human-readable string.
    
    Args:
        flags: TCP flags as integer
        
    Returns:
        str: Comma-separated flag names
    """
    flag_names = []
    for bit, name in TCP_FLAGS.items():
        if flags & bit:
            flag_names.append(name)
    return ",".join(flag_names) if flag_names else "NONE"


def get_protocol_name(proto: int) -> str:
    """
    Get protocol name from number.
    
    Args:
        proto: Protocol number
        
    Returns:
        str: Protocol name
    """
    return PROTOCOL_NAMES.get(proto, f"PROTO_{proto}")


def parse_packet(packet: Packet, interface: str = "unknown") -> Optional[PacketEvent]:
    """
    Parse a Scapy packet into a normalized PacketEvent.
    
    Args:
        packet: Raw Scapy packet
        interface: Name of the capture interface
        
    Returns:
        Optional[PacketEvent]: Parsed event or None if not parseable
    """
    try:
        # Get timestamp
        timestamp = float(packet.time) if hasattr(packet, "time") else time.time()
        
        # Must have IP layer for our analysis
        if not packet.haslayer(IP):
            # Check for ARP
            if packet.haslayer(ARP):
                return _parse_arp_packet(packet, interface, timestamp)
            return None
        
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol_num = ip_layer.proto
        protocol = get_protocol_name(protocol_num)
        packet_size = len(packet)
        
        # Initialize optional fields
        src_port = None
        dst_port = None
        tcp_flags = None
        
        # Parse transport layer
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            tcp_flags = parse_tcp_flags(int(tcp_layer.flags))
            
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            
        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            # Use ICMP type/code as pseudo-ports for analysis
            src_port = icmp_layer.type
            dst_port = icmp_layer.code
        
        return PacketEvent(
            timestamp=timestamp,
            interface=interface,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            packet_size=packet_size,
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=tcp_flags,
            direction="unknown",
        )
        
    except Exception as e:
        logger.debug(f"Failed to parse packet: {e}")
        return None


def _parse_arp_packet(packet: Packet, interface: str, timestamp: float) -> Optional[PacketEvent]:
    """Parse ARP packet into PacketEvent."""
    try:
        arp = packet[ARP]
        return PacketEvent(
            timestamp=timestamp,
            interface=interface,
            src_ip=arp.psrc,
            dst_ip=arp.pdst,
            protocol="ARP",
            packet_size=len(packet),
            src_port=arp.op,  # ARP operation (1=request, 2=reply)
            dst_port=None,
            tcp_flags=None,
            direction="unknown",
        )
    except Exception:
        return None


def is_syn_packet(event: PacketEvent) -> bool:
    """Check if packet is a TCP SYN packet."""
    if event.protocol != "TCP" or not event.tcp_flags:
        return False
    flags = event.tcp_flags.upper()
    return "SYN" in flags and "ACK" not in flags


def is_ack_packet(event: PacketEvent) -> bool:
    """Check if packet is a TCP ACK packet."""
    if event.protocol != "TCP" or not event.tcp_flags:
        return False
    return "ACK" in event.tcp_flags.upper()


def is_rst_packet(event: PacketEvent) -> bool:
    """Check if packet is a TCP RST packet."""
    if event.protocol != "TCP" or not event.tcp_flags:
        return False
    return "RST" in event.tcp_flags.upper()


def is_fin_packet(event: PacketEvent) -> bool:
    """Check if packet is a TCP FIN packet."""
    if event.protocol != "TCP" or not event.tcp_flags:
        return False
    return "FIN" in event.tcp_flags.upper()


class PacketParser:
    """
    Stateful packet parser with statistics tracking.
    """
    
    def __init__(self, interface: str = "unknown"):
        """
        Initialize parser.
        
        Args:
            interface: Name of the capture interface
        """
        self.interface = interface
        self.packets_parsed = 0
        self.packets_dropped = 0
        self.parse_errors = 0
    
    def parse(self, packet: Packet) -> Optional[PacketEvent]:
        """
        Parse a single packet.
        
        Args:
            packet: Raw Scapy packet
            
        Returns:
            Optional[PacketEvent]: Parsed event or None
        """
        try:
            event = parse_packet(packet, self.interface)
            if event:
                self.packets_parsed += 1
            else:
                self.packets_dropped += 1
            return event
        except Exception as e:
            self.parse_errors += 1
            logger.error(f"Parse error: {e}")
            return None
    
    def parse_batch(self, packets: list) -> Generator[PacketEvent, None, None]:
        """
        Parse a batch of packets.
        
        Args:
            packets: List of raw Scapy packets
            
        Yields:
            PacketEvent: Successfully parsed events
        """
        for packet in packets:
            event = self.parse(packet)
            if event:
                yield event
    
    def get_stats(self) -> dict:
        """Get parser statistics."""
        return {
            "packets_parsed": self.packets_parsed,
            "packets_dropped": self.packets_dropped,
            "parse_errors": self.parse_errors,
            "success_rate": self.packets_parsed / max(1, self.packets_parsed + self.packets_dropped),
        }
    
    def reset_stats(self) -> None:
        """Reset parser statistics."""
        self.packets_parsed = 0
        self.packets_dropped = 0
        self.parse_errors = 0
