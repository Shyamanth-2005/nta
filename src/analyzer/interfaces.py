"""
Network interface discovery and management.

Provides cross-platform interface discovery with detailed information.
"""

import logging
import socket
from dataclasses import dataclass
from typing import List, Optional, Dict, Any

from scapy.all import get_if_list, get_if_addr, conf

logger = logging.getLogger("analyzer.interfaces")


@dataclass
class NetworkInterface:
    """
    Network interface information.
    
    Attributes:
        name: Interface name (e.g., "eth0", "Wi-Fi")
        ip_address: IP address assigned to interface
        is_up: Whether interface is active
        is_loopback: Whether interface is loopback
        description: Human-readable description
    """
    name: str
    ip_address: Optional[str] = None
    is_up: bool = True
    is_loopback: bool = False
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "ip_address": self.ip_address,
            "is_up": self.is_up,
            "is_loopback": self.is_loopback,
            "description": self.description,
        }
    
    def __str__(self) -> str:
        ip = self.ip_address or "No IP"
        status = "UP" if self.is_up else "DOWN"
        return f"{self.name} ({ip}) [{status}]"


def get_interfaces() -> List[NetworkInterface]:
    """
    Get list of available network interfaces.
    
    Returns:
        List[NetworkInterface]: Available interfaces with details
    """
    interfaces = []
    
    try:
        if_names = get_if_list()
        
        for name in if_names:
            try:
                # Get IP address for interface
                ip_addr = None
                try:
                    ip_addr = get_if_addr(name)
                    if ip_addr == "0.0.0.0":
                        ip_addr = None
                except Exception:
                    pass
                
                # Determine if loopback
                is_loopback = name.lower() in ("lo", "loopback", "lo0") or \
                              (ip_addr and ip_addr.startswith("127."))
                
                # Create interface object
                iface = NetworkInterface(
                    name=name,
                    ip_address=ip_addr,
                    is_up=True,
                    is_loopback=is_loopback,
                    description=_get_interface_description(name),
                )
                interfaces.append(iface)
                
            except Exception as e:
                logger.debug(f"Error getting info for interface {name}: {e}")
                interfaces.append(NetworkInterface(name=name))
        
    except Exception as e:
        logger.error(f"Failed to enumerate interfaces: {e}")
    
    return interfaces


def _get_interface_description(name: str) -> str:
    """Get human-readable description for interface."""
    # Common interface name patterns
    descriptions = {
        "eth": "Ethernet adapter",
        "en": "Ethernet adapter",
        "wlan": "Wireless adapter",
        "wi-fi": "Wireless adapter",
        "wifi": "Wireless adapter",
        "lo": "Loopback interface",
        "docker": "Docker network",
        "veth": "Virtual Ethernet",
        "br": "Bridge interface",
        "virbr": "Virtual bridge",
        "vmnet": "VMware network",
        "vbox": "VirtualBox network",
        "tun": "Tunnel interface",
        "tap": "TAP interface",
    }
    
    name_lower = name.lower()
    for prefix, desc in descriptions.items():
        if name_lower.startswith(prefix):
            return desc
    
    return "Network interface"


def get_default_interface() -> Optional[str]:
    """
    Get the default network interface.
    
    Returns:
        Optional[str]: Default interface name or None
    """
    try:
        # Try Scapy's default interface
        if conf.iface:
            return str(conf.iface)
    except Exception:
        pass
    
    # Fallback: find first non-loopback interface with IP
    interfaces = get_interfaces()
    for iface in interfaces:
        if not iface.is_loopback and iface.ip_address:
            return iface.name
    
    # Last resort: return first interface
    if interfaces:
        return interfaces[0].name
    
    return None


def validate_interface(name: str) -> bool:
    """
    Check if interface exists and is available.
    
    Args:
        name: Interface name to validate
        
    Returns:
        bool: True if interface is valid
    """
    interfaces = get_interfaces()
    return any(iface.name == name for iface in interfaces)


def print_interfaces(interfaces: Optional[List[NetworkInterface]] = None) -> None:
    """
    Print formatted list of interfaces.
    
    Args:
        interfaces: List of interfaces to print (or None to discover)
    """
    if interfaces is None:
        interfaces = get_interfaces()
    
    if not interfaces:
        print("No network interfaces found.")
        return
    
    print("\n┌─────────────────────────────────────────────────────────────┐")
    print("│                  Available Network Interfaces               │")
    print("├──────────────────┬─────────────────┬────────┬───────────────┤")
    print("│ Name             │ IP Address      │ Status │ Type          │")
    print("├──────────────────┼─────────────────┼────────┼───────────────┤")
    
    for iface in interfaces:
        name = iface.name[:16].ljust(16)
        ip = (iface.ip_address or "N/A")[:15].ljust(15)
        status = "UP".ljust(6) if iface.is_up else "DOWN".ljust(6)
        iface_type = ("Loopback" if iface.is_loopback else "Physical")[:13].ljust(13)
        print(f"│ {name} │ {ip} │ {status} │ {iface_type} │")
    
    print("└──────────────────┴─────────────────┴────────┴───────────────┘")
    
    default = get_default_interface()
    if default:
        print(f"\nDefault interface: {default}")
