"""
Generate a demo PCAP file with realistic network traffic patterns.

Creates a capture.pcap file containing:
- Normal HTTP/HTTPS traffic (TCP SYN/ACK, data)
- DNS queries (UDP to port 53)
- ICMP ping traffic
- SYN flood attack pattern (triggers detector)
- Port scan activity (triggers detector)
- Mixed protocol traffic

Usage:
    python scripts/generate_demo_pcap.py

Output:
    capture.pcap in the project root directory
"""

import time
import random
from pathlib import Path

from scapy.all import (
    IP, TCP, UDP, ICMP, Ether, wrpcap,
    RandMAC, conf
)

# Suppress Scapy warnings
conf.verb = 0

# Configuration
OUTPUT_FILE = "capture.pcap"
BASE_TIME = 1704067200.0  # 2024-01-01 00:00:00 UTC

# Network topology for simulation
INTERNAL_IP = "192.168.1.100"
INTERNAL_MAC = str(RandMAC())

EXTERNAL_SERVERS = [
    "93.184.216.34",    # example.com
    "142.250.80.46",    # google.com
    "151.101.1.69",     # reddit.com
    "104.244.42.65",    # twitter.com
    "185.125.190.56",   # wikipedia.org
]

DNS_SERVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]

SCAN_SOURCE_IP = "10.0.0.50"
FLOOD_SOURCE_IPS = [f"172.16.{i}.{j}" for i in range(1, 5) for j in range(1, 20)]


def create_ethernet_layer(src_mac=None, dst_mac=None):
    """Create Ethernet layer with random MACs if not provided."""
    return Ether(
        src=src_mac or INTERNAL_MAC,
        dst=dst_mac or str(RandMAC())
    )


def create_tcp_syn(src_ip, dst_ip, src_port, dst_port, timestamp):
    """Create a TCP SYN packet."""
    pkt = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=src_port, dport=dst_port, flags="S", seq=random.randint(1000, 999999))
    )
    pkt.time = timestamp
    return pkt


def create_tcp_syn_ack(src_ip, dst_ip, src_port, dst_port, timestamp):
    """Create a TCP SYN-ACK packet."""
    pkt = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=src_port, dport=dst_port, flags="SA", seq=random.randint(1000, 999999), ack=random.randint(1000, 999999))
    )
    pkt.time = timestamp
    return pkt


def create_tcp_ack(src_ip, dst_ip, src_port, dst_port, timestamp):
    """Create a TCP ACK packet."""
    pkt = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=src_port, dport=dst_port, flags="A", seq=random.randint(1000, 999999), ack=random.randint(1000, 999999))
    )
    pkt.time = timestamp
    return pkt


def create_tcp_data(src_ip, dst_ip, src_port, dst_port, timestamp, size=500):
    """Create TCP data packet with PSH+ACK flags."""
    pkt = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=src_port, dport=dst_port, flags="PA", seq=random.randint(1000, 999999), ack=random.randint(1000, 999999)) /
        ("X" * size)
    )
    pkt.time = timestamp
    return pkt


def create_tcp_rst(src_ip, dst_ip, src_port, dst_port, timestamp):
    """Create a TCP RST packet."""
    pkt = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=src_port, dport=dst_port, flags="R", seq=random.randint(1000, 999999))
    )
    pkt.time = timestamp
    return pkt


def create_tcp_fin(src_ip, dst_ip, src_port, dst_port, timestamp):
    """Create a TCP FIN packet."""
    pkt = (
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=src_port, dport=dst_port, flags="FA", seq=random.randint(1000, 999999), ack=random.randint(1000, 999999))
    )
    pkt.time = timestamp
    return pkt


def create_dns_query(src_ip, timestamp):
    """Create a DNS query packet."""
    dst_dns = random.choice(DNS_SERVERS)
    src_port = random.randint(1024, 65535)
    pkt = (
        IP(src=src_ip, dst=dst_dns) /
        UDP(sport=src_port, dport=53) /
        ("DNSQUERY" + str(random.randint(1000, 9999)))
    )
    pkt.time = timestamp
    return pkt


def create_dns_response(src_ip, timestamp):
    """Create a DNS response packet."""
    dst_dns = random.choice(DNS_SERVERS)
    src_port = random.randint(1024, 65535)
    pkt = (
        IP(src=dst_dns, dst=src_ip) /
        UDP(sport=53, dport=src_port) /
        ("DNSRESP" + str(random.randint(1000, 9999)))
    )
    pkt.time = timestamp
    return pkt


def create_icmp_ping(src_ip, dst_ip, timestamp):
    """Create an ICMP echo request."""
    pkt = (
        IP(src=src_ip, dst=dst_ip) /
        ICMP(type=8, code=0) /
        ("PING" + str(random.randint(1000, 9999)))
    )
    pkt.time = timestamp
    return pkt


def create_icmp_pong(src_ip, dst_ip, timestamp):
    """Create an ICMP echo reply."""
    pkt = (
        IP(src=dst_ip, dst=src_ip) /
        ICMP(type=0, code=0) /
        ("PONG" + str(random.randint(1000, 9999)))
    )
    pkt.time = timestamp
    return pkt


def generate_normal_traffic(start_time, duration=30):
    """Generate realistic normal network traffic."""
    packets = []
    current_time = start_time
    src_port_counter = 10000

    for i in range(duration * 10):  # ~10 packets per second
        # Random traffic type
        traffic_type = random.choices(
            ["http_request", "http_response", "dns_query", "dns_response", "icmp", "tcp_ack", "tcp_fin"],
            weights=[25, 25, 15, 15, 5, 10, 5],
            k=1
        )[0]

        dst_ip = random.choice(EXTERNAL_SERVERS)
        src_port = src_port_counter
        dst_port = random.choice([80, 443, 8080, 8443])
        src_port_counter += 1

        if traffic_type == "http_request":
            # TCP SYN to web server
            packets.append(create_tcp_syn(INTERNAL_IP, dst_ip, src_port, dst_port, current_time))
            # Follow up with ACK
            packets.append(create_tcp_ack(INTERNAL_IP, dst_ip, src_port, dst_port, current_time + 0.01))
            # Data packet
            packets.append(create_tcp_data(INTERNAL_IP, dst_ip, src_port, dst_port, current_time + 0.02, size=random.randint(200, 800)))

        elif traffic_type == "http_response":
            # Server response SYN-ACK
            packets.append(create_tcp_syn_ack(dst_ip, INTERNAL_IP, dst_port, src_port, current_time))
            # Response data
            packets.append(create_tcp_data(dst_ip, INTERNAL_IP, dst_port, src_port, current_time + 0.01, size=random.randint(500, 1500)))
            # Connection close
            packets.append(create_tcp_fin(dst_ip, INTERNAL_IP, dst_port, src_port, current_time + 0.05))

        elif traffic_type == "dns_query":
            packets.append(create_dns_query(INTERNAL_IP, current_time))

        elif traffic_type == "dns_response":
            packets.append(create_dns_response(INTERNAL_IP, current_time))

        elif traffic_type == "icmp":
            target = random.choice(["8.8.8.8", "1.1.1.1", "142.250.80.46"])
            packets.append(create_icmp_ping(INTERNAL_IP, target, current_time))
            packets.append(create_icmp_pong(INTERNAL_IP, target, current_time + 0.05))

        elif traffic_type == "tcp_ack":
            packets.append(create_tcp_ack(INTERNAL_IP, dst_ip, src_port, dst_port, current_time))

        elif traffic_type == "tcp_fin":
            packets.append(create_tcp_fin(INTERNAL_IP, dst_ip, src_port, dst_port, current_time))

        current_time += 0.1 + random.uniform(0, 0.1)

    return packets


def generate_syn_flood(start_time, count=150):
    """Generate SYN flood attack pattern - triggers SYN flood detector."""
    packets = []
    current_time = start_time

    for i in range(count):
        src_ip = random.choice(FLOOD_SOURCE_IPS)
        dst_ip = INTERNAL_IP
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 3389])

        # SYN packet without completing handshake
        packets.append(create_tcp_syn(src_ip, dst_ip, src_port, dst_port, current_time))
        current_time += 0.03  # Rapid fire - ~30 packets per second

    return packets


def generate_port_scan(start_time, count=50):
    """Generate port scan activity - triggers port scan detector."""
    packets = []
    current_time = start_time
    src_ip = SCAN_SOURCE_IP
    dst_ip = INTERNAL_IP

    # Scan many ports on the target
    for port in range(20, 20 + count):
        src_port = random.randint(1024, 65535)
        
        # SYN to each port
        packets.append(create_tcp_syn(src_ip, dst_ip, src_port, port, current_time))
        # Target responds with RST (port closed)
        packets.append(create_tcp_rst(dst_ip, src_ip, port, src_port, current_time + 0.01))
        
        current_time += 0.05

    return packets


def generate_udp_traffic(start_time, count=30):
    """Generate miscellaneous UDP traffic."""
    packets = []
    current_time = start_time

    for i in range(count):
        dst_ip = random.choice(EXTERNAL_SERVERS)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([53, 123, 5353, 1900])

        packets.append(
            IP(src=INTERNAL_IP, dst=dst_ip) /
            UDP(sport=src_port, dport=dst_port) /
            ("UDPDATA" + str(random.randint(1000, 9999)))
        )
        packets[-1].time = current_time
        current_time += 0.2

    return packets


def main():
    """Generate the demo PCAP file."""
    print("🔧 Generating demo PCAP file...")
    
    all_packets = []
    current_time = BASE_TIME

    # Phase 1: Normal traffic (0-15 seconds)
    print("  📡 Generating normal traffic (0-15s)...")
    normal_1 = generate_normal_traffic(current_time, duration=15)
    all_packets.extend(normal_1)
    current_time += 15

    # Phase 2: Normal traffic + DNS activity (15-20 seconds)
    print("  🔍 Generating DNS traffic (15-20s)...")
    dns_traffic = generate_udp_traffic(current_time, count=20)
    all_packets.extend(dns_traffic)
    current_time += 5

    # Phase 3: SYN flood attack (20-25 seconds)
    print("  🚨 Generating SYN flood pattern (20-25s)...")
    syn_flood = generate_syn_flood(current_time, count=150)
    all_packets.extend(syn_flood)
    current_time += 5

    # Phase 4: More normal traffic (25-30 seconds)
    print("  📡 Generating normal traffic (25-30s)...")
    normal_2 = generate_normal_traffic(current_time, duration=5)
    all_packets.extend(normal_2)
    current_time += 5

    # Phase 5: Port scan activity (30-35 seconds)
    print("  🔎 Generating port scan pattern (30-35s)...")
    port_scan = generate_port_scan(current_time, count=50)
    all_packets.extend(port_scan)
    current_time += 5

    # Phase 6: Final normal traffic (35-40 seconds)
    print("  📡 Generating normal traffic (35-40s)...")
    normal_3 = generate_normal_traffic(current_time, duration=5)
    all_packets.extend(normal_3)

    # Sort packets by timestamp
    all_packets.sort(key=lambda p: float(p.time))

    # Write to PCAP file
    output_path = Path(OUTPUT_FILE)
    wrpcap(str(output_path), all_packets)

    # Print statistics
    print(f"\n✅ PCAP file generated: {output_path.resolve()}")
    print(f"   Total packets: {len(all_packets):,}")
    print(f"   Duration: ~40 seconds")
    print(f"   File size: {output_path.stat().st_size / 1024:.1f} KB")
    
    print(f"\n📊 Traffic Breakdown:")
    print(f"   • Normal HTTP/HTTPS traffic: ~250 packets")
    print(f"   • DNS queries/responses: ~50 packets")
    print(f"   • SYN flood attack: 150 packets (triggers detector)")
    print(f"   • Port scan: 100 packets (triggers detector)")
    print(f"   • ICMP/UDP traffic: ~50 packets")
    
    print(f"\n🎯 Expected Detections:")
    print(f"   • SYN flood detector (150 SYN packets in 5s)")
    print(f"   • Port scan detector (50 unique ports scanned)")
    
    print(f"\n🚀 To replay this capture:")
    print(f"   nta replay {OUTPUT_FILE}")
    print(f"   nta replay {OUTPUT_FILE} --window-size 5")


if __name__ == "__main__":
    main()
