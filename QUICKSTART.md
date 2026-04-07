# Network Traffic Analyzer - Quick Start Guide

Get up and running with the Network Traffic Analyzer in minutes.

## Prerequisites

- **Python 3.8+**
- **Administrator/root privileges** for packet capture
- **Windows**: [Npcap](https://npcap.com/) installed
- **Linux**: `libpcap-dev` package installed

## Installation

```bash
# Clone the repository
git clone https://github.com/Shyamanth-2005/nta.git
cd nta

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev]"

# or
python -m pip install -e ".[dev]"
```

## Basic Usage

### 1. List Available Interfaces

```bash
nta interfaces
```

This shows all network interfaces available for monitoring:

```
┌─────────────────────────────────────────────────────────────┐
│                  Available Network Interfaces               │
├──────────────────┬─────────────────┬────────┬───────────────┤
│ Name             │ IP Address      │ Status │ Type          │
├──────────────────┼─────────────────┼────────┼───────────────┤
│ Wi-Fi            │ 192.168.1.100   │ UP     │ Physical      │
│ Ethernet         │ N/A             │ UP     │ Physical      │
│ Loopback         │ 127.0.0.1       │ UP     │ Loopback      │
└──────────────────┴─────────────────┴────────┴───────────────┘
```

### 2. Start Monitoring

```bash
# Monitor default interface
nta monitor

# Monitor specific interface
nta monitor Wi-Fi

# Monitor with custom window size (10 seconds)
nta monitor Wi-Fi --window-size 10

# Capture limited packets
nta monitor Wi-Fi --max-packets 1000
```

**What you'll see:**

```
============================================================
🔍 Network Traffic Analyzer Started
============================================================
   Session ID: session_a1b2c3d4
   Mode: live
   Interface: Wi-Fi
   Window Size: 5s
   Detectors: syn_flood, port_scan, protocol_shift, traffic_anomaly
============================================================
Press Ctrl+C to stop monitoring...

📊 Window Summary [14:30:05]
   Packets: 150 (30.0/s)
   Bytes: 45,000 (9,000/s)
   Unique IPs: 5 src, 12 dst
   Protocols: TCP:120, UDP:25, ICMP:5
```

### 3. Stop Monitoring

Press `Ctrl+C` to stop. A report is automatically generated:

```
============================================================
🛑 Stopping Network Traffic Analyzer...
============================================================

📈 Session Summary
   Duration: 2m 30s
   Packets: 4,500
   Windows: 30
   Alerts: 2

📄 Report generated: data/reports/report_session_a1b2c3d4_20240101_143505.md
```

### 4. View Reports

```bash
# List all sessions
nta sessions

# Generate report for latest session
nta report latest

# Generate report with CSV export
nta report latest --csv

# Generate report with JSON export
nta report latest --json
```

## Common Use Cases

### Analyze a PCAP File

```bash
nta replay capture.pcap
nta replay capture.pcap --window-size 1
```

### Train a Baseline

Capture normal traffic to establish baseline behavior:

```bash
# Train baseline named "office_network"
nta baseline train office_network --windows 20

# List available baselines
nta baseline list

# Show baseline details
nta baseline show office_network
```

### Configuration

```bash
# Create default configuration file
nta config init

# View current configuration
nta config show
```

## Alert Types

The analyzer detects these anomalies:

| Detector            | Description                                             |
| ------------------- | ------------------------------------------------------- |
| **syn_flood**       | High volume of TCP SYN packets (potential DoS attack)   |
| **port_scan**       | Many unique destination ports accessed (reconnaissance) |
| **protocol_shift**  | Unusual change in protocol distribution                 |
| **traffic_anomaly** | Traffic rate spikes, packet size anomalies              |

## Example Alert

```
============================================================
⚠️  ALERT: High SYN packet volume detected: 150 SYN packets in 5.0s
============================================================
  Severity:   [HIGH]
  Detector:   syn_flood
  Category:   network_attack
  Time:       2024-01-01 14:35:10
  Evidence:
    - syn_count: 150
    - threshold: 100
    - syn_rate: 30.0
  Interpretation: Possible SYN flood attack...
```

## Troubleshooting

### Permission Denied

**Windows:** Run Command Prompt as Administrator  
**Linux:** Use `sudo` or add user to `pcap` group

### Interface Not Found

1. Run `nta interfaces` to see available interfaces
2. Use the exact interface name shown in the list
3. Check if Npcap (Windows) or libpcap (Linux) is installed

### No Packets Captured

1. Verify the interface has network activity
2. Try a different interface
3. Check firewall settings

## Next Steps

- Read the full [DOCUMENTATION.md](DOCUMENTATION.md) for advanced features
- Configure detection thresholds in `nta.config.yaml`
- Set up automated monitoring with baseline comparison
- Export data for analysis with `--csv` and `--json` flags
