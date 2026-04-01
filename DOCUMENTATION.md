# Network Traffic Analyzer Documentation

Complete documentation for the Network Traffic Analyzer - a real-time network monitoring and anomaly detection system.

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [CLI Reference](#cli-reference)
5. [Detectors](#detectors)
6. [Baselines](#baselines)
7. [Reports](#reports)
8. [Architecture](#architecture)
9. [API Reference](#api-reference)
10. [Troubleshooting](#troubleshooting)

---

## Overview

The Network Traffic Analyzer is a Python-based tool for:

- **Real-time packet capture** from network interfaces
- **Offline PCAP analysis** for forensics and testing
- **Anomaly detection** using rule-based detectors
- **Baseline learning** for normal traffic behavior
- **Report generation** in Markdown, CSV, and JSON formats

### Key Features

- ✅ Live packet capture with Scapy
- ✅ Configurable time windows for aggregation
- ✅ Multiple anomaly detectors (SYN flood, port scan, protocol shift)
- ✅ Baseline training and comparison
- ✅ Structured alerting with evidence
- ✅ Session persistence and reporting
- ✅ Cross-platform (Windows with Npcap, Linux with libpcap)

---

## Installation

### System Requirements

| Component | Requirement |
|-----------|-------------|
| Python | 3.8 or higher |
| OS | Windows 10+, Linux, macOS |
| Privileges | Administrator/root for packet capture |

### Windows Setup

1. Install [Npcap](https://npcap.com/) (required for packet capture)
2. During installation, check "Install Npcap in WinPcap API-compatible Mode"

### Linux Setup

```bash
# Debian/Ubuntu
sudo apt-get install libpcap-dev python3-dev

# Fedora/RHEL
sudo dnf install libpcap-devel python3-devel

# Add user to pcap group (optional, avoids sudo)
sudo groupadd pcap
sudo usermod -aG pcap $USER
sudo chgrp pcap /usr/sbin/tcpdump
sudo chmod 750 /usr/sbin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
```

### Python Installation

```bash
# Create virtual environment
python -m venv .venv

# Activate (Windows)
.venv\Scripts\activate

# Activate (Linux/Mac)
source .venv/bin/activate

# Install package
pip install -e ".[dev]"

# Verify installation
nta --version
```

---

## Configuration

### Configuration File

Create a configuration file with:

```bash
nta config init
```

This creates `nta.config.yaml`:

```yaml
interface: null  # Auto-detect or specify
window_size: 5   # Window duration in seconds
capture_filter: null  # BPF filter string
output_dir: data
log_level: INFO
max_packets: null  # Unlimited

thresholds:
  syn_flood:
    count: 100      # SYN packets per window
    rate: 50        # SYN packets per second
  port_scan:
    ports: 15       # Unique ports per source
    rate: 10        # Ports per second
  protocol_shift:
    change_percent: 25  # Protocol change threshold
  traffic_anomaly:
    rate_multiplier: 3.0  # Traffic spike multiplier
    size_deviation: 2.0   # Packet size std devs

alerts:
  suppression_window: 60  # Seconds to suppress duplicates
  output_format: both     # json, text, or both
  console_output: true
  file_output: true

baseline:
  min_windows: 10
  profile: default

detectors:
  - syn_flood
  - port_scan
  - protocol_shift
  - traffic_anomaly

reports:
  format: markdown
  include_raw_data: false
  top_talkers_count: 10
```

### Configuration Priority

Configuration is loaded with this priority (highest to lowest):

1. CLI arguments
2. Environment variables
3. Config file
4. Default values

### Environment Variables

```bash
export NTA_INTERFACE="eth0"
export NTA_WINDOW_SIZE="10"
export NTA_OUTPUT_DIR="/var/log/nta"
export NTA_LOG_LEVEL="DEBUG"
```

---

## CLI Reference

### Global Options

```bash
nta [--config FILE] [--version] COMMAND [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--config`, `-c` | Path to configuration file |
| `--version`, `-v` | Show version information |

### Commands

#### `nta interfaces`

List available network interfaces.

```bash
nta interfaces
```

#### `nta monitor`

Start live traffic monitoring.

```bash
nta monitor [INTERFACE] [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `INTERFACE` | Network interface name (optional) |
| `--window-size`, `-w` | Window size in seconds |
| `--filter`, `-f` | BPF filter string |
| `--max-packets`, `-n` | Maximum packets to capture |

**Examples:**

```bash
# Monitor default interface
nta monitor

# Monitor specific interface with 10s windows
nta monitor eth0 --window-size 10

# Monitor with packet limit
nta monitor Wi-Fi --max-packets 10000

# Monitor with BPF filter (TCP only)
nta monitor eth0 --filter "tcp"
```

#### `nta replay`

Analyze a PCAP file.

```bash
nta replay PCAP_FILE [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `PCAP_FILE` | Path to PCAP file |
| `--window-size`, `-w` | Window size in seconds |

**Examples:**

```bash
nta replay capture.pcap
nta replay traffic.pcapng --window-size 1
```

#### `nta baseline`

Manage traffic baselines.

```bash
nta baseline SUBCOMMAND [OPTIONS]
```

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `train NAME` | Train a new baseline |
| `list` | List available baselines |
| `show NAME` | Show baseline details |
| `delete NAME` | Delete a baseline |

**Examples:**

```bash
# Train baseline with 20 windows
nta baseline train office --windows 20 --interface eth0

# List baselines
nta baseline list

# Show details
nta baseline show office

# Delete
nta baseline delete old_baseline
```

#### `nta report`

Generate session reports.

```bash
nta report [SESSION_ID] [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `SESSION_ID` | Session ID or "latest" |
| `--csv` | Export CSV data |
| `--json` | Export JSON data |

**Examples:**

```bash
nta report latest
nta report latest --csv --json
nta report session_a1b2c3d4
```

#### `nta sessions`

List monitoring sessions.

```bash
nta sessions
```

#### `nta config`

Configuration management.

```bash
nta config SUBCOMMAND [OPTIONS]
```

| Subcommand | Description |
|------------|-------------|
| `init` | Create default configuration |
| `show` | Display current configuration |

**Examples:**

```bash
nta config init
nta config init --output my_config.yaml
nta config show --format yaml
nta config show --format json
```

---

## Detectors

### SYN Flood Detector

**Name:** `syn_flood`  
**Category:** `network_attack`

Detects TCP SYN flood attacks by monitoring:

- SYN packet count per window
- SYN packet rate per second
- SYN-to-ACK ratio imbalance

**Configuration:**

```yaml
thresholds:
  syn_flood:
    count: 100  # SYN packets per window
    rate: 50    # SYN packets per second
```

**Alert Example:**

```
High SYN packet volume detected: 150 SYN packets in 5.0s
```

### Port Scan Detector

**Name:** `port_scan`  
**Category:** `reconnaissance`

Detects port scanning activity by monitoring:

- Unique destination ports per source IP
- Port access rate
- RST packet ratio (refused connections)

**Configuration:**

```yaml
thresholds:
  port_scan:
    ports: 15  # Unique ports threshold
    rate: 10   # Ports per second
```

**Detection Types:**

- **Vertical Scan:** One source → many ports on one target
- **Horizontal Scan:** One source → same port on many targets

### Protocol Shift Detector

**Name:** `protocol_shift`  
**Category:** `anomaly`

Detects unusual changes in protocol distribution:

- Comparison with previous window
- Deviation from baseline
- Presence of unusual protocols

**Configuration:**

```yaml
thresholds:
  protocol_shift:
    change_percent: 25  # Percentage change threshold
```

### Traffic Anomaly Detector

**Name:** `traffic_anomaly`  
**Category:** `anomaly`

Detects general traffic anomalies:

- Traffic rate spikes vs baseline
- Packet size anomalies
- Destination entropy anomalies

**Configuration:**

```yaml
thresholds:
  traffic_anomaly:
    rate_multiplier: 3.0   # Traffic spike threshold
    size_deviation: 2.0    # Standard deviations
```

---

## Baselines

### What is a Baseline?

A baseline captures the statistical profile of "normal" traffic. By comparing live traffic against a baseline, the analyzer can detect anomalies that deviate from expected behavior.

### Baseline Metrics

| Metric | Description |
|--------|-------------|
| `mean_pps` | Average packets per second |
| `mean_bps` | Average bytes per second |
| `mean_packet_size` | Average packet size |
| `protocol_distribution` | Expected protocol mix |
| `mean_syn_count` | Normal SYN traffic level |
| `mean_dst_ip_entropy` | Expected destination diversity |

### Training a Baseline

```bash
# Train during normal operation
nta baseline train normal_hours --windows 50

# Train on specific interface
nta baseline train office_wifi --interface Wi-Fi --windows 30
```

**Best Practices:**

1. Train during known-good traffic periods
2. Collect at least 10-20 windows minimum
3. Train separate baselines for different network profiles
4. Retrain periodically to adapt to network changes

### Using Baselines

Baselines are automatically loaded when available. The traffic anomaly detector uses baseline data for comparison.

---

## Reports

### Report Sections

Generated reports include:

1. **Session Summary** - Duration, interface, packet counts
2. **Traffic Statistics** - Rates, sizes, unique IPs
3. **Alert Summary** - Counts by severity and detector
4. **Top Talkers** - Most active source IPs
5. **Protocol Distribution** - Protocol breakdown
6. **Alert Timeline** - Chronological alert list

### Export Formats

| Format | Command | Use Case |
|--------|---------|----------|
| Markdown | Default | Human-readable reports |
| CSV | `--csv` | Spreadsheet analysis |
| JSON | `--json` | Programmatic processing |

### Report Location

Reports are saved to `data/reports/` by default.

---

## Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI                                  │
│   (interfaces, monitor, replay, baseline, report, config)   │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│                    NetworkAnalyzer                           │
│  (Orchestrates capture, detection, alerting, reporting)     │
└───┬─────────────┬─────────────┬─────────────┬───────────────┘
    │             │             │             │
    ▼             ▼             ▼             ▼
┌─────────┐ ┌──────────┐ ┌───────────┐ ┌───────────┐
│ Capture │ │ Window   │ │ Detection │ │ Alert     │
│ Engine  │ │ Aggreg.  │ │ Engine    │ │ Manager   │
└────┬────┘ └────┬─────┘ └─────┬─────┘ └─────┬─────┘
     │           │             │             │
     ▼           ▼             ▼             ▼
┌─────────┐ ┌──────────┐ ┌───────────┐ ┌───────────┐
│ Parser  │ │ Feature  │ │ Detectors │ │ Storage   │
│         │ │ Extract. │ │ (plugins) │ │           │
└─────────┘ └──────────┘ └───────────┘ └───────────┘
```

### Data Flow

1. **Capture Layer** - Raw packets from interface or PCAP
2. **Parser** - Normalize packets to `PacketEvent` objects
3. **Window Aggregator** - Compute `WindowSummary` statistics
4. **Detection Engine** - Run detectors, produce `Alert` objects
5. **Alert Manager** - Deduplicate, output, store alerts
6. **Storage** - Persist sessions, windows, alerts
7. **Reporting** - Generate human-readable reports

### Module Structure

```
src/analyzer/
├── __init__.py      # Package initialization
├── cli.py           # Command-line interface
├── config.py        # Configuration management
├── models.py        # Data models (PacketEvent, Alert, etc.)
├── interfaces.py    # Network interface discovery
├── capture.py       # Packet capture engine
├── parser.py        # Packet parsing
├── features.py      # Feature extraction
├── windows.py       # Window aggregation
├── baseline.py      # Baseline management
├── alerts.py        # Alert handling
├── reporting.py     # Report generation
├── storage.py       # Data persistence
└── detectors/       # Detection modules
    ├── __init__.py
    ├── base.py      # Base detector class
    ├── syn_flood.py
    ├── port_scan.py
    ├── protocol_shift.py
    └── traffic_anomaly.py
```

---

## API Reference

### PacketEvent

Normalized packet representation.

```python
from analyzer.models import PacketEvent

event = PacketEvent(
    timestamp=1704067200.0,
    interface="eth0",
    src_ip="192.168.1.100",
    dst_ip="192.168.1.1",
    protocol="TCP",
    packet_size=100,
    src_port=12345,
    dst_port=80,
    tcp_flags="SYN",
    direction="outbound",
)
```

### WindowSummary

Aggregated window statistics.

```python
from analyzer.models import WindowSummary

summary = WindowSummary(
    window_start=1704067200.0,
    window_end=1704067205.0,
    packet_count=100,
    byte_count=10000,
    packets_per_second=20.0,
    bytes_per_second=2000.0,
    unique_src_ips=5,
    unique_dst_ips=3,
    protocol_counts={"TCP": 70, "UDP": 30},
    syn_count=15,
    dst_ip_entropy=1.5,
)
```

### Alert

Detection alert with evidence.

```python
from analyzer.models import Alert, AlertSeverity

alert = Alert(
    alert_id="syn_flood-abc123",
    timestamp=1704067205.0,
    severity=AlertSeverity.HIGH,
    category="network_attack",
    detector="syn_flood",
    summary="High SYN packet volume detected",
    evidence={"syn_count": 150, "threshold": 100},
    interpretation="Possible SYN flood attack",
)
```

### Creating Custom Detectors

```python
from analyzer.detectors.base import BaseDetector
from analyzer.models import WindowSummary, Alert, AlertSeverity

class MyDetector(BaseDetector):
    name = "my_detector"
    category = "custom"
    description = "My custom detector"
    
    def evaluate(self, window: WindowSummary) -> list[Alert]:
        alerts = []
        
        if window.packet_count > 1000:
            alert = self.create_alert(
                severity=AlertSeverity.MEDIUM,
                summary="High packet count detected",
                evidence={"packet_count": window.packet_count},
                window=window,
                interpretation="Unusual traffic volume",
            )
            alerts.append(alert)
        
        return alerts
```

---

## Troubleshooting

### Common Issues

#### "Permission denied" Error

**Cause:** Packet capture requires elevated privileges.

**Solution:**
- **Windows:** Run as Administrator
- **Linux:** Use `sudo` or configure capabilities

```bash
# Linux capability method
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

#### "No suitable interface found"

**Cause:** No network interfaces detected or Npcap not installed.

**Solution:**
1. Run `nta interfaces` to list interfaces
2. Install Npcap (Windows) or libpcap (Linux)
3. Check interface name spelling

#### No Packets Captured

**Cause:** Interface has no traffic or wrong interface selected.

**Solution:**
1. Verify network activity on the interface
2. Try a different interface
3. Check capture filter if specified
4. Verify Npcap/libpcap is working

#### High CPU Usage

**Cause:** Processing cannot keep up with traffic volume.

**Solution:**
1. Increase window size (`--window-size 10`)
2. Use BPF filter to reduce traffic (`--filter "tcp port 80"`)
3. Disable some detectors in configuration

### Debug Mode

Enable debug logging for troubleshooting:

```bash
# In config file
log_level: DEBUG

# Or environment variable
export NTA_LOG_LEVEL=DEBUG
```

### Getting Help

```bash
# General help
nta --help

# Command-specific help
nta monitor --help
nta baseline --help
```

---

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.

## Support

For issues and feature requests, please use GitHub Issues.
