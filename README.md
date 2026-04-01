# 🔍 Network Traffic Analyzer

**Real-time network monitoring and anomaly detection system with a beautiful interactive CLI**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ Features

- 🌐 **Real-time packet capture** from network interfaces
- 📊 **Time-windowed aggregation** for traffic analysis
- 🚨 **Anomaly detection** with multiple detectors:
  - SYN flood detection
  - Port scan detection
  - Protocol shift detection
  - Traffic anomaly detection
- 📈 **Baseline learning** for normal traffic patterns
- 📄 **Report generation** in Markdown, CSV, and JSON formats
- 🎨 **Beautiful interactive CLI** with rich formatting
- 🔄 **PCAP replay** for offline analysis
- 💾 **Session persistence** for historical analysis

## 🎨 Beautiful CLI Interface

The Network Traffic Analyzer features a stunning, colorful terminal interface powered by [Rich](https://github.com/Textualize/rich):

- **Colorful banners and borders**
- **Interactive tables** with styled columns
- **Progress indicators** with spinners
- **Severity-coded alerts** (Critical → Low)
- **Real-time panels** showing network statistics
- **Tree views** for baseline data
- **Formatted metrics** with human-readable units

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Shyamanth-2005/network-traffic-analyzer.git
cd network-traffic-analyzer

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -e .
```

### Basic Usage

```bash
# List available network interfaces (with beautiful formatting!)
nta interfaces

# Start monitoring (requires admin/root privileges)
nta monitor

# Monitor specific interface
nta monitor Wi-Fi

# Replay PCAP file
nta replay capture.pcap

# Train baseline
nta baseline train my_baseline --windows 20

# Generate report
nta report latest
```

## 📚 Documentation

- **[QUICKSTART.md](QUICKSTART.md)** - Get up and running in minutes
- **[DOCUMENTATION.md](DOCUMENTATION.md)** - Comprehensive reference
- **[PLAN.md](PLAN.md)** - Project roadmap and architecture

## 🛠️ Tech Stack

- **Python 3.8+**
- **Scapy** - Packet capture and parsing
- **Rich** - Terminal UI framework
- **Textual** - TUI components
- **Prompt Toolkit** - Interactive prompts
- **PyYAML** - Configuration management
- **Pygments** - Syntax highlighting

## 🔒 Requirements

- **Administrator/root privileges** for packet capture
- **Windows**: [Npcap](https://npcap.com/) installed
- **Linux**: `libpcap-dev` package

## 📊 Example Output

### Interface Listing
```
╔═══════════════════════════════════════╗
║   Network Traffic Analyzer           ║
║   Real-time Monitoring & Detection   ║
╚═══════════════════════════════════════╝

🌐 Available Network Interfaces
╔════════════╤════════════════╤════════╗
║ Interface  │ IP Address     │ Status ║
╟────────────┼────────────────┼────────╢
║ Wi-Fi      │ 192.168.1.100  │ ● UP   ║
║ Ethernet   │ N/A            │ ● UP   ║
║ Loopback   │ 127.0.0.1      │ ● UP   ║
╚════════════╧════════════════╧════════╝
```

### Window Summary
```
┌─────────────────────────────────────┐
│        📊 Window Summary            │
├─────────────────────────────────────┤
│ Time: 14:30:05 → 14:30:10          │
│                                     │
│ 📦 Packets: 150 (30.0/s)          │
│ 💾 Bytes: 45.0 KB (9.0 KB/s)      │
│                                     │
│ 🔹 Source IPs: 5                   │
│ 🔸 Dest IPs: 12                    │
│                                     │
│ Protocol Distribution:              │
│   TCP      [120] ████████ 80.0%   │
│   UDP      [ 25] ██ 16.7%         │
│   ICMP     [  5] ▌ 3.3%           │
└─────────────────────────────────────┘
```

### Alert Display
```
┌─────────────────────────────────────┐
│ ⚠️  Alert: syn_flood-abc123        │
├─────────────────────────────────────┤
│ ● HIGH                              │
│                                     │
│ High SYN packet volume detected:   │
│ 150 SYN packets in 5.0s            │
│                                     │
│ Evidence:                           │
│   • syn_count: 150                 │
│   • threshold: 100                 │
│   • syn_rate: 30.0                 │
└─────────────────────────────────────┘
```

## 🗺️ Project Structure

```
network-traffic-analyzer/
├── src/analyzer/          # Main package
│   ├── cli.py            # CLI interface
│   ├── ui.py             # Rich UI components (NEW!)
│   ├── capture.py        # Packet capture
│   ├── parser.py         # Packet parsing
│   ├── windows.py        # Window aggregation
│   ├── features.py       # Feature extraction
│   ├── baseline.py       # Baseline management
│   ├── reporting.py      # Report generation
│   ├── alerts.py         # Alert management
│   ├── models.py         # Data models
│   └── detectors/        # Detection modules
├── tests/                # Test suite (85 tests)
├── docs/                 # Documentation
├── examples/             # Example configs
└── data/                 # Runtime data (logs, reports, baselines)
```

## 🧪 Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=analyzer

# Run specific test file
pytest tests/test_detectors.py
```

All 85 tests pass! ✅

## 🎯 Detector Configuration

Configure detection thresholds in `nta.config.yaml`:

```yaml
thresholds:
  syn_flood:
    count: 100      # SYN packets per window
    rate: 50        # SYN packets per second
  port_scan:
    ports: 15       # Unique ports threshold
  protocol_shift:
    change_percent: 25  # Protocol change %
  traffic_anomaly:
    rate_multiplier: 3.0
    size_deviation: 2.0

detectors:
  - syn_flood
  - port_scan
  - protocol_shift
  - traffic_anomaly
```

## 📈 Roadmap

- [x] **Phase 0-3**: Core functionality (Completed)
  - [x] Package structure
  - [x] Monitoring MVP
  - [x] Detection MVP
  - [x] Baselines & reports
  - [x] Rich interactive UI
- [ ] **Phase 4**: Performance optimization
- [ ] **Phase 5**: PyPI package distribution
- [ ] **Phase 6**: Sniffer detection
- [ ] **Phase 7**: Service mode
- [ ] **Phase 8**: Plugin system & API
- [ ] **Phase 9**: ML integration

See [PLAN.md](PLAN.md) for detailed roadmap.

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## 📜 License

MIT License - see [LICENSE](LICENSE) for details

## 🙏 Acknowledgments

- **Scapy** - Powerful packet manipulation library
- **Rich** - Beautiful terminal formatting
- **Anthropic Claude** - AI-assisted development

## 📧 Contact

For questions or feedback:
- GitHub Issues: [network-traffic-analyzer/issues](https://github.com/Shyamanth-2005/network-traffic-analyzer/issues)
- Author: [Shyamanth](https://github.com/Shyamanth-2005)

---

**⚠️ Disclaimer**: This tool is for educational and authorized security testing only. Always obtain proper authorization before monitoring network traffic.
