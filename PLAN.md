# Network Traffic Analyzer Plan

## 1. Document Purpose

This file defines the target product scope, detailed requirements, core components, and system design choices for the `network-traffic-analyzer` project.

The plan is based on two inputs:

- The project presentation `Purple Gradient Modern Cryptocurrency Presentation (1).pdf`
- The current prototype implementation under `src/`

The PDF establishes the intended direction:

- Real-time network monitoring and security analysis
- Live packet capture and feature extraction
- Baseline-driven anomaly detection
- Explainable alerting and reporting
- Advanced detection of unauthorized sniffers inside a network
- Optional machine learning support for anomaly detection

The current source code establishes the current implementation baseline:

- `src/test_capture.py`: basic packet sniffing smoke test
- `src/packet_features.py`: prints TCP flow details
- `src/traffic_window.py`: counts packets per source IP in a fixed time window
- `src/syn_detector.py`: detects possible SYN flood and port scan activity using simple thresholds
- `src/interfaces.py`: returns available interfaces
- `src/alerts.log`: demonstrates alert logging output from prototype runs

This document turns that prototype plus the presentation goals into a concrete build plan.

## 2. Project Summary

### Product Statement

Build a real-time network traffic analyzer that captures live packets, extracts protocol and behavioral features, learns or defines normal traffic patterns, detects anomalous and suspicious activity, and generates explainable alerts and reports for a student or lab-scale environment.

### Problem Statement

Modern networks carry high-volume, mixed-purpose traffic. Traditional packet sniffing helps with debugging and protocol analysis, but it does not by itself provide strong behavioral detection, explainable anomaly identification, or lightweight detection of suspicious sniffing activity inside a network.

### Intended Outcome

The project should demonstrate:

- Networking fundamentals through live packet processing
- Cybersecurity reasoning through attack-oriented heuristics
- Research-oriented thinking through anomaly modeling and evaluation
- A path from rule-based monitoring to optional ML-assisted detection

## 3. What the PDF Says the Project Must Do

The presentation defines the following high-level requirements.

### Core objectives

- Capture live network packets
- Extract packet and flow-level traffic features
- Build a baseline of normal traffic behavior
- Detect anomalies from behavioral changes
- Generate reports from observed activity

### Advanced objectives

- Detect unauthorized traffic analyzers or sniffers inside a network
- Explore ML-based anomaly detection models

### Required feature families from the presentation

- Source and destination IP
- Protocol type such as TCP, UDP, ICMP
- Packet size distribution
- Inter-arrival time
- Traffic frequency
- Entropy of destination IPs

### Required detection ideas from the presentation

- Statistical deviations in mean packet size
- Traffic rate deviations
- Protocol distribution changes
- Optional ML models such as Isolation Forest, autoencoders, or DBSCAN
- Sniffer detection using ARP behavior, promiscuous mode indicators, latency and response-time analysis, and abnormal packet duplication patterns

## 4. Current State Assessment

The repository currently contains an early prototype, not a cohesive application.

### What already exists

- Live packet capture via Scapy
- Manual interface listing
- Packet-level TCP logging
- Per-source packet counting over a fixed window
- Simple rule-based detection for:
  - SYN flood suspicion
  - Possible port scanning
- Alert logging to a flat file

### Current implementation limitations

- Hardcoded interface name (`Wi-Fi`)
- Top-level `sniff(...)` calls execute immediately on script run/import
- No unified CLI or application entry point
- No shared packet model or aggregation pipeline
- No persistent baseline storage
- No anomaly scoring engine beyond fixed thresholds
- No sniffer detection implementation yet
- No structured configuration
- No tests
- No separation between capture, feature extraction, detection, storage, and reporting
- No documented operating assumptions or permissions model

### Current prototype value

The current scripts are still useful because they prove:

- Scapy capture works in the intended environment
- Basic packet parsing is understood
- Time-window aggregation is already partially explored
- The project can already produce explainable rule-based alerts

## 5. Scope Definition

### In scope for v1

- Live packet capture from a selected interface
- Optional offline analysis from PCAP files for repeatable testing
- Packet parsing for IPv4 traffic and common transport protocols
- Windowed feature extraction and aggregation
- Baseline generation for normal traffic
- Rule-based anomaly detection
- Explainable alert generation
- Persistent storage of aggregated observations and alerts
- Periodic report generation
- A modular architecture that can support optional ML extensions

### In scope for v1.5 or v2

- ML-assisted anomaly detection
- Sniffer detection module
- Dashboard or web UI
- Remote alert delivery such as email, webhook, or SIEM export
- Multi-host or distributed deployment

### Out of scope for the first deliverable

- Full payload inspection and deep packet inspection
- TLS decryption
- Enterprise-scale distributed telemetry
- Autonomous response or packet blocking
- Kernel-level packet acceleration

## 6. Target Users and Use Cases

### Primary users

- Students building a cybersecurity project
- Lab administrators or researchers analyzing local network behavior
- Instructors evaluating network anomaly detection workflows

### Primary use cases

- Start monitoring a chosen network interface in real time
- View traffic summaries in fixed windows
- Detect spikes in SYN traffic, port scans, or unusual protocol shifts
- Generate an alert log with the reason for each alert
- Export a summary report after a capture session
- Replay PCAP files to compare detector behavior across datasets
- Experiment with additional anomaly detection strategies

## 7. Detailed Functional Requirements

### FR-01 Packet capture

- The system must capture packets from a user-selected network interface.
- The system should support both live capture and offline PCAP replay.
- The system must allow BPF-style filtering or protocol filtering where practical.
- The system must fail clearly if packet capture permissions are missing.

### FR-02 Interface discovery

- The system must list available interfaces before capture starts.
- The user must be able to choose the interface through CLI arguments or config.
- The active interface must be recorded in session metadata.

### FR-03 Packet parsing

- The system must parse at least Ethernet, IP, TCP, UDP, and ICMP where present.
- The system must extract timestamps, source and destination addresses, protocol identifiers, packet sizes, and TCP flag information.
- The parser must ignore unsupported packets without crashing the pipeline.

### FR-04 Feature extraction

- The system must compute per-packet features.
- The system must aggregate features into fixed-size time windows.
- The feature set for v1 must include:
  - packets per second
  - bytes per second
  - source IP count
  - destination IP count
  - destination port count
  - TCP SYN count
  - TCP ACK count
  - protocol distribution
  - packet size mean, min, max, and variance
  - inter-arrival time mean and variance
  - destination IP entropy

### FR-05 Baseline generation

- The system must support a baseline mode that learns normal behavior over one or more capture sessions.
- The baseline must be stored locally so it can be reused later.
- The baseline must store statistical summaries per monitored interface and capture profile.
- The system must support resetting or rebuilding the baseline.

### FR-06 Rule-based anomaly detection

- The system must detect abnormal traffic rates relative to baseline.
- The system must detect unusual SYN surges.
- The system must detect likely port scans using unique destination port fan-out.
- The system must detect major protocol distribution changes.
- Every alert must include:
  - timestamp
  - severity
  - detector name
  - reason
  - supporting metrics

### FR-07 Sniffer detection

- The system must reserve a dedicated module for sniffer detection even if advanced methods are implemented later.
- The design must support:
  - ARP behavior analysis
  - detection of suspicious promiscuous-mode indicators
  - latency and response-time based heuristics
  - duplicate or mirrored packet pattern analysis
- Active probing techniques must be optional and clearly marked as authorized-lab-only behavior.

### FR-08 ML anomaly detection

- The system must define an extension point for ML-based detection.
- The first version does not need to ship with a trained model, but the interfaces must support:
  - training
  - loading
  - scoring
  - fallback when no model is available

### FR-09 Alerting and logging

- The system must log alerts to a structured file format.
- The system should support both human-readable log output and machine-readable JSONL.
- The system must avoid duplicate spam alerts for the same repeated condition within the same suppression window.

### FR-10 Reporting

- The system must generate a capture session report.
- The report must summarize:
  - session duration
  - interface used
  - top talkers
  - protocol mix
  - anomaly counts by type
  - timeline of major alerts
- The initial report output may be Markdown plus CSV artifacts.

### FR-11 Configuration

- The system must support configurable:
  - interface
  - window length
  - thresholds
  - capture filters
  - output paths
  - baseline profile
  - enabled detectors
- Configuration must be available through CLI flags first.
- A file-based config format may be added once the runtime version is standardized.

### FR-12 Session lifecycle

- The application must support:
  - start monitoring
  - stop monitoring cleanly
  - periodic flush of aggregates
  - graceful shutdown with final report generation

## 8. Non-Functional Requirements

### NFR-01 Performance

- The system should handle low-to-moderate lab traffic on a single machine without freezing the capture loop.
- The pipeline should avoid expensive per-packet disk writes.
- Window aggregation should be in-memory with periodic persistence.

### NFR-02 Reliability

- A malformed packet or unsupported protocol must not crash the monitor.
- File writes must be append-safe and recoverable.
- Detector failures should degrade gracefully and be logged.

### NFR-03 Explainability

- Every alert must be explainable from observed metrics.
- Statistical detectors must expose the metric, observed value, expected value, and threshold or score.
- ML results must include a fallback explanation when possible, such as which features were abnormal.

### NFR-04 Usability

- The first release should be CLI-first.
- Output should be readable during live runs and reviewable after runs.
- Error messages must help the user fix permission, interface, or dependency issues.

### NFR-05 Security and privacy

- The system should prefer metadata and behavioral analysis over payload storage.
- Raw payload retention should be disabled by default.
- Active probing for sniffer detection must be opt-in.

### NFR-06 Portability

- The project should run on Windows with Npcap and on Linux with libpcap-compatible capture.
- Linux will generally provide the best capture reliability and should be the preferred evaluation platform.

### NFR-07 Testability

- Core logic must be testable without requiring live packet capture.
- Detector logic must accept synthetic packet events or precomputed window features.

## 9. Core Components

### 9.1 Capture layer

Responsibilities:

- Discover interfaces
- Start live packet capture
- Replay PCAP files
- Normalize timestamps and pass packets downstream

Why it exists:

- Current scripts capture directly inside file scope
- The new system needs a controlled lifecycle and reusable adapters

### 9.2 Packet parsing layer

Responsibilities:

- Convert Scapy packets into normalized internal events
- Extract protocol metadata safely
- Ignore irrelevant packets without breaking the stream

### 9.3 Feature extraction layer

Responsibilities:

- Produce packet-level derived features
- Track per-window aggregate statistics
- Support both traffic-level and detector-specific metrics

### 9.4 Window aggregator

Responsibilities:

- Maintain rolling or tumbling windows
- Flush completed windows for persistence and detection
- Support configurable window durations

### 9.5 Baseline manager

Responsibilities:

- Build baseline statistics from clean or labeled sessions
- Store and load baselines
- Compare live windows against expected behavior

### 9.6 Detection engine

Responsibilities:

- Run one or more detectors against aggregated windows
- Produce structured alerts
- Manage suppression and severity mapping

Submodules:

- traffic anomaly detector
- SYN flood detector
- port scan detector
- protocol shift detector
- sniffer detection module
- optional ML detector adapter

### 9.7 Alert manager

Responsibilities:

- Deduplicate alerts
- Route alerts to console, file, and future sinks
- Format alert evidence clearly

### 9.8 Storage layer

Responsibilities:

- Persist window summaries
- Persist alerts
- Persist baseline profiles
- Persist session metadata

### 9.9 Reporting layer

Responsibilities:

- Generate end-of-run reports
- Create CSV and Markdown artifacts
- Summarize session behavior for evaluation

### 9.10 CLI and application orchestration

Responsibilities:

- Parse arguments
- Select capture mode
- Start and stop the monitoring session
- Enable or disable detectors

## 10. Proposed Architecture

```text
+------------------+
| CLI / Config     |
+---------+--------+
          |
          v
+------------------+      +------------------+
| Interface Select |----->| Capture Adapter  |
+---------+--------+      +---------+--------+
          |                         |
          |                         v
          |               +------------------+
          |               | Packet Parser    |
          |               +---------+--------+
          |                         |
          |                         v
          |               +------------------+
          |               | Feature Extractor|
          |               +---------+--------+
          |                         |
          |                         v
          |               +------------------+
          |               | Window Aggregator|
          |               +----+--------+----+
          |                    |        |
          |                    |        |
          |                    v        v
          |          +----------------+ +----------------+
          |          | Baseline Store | | Detector Engine|
          |          +--------+-------+ +--------+-------+
          |                   |                  |
          |                   |                  v
          |                   |        +----------------+
          |                   +------->| Alert Manager  |
          |                            +--------+-------+
          |                                     |
          |                                     v
          |                            +----------------+
          +--------------------------->| Reports/Logs   |
                                       +----------------+
```

## 11. System Design Choices

### Choice 1: Python plus Scapy

Reason:

- Already used in the prototype
- Good fit for packet inspection and rapid iteration
- Appropriate for a student-scale security project

Tradeoff:

- Not ideal for very high throughput
- Capture behavior varies by platform

Decision:

- Keep Python and Scapy for v1
- Design the pipeline so the capture adapter can be replaced later if needed

### Choice 2: CLI-first architecture

Reason:

- The current code is script-based
- A CLI is faster to build, easier to test, and enough for a serious project milestone

Tradeoff:

- Lower immediate usability than a dashboard

Decision:

- Build a stable CLI first
- Add a dashboard later only after the data model is stable

### Choice 3: Behavioral analysis over payload analysis

Reason:

- The PDF emphasizes behavior, deviations, and traffic patterns
- This improves privacy and keeps the project technically manageable

Tradeoff:

- Some attacks remain harder to classify without payload context

Decision:

- Focus on metadata, timing, counts, distributions, and flow behavior

### Choice 4: Aggregated windows as the main detection unit

Reason:

- Current prototype already uses window-based counting
- Many anomaly signals are statistical rather than single-packet events

Tradeoff:

- Very short attacks may be blurred by long windows

Decision:

- Use configurable tumbling windows
- Start with `1s`, `5s`, and `10s` evaluation options

### Choice 5: SQLite or local structured files for persistence

Reason:

- No external infrastructure required
- Easy to query for reports and evaluation

Tradeoff:

- Not intended for multi-node scale

Decision:

- Store session metadata, aggregates, and alerts locally
- Use JSONL for append-only logs and SQLite for queryable summaries if the implementation grows

### Choice 6: Detector modularity

Reason:

- The project combines statistical, heuristic, and optional ML methods
- Sniffer detection should not be tightly coupled to SYN flood detection

Decision:

- Each detector must implement a common interface such as `evaluate(window) -> list[Alert]`

### Choice 7: Offline replay support

Reason:

- Live traffic is hard to reproduce consistently
- Repeatable evaluation is necessary for research-style validation

Decision:

- Support PCAP replay early, not as a late add-on

## 12. Data Model and Detection Inputs

### Packet event

Each normalized packet event should include:

- timestamp
- interface
- src_ip
- dst_ip
- protocol
- packet_size
- src_port if present
- dst_port if present
- tcp_flags if present
- direction if inferable

### Window summary

Each completed window should include:

- window_start
- window_end
- packet_count
- byte_count
- packets_per_second
- bytes_per_second
- unique_src_ips
- unique_dst_ips
- unique_dst_ports
- protocol_counts
- mean_packet_size
- packet_size_variance
- mean_inter_arrival_time
- inter_arrival_variance
- syn_count
- ack_count
- rst_count
- dst_ip_entropy
- optional top talkers

### Alert record

Each alert should include:

- alert_id
- timestamp
- severity
- category
- detector
- summary
- evidence
- window reference
- recommended interpretation

## 13. Suggested Module Layout

```text
network-traffic-analyzer/
├── pyproject.toml              # Package metadata and build configuration
├── setup.py                    # Build script (optional, for legacy compatibility)
├── README.md                   # Installation and usage documentation
├── LICENSE                     # Open source license (MIT/Apache 2.0)
├── CHANGELOG.md               # Version history
├── requirements.txt           # Production dependencies
├── requirements-dev.txt       # Development dependencies
├── .gitignore
├── src/
│   └── analyzer/              # Main package directory
│       ├── __init__.py        # Package initialization, version info
│       ├── __main__.py        # Entry point for `python -m analyzer`
│       ├── cli.py             # CLI commands and argument parsing
│       ├── config.py          # Configuration management
│       ├── interfaces.py      # Network interface discovery
│       ├── capture.py         # Packet capture orchestration
│       ├── parser.py          # Packet parsing and normalization
│       ├── models.py          # Data models (PacketEvent, WindowSummary, Alert)
│       ├── features.py        # Feature extraction logic
│       ├── windows.py         # Window aggregation engine
│       ├── baseline.py        # Baseline training and comparison
│       ├── alerts.py          # Alert management and deduplication
│       ├── reporting.py       # Report generation
│       ├── storage.py         # Storage adapters (SQLite, JSONL)
│       ├── service.py         # Service mode and daemon support (Phase 7)
│       ├── api.py             # REST API server (Phase 8)
│       ├── plugins.py         # Plugin loader and registry (Phase 8)
│       └── detectors/
│           ├── __init__.py    # Detector registry
│           ├── base.py        # Base detector interface
│           ├── syn_flood.py   # SYN flood detection
│           ├── port_scan.py   # Port scanning detection
│           ├── protocol_shift.py  # Protocol distribution anomalies
│           ├── traffic_anomaly.py # Traffic rate anomalies
│           ├── sniffer.py     # Sniffer detection heuristics
│           └── ml_adapter.py  # ML model integration (Phase 9)
├── tests/
│   ├── __init__.py
│   ├── conftest.py            # Pytest fixtures
│   ├── test_parser.py         # Parser unit tests
│   ├── test_windows.py        # Window aggregation tests
│   ├── test_detectors.py      # Detector unit tests
│   ├── test_baseline.py       # Baseline training tests
│   ├── test_reporting.py      # Report generation tests
│   ├── test_cli.py            # CLI integration tests
│   ├── test_performance.py    # Performance benchmarks (Phase 4)
│   └── fixtures/              # Test data (sample PCAPs, configs)
│       ├── small_capture.pcap
│       ├── syn_flood.pcap
│       └── port_scan.pcap
├── docs/
│   ├── installation.md        # Installation guide (Phase 5)
│   ├── quickstart.md          # Quick start tutorial
│   ├── configuration.md       # Configuration reference
│   ├── detectors.md           # Detector documentation
│   ├── api.md                 # API reference (Phase 8)
│   └── plugin_development.md  # Plugin development guide (Phase 8)
├── examples/
│   ├── basic_monitoring.py    # Example scripts
│   ├── custom_detector.py     # Custom detector example (Phase 8)
│   └── configs/
│       ├── home_network.yaml  # Example configuration files
│       ├── lab_network.yaml
│       └── high_security.yaml
├── scripts/
│   ├── build_package.sh       # Build and test script (Phase 5)
│   ├── publish_pypi.sh        # PyPI publishing script (Phase 5)
│   └── install_service.sh     # Service installation script (Phase 7)
└── data/                      # Runtime data directory (gitignored)
    ├── baselines/             # Stored baselines
    ├── logs/                  # Application logs
    ├── reports/               # Generated reports
    └── sessions/              # Session metadata
```

### Package Entry Points (Phase 5)

After installation, the package provides the following console commands:

```toml
[project.scripts]
nta = "analyzer.cli:main"
network-traffic-analyzer = "analyzer.cli:main"
```

This allows users to run:
```bash
nta --help
nta interfaces
nta monitor eth0
nta baseline train
nta report latest
```

## 14. Mapping the Existing Prototype into the Target Design

### Existing file to target module mapping

- `src/interfaces.py` -> keep the concept, move into `analyzer/interfaces.py`
- `src/test_capture.py` -> replace with capture smoke tests
- `src/packet_features.py` -> fold into parser plus feature extractor
- `src/traffic_window.py` -> evolve into reusable window aggregation
- `src/syn_detector.py` -> split into:
  - capture orchestration
  - SYN flood detector
  - port scan detector
  - alert manager
- `src/alerts.log` -> replace with structured run outputs under an output directory

### Required refactors

- Remove top-level execution side effects from modules
- Centralize configuration and interface selection
- Replace direct prints with structured logging
- Separate packet ingestion from detection logic
- Make detectors testable with synthetic inputs

## 15. Identified Bottlenecks and Enhancements

### Bottleneck Analysis

#### B1: Architecture Bottlenecks
- **Monolithic packet processing**: Single-threaded packet capture may become a bottleneck under high traffic
- **In-memory window aggregation**: Large windows without batching could cause memory issues
- **Sequential detector execution**: Detectors run one-by-one, slowing down high-frequency analysis
- **No async I/O**: File writes and storage operations block the capture pipeline

#### B2: Performance Bottlenecks
- **Feature extraction overhead**: Computing entropy, variance, and distributions per-packet is expensive
- **No packet batching**: Processing packets individually increases overhead
- **Lack of caching**: Repeated calculations (like baseline statistics) aren't cached
- **String operations in hot path**: Protocol lookups and IP string conversions add latency

#### B3: Scalability Bottlenecks
- **No horizontal scaling**: Single-process design limits throughput
- **Local-only storage**: SQLite becomes a bottleneck for high-volume persistent writes
- **No distributed baseline**: Baseline is host-specific, preventing network-wide learning
- **Missing rate limiting**: No backpressure mechanism when detectors can't keep up

#### B4: Usability Bottlenecks
- **Manual installation**: No package manager support limits adoption
- **No service mode**: Tool must run interactively, can't run as daemon
- **Limited output formats**: Only logs and markdown, no real-time streaming
- **Configuration complexity**: Too many CLI flags without sensible defaults

#### B5: Development Bottlenecks
- **Missing test infrastructure**: No continuous validation of detector accuracy
- **No performance benchmarks**: Can't track optimization improvements
- **Lack of profiling hooks**: Hard to identify runtime bottlenecks
- **No plugin system**: Adding custom detectors requires code changes

### Enhancement Roadmap

#### E1: Performance Enhancements
- **Packet batching**: Process packets in micro-batches (100-1000 packets) to reduce per-packet overhead
- **Lazy feature computation**: Only compute features needed by enabled detectors
- **Feature caching**: Cache expensive calculations like entropy across windows
- **Async I/O pipeline**: Use asyncio for non-blocking storage and alert delivery
- **Multi-threaded detection**: Run detectors in parallel using thread pool
- **Numeric optimization**: Use numpy arrays for vectorized feature computation

#### E2: Scalability Enhancements
- **Configurable storage backends**: Support both SQLite (default) and external databases
- **Streaming aggregation**: Support Apache Kafka or Redis Streams for distributed deployment
- **Backpressure handling**: Drop or sample packets when pipeline can't keep up
- **Multi-process capture**: Support multiple interfaces in parallel processes

#### E3: Usability Enhancements
- **Package manager distribution**: Publish to PyPI as installable package
- **Service mode**: Add systemd/Windows service support for background operation
- **Interactive configuration wizard**: Guide first-time setup
- **Dashboard integration**: Provide REST API for external visualization tools
- **Export to SIEM**: Support common formats (CEF, LEEF, Syslog)

#### E4: Architecture Enhancements
- **Plugin architecture**: Dynamic detector loading from external modules
- **Pipeline configurability**: Allow custom feature extractors via config
- **Modular storage adapters**: Plug different storage backends without code changes
- **Event bus architecture**: Decouple components via publish-subscribe pattern

## 15.1 Delivery Phases (Enhanced)

### Phase 0: Baseline cleanup and project structure ✅ COMPLETED
**Duration**: Foundation phase
**Goal**: Transform prototype into production-ready structure
**Status**: ✅ Implemented (2024)

- ✅ Create professional package structure with proper __init__.py files
- ✅ Add a real CLI entry point using argparse or Click
- ✅ Move prototype logic into reusable, testable modules
- ✅ Add logging with configurable levels (DEBUG, INFO, WARNING, ERROR)
- ✅ Create output directories structure (logs/, reports/, baselines/, sessions/)
- ✅ Add basic configuration file support (YAML/JSON)
- ✅ Set up project metadata (pyproject.toml, setup.py)
- ✅ Add requirements.txt and requirements-dev.txt

**Bottlenecks addressed**: B4 (configuration complexity), B5 (development infrastructure)

### Phase 1: Monitoring MVP ✅ COMPLETED
**Duration**: Core functionality
**Goal**: Stable packet capture and feature extraction
**Status**: ✅ Implemented (2024)

- ✅ Interface discovery with platform detection
- ✅ Live capture with graceful error handling
- ✅ PCAP file replay for testing
- ✅ Robust packet parsing with error recovery
- ✅ Window aggregation with configurable sizes
- ✅ Traffic summary output (console + file)
- ✅ Basic performance metrics collection
- ✅ Memory usage monitoring and limits

**Bottlenecks addressed**: B1 (architecture), B2 (performance - via batching)

### Phase 2: Detection MVP ✅ COMPLETED
**Duration**: Core detection capabilities
**Goal**: Working detector suite with explainable alerts
**Status**: ✅ Implemented (2024)

- ✅ Base detector interface and registry
- ✅ SYN flood detector with dynamic thresholds
- ✅ Port scan detector (vertical and horizontal)
- ✅ Protocol distribution change detector
- ✅ Structured alert format with evidence
- ✅ Alert deduplication and suppression
- ✅ Severity scoring system
- ✅ Console and file alert output

**Bottlenecks addressed**: B1 (sequential execution - via detector registry)

### Phase 3: Baselines and reports ✅ COMPLETED
**Duration**: Intelligence and reporting
**Goal**: Learn normal behavior and generate insights
**Status**: ✅ Implemented (2024)

- ✅ Baseline training mode with validation
- ✅ Baseline storage and versioning
- ✅ Baseline comparison with statistical tests
- ✅ Markdown report generation
- ✅ CSV data export for analysis
- ✅ Session metadata persistence
- ✅ Historical trend analysis
- ✅ Top talkers and flow summaries

**Bottlenecks addressed**: B3 (baseline caching)

### Phase 4: Performance optimization
**Duration**: Optimization phase
**Goal**: Handle high-traffic scenarios efficiently

**NEW PHASE - addresses critical bottlenecks**

- Implement packet batching (100-1000 packet micro-batches)
- Add numpy-based vectorized feature computation
- Implement feature computation caching
- Add async I/O for storage operations
- Implement multi-threaded detector execution
- Add backpressure and packet sampling under load
- Performance profiling and benchmarking suite
- Memory profiling and optimization
- Add performance regression tests

**Bottlenecks addressed**: B1 (async I/O), B2 (all performance bottlenecks), B3 (rate limiting)

### Phase 5: NPM-style package distribution
**Duration**: Distribution phase
**Goal**: Make tool installable and usable via package manager

**NEW PHASE - critical for usability**

#### 5.1: Python Package Preparation
- Finalize pyproject.toml with all metadata
- Create comprehensive README.md with installation instructions
- Add LICENSE file (MIT/Apache 2.0)
- Create CHANGELOG.md
- Add entry points for CLI commands
- Write installation and quick-start documentation
- Create example configuration files
- Add platform-specific installation notes (Windows/Linux permissions)

#### 5.2: PyPI Publication
- Set up PyPI account and tokens
- Test package build: `python -m build`
- Test package installation locally: `pip install dist/*.whl`
- Publish to TestPyPI first for validation
- Publish to PyPI: `twine upload dist/*`
- Verify installation: `pip install network-traffic-analyzer`
- Test CLI commands after installation

#### 5.3: CLI Command Structure
After installation via `pip install network-traffic-analyzer`, users should access via:

```bash
# Main command
nta --help

# Subcommands
nta interfaces              # List available network interfaces
nta monitor <interface>     # Start monitoring
nta baseline train          # Train baseline from traffic
nta baseline apply          # Monitor with baseline comparison
nta report <session-id>     # Generate report for session
nta replay <pcap-file>      # Analyze PCAP file
nta config init             # Create default config file
nta version                 # Show version info
```

#### 5.4: Package Features
- **Global installation**: `pip install network-traffic-analyzer`
- **Isolated environments**: Works with venv, conda, poetry
- **Version management**: Semantic versioning (1.0.0, 1.1.0, etc.)
- **Dependency resolution**: Automatic installation of scapy, numpy, etc.
- **Upgrade support**: `pip install --upgrade network-traffic-analyzer`
- **Uninstall support**: `pip uninstall network-traffic-analyzer`

#### 5.5: Configuration Management
- Default config location: `~/.config/nta/config.yaml` (Linux) or `%APPDATA%\nta\config.yaml` (Windows)
- Project-local config: `./nta.config.yaml` (overrides global)
- Environment variables: `NTA_CONFIG_PATH`, `NTA_INTERFACE`, etc.
- Config validation on startup

#### 5.6: Distribution Enhancements
- Add `--version` flag showing package version
- Include sample PCAP files in package data
- Bundle default baseline profiles
- Include detector templates for custom extensions
- Add shell completion (bash, zsh, fish)
- Create Docker image for containerized deployment
- Add Homebrew formula for macOS (optional)
- Create Windows installer with dependencies (optional)

**Bottlenecks addressed**: B4 (manual installation, usability), B5 (development workflow)

### Phase 6: Sniffer detection research track
**Duration**: Advanced detection
**Goal**: Detect unauthorized monitoring tools

- ARP behavior analysis module
- Promiscuous mode detection heuristics
- Latency-based anomaly detection
- Packet duplication pattern analysis
- Optional active probing (opt-in, lab-only)
- Controlled validation methodology
- Sniffer detection report section

**Bottlenecks addressed**: None (new capability)

### Phase 7: Service mode and automation
**Duration**: Production deployment
**Goal**: Run as background service

**NEW PHASE - critical for production use**

- Daemon mode for background operation
- systemd service file for Linux
- Windows service support
- Automatic startup configuration
- Log rotation and management
- Health check endpoints
- Graceful restart without data loss
- Process supervision and auto-recovery

**Bottlenecks addressed**: B4 (service mode)

### Phase 8: Advanced features
**Duration**: Extended capabilities
**Goal**: Plugin system and extensibility

**NEW PHASE - addresses extensibility bottlenecks**

- Plugin architecture for custom detectors
- Dynamic detector loading from config
- REST API for external tools
- Real-time alert streaming (WebSocket/SSE)
- Integration with SIEM platforms
- Export to common formats (CEF, LEEF, Syslog)
- Dashboard API endpoints
- Prometheus metrics export

**Bottlenecks addressed**: B3 (output formats), B4 (integration), B5 (plugin system)

### Phase 9: Optional ML extension
**Duration**: Machine learning integration
**Goal**: Advanced anomaly detection

- Feature engineering pipeline for ML
- Model training with labeled datasets
- Support for multiple algorithms (Isolation Forest, Autoencoder, DBSCAN)
- Offline evaluation and model validation
- Model versioning and storage
- Online learning capability
- Model scoring integration
- Fallback to rule-based on model failure
- Explainable AI integration (SHAP, LIME)

**Bottlenecks addressed**: B3 (distributed learning preparation)

### Phase 10: Distributed deployment (Future)
**Duration**: Enterprise scale
**Goal**: Multi-node deployment

- Agent-coordinator architecture
- Centralized baseline management
- Distributed alert aggregation
- Network-wide traffic correlation
- Load balancing across sensors
- Failover and redundancy
- Centralized configuration management

**Bottlenecks addressed**: B3 (all scalability bottlenecks)

## 16. Acceptance Criteria

### Phase 0-3: Academic Deliverable (MVP)
The project should be considered complete for the main academic deliverable when all of the following are true:

- A user can list interfaces and start monitoring a selected interface from the CLI
- The system captures packets and emits stable window summaries
- The system generates structured alerts for at least SYN flood and port scan conditions
- Alerts include enough evidence to explain why they fired
- The system stores or exports session results
- The system generates a readable report after a run
- The architecture cleanly supports adding baseline-based and ML-based detectors
- The codebase is modular enough that capture, aggregation, and detection can be tested independently

### Phase 4-5: Production-Ready Release
The project should be considered production-ready when:

- Performance benchmarks show handling of at least 1000 packets/second without dropped packets
- Memory usage remains stable over 24+ hour runs
- Package is installable via `pip install network-traffic-analyzer`
- CLI commands work immediately after installation without manual configuration
- Documentation includes installation, quick-start, and troubleshooting guides
- All detector accuracy metrics are documented and validated
- Unit test coverage exceeds 80%
- Integration tests validate end-to-end workflows

### Phase 6-8: Enterprise-Ready
The project should be considered enterprise-ready when:

- Service mode supports 24/7 operation with automatic recovery
- REST API enables integration with external tools
- Alert export supports at least 2 SIEM platforms
- Plugin system allows custom detectors without core code changes
- Documentation includes API reference and plugin development guide
- Performance profiling shows no memory leaks or resource exhaustion
- Security audit passes with no critical vulnerabilities

### Phase 9-10: Research-Grade Platform
The project should be considered research-grade when:

- ML pipeline supports multiple algorithms with validated accuracy metrics
- Distributed deployment supports multi-node correlation
- Published benchmarks compare performance against academic baselines
- Reproducible evaluation datasets are publicly available
- Research documentation includes methodology and validation results

## 17. Risks and Constraints

### Technical risks

- Packet capture privileges differ across Windows and Linux
- Scapy capture reliability can vary by interface and driver
- High false positives are likely with naive thresholds
- Sniffer detection is difficult to validate without careful lab setup

### Project risks

- ML may consume time without improving explainability
- Real-world traffic labeling may be limited
- Hardcoded environment assumptions may make demos unreliable

### Mitigations

- Keep rule-based detectors as the primary milestone
- Add PCAP replay for repeatable testing
- Separate experimental sniffer detection from core traffic anomaly features
- Use explainable metrics before introducing ML

## 18. Recommended Immediate Next Steps

### For Academic Deliverable (Phases 0-3)
1. Convert the prototype scripts into import-safe modules
2. Create a single CLI entry point with commands such as `interfaces`, `monitor`, and `report`
3. Implement normalized packet events and window summaries
4. Move the current SYN flood and port scan logic into detector classes
5. Replace ad hoc logging with structured alert output
6. Add PCAP replay and unit tests so detection can be validated repeatedly

### For Production Package (Phases 4-5)
1. Set up pyproject.toml with proper package metadata and entry points
2. Implement packet batching and async I/O for performance
3. Create comprehensive documentation (README, installation guide, API docs)
4. Write integration tests for end-to-end workflows
5. Build and test package locally before PyPI submission
6. Publish to TestPyPI first, then PyPI
7. Verify installation and CLI commands work globally

### For Enterprise Features (Phases 6-8)
1. Design plugin architecture with clear interface contracts
2. Implement service mode with systemd/Windows service files
3. Create REST API with OpenAPI/Swagger documentation
4. Develop SIEM export adapters for common platforms
5. Build real-time streaming endpoints for dashboards
6. Add comprehensive security audit and penetration testing

### Critical Path for Each Phase

**Phase 0-1 (Weeks 1-3)**: Foundation
- Module structure → CLI entry → Basic capture → Window aggregation

**Phase 2-3 (Weeks 4-6)**: Detection
- Detector interface → Rule-based detectors → Baseline system → Reports

**Phase 4 (Week 7)**: Optimization
- Profiling → Batching → Async I/O → Benchmarking

**Phase 5 (Week 8)**: Package Distribution
- pyproject.toml → Build → Test → Publish → Documentation

**Phase 6-8 (Weeks 9-12)**: Advanced Features
- Service mode → API → Plugins → SIEM integration

**Phase 9-10 (Weeks 13-16)**: Research Extensions
- ML pipeline → Distributed architecture → Evaluation datasets

## 19. Definition of Success

### Academic Success (Phases 0-3)
If implemented according to this plan through Phase 3, the project will no longer be a set of packet-sniffing experiments. It will become a **structured real-time network monitoring and anomaly detection system** aligned with the presentation goals, while still grounded in the prototype that already exists in `src/`.

**Success metrics**:
- Demonstrates networking and cybersecurity fundamentals
- Produces explainable alerts with evidence
- Generates professional reports suitable for academic presentation
- Architecture supports future ML extensions
- Code quality suitable for portfolio inclusion

### Production Success (Phases 4-5)
If implemented through Phase 5, the project becomes a **production-ready, installable package** that anyone can use via simple pip installation.

**Success metrics**:
- Available on PyPI as `network-traffic-analyzer`
- Works immediately after `pip install` on Windows and Linux
- CLI interface is intuitive and well-documented
- Performance suitable for real lab/office network monitoring
- Handles edge cases gracefully with clear error messages

**User experience goal**:
```bash
pip install network-traffic-analyzer
nta interfaces
nta monitor eth0
# ... monitoring in progress with real-time alerts ...
nta report latest
```

### Enterprise Success (Phases 6-8)
If implemented through Phase 8, the project becomes an **enterprise-grade monitoring platform** suitable for production deployment.

**Success metrics**:
- Runs as background service with auto-recovery
- Integrates with existing security infrastructure (SIEM)
- Supports custom detectors via plugin system
- Provides REST API for external tools and dashboards
- Production-tested for 24/7 operation

### Research Success (Phases 9-10)
If implemented through Phase 10, the project becomes a **research platform** for network anomaly detection studies.

**Success metrics**:
- Publishable evaluation methodology and results
- Reproducible benchmarks on standard datasets
- Distributed deployment for network-wide correlation
- ML pipeline validated against academic baselines
- Contributes to open-source security research community

### Key Differentiators

This project will stand out because it:
1. **Starts simple**: Academic prototype → Production tool → Research platform
2. **Stays explainable**: Every alert has clear evidence and reasoning
3. **Remains accessible**: Easy installation, clear documentation, low barrier to entry
4. **Grows modularly**: Clean architecture supports extensions without rewrites
5. **Balances goals**: Security analysis + Performance + Usability + Research potential

The enhanced plan addresses **5 major bottleneck categories**, adds **4 new critical phases** (performance optimization, package distribution, service mode, plugin system), and provides a clear path from student project to production-ready security tool.
