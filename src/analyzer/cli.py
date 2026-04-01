"""
Command-line interface for the network traffic analyzer.

Provides commands for:
- Listing network interfaces
- Starting live monitoring
- Replaying PCAP files
- Training and managing baselines
- Generating reports
"""

import argparse
import logging
import signal
import sys
import time
import uuid
from pathlib import Path
from typing import Optional, List

from analyzer.config import Config, load_config, create_default_config
from analyzer.logging_config import setup_logging, get_logger
from analyzer.interfaces import get_interfaces, get_default_interface, print_interfaces, validate_interface
from analyzer.capture import CaptureEngine
from analyzer.parser import PacketParser
from analyzer.windows import WindowAggregator
from analyzer.features import FeatureExtractor
from analyzer.detectors import DetectorRegistry, DetectionEngine
from analyzer.alerts import AlertManager
from analyzer.baseline import BaselineManager
from analyzer.reporting import ReportGenerator
from analyzer.storage import SessionStorage
from analyzer.models import SessionMetadata, WindowSummary, PacketEvent
from analyzer import ui

logger = get_logger("analyzer.cli")


class NetworkAnalyzer:
    """
    Main network traffic analyzer application.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the analyzer.
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.session_id = f"session_{uuid.uuid4().hex[:8]}"
        self.running = False
        
        # Set up logging
        setup_logging(
            level=config.log_level,
            log_dir=config.get_logs_path(),
            console=True,
            file_logging=True,
        )
        
        # Initialize components
        self.alert_manager = AlertManager(
            output_dir=config.get_logs_path(),
            console_output=config.alerts.console_output,
            file_output=config.alerts.file_output,
            output_format=config.alerts.output_format,
            suppression_window=config.alerts.suppression_window,
        )
        
        self.window_aggregator = WindowAggregator(
            window_size=config.window_size,
            on_window_complete=self._on_window_complete,
        )
        
        # Create detectors
        self.detection_engine = DetectionEngine()
        for detector_name in config.detectors:
            detector = DetectorRegistry.create(detector_name)
            if detector:
                self.detection_engine.add_detector(detector)
                logger.info(f"Loaded detector: {detector_name}")
        
        # Baseline manager
        self.baseline_manager = BaselineManager(config.get_baselines_path())
        
        # Session storage
        self.session_storage = SessionStorage(config.get_sessions_path())
        
        # Report generator
        self.report_generator = ReportGenerator(config.get_reports_path())
        
        # Session metadata
        self.session = SessionMetadata(
            session_id=self.session_id,
            start_time=time.time(),
            interface=config.interface or "",
            mode="pcap" if config.pcap_file else "live",
            config=config.to_dict(),
        )
        
        # Capture engine (initialized when starting)
        self.capture_engine: Optional[CaptureEngine] = None
        
        # Training mode flag
        self.training_mode = False
    
    def _on_window_complete(self, window: WindowSummary) -> None:
        """Handle completed window."""
        self.session.window_count += 1
        
        # Print window summary
        self._print_window_summary(window)
        
        # Run detectors
        alerts = self.detection_engine.evaluate(window)
        
        # Add alerts to manager
        added = self.alert_manager.add_alerts(alerts)
        self.session.alert_count += added
        
        # If in training mode, add to baseline
        if self.training_mode:
            ready = self.baseline_manager.add_training_window(window)
            if ready:
                logger.info("Baseline training data collection complete")
    
    def _print_window_summary(self, window: WindowSummary) -> None:
        """Print window summary to console."""
        # Use rich panel for beautiful display
        panel = ui.create_window_summary_panel(window)
        ui.console.print(panel)
    
    def _on_packet(self, event: PacketEvent) -> None:
        """Handle parsed packet."""
        self.session.packet_count += 1
        self.window_aggregator.add_packet(event)
    
    def start_monitoring(self, interface: Optional[str] = None, pcap_file: Optional[str] = None) -> None:
        """
        Start network monitoring.
        
        Args:
            interface: Network interface (for live capture)
            pcap_file: PCAP file path (for replay)
        """
        # Determine capture source
        if pcap_file:
            self.session.mode = "pcap"
            logger.info(f"Starting PCAP replay: {pcap_file}")
        else:
            interface = interface or self.config.interface or get_default_interface()
            if not interface:
                logger.error("No interface specified and no default found")
                sys.exit(1)
            
            if not validate_interface(interface):
                logger.error(f"Invalid interface: {interface}")
                sys.exit(1)
            
            self.session.interface = interface
            self.session.mode = "live"
            logger.info(f"Starting live capture on: {interface}")
        
        # Create capture engine
        self.capture_engine = CaptureEngine(
            interface=interface,
            pcap_file=pcap_file,
            filter_str=self.config.capture_filter,
            max_packets=self.config.max_packets,
            on_packet=self._on_packet,
        )
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        self.running = True
        self.session.start_time = time.time()
        
        # Display session info panel
        ui.console.print()
        session_panel = ui.create_session_info_panel(
            session_id=self.session_id,
            mode=self.session.mode,
            interface=interface or pcap_file or "N/A",
            window_size=self.config.window_size,
            detectors=self.config.detectors,
        )
        ui.console.print(session_panel)
        ui.print_info("[bold]Press Ctrl+C to stop monitoring...[/bold]")
        ui.console.print()
        
        try:
            # Start capture (blocking)
            self.capture_engine.start(blocking=True)
        except Exception as e:
            logger.error(f"Capture error: {e}")
        finally:
            self.stop_monitoring()
    
    def stop_monitoring(self) -> None:
        """Stop monitoring and generate report."""
        if not self.running:
            return
        
        self.running = False
        self.session.end_time = time.time()
        
        ui.print_section_header("Stopping Network Traffic Analyzer", "🛑")
        
        # Stop capture
        if self.capture_engine:
            self.capture_engine.stop()
        
        # Flush final window
        final_window = self.window_aggregator.flush()
        if final_window:
            logger.info("Processed final partial window")
        
        # Get all windows
        windows = self.window_aggregator.completed_windows
        alerts = self.alert_manager.alerts
        
        # Save session data
        self.session_storage.save_metadata(self.session)
        self.session_storage.save_windows(self.session_id, windows)
        self.session_storage.save_alerts(self.session_id, alerts)
        
        # Print summary
        self._print_final_summary()
        
        # Generate report
        report_path = self.report_generator.generate_markdown_report(
            self.session, windows, alerts
        )
        ui.print_success(f"Report generated: {report_path}")
        
        # Export CSV
        if windows:
            csv_path = self.report_generator.export_csv(windows, f"windows_{self.session_id}.csv")
            ui.print_success(f"CSV export: {csv_path}")
    
    def _print_final_summary(self) -> None:
        """Print final session summary."""
        duration = self.session.duration or 0
        
        # Create statistics table
        stats_data = {
            "duration": self._format_duration(duration),
            "packets": self.session.packet_count,
            "windows": self.session.window_count,
            "alerts": self.session.alert_count,
        }
        
        stats_table = ui.create_statistics_table(stats_data)
        ui.console.print(stats_table)
        
        # Show alert breakdown if any
        alert_stats = self.alert_manager.get_stats()
        if alert_stats["by_severity"]:
            ui.console.print(f"\n[bold]Alert Breakdown:[/bold]")
            for severity, count in alert_stats["by_severity"].items():
                color = ui.UITheme.SEVERITY_COLORS.get(severity, "white")
                ui.console.print(f"  [{color}]● {severity.value}:[/{color}] {count}")
    
    def _signal_handler(self, signum, frame) -> None:
        """Handle interrupt signals."""
        print("\n\nReceived interrupt signal...")
        self.stop_monitoring()
        sys.exit(0)
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration for display."""
        hours, remainder = divmod(int(seconds), 3600)
        minutes, secs = divmod(remainder, 60)
        if hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        return f"{secs}s"
    
    def train_baseline(self, profile_name: str, windows_count: int = 10) -> None:
        """
        Start baseline training mode.
        
        Args:
            profile_name: Name for the baseline profile
            windows_count: Number of windows to collect
        """
        self.training_mode = True
        self.baseline_manager.start_training(min_windows=windows_count)
        
        print(f"\n🎓 Baseline Training Mode")
        print(f"   Profile: {profile_name}")
        print(f"   Windows to collect: {windows_count}")
        print(f"   Training will complete automatically after collecting enough data.")
        print()
        
        # Start monitoring
        self.start_monitoring()
        
        # After monitoring stops, complete training
        if self.baseline_manager.builder.is_ready:
            baseline = self.baseline_manager.complete_training(
                profile_name,
                self.session.interface,
            )
            if baseline:
                print(f"\n✅ Baseline '{profile_name}' created successfully!")
                print(f"   Windows analyzed: {baseline.window_count}")
                print(f"   Avg packets/sec: {baseline.mean_pps:.2f}")
                print(f"   Avg bytes/sec: {baseline.mean_bps:.2f}")


def cmd_interfaces(args: argparse.Namespace) -> None:
    """List network interfaces."""
    ui.print_banner()
    
    interfaces = get_interfaces()
    if not interfaces:
        ui.print_error("No network interfaces found")
        return
    
    # Convert interface data to dict format
    interface_list = []
    for iface in interfaces:
        interface_list.append({
            "name": iface.name,
            "ip": iface.ip_address,
            "status": "UP" if iface.is_up else "DOWN",
            "type": "Loopback" if iface.is_loopback else "Physical",
        })
    
    table = ui.create_interfaces_table(interface_list)
    ui.console.print(table)
    
    default_iface = get_default_interface()
    if default_iface:
        ui.print_info(f"Default interface: [bright_cyan]{default_iface}[/bright_cyan]")


def cmd_monitor(args: argparse.Namespace) -> None:
    """Start live monitoring."""
    ui.print_banner()
    
    config = load_config(args.config)
    
    # Apply CLI overrides
    if args.interface:
        config.interface = args.interface
    if args.window_size:
        config.window_size = args.window_size
    if args.filter:
        config.capture_filter = args.filter
    if args.max_packets:
        config.max_packets = args.max_packets
    
    analyzer = NetworkAnalyzer(config)
    analyzer.start_monitoring(interface=args.interface)


def cmd_replay(args: argparse.Namespace) -> None:
    """Replay PCAP file."""
    config = load_config(args.config)
    
    if args.window_size:
        config.window_size = args.window_size
    
    analyzer = NetworkAnalyzer(config)
    analyzer.start_monitoring(pcap_file=args.pcap_file)


def cmd_baseline(args: argparse.Namespace) -> None:
    """Baseline management commands."""
    config = load_config(args.config)
    manager = BaselineManager(config.get_baselines_path())
    
    if args.baseline_cmd == "train":
        if args.interface:
            config.interface = args.interface
        
        analyzer = NetworkAnalyzer(config)
        analyzer.train_baseline(args.name, args.windows)
    
    elif args.baseline_cmd == "list":
        baselines = manager.list_baselines()
        if baselines:
            print("\n📋 Available Baselines:")
            for name in baselines:
                baseline = manager.load_baseline(name)
                if baseline:
                    print(f"   • {name}")
                    print(f"     Windows: {baseline.window_count}, Created: {time.ctime(baseline.created_at)}")
        else:
            print("No baselines found.")
    
    elif args.baseline_cmd == "show":
        baseline = manager.load_baseline(args.name)
        if baseline:
            print(f"\n📊 Baseline: {baseline.profile_name}")
            print(f"   Interface: {baseline.interface}")
            print(f"   Windows: {baseline.window_count}")
            print(f"   Created: {time.ctime(baseline.created_at)}")
            print(f"\n   Traffic Statistics:")
            print(f"     Packets/sec: {baseline.mean_pps:.2f} ± {baseline.std_pps:.2f}")
            print(f"     Bytes/sec: {baseline.mean_bps:.2f} ± {baseline.std_bps:.2f}")
            print(f"     Packet size: {baseline.mean_packet_size:.1f} ± {baseline.std_packet_size:.1f}")
            print(f"\n   Protocol Distribution:")
            for proto, pct in baseline.protocol_distribution.items():
                print(f"     {proto}: {pct*100:.1f}%")
        else:
            print(f"Baseline '{args.name}' not found.")
    
    elif args.baseline_cmd == "delete":
        if manager.delete_baseline(args.name):
            print(f"Deleted baseline: {args.name}")
        else:
            print(f"Baseline '{args.name}' not found.")


def cmd_report(args: argparse.Namespace) -> None:
    """Generate report for a session."""
    config = load_config(args.config)
    storage = SessionStorage(config.get_sessions_path())
    generator = ReportGenerator(config.get_reports_path())
    
    # Get session ID
    session_id = args.session_id
    if session_id == "latest":
        session_id = storage.get_latest_session()
        if not session_id:
            print("No sessions found.")
            return
    
    # Load session data
    session = storage.load_metadata(session_id)
    if not session:
        print(f"Session '{session_id}' not found.")
        return
    
    windows = storage.load_windows(session_id)
    alerts = storage.load_alerts(session_id)
    
    print(f"Generating report for session: {session_id}")
    
    # Generate report
    report_path = generator.generate_markdown_report(session, windows, alerts)
    print(f"✅ Report generated: {report_path}")
    
    # Optional CSV export
    if args.csv:
        csv_path = generator.export_csv(windows, f"windows_{session_id}.csv")
        print(f"📊 CSV export: {csv_path}")
    
    # Optional JSON export
    if args.json:
        json_path = generator.export_json(session, windows, alerts, f"session_{session_id}.json")
        print(f"📄 JSON export: {json_path}")


def cmd_sessions(args: argparse.Namespace) -> None:
    """List monitoring sessions."""
    config = load_config(args.config)
    storage = SessionStorage(config.get_sessions_path())
    
    sessions = storage.list_sessions()
    
    if not sessions:
        print("No sessions found.")
        return
    
    print("\n📋 Monitoring Sessions:")
    print("-" * 70)
    
    for session_id in sorted(sessions, reverse=True):
        metadata = storage.load_metadata(session_id)
        if metadata:
            start = time.strftime("%Y-%m-%d %H:%M", time.localtime(metadata.start_time))
            duration = metadata.duration or 0
            print(f"  {session_id}")
            print(f"    Started: {start} | Duration: {duration:.0f}s | Packets: {metadata.packet_count:,} | Alerts: {metadata.alert_count}")
    
    print()


def cmd_config(args: argparse.Namespace) -> None:
    """Configuration commands."""
    if args.config_cmd == "init":
        output = args.output or "nta.config.yaml"
        create_default_config(output)
    
    elif args.config_cmd == "show":
        config = load_config(args.config)
        print(config.to_yaml() if args.format == "yaml" else config.to_json())


def cmd_version(args: argparse.Namespace) -> None:
    """Show version information."""
    from analyzer import __version__
    print(f"Network Traffic Analyzer v{__version__}")


def main() -> None:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="nta",
        description="Network Traffic Analyzer - Real-time network monitoring and anomaly detection",
    )
    parser.add_argument("--config", "-c", help="Path to configuration file")
    parser.add_argument("--version", "-v", action="store_true", help="Show version")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # interfaces command
    interfaces_parser = subparsers.add_parser("interfaces", help="List network interfaces")
    interfaces_parser.set_defaults(func=cmd_interfaces)
    
    # monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Start live monitoring")
    monitor_parser.add_argument("interface", nargs="?", help="Network interface to monitor")
    monitor_parser.add_argument("--window-size", "-w", type=int, help="Window size in seconds")
    monitor_parser.add_argument("--filter", "-f", help="BPF filter string")
    monitor_parser.add_argument("--max-packets", "-n", type=int, help="Max packets to capture")
    monitor_parser.set_defaults(func=cmd_monitor)
    
    # replay command
    replay_parser = subparsers.add_parser("replay", help="Replay PCAP file")
    replay_parser.add_argument("pcap_file", help="Path to PCAP file")
    replay_parser.add_argument("--window-size", "-w", type=int, help="Window size in seconds")
    replay_parser.set_defaults(func=cmd_replay)
    
    # baseline command
    baseline_parser = subparsers.add_parser("baseline", help="Baseline management")
    baseline_subparsers = baseline_parser.add_subparsers(dest="baseline_cmd")
    
    train_parser = baseline_subparsers.add_parser("train", help="Train new baseline")
    train_parser.add_argument("name", help="Baseline profile name")
    train_parser.add_argument("--interface", "-i", help="Network interface")
    train_parser.add_argument("--windows", "-w", type=int, default=10, help="Windows to collect")
    
    list_parser = baseline_subparsers.add_parser("list", help="List baselines")
    show_parser = baseline_subparsers.add_parser("show", help="Show baseline details")
    show_parser.add_argument("name", help="Baseline profile name")
    delete_parser = baseline_subparsers.add_parser("delete", help="Delete baseline")
    delete_parser.add_argument("name", help="Baseline profile name")
    
    baseline_parser.set_defaults(func=cmd_baseline)
    
    # report command
    report_parser = subparsers.add_parser("report", help="Generate session report")
    report_parser.add_argument("session_id", nargs="?", default="latest", help="Session ID or 'latest'")
    report_parser.add_argument("--csv", action="store_true", help="Export CSV")
    report_parser.add_argument("--json", action="store_true", help="Export JSON")
    report_parser.set_defaults(func=cmd_report)
    
    # sessions command
    sessions_parser = subparsers.add_parser("sessions", help="List monitoring sessions")
    sessions_parser.set_defaults(func=cmd_sessions)
    
    # config command
    config_parser = subparsers.add_parser("config", help="Configuration management")
    config_subparsers = config_parser.add_subparsers(dest="config_cmd")
    
    init_parser = config_subparsers.add_parser("init", help="Create default config")
    init_parser.add_argument("--output", "-o", help="Output file path")
    
    show_config_parser = config_subparsers.add_parser("show", help="Show current config")
    show_config_parser.add_argument("--format", choices=["yaml", "json"], default="yaml")
    
    config_parser.set_defaults(func=cmd_config)
    
    # version command
    version_parser = subparsers.add_parser("version", help="Show version")
    version_parser.set_defaults(func=cmd_version)
    
    # Parse arguments
    args = parser.parse_args()
    
    if args.version:
        cmd_version(args)
        return
    
    if not args.command:
        parser.print_help()
        return
    
    # Execute command
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
