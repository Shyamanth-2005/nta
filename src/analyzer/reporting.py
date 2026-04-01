"""
Report generation.

Creates comprehensive reports from monitoring sessions:
- Markdown reports
- CSV exports
- JSON data dumps
"""

import logging
import time
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from analyzer.models import WindowSummary, Alert, SessionMetadata, AlertSeverity

logger = logging.getLogger("analyzer.reporting")


class ReportGenerator:
    """
    Generates monitoring session reports.
    """
    
    def __init__(self, output_dir: Path):
        """
        Initialize report generator.
        
        Args:
            output_dir: Directory for report output
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_markdown_report(
        self,
        session: SessionMetadata,
        windows: List[WindowSummary],
        alerts: List[Alert],
        top_talkers_count: int = 10,
    ) -> Path:
        """
        Generate a Markdown report for a monitoring session.
        
        Args:
            session: Session metadata
            windows: List of window summaries
            alerts: List of generated alerts
            top_talkers_count: Number of top talkers to include
            
        Returns:
            Path: Path to generated report
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{session.session_id}_{timestamp}.md"
        filepath = self.output_dir / filename
        
        report = []
        
        # Header
        report.append("# Network Traffic Analysis Report")
        report.append("")
        report.append(f"**Session ID:** {session.session_id}")
        report.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        # Session Summary
        report.append("## Session Summary")
        report.append("")
        report.append("| Metric | Value |")
        report.append("|--------|-------|")
        report.append(f"| Interface | {session.interface} |")
        report.append(f"| Mode | {session.mode} |")
        report.append(f"| Start Time | {datetime.fromtimestamp(session.start_time).strftime('%Y-%m-%d %H:%M:%S')} |")
        if session.end_time:
            report.append(f"| End Time | {datetime.fromtimestamp(session.end_time).strftime('%Y-%m-%d %H:%M:%S')} |")
            report.append(f"| Duration | {self._format_duration(session.duration)} |")
        report.append(f"| Total Packets | {session.packet_count:,} |")
        report.append(f"| Total Alerts | {session.alert_count} |")
        report.append(f"| Windows Analyzed | {session.window_count} |")
        report.append("")
        
        # Traffic Statistics
        if windows:
            report.extend(self._generate_traffic_section(windows))
        
        # Alert Summary
        report.extend(self._generate_alerts_section(alerts))
        
        # Top Talkers
        if windows:
            report.extend(self._generate_top_talkers_section(windows, top_talkers_count))
        
        # Protocol Distribution
        if windows:
            report.extend(self._generate_protocol_section(windows))
        
        # Alert Timeline
        if alerts:
            report.extend(self._generate_timeline_section(alerts))
        
        # Write report
        with open(filepath, "w") as f:
            f.write("\n".join(report))
        
        logger.info(f"Generated report: {filepath}")
        return filepath
    
    def _generate_traffic_section(self, windows: List[WindowSummary]) -> List[str]:
        """Generate traffic statistics section."""
        section = []
        section.append("## Traffic Statistics")
        section.append("")
        
        total_packets = sum(w.packet_count for w in windows)
        total_bytes = sum(w.byte_count for w in windows)
        total_duration = sum(w.duration for w in windows)
        
        avg_pps = total_packets / total_duration if total_duration > 0 else 0
        avg_bps = total_bytes / total_duration if total_duration > 0 else 0
        
        all_sizes = []
        for w in windows:
            if w.packet_count > 0:
                all_sizes.extend([w.mean_packet_size] * w.packet_count)
        avg_size = sum(all_sizes) / len(all_sizes) if all_sizes else 0
        
        section.append("| Metric | Value |")
        section.append("|--------|-------|")
        section.append(f"| Total Packets | {total_packets:,} |")
        section.append(f"| Total Bytes | {self._format_bytes(total_bytes)} |")
        section.append(f"| Avg Packets/sec | {avg_pps:.2f} |")
        section.append(f"| Avg Bytes/sec | {self._format_bytes(avg_bps)}/s |")
        section.append(f"| Avg Packet Size | {avg_size:.1f} bytes |")
        section.append(f"| Unique Source IPs | {max(w.unique_src_ips for w in windows) if windows else 0} |")
        section.append(f"| Unique Dest IPs | {max(w.unique_dst_ips for w in windows) if windows else 0} |")
        section.append("")
        
        return section
    
    def _generate_alerts_section(self, alerts: List[Alert]) -> List[str]:
        """Generate alerts summary section."""
        section = []
        section.append("## Alert Summary")
        section.append("")
        
        if not alerts:
            section.append("*No alerts generated during this session.*")
            section.append("")
            return section
        
        # Count by severity
        by_severity = {}
        for a in alerts:
            sev = a.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        # Count by detector
        by_detector = {}
        for a in alerts:
            by_detector[a.detector] = by_detector.get(a.detector, 0) + 1
        
        section.append("### By Severity")
        section.append("")
        section.append("| Severity | Count |")
        section.append("|----------|-------|")
        for sev in ["critical", "high", "medium", "low"]:
            if sev in by_severity:
                section.append(f"| {sev.upper()} | {by_severity[sev]} |")
        section.append("")
        
        section.append("### By Detector")
        section.append("")
        section.append("| Detector | Count |")
        section.append("|----------|-------|")
        for detector, count in sorted(by_detector.items(), key=lambda x: -x[1]):
            section.append(f"| {detector} | {count} |")
        section.append("")
        
        return section
    
    def _generate_top_talkers_section(self, windows: List[WindowSummary], top_n: int) -> List[str]:
        """Generate top talkers section."""
        section = []
        section.append("## Top Talkers")
        section.append("")
        
        # Aggregate top talkers across all windows
        talker_totals: Dict[str, int] = {}
        for w in windows:
            for ip, count in w.top_talkers:
                talker_totals[ip] = talker_totals.get(ip, 0) + count
        
        top_talkers = sorted(talker_totals.items(), key=lambda x: -x[1])[:top_n]
        
        if not top_talkers:
            section.append("*No traffic data available.*")
            section.append("")
            return section
        
        section.append("| Rank | Source IP | Packet Count |")
        section.append("|------|-----------|--------------|")
        for i, (ip, count) in enumerate(top_talkers, 1):
            section.append(f"| {i} | {ip} | {count:,} |")
        section.append("")
        
        return section
    
    def _generate_protocol_section(self, windows: List[WindowSummary]) -> List[str]:
        """Generate protocol distribution section."""
        section = []
        section.append("## Protocol Distribution")
        section.append("")
        
        # Aggregate protocol counts
        protocol_totals: Dict[str, int] = {}
        total_packets = 0
        for w in windows:
            for proto, count in w.protocol_counts.items():
                protocol_totals[proto] = protocol_totals.get(proto, 0) + count
                total_packets += count
        
        if not protocol_totals:
            section.append("*No protocol data available.*")
            section.append("")
            return section
        
        section.append("| Protocol | Count | Percentage |")
        section.append("|----------|-------|------------|")
        for proto, count in sorted(protocol_totals.items(), key=lambda x: -x[1]):
            pct = (count / total_packets * 100) if total_packets > 0 else 0
            section.append(f"| {proto} | {count:,} | {pct:.1f}% |")
        section.append("")
        
        return section
    
    def _generate_timeline_section(self, alerts: List[Alert]) -> List[str]:
        """Generate alert timeline section."""
        section = []
        section.append("## Alert Timeline")
        section.append("")
        
        # Sort alerts by time
        sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)
        
        section.append("| Time | Severity | Detector | Summary |")
        section.append("|------|----------|----------|---------|")
        for alert in sorted_alerts[:50]:  # Limit to 50 alerts
            time_str = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
            summary = alert.summary[:50] + "..." if len(alert.summary) > 50 else alert.summary
            section.append(f"| {time_str} | {alert.severity.value.upper()} | {alert.detector} | {summary} |")
        
        if len(sorted_alerts) > 50:
            section.append(f"| ... | ... | ... | *({len(sorted_alerts) - 50} more alerts)* |")
        section.append("")
        
        return section
    
    def export_csv(
        self,
        windows: List[WindowSummary],
        filename: str = "windows.csv",
    ) -> Path:
        """
        Export window summaries to CSV.
        
        Args:
            windows: List of window summaries
            filename: Output filename
            
        Returns:
            Path: Path to CSV file
        """
        filepath = self.output_dir / filename
        
        headers = [
            "window_start", "window_end", "packet_count", "byte_count",
            "packets_per_second", "bytes_per_second", "unique_src_ips",
            "unique_dst_ips", "unique_dst_ports", "mean_packet_size",
            "syn_count", "ack_count", "rst_count", "dst_ip_entropy"
        ]
        
        with open(filepath, "w") as f:
            f.write(",".join(headers) + "\n")
            
            for w in windows:
                row = [
                    str(w.window_start),
                    str(w.window_end),
                    str(w.packet_count),
                    str(w.byte_count),
                    f"{w.packets_per_second:.2f}",
                    f"{w.bytes_per_second:.2f}",
                    str(w.unique_src_ips),
                    str(w.unique_dst_ips),
                    str(w.unique_dst_ports),
                    f"{w.mean_packet_size:.1f}",
                    str(w.syn_count),
                    str(w.ack_count),
                    str(w.rst_count),
                    f"{w.dst_ip_entropy:.3f}",
                ]
                f.write(",".join(row) + "\n")
        
        logger.info(f"Exported {len(windows)} windows to {filepath}")
        return filepath
    
    def export_alerts_csv(self, alerts: List[Alert], filename: str = "alerts.csv") -> Path:
        """Export alerts to CSV."""
        filepath = self.output_dir / filename
        
        headers = ["timestamp", "severity", "detector", "category", "summary"]
        
        with open(filepath, "w") as f:
            f.write(",".join(headers) + "\n")
            
            for a in alerts:
                row = [
                    datetime.fromtimestamp(a.timestamp).isoformat(),
                    a.severity.value,
                    a.detector,
                    a.category,
                    f'"{a.summary}"',
                ]
                f.write(",".join(row) + "\n")
        
        logger.info(f"Exported {len(alerts)} alerts to {filepath}")
        return filepath
    
    def export_json(
        self,
        session: SessionMetadata,
        windows: List[WindowSummary],
        alerts: List[Alert],
        filename: str = "session_data.json",
    ) -> Path:
        """Export all session data to JSON."""
        filepath = self.output_dir / filename
        
        data = {
            "session": session.to_dict(),
            "windows": [w.to_dict() for w in windows],
            "alerts": [a.to_dict() for a in alerts],
            "generated_at": datetime.now().isoformat(),
        }
        
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Exported session data to {filepath}")
        return filepath
    
    def _format_duration(self, seconds: Optional[float]) -> str:
        """Format duration in human-readable form."""
        if seconds is None:
            return "N/A"
        
        hours, remainder = divmod(int(seconds), 3600)
        minutes, secs = divmod(remainder, 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        else:
            return f"{secs}s"
    
    def _format_bytes(self, bytes_val: float) -> str:
        """Format bytes in human-readable form."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if bytes_val < 1024:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.2f} PB"
