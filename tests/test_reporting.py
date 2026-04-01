"""Tests for the reporting module."""

import pytest
import time
from pathlib import Path

from analyzer.reporting import ReportGenerator
from analyzer.models import SessionMetadata, WindowSummary, Alert, AlertSeverity


class TestReportGenerator:
    """Tests for ReportGenerator class."""
    
    def test_initialization(self, tmp_data_dir):
        """Test generator initialization."""
        generator = ReportGenerator(tmp_data_dir / "reports")
        
        assert generator.output_dir.exists()
    
    def test_generate_markdown_report(self, tmp_data_dir, sample_window_summary, sample_alert):
        """Test generating markdown report."""
        generator = ReportGenerator(tmp_data_dir / "reports")
        
        session = SessionMetadata(
            session_id="test-session",
            start_time=time.time() - 300,
            end_time=time.time(),
            interface="eth0",
            mode="live",
            packet_count=1000,
            alert_count=5,
            window_count=60,
        )
        
        windows = [sample_window_summary]
        alerts = [sample_alert]
        
        report_path = generator.generate_markdown_report(session, windows, alerts)
        
        assert report_path.exists()
        
        # Check content
        content = report_path.read_text()
        assert "# Network Traffic Analysis Report" in content
        assert "test-session" in content
        assert "eth0" in content
    
    def test_export_csv(self, tmp_data_dir, sample_window_summary):
        """Test CSV export."""
        generator = ReportGenerator(tmp_data_dir / "reports")
        windows = [sample_window_summary]
        
        csv_path = generator.export_csv(windows, "test_windows.csv")
        
        assert csv_path.exists()
        
        # Check content
        content = csv_path.read_text()
        lines = content.strip().split("\n")
        assert len(lines) == 2  # Header + 1 data row
        assert "packet_count" in lines[0]
    
    def test_export_alerts_csv(self, tmp_data_dir, sample_alert):
        """Test alerts CSV export."""
        generator = ReportGenerator(tmp_data_dir / "reports")
        alerts = [sample_alert]
        
        csv_path = generator.export_alerts_csv(alerts, "test_alerts.csv")
        
        assert csv_path.exists()
    
    def test_export_json(self, tmp_data_dir, sample_window_summary, sample_alert):
        """Test JSON export."""
        generator = ReportGenerator(tmp_data_dir / "reports")
        
        session = SessionMetadata(
            session_id="test-session",
            start_time=time.time(),
            interface="eth0",
        )
        
        json_path = generator.export_json(
            session, 
            [sample_window_summary], 
            [sample_alert],
            "test_data.json"
        )
        
        assert json_path.exists()
        
        import json
        with open(json_path) as f:
            data = json.load(f)
        
        assert "session" in data
        assert "windows" in data
        assert "alerts" in data
    
    def test_format_duration(self, tmp_data_dir):
        """Test duration formatting."""
        generator = ReportGenerator(tmp_data_dir / "reports")
        
        assert "5s" in generator._format_duration(5)
        assert "1m" in generator._format_duration(65)
        assert "1h" in generator._format_duration(3665)
    
    def test_format_bytes(self, tmp_data_dir):
        """Test bytes formatting."""
        generator = ReportGenerator(tmp_data_dir / "reports")
        
        assert "B" in generator._format_bytes(100)
        assert "KB" in generator._format_bytes(1500)
        assert "MB" in generator._format_bytes(1500000)
    
    def test_empty_windows(self, tmp_data_dir):
        """Test report with no windows."""
        generator = ReportGenerator(tmp_data_dir / "reports")
        
        session = SessionMetadata(
            session_id="empty-session",
            start_time=time.time(),
            interface="eth0",
        )
        
        report_path = generator.generate_markdown_report(session, [], [])
        
        assert report_path.exists()
    
    def test_empty_alerts(self, tmp_data_dir, sample_window_summary):
        """Test report with no alerts."""
        generator = ReportGenerator(tmp_data_dir / "reports")
        
        session = SessionMetadata(
            session_id="no-alerts-session",
            start_time=time.time(),
            interface="eth0",
        )
        
        report_path = generator.generate_markdown_report(session, [sample_window_summary], [])
        
        assert report_path.exists()
        content = report_path.read_text()
        assert "No alerts generated" in content
