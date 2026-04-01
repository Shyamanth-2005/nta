"""Tests for the baseline module."""

import pytest
import time
from pathlib import Path

from analyzer.baseline import BaselineStatistics, BaselineBuilder, BaselineManager
from analyzer.models import WindowSummary


class TestBaselineStatistics:
    """Tests for BaselineStatistics dataclass."""
    
    def test_creation(self):
        """Test creating baseline statistics."""
        stats = BaselineStatistics(
            mean_pps=100.0,
            std_pps=10.0,
            mean_bps=10000.0,
            std_bps=1000.0,
        )
        
        assert stats.mean_pps == 100.0
        assert stats.std_pps == 10.0
    
    def test_to_dict(self):
        """Test converting to dictionary."""
        stats = BaselineStatistics(mean_pps=100.0)
        
        data = stats.to_dict()
        
        assert isinstance(data, dict)
        assert data["mean_pps"] == 100.0
    
    def test_to_json(self):
        """Test converting to JSON."""
        stats = BaselineStatistics(mean_pps=100.0)
        
        json_str = stats.to_json()
        
        assert isinstance(json_str, str)
        assert "mean_pps" in json_str
    
    def test_from_dict(self):
        """Test creating from dictionary."""
        data = {
            "mean_pps": 50.0,
            "std_pps": 5.0,
            "mean_bps": 5000.0,
            "std_bps": 500.0,
            "mean_packet_size": 200.0,
            "std_packet_size": 20.0,
            "protocol_distribution": {"TCP": 0.7, "UDP": 0.3},
            "mean_unique_src_ips": 10.0,
            "std_unique_src_ips": 2.0,
            "mean_unique_dst_ips": 5.0,
            "std_unique_dst_ips": 1.0,
            "mean_unique_dst_ports": 15.0,
            "std_unique_dst_ports": 3.0,
            "mean_syn_count": 20.0,
            "std_syn_count": 4.0,
            "mean_dst_ip_entropy": 2.0,
            "std_dst_ip_entropy": 0.5,
            "window_count": 10,
            "created_at": time.time(),
            "profile_name": "test",
            "interface": "eth0",
        }
        
        stats = BaselineStatistics.from_dict(data)
        
        assert stats.mean_pps == 50.0
        assert stats.profile_name == "test"


class TestBaselineBuilder:
    """Tests for BaselineBuilder class."""
    
    def test_initialization(self):
        """Test builder initialization."""
        builder = BaselineBuilder(min_windows=5)
        
        assert builder.min_windows == 5
        assert builder.window_count == 0
    
    def test_add_window(self, sample_window_summary):
        """Test adding window."""
        builder = BaselineBuilder()
        
        builder.add_window(sample_window_summary)
        
        assert builder.window_count == 1
    
    def test_is_ready(self, sample_window_summary):
        """Test readiness check."""
        builder = BaselineBuilder(min_windows=3)
        
        assert not builder.is_ready
        
        for _ in range(3):
            builder.add_window(sample_window_summary)
        
        assert builder.is_ready
    
    def test_build_insufficient_data(self, sample_window_summary):
        """Test building with insufficient data."""
        builder = BaselineBuilder(min_windows=10)
        builder.add_window(sample_window_summary)
        
        baseline = builder.build()
        
        assert baseline is None
    
    def test_build_success(self, sample_window_summary):
        """Test successful build."""
        builder = BaselineBuilder(min_windows=3)
        
        for i in range(5):
            # Create variation
            window = WindowSummary(
                window_start=time.time() + i * 5,
                window_end=time.time() + (i + 1) * 5,
                packet_count=100 + i * 10,
                byte_count=10000 + i * 1000,
                packets_per_second=20.0 + i,
                bytes_per_second=2000.0 + i * 100,
                unique_src_ips=5 + i,
                unique_dst_ips=3,
                unique_dst_ports=10,
                protocol_counts={"TCP": 70, "UDP": 30},
                syn_count=10,
                dst_ip_entropy=1.5,
            )
            builder.add_window(window)
        
        baseline = builder.build("test_profile", "eth0")
        
        assert baseline is not None
        assert baseline.window_count == 5
        assert baseline.profile_name == "test_profile"
        assert baseline.mean_pps > 0
    
    def test_reset(self, sample_window_summary):
        """Test builder reset."""
        builder = BaselineBuilder()
        builder.add_window(sample_window_summary)
        
        builder.reset()
        
        assert builder.window_count == 0


class TestBaselineManager:
    """Tests for BaselineManager class."""
    
    def test_initialization(self, tmp_data_dir):
        """Test manager initialization."""
        manager = BaselineManager(tmp_data_dir / "baselines")
        
        assert manager.baselines_dir.exists()
    
    def test_save_and_load_baseline(self, tmp_data_dir):
        """Test saving and loading baseline."""
        manager = BaselineManager(tmp_data_dir / "baselines")
        
        baseline = BaselineStatistics(
            mean_pps=100.0,
            std_pps=10.0,
            window_count=10,
            created_at=time.time(),
            profile_name="test_save",
        )
        
        # Save
        path = manager.save_baseline(baseline)
        assert path.exists()
        
        # Load
        loaded = manager.load_baseline("test_save")
        assert loaded is not None
        assert loaded.mean_pps == 100.0
    
    def test_list_baselines(self, tmp_data_dir):
        """Test listing baselines."""
        manager = BaselineManager(tmp_data_dir / "baselines")
        
        # Create some baselines
        for name in ["baseline1", "baseline2"]:
            baseline = BaselineStatistics(
                profile_name=name,
                created_at=time.time(),
            )
            manager.save_baseline(baseline)
        
        baselines = manager.list_baselines()
        
        assert "baseline1" in baselines
        assert "baseline2" in baselines
    
    def test_delete_baseline(self, tmp_data_dir):
        """Test deleting baseline."""
        manager = BaselineManager(tmp_data_dir / "baselines")
        
        baseline = BaselineStatistics(
            profile_name="to_delete",
            created_at=time.time(),
        )
        manager.save_baseline(baseline)
        
        result = manager.delete_baseline("to_delete")
        
        assert result is True
        assert "to_delete" not in manager.list_baselines()
    
    def test_set_current(self, tmp_data_dir):
        """Test setting current baseline."""
        manager = BaselineManager(tmp_data_dir / "baselines")
        
        baseline = BaselineStatistics(
            profile_name="current_test",
            mean_pps=50.0,
            created_at=time.time(),
        )
        manager.save_baseline(baseline)
        
        result = manager.set_current("current_test")
        
        assert result is True
        assert manager.current_baseline is not None
        assert manager.current_baseline.mean_pps == 50.0
    
    def test_compare_window(self, tmp_data_dir, sample_window_summary):
        """Test comparing window against baseline."""
        manager = BaselineManager(tmp_data_dir / "baselines")
        
        baseline = BaselineStatistics(
            profile_name="compare_test",
            mean_pps=20.0,
            std_pps=5.0,
            mean_bps=2000.0,
            std_bps=500.0,
            mean_packet_size=100.0,
            std_packet_size=20.0,
            mean_syn_count=10.0,
            std_syn_count=3.0,
            mean_dst_ip_entropy=1.5,
            std_dst_ip_entropy=0.3,
            created_at=time.time(),
        )
        manager.save_baseline(baseline)
        manager.set_current("compare_test")
        
        comparison = manager.compare_window(sample_window_summary)
        
        assert "deviations" in comparison
        assert "anomalies" in comparison
        assert "pps" in comparison["deviations"]
    
    def test_training_workflow(self, tmp_data_dir, sample_window_summary):
        """Test complete training workflow."""
        manager = BaselineManager(tmp_data_dir / "baselines")
        
        # Start training
        manager.start_training(min_windows=3)
        
        # Add windows
        for _ in range(3):
            ready = manager.add_training_window(sample_window_summary)
        
        assert ready is True
        
        # Complete training
        baseline = manager.complete_training("workflow_test", "eth0")
        
        assert baseline is not None
        assert baseline.profile_name == "workflow_test"
        assert manager.current_baseline == baseline
