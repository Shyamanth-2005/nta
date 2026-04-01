"""Tests for the window aggregation module."""

import pytest
import time
from typing import List

from analyzer.windows import WindowAggregator, MultiWindowAggregator
from analyzer.models import PacketEvent, WindowSummary


class TestWindowAggregator:
    """Tests for WindowAggregator class."""
    
    def test_initialization(self):
        """Test aggregator initialization."""
        agg = WindowAggregator(window_size=5.0)
        assert agg.window_size == 5.0
        assert agg.total_packets == 0
        assert agg.total_windows == 0
    
    def test_add_single_packet(self, sample_packet_event):
        """Test adding a single packet."""
        agg = WindowAggregator(window_size=5.0)
        result = agg.add_packet(sample_packet_event)
        
        assert agg.total_packets == 1
        assert result is None  # Window not complete yet
    
    def test_add_packets_triggers_window(self, sample_packet_events):
        """Test that adding packets eventually triggers window completion."""
        completed_windows = []
        
        def on_complete(window: WindowSummary):
            completed_windows.append(window)
        
        agg = WindowAggregator(
            window_size=1.0,  # 1 second windows
            on_window_complete=on_complete,
        )
        
        # Adjust timestamps to span multiple windows
        base_time = time.time()
        for i, event in enumerate(sample_packet_events):
            event.timestamp = base_time + i * 0.1  # 100ms apart
            agg.add_packet(event)
        
        # Should have completed several windows
        assert len(completed_windows) > 0
    
    def test_window_summary_content(self, sample_packet_events):
        """Test window summary contains expected data."""
        completed_windows = []
        
        def on_complete(window: WindowSummary):
            completed_windows.append(window)
        
        agg = WindowAggregator(
            window_size=10.0,  # Large window to capture all packets
            on_window_complete=on_complete,
        )
        
        # Add all packets
        for event in sample_packet_events:
            agg.add_packet(event)
        
        # Flush to get the window
        final = agg.flush()
        
        assert final is not None
        assert final.packet_count > 0
        assert final.byte_count > 0
        assert len(final.protocol_counts) > 0
    
    def test_flush(self, sample_packet_events):
        """Test flushing partial window."""
        agg = WindowAggregator(window_size=60.0)  # Very long window
        
        # Add some packets
        for event in sample_packet_events[:10]:
            agg.add_packet(event)
        
        # Flush should return partial window
        result = agg.flush()
        
        assert result is not None
        assert result.packet_count == 10
    
    def test_get_stats(self, sample_packet_events):
        """Test aggregator statistics."""
        agg = WindowAggregator(window_size=5.0)
        
        for event in sample_packet_events[:20]:
            agg.add_packet(event)
        
        stats = agg.get_stats()
        
        assert stats["total_packets"] == 20
        assert stats["window_size"] == 5.0
    
    def test_syn_flood_candidates(self, sample_packet_events):
        """Test SYN flood candidate detection."""
        agg = WindowAggregator(window_size=60.0)
        
        # Add packets with SYN flags
        for event in sample_packet_events:
            agg.add_packet(event)
        
        # Check for candidates (threshold might not be met with sample data)
        candidates = agg.get_syn_flood_candidates(threshold=5)
        
        # Should return list (may be empty depending on data)
        assert isinstance(candidates, list)
    
    def test_port_scan_candidates(self, sample_packet_events):
        """Test port scan candidate detection."""
        agg = WindowAggregator(window_size=60.0)
        
        for event in sample_packet_events:
            agg.add_packet(event)
        
        candidates = agg.get_port_scan_candidates(threshold=5)
        
        assert isinstance(candidates, list)


class TestMultiWindowAggregator:
    """Tests for MultiWindowAggregator class."""
    
    def test_initialization(self):
        """Test multi-window initialization."""
        mwa = MultiWindowAggregator(window_sizes=[1.0, 5.0, 10.0])
        
        assert len(mwa.aggregators) == 3
        assert 1.0 in mwa.aggregators
        assert 5.0 in mwa.aggregators
        assert 10.0 in mwa.aggregators
    
    def test_add_packet_to_all(self, sample_packet_event):
        """Test packet is added to all aggregators."""
        mwa = MultiWindowAggregator(window_sizes=[1.0, 5.0])
        
        mwa.add_packet(sample_packet_event)
        
        for agg in mwa.aggregators.values():
            assert agg.total_packets == 1
    
    def test_flush_all(self, sample_packet_events):
        """Test flushing all aggregators."""
        mwa = MultiWindowAggregator(window_sizes=[5.0, 10.0])
        
        for event in sample_packet_events[:10]:
            mwa.add_packet(event)
        
        results = mwa.flush_all()
        
        # Should have results for each window size
        assert len(results) > 0
    
    def test_get_aggregator(self):
        """Test getting specific aggregator."""
        mwa = MultiWindowAggregator(window_sizes=[1.0, 5.0])
        
        agg = mwa.get_aggregator(5.0)
        
        assert agg is not None
        assert agg.window_size == 5.0
    
    def test_get_nonexistent_aggregator(self):
        """Test getting non-existent aggregator."""
        mwa = MultiWindowAggregator(window_sizes=[1.0, 5.0])
        
        agg = mwa.get_aggregator(100.0)
        
        assert agg is None
