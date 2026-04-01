"""
Window aggregation engine.

Manages time-based windows for traffic analysis:
- Tumbling windows (non-overlapping)
- Configurable window sizes
- Automatic window completion and flushing
"""

import logging
import time
from typing import Optional, Callable, List
from threading import Lock

from analyzer.models import PacketEvent, WindowSummary
from analyzer.features import FeatureExtractor, PortScanTracker, SYNTracker

logger = logging.getLogger("analyzer.windows")


class WindowAggregator:
    """
    Tumbling window aggregator for packet analysis.
    
    Collects packets into fixed-duration windows and computes
    statistical summaries when windows complete.
    """
    
    def __init__(
        self,
        window_size: float = 5.0,
        on_window_complete: Optional[Callable[[WindowSummary], None]] = None,
    ):
        """
        Initialize window aggregator.
        
        Args:
            window_size: Window duration in seconds
            on_window_complete: Callback when window completes
        """
        self.window_size = window_size
        self.on_window_complete = on_window_complete
        
        # Feature extractors
        self.feature_extractor = FeatureExtractor()
        self.port_tracker = PortScanTracker()
        self.syn_tracker = SYNTracker()
        
        # Window state
        self.window_start: Optional[float] = None
        self.window_end: Optional[float] = None
        self.completed_windows: List[WindowSummary] = []
        
        # Thread safety
        self._lock = Lock()
        
        # Statistics
        self.total_packets = 0
        self.total_windows = 0
    
    def add_packet(self, event: PacketEvent) -> Optional[WindowSummary]:
        """
        Add a packet to the current window.
        
        If the packet's timestamp exceeds the current window,
        the window is completed and a new one starts.
        
        Args:
            event: Parsed packet event
            
        Returns:
            Optional[WindowSummary]: Completed window summary if window closed
        """
        with self._lock:
            completed = None
            
            # Initialize window on first packet
            if self.window_start is None:
                self._start_new_window(event.timestamp)
            
            # Check if packet belongs to current window
            if event.timestamp >= self.window_end:
                # Complete current window
                completed = self._complete_window()
                # Start new window
                self._start_new_window(event.timestamp)
            
            # Add packet to current window
            self._add_to_window(event)
            self.total_packets += 1
            
            return completed
    
    def _start_new_window(self, timestamp: float) -> None:
        """Start a new window at the given timestamp."""
        # Align to window boundaries
        self.window_start = (timestamp // self.window_size) * self.window_size
        self.window_end = self.window_start + self.window_size
        
        # Reset extractors
        self.feature_extractor.reset()
        self.port_tracker.reset()
        self.syn_tracker.reset()
        
        logger.debug(f"Started new window: {self.window_start:.2f} - {self.window_end:.2f}")
    
    def _add_to_window(self, event: PacketEvent) -> None:
        """Add packet to current window's extractors."""
        self.feature_extractor.add_packet(event)
        self.port_tracker.add_packet(event)
        
        # Track SYN packets
        if event.tcp_flags and "SYN" in event.tcp_flags.upper() and "ACK" not in event.tcp_flags.upper():
            self.syn_tracker.add_syn(event.src_ip)
    
    def _complete_window(self) -> WindowSummary:
        """Complete the current window and return summary."""
        summary = self.feature_extractor.compute_window_summary(
            self.window_start,
            self.window_end,
        )
        
        self.completed_windows.append(summary)
        self.total_windows += 1
        
        # Invoke callback
        if self.on_window_complete:
            try:
                self.on_window_complete(summary)
            except Exception as e:
                logger.error(f"Window callback error: {e}")
        
        logger.debug(f"Completed window with {summary.packet_count} packets")
        return summary
    
    def flush(self) -> Optional[WindowSummary]:
        """
        Force completion of current window.
        
        Call this when stopping capture to get the final partial window.
        
        Returns:
            Optional[WindowSummary]: Current window summary if any packets
        """
        with self._lock:
            if self.window_start is not None and self.feature_extractor.packet_count > 0:
                # Use current time as window end for partial window
                actual_end = time.time()
                summary = self.feature_extractor.compute_window_summary(
                    self.window_start,
                    min(actual_end, self.window_end),
                )
                self.completed_windows.append(summary)
                self.total_windows += 1
                
                if self.on_window_complete:
                    try:
                        self.on_window_complete(summary)
                    except Exception as e:
                        logger.error(f"Window callback error: {e}")
                
                # Reset state
                self.window_start = None
                self.window_end = None
                self.feature_extractor.reset()
                
                return summary
            
            return None
    
    def get_port_scan_candidates(self, threshold: int = 15) -> List[tuple]:
        """Get current port scan candidates from port tracker."""
        with self._lock:
            return self.port_tracker.get_vertical_scan_candidates(threshold)
    
    def get_syn_flood_candidates(self, threshold: int = 100) -> List[tuple]:
        """Get current SYN flood candidates from SYN tracker."""
        with self._lock:
            return self.syn_tracker.get_flood_candidates(threshold)
    
    def get_stats(self) -> dict:
        """Get aggregator statistics."""
        return {
            "total_packets": self.total_packets,
            "total_windows": self.total_windows,
            "window_size": self.window_size,
            "current_window_start": self.window_start,
            "current_window_packets": self.feature_extractor.packet_count if self.feature_extractor else 0,
        }
    
    def get_recent_windows(self, count: int = 10) -> List[WindowSummary]:
        """Get most recent completed windows."""
        return self.completed_windows[-count:]


class MultiWindowAggregator:
    """
    Manages multiple window sizes simultaneously.
    
    Useful for detecting patterns at different time scales.
    """
    
    def __init__(
        self,
        window_sizes: List[float] = [1.0, 5.0, 10.0],
        on_window_complete: Optional[Callable[[float, WindowSummary], None]] = None,
    ):
        """
        Initialize multi-window aggregator.
        
        Args:
            window_sizes: List of window durations in seconds
            on_window_complete: Callback (window_size, summary) when window completes
        """
        self.aggregators = {}
        self.on_window_complete = on_window_complete
        
        for size in window_sizes:
            self.aggregators[size] = WindowAggregator(
                window_size=size,
                on_window_complete=lambda s, ws=size: self._handle_complete(ws, s),
            )
    
    def _handle_complete(self, window_size: float, summary: WindowSummary) -> None:
        """Handle window completion from child aggregator."""
        if self.on_window_complete:
            self.on_window_complete(window_size, summary)
    
    def add_packet(self, event: PacketEvent) -> None:
        """Add packet to all window aggregators."""
        for aggregator in self.aggregators.values():
            aggregator.add_packet(event)
    
    def flush_all(self) -> dict:
        """
        Flush all aggregators.
        
        Returns:
            Dict mapping window_size to final summary
        """
        results = {}
        for size, aggregator in self.aggregators.items():
            summary = aggregator.flush()
            if summary:
                results[size] = summary
        return results
    
    def get_aggregator(self, window_size: float) -> Optional[WindowAggregator]:
        """Get aggregator for specific window size."""
        return self.aggregators.get(window_size)
