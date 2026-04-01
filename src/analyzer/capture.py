"""
Packet capture engine.

Provides:
- Live packet capture from network interfaces
- PCAP file replay for offline analysis
- Graceful shutdown and error handling
"""

import logging
import time
import threading
from pathlib import Path
from typing import Optional, Callable, List
from queue import Queue, Empty

from scapy.all import sniff, rdpcap, Packet

from analyzer.models import PacketEvent
from analyzer.parser import PacketParser

logger = logging.getLogger("analyzer.capture")


class CaptureEngine:
    """
    Network packet capture engine.
    
    Supports both live capture and PCAP replay with unified interface.
    """
    
    def __init__(
        self,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        filter_str: Optional[str] = None,
        max_packets: Optional[int] = None,
        on_packet: Optional[Callable[[PacketEvent], None]] = None,
    ):
        """
        Initialize capture engine.
        
        Args:
            interface: Network interface for live capture
            pcap_file: PCAP file path for offline replay
            filter_str: BPF filter string
            max_packets: Maximum packets to capture
            on_packet: Callback for each parsed packet
        """
        self.interface = interface
        self.pcap_file = pcap_file
        self.filter_str = filter_str
        self.max_packets = max_packets
        self.on_packet = on_packet
        
        # State
        self._running = False
        self._stop_event = threading.Event()
        self._capture_thread: Optional[threading.Thread] = None
        
        # Parser
        self.parser = PacketParser(interface=interface or "pcap")
        
        # Statistics
        self.packets_captured = 0
        self.packets_processed = 0
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self._errors: List[str] = []
    
    @property
    def is_live(self) -> bool:
        """Check if this is live capture (vs PCAP replay)."""
        return self.pcap_file is None
    
    @property
    def is_running(self) -> bool:
        """Check if capture is currently running."""
        return self._running
    
    def start(self, blocking: bool = True) -> None:
        """
        Start packet capture.
        
        Args:
            blocking: If True, block until capture completes/stops
        """
        if self._running:
            logger.warning("Capture already running")
            return
        
        self._running = True
        self._stop_event.clear()
        self.start_time = time.time()
        
        if blocking:
            self._capture_loop()
        else:
            self._capture_thread = threading.Thread(target=self._capture_loop)
            self._capture_thread.daemon = True
            self._capture_thread.start()
    
    def stop(self) -> None:
        """Stop packet capture gracefully."""
        if not self._running:
            return
        
        logger.info("Stopping capture...")
        self._stop_event.set()
        self._running = False
        self.end_time = time.time()
        
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=5.0)
    
    def _capture_loop(self) -> None:
        """Main capture loop."""
        try:
            if self.pcap_file:
                self._replay_pcap()
            else:
                self._live_capture()
        except PermissionError:
            error = "Permission denied. Run with administrator/root privileges for packet capture."
            logger.error(error)
            self._errors.append(error)
        except Exception as e:
            error = f"Capture error: {e}"
            logger.error(error)
            self._errors.append(error)
        finally:
            self._running = False
            self.end_time = time.time()
    
    def _live_capture(self) -> None:
        """Perform live packet capture."""
        logger.info(f"Starting live capture on {self.interface}")
        
        def packet_handler(packet: Packet) -> None:
            if self._stop_event.is_set():
                return
            self._process_packet(packet)
        
        def stop_filter(packet: Packet) -> bool:
            return self._stop_event.is_set() or \
                   (self.max_packets and self.packets_captured >= self.max_packets)
        
        try:
            sniff(
                iface=self.interface,
                prn=packet_handler,
                filter=self.filter_str,
                store=False,
                stop_filter=stop_filter,
            )
        except Exception as e:
            if not self._stop_event.is_set():
                raise e
    
    def _replay_pcap(self) -> None:
        """Replay packets from PCAP file."""
        path = Path(self.pcap_file)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")
        
        logger.info(f"Replaying PCAP file: {self.pcap_file}")
        
        try:
            packets = rdpcap(str(path))
            logger.info(f"Loaded {len(packets)} packets from PCAP")
            
            for i, packet in enumerate(packets):
                if self._stop_event.is_set():
                    break
                if self.max_packets and i >= self.max_packets:
                    break
                
                self._process_packet(packet)
                
        except Exception as e:
            raise RuntimeError(f"Failed to read PCAP file: {e}")
    
    def _process_packet(self, packet: Packet) -> None:
        """Process a single captured packet."""
        self.packets_captured += 1
        
        # Parse packet
        event = self.parser.parse(packet)
        if event is None:
            return
        
        self.packets_processed += 1
        
        # Invoke callback
        if self.on_packet:
            try:
                self.on_packet(event)
            except Exception as e:
                logger.error(f"Packet callback error: {e}")
    
    def get_stats(self) -> dict:
        """Get capture statistics."""
        duration = 0.0
        if self.start_time:
            end = self.end_time or time.time()
            duration = end - self.start_time
        
        return {
            "mode": "pcap" if self.pcap_file else "live",
            "interface": self.interface,
            "pcap_file": self.pcap_file,
            "packets_captured": self.packets_captured,
            "packets_processed": self.packets_processed,
            "duration_seconds": duration,
            "packets_per_second": self.packets_captured / max(1, duration),
            "is_running": self._running,
            "errors": self._errors,
            "parser_stats": self.parser.get_stats(),
        }
    
    def get_errors(self) -> List[str]:
        """Get list of capture errors."""
        return self._errors.copy()


class BufferedCaptureEngine(CaptureEngine):
    """
    Capture engine with packet buffering for batch processing.
    """
    
    def __init__(
        self,
        batch_size: int = 100,
        on_batch: Optional[Callable[[List[PacketEvent]], None]] = None,
        **kwargs
    ):
        """
        Initialize buffered capture engine.
        
        Args:
            batch_size: Number of packets per batch
            on_batch: Callback for packet batches
            **kwargs: Arguments passed to CaptureEngine
        """
        super().__init__(**kwargs)
        self.batch_size = batch_size
        self.on_batch = on_batch
        self._buffer: List[PacketEvent] = []
        self._buffer_lock = threading.Lock()
    
    def _process_packet(self, packet: Packet) -> None:
        """Process packet into buffer."""
        self.packets_captured += 1
        
        event = self.parser.parse(packet)
        if event is None:
            return
        
        self.packets_processed += 1
        
        with self._buffer_lock:
            self._buffer.append(event)
            
            if len(self._buffer) >= self.batch_size:
                batch = self._buffer
                self._buffer = []
                self._process_batch(batch)
        
        # Also call individual callback if set
        if self.on_packet:
            try:
                self.on_packet(event)
            except Exception as e:
                logger.error(f"Packet callback error: {e}")
    
    def _process_batch(self, batch: List[PacketEvent]) -> None:
        """Process a batch of packets."""
        if self.on_batch:
            try:
                self.on_batch(batch)
            except Exception as e:
                logger.error(f"Batch callback error: {e}")
    
    def flush_buffer(self) -> List[PacketEvent]:
        """
        Flush remaining packets from buffer.
        
        Returns:
            List[PacketEvent]: Remaining buffered packets
        """
        with self._buffer_lock:
            batch = self._buffer
            self._buffer = []
            
            if batch and self.on_batch:
                try:
                    self.on_batch(batch)
                except Exception as e:
                    logger.error(f"Batch callback error: {e}")
            
            return batch
