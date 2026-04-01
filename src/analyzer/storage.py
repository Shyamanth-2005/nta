"""
Storage adapters for persistent data.

Supports:
- JSONL for append-only logs
- SQLite for queryable data
- File-based session storage
"""

import logging
import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
import sqlite3

from analyzer.models import WindowSummary, Alert, SessionMetadata

logger = logging.getLogger("analyzer.storage")


class JSONLStorage:
    """
    Append-only JSONL storage for streaming data.
    """
    
    def __init__(self, filepath: Path):
        """
        Initialize JSONL storage.
        
        Args:
            filepath: Path to JSONL file
        """
        self.filepath = Path(filepath)
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
    
    def append(self, data: Dict[str, Any]) -> None:
        """Append a single record."""
        with open(self.filepath, "a") as f:
            f.write(json.dumps(data) + "\n")
    
    def append_many(self, records: List[Dict[str, Any]]) -> None:
        """Append multiple records."""
        with open(self.filepath, "a") as f:
            for record in records:
                f.write(json.dumps(record) + "\n")
    
    def read_all(self) -> List[Dict[str, Any]]:
        """Read all records."""
        if not self.filepath.exists():
            return []
        
        records = []
        with open(self.filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records
    
    def count(self) -> int:
        """Count number of records."""
        if not self.filepath.exists():
            return 0
        
        with open(self.filepath, "r") as f:
            return sum(1 for _ in f)
    
    def clear(self) -> None:
        """Clear all records."""
        if self.filepath.exists():
            self.filepath.unlink()


class SessionStorage:
    """
    Manages storage for monitoring sessions.
    """
    
    def __init__(self, sessions_dir: Path):
        """
        Initialize session storage.
        
        Args:
            sessions_dir: Directory for session data
        """
        self.sessions_dir = Path(sessions_dir)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
    
    def create_session_dir(self, session_id: str) -> Path:
        """Create directory for a session."""
        session_dir = self.sessions_dir / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        return session_dir
    
    def save_metadata(self, session: SessionMetadata) -> Path:
        """Save session metadata."""
        session_dir = self.create_session_dir(session.session_id)
        filepath = session_dir / "metadata.json"
        
        with open(filepath, "w") as f:
            f.write(session.to_json())
        
        return filepath
    
    def load_metadata(self, session_id: str) -> Optional[SessionMetadata]:
        """Load session metadata."""
        filepath = self.sessions_dir / session_id / "metadata.json"
        
        if not filepath.exists():
            return None
        
        with open(filepath, "r") as f:
            data = json.load(f)
        
        return SessionMetadata(**{
            k: v for k, v in data.items()
            if k in SessionMetadata.__dataclass_fields__
        })
    
    def save_windows(self, session_id: str, windows: List[WindowSummary]) -> Path:
        """Save window summaries for a session."""
        session_dir = self.create_session_dir(session_id)
        storage = JSONLStorage(session_dir / "windows.jsonl")
        
        for window in windows:
            storage.append(window.to_dict())
        
        return session_dir / "windows.jsonl"
    
    def load_windows(self, session_id: str) -> List[WindowSummary]:
        """Load window summaries for a session."""
        filepath = self.sessions_dir / session_id / "windows.jsonl"
        storage = JSONLStorage(filepath)
        
        return [WindowSummary.from_dict(d) for d in storage.read_all()]
    
    def save_alerts(self, session_id: str, alerts: List[Alert]) -> Path:
        """Save alerts for a session."""
        session_dir = self.create_session_dir(session_id)
        storage = JSONLStorage(session_dir / "alerts.jsonl")
        
        for alert in alerts:
            storage.append(alert.to_dict())
        
        return session_dir / "alerts.jsonl"
    
    def load_alerts(self, session_id: str) -> List[Alert]:
        """Load alerts for a session."""
        filepath = self.sessions_dir / session_id / "alerts.jsonl"
        storage = JSONLStorage(filepath)
        
        return [Alert.from_dict(d) for d in storage.read_all()]
    
    def list_sessions(self) -> List[str]:
        """List all session IDs."""
        return [
            d.name for d in self.sessions_dir.iterdir()
            if d.is_dir() and (d / "metadata.json").exists()
        ]
    
    def get_latest_session(self) -> Optional[str]:
        """Get the most recent session ID."""
        sessions = []
        for session_id in self.list_sessions():
            metadata = self.load_metadata(session_id)
            if metadata:
                sessions.append((session_id, metadata.start_time))
        
        if not sessions:
            return None
        
        sessions.sort(key=lambda x: x[1], reverse=True)
        return sessions[0][0]
    
    def delete_session(self, session_id: str) -> bool:
        """Delete a session and all its data."""
        session_dir = self.sessions_dir / session_id
        
        if not session_dir.exists():
            return False
        
        import shutil
        shutil.rmtree(session_dir)
        return True


class SQLiteStorage:
    """
    SQLite storage for queryable session data.
    """
    
    def __init__(self, db_path: Path):
        """
        Initialize SQLite storage.
        
        Args:
            db_path: Path to SQLite database
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize database schema."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                start_time REAL,
                end_time REAL,
                interface TEXT,
                mode TEXT,
                packet_count INTEGER,
                alert_count INTEGER,
                window_count INTEGER,
                config TEXT
            )
        """)
        
        # Windows table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS windows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                window_start REAL,
                window_end REAL,
                packet_count INTEGER,
                byte_count INTEGER,
                packets_per_second REAL,
                bytes_per_second REAL,
                unique_src_ips INTEGER,
                unique_dst_ips INTEGER,
                unique_dst_ports INTEGER,
                syn_count INTEGER,
                ack_count INTEGER,
                rst_count INTEGER,
                dst_ip_entropy REAL,
                protocol_counts TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        """)
        
        # Alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                alert_id TEXT,
                timestamp REAL,
                severity TEXT,
                category TEXT,
                detector TEXT,
                summary TEXT,
                evidence TEXT,
                window_start REAL,
                window_end REAL,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def save_session(self, session: SessionMetadata) -> None:
        """Save session metadata."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO sessions
            (session_id, start_time, end_time, interface, mode, packet_count, alert_count, window_count, config)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session.session_id,
            session.start_time,
            session.end_time,
            session.interface,
            session.mode,
            session.packet_count,
            session.alert_count,
            session.window_count,
            json.dumps(session.config),
        ))
        
        conn.commit()
        conn.close()
    
    def save_window(self, session_id: str, window: WindowSummary) -> None:
        """Save a window summary."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO windows
            (session_id, window_start, window_end, packet_count, byte_count,
             packets_per_second, bytes_per_second, unique_src_ips, unique_dst_ips,
             unique_dst_ports, syn_count, ack_count, rst_count, dst_ip_entropy, protocol_counts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id,
            window.window_start,
            window.window_end,
            window.packet_count,
            window.byte_count,
            window.packets_per_second,
            window.bytes_per_second,
            window.unique_src_ips,
            window.unique_dst_ips,
            window.unique_dst_ports,
            window.syn_count,
            window.ack_count,
            window.rst_count,
            window.dst_ip_entropy,
            json.dumps(window.protocol_counts),
        ))
        
        conn.commit()
        conn.close()
    
    def save_alert(self, session_id: str, alert: Alert) -> None:
        """Save an alert."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO alerts
            (session_id, alert_id, timestamp, severity, category, detector, summary, evidence, window_start, window_end)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id,
            alert.alert_id,
            alert.timestamp,
            alert.severity.value,
            alert.category,
            alert.detector,
            alert.summary,
            json.dumps(alert.evidence),
            alert.window_start,
            alert.window_end,
        ))
        
        conn.commit()
        conn.close()
    
    def get_session_stats(self, session_id: str) -> Dict[str, Any]:
        """Get aggregated statistics for a session."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Get session info
        cursor.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
        session_row = cursor.fetchone()
        
        # Get window stats
        cursor.execute("""
            SELECT 
                COUNT(*) as window_count,
                SUM(packet_count) as total_packets,
                SUM(byte_count) as total_bytes,
                AVG(packets_per_second) as avg_pps,
                AVG(bytes_per_second) as avg_bps
            FROM windows WHERE session_id = ?
        """, (session_id,))
        window_stats = cursor.fetchone()
        
        # Get alert counts
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM alerts WHERE session_id = ?
            GROUP BY severity
        """, (session_id,))
        alert_counts = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            "session_id": session_id,
            "window_count": window_stats[0] or 0,
            "total_packets": window_stats[1] or 0,
            "total_bytes": window_stats[2] or 0,
            "avg_pps": window_stats[3] or 0,
            "avg_bps": window_stats[4] or 0,
            "alerts_by_severity": alert_counts,
        }
