import sqlite3
import hashlib
from datetime import datetime
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
import threading

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False


class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ThreatType(Enum):
    BRUTE_FORCE = "brute_force"
    FAILED_LOGIN = "failed_login"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PORT_SCAN = "port_scan"
    SUSPICIOUS_PROCESS = "suspicious_process"
    MALWARE_INDICATOR = "malware_indicator"
    ANOMALY = "anomaly"


@dataclass
class LogEvent:
    id: Optional[int]
    timestamp: datetime
    source: str  # "windows" or "linux"
    hostname: str
    event_type: str
    event_id: Optional[int]
    username: Optional[str]
    source_ip: Optional[str]
    message: str
    raw_data: str
    hash: str
    
    @staticmethod
    def compute_hash(raw_data: str) -> str:
        return hashlib.sha256(raw_data.encode()).hexdigest()


@dataclass
class ThreatAlert:
    id: Optional[int]
    timestamp: datetime
    threat_type: ThreatType
    severity: Severity
    source_ip: Optional[str]
    target_user: Optional[str]
    hostname: str
    description: str
    event_count: int
    acknowledged: bool = False
    related_event_ids: List[int] = None


class Database:
    """Database abstraction layer supporting SQLite and PostgreSQL."""
    
    _local = threading.local()
    
    def __init__(self, config):
        self.config = config
        self.db_type = config.type
        self._init_schema()
    
    @contextmanager
    def get_connection(self):
        """Get database connection (thread-safe)."""
        if self.db_type == "sqlite":
            if not hasattr(self._local, 'connection') or self._local.connection is None:
                self._local.connection = sqlite3.connect(
                    str(self.config.sqlite_path),
                    check_same_thread=False
                )
                self._local.connection.row_factory = sqlite3.Row
            yield self._local.connection
        else:
            if not POSTGRES_AVAILABLE:
                raise ImportError("psycopg2 required for PostgreSQL support")
            conn = psycopg2.connect(
                host=self.config.pg_host,
                port=self.config.pg_port,
                database=self.config.pg_database,
                user=self.config.pg_user,
                password=self.config.pg_password,
                cursor_factory=RealDictCursor
            )
            try:
                yield conn
            finally:
                conn.close()
    
    def _init_schema(self):
        """Initialize database schema."""
        schema = """
        CREATE TABLE IF NOT EXISTS log_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP NOT NULL,
            source VARCHAR(20) NOT NULL,
            hostname VARCHAR(255) NOT NULL,
            event_type VARCHAR(100) NOT NULL,
            event_id INTEGER,
            username VARCHAR(255),
            source_ip VARCHAR(45),
            message TEXT,
            raw_data TEXT,
            hash VARCHAR(64) UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS threat_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP NOT NULL,
            threat_type VARCHAR(50) NOT NULL,
            severity INTEGER NOT NULL,
            source_ip VARCHAR(45),
            target_user VARCHAR(255),
            hostname VARCHAR(255) NOT NULL,
            description TEXT,
            event_count INTEGER DEFAULT 1,
            acknowledged BOOLEAN DEFAULT FALSE,
            related_event_ids TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS statistics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stat_date DATE NOT NULL,
            stat_hour INTEGER,
            total_events INTEGER DEFAULT 0,
            failed_logins INTEGER DEFAULT 0,
            successful_logins INTEGER DEFAULT 0,
            threats_detected INTEGER DEFAULT 0,
            unique_source_ips INTEGER DEFAULT 0,
            UNIQUE(stat_date, stat_hour)
        );
        
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON log_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_source_ip ON log_events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_events_username ON log_events(username);
        CREATE INDEX IF NOT EXISTS idx_events_type ON log_events(event_type);
        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON threat_alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_type ON threat_alerts(threat_type);
        """
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            for statement in schema.split(';'):
                if statement.strip():
                    cursor.execute(statement)
            conn.commit()
    
    def insert_event(self, event: LogEvent) -> Optional[int]:
        """Insert a log event, returns ID or None if duplicate."""
        sql = """
        INSERT OR IGNORE INTO log_events 
        (timestamp, source, hostname, event_type, event_id, username, 
         source_ip, message, raw_data, hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (
                event.timestamp, event.source, event.hostname,
                event.event_type, event.event_id, event.username,
                event.source_ip, event.message, event.raw_data, event.hash
            ))
            conn.commit()
            return cursor.lastrowid if cursor.rowcount > 0 else None
    
    def insert_alert(self, alert: ThreatAlert) -> int:
        """Insert a threat alert."""
        sql = """
        INSERT INTO threat_alerts 
        (timestamp, threat_type, severity, source_ip, target_user,
         hostname, description, event_count, related_event_ids)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        related_ids = ','.join(map(str, alert.related_event_ids or []))
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (
                alert.timestamp, alert.threat_type.value, alert.severity.value,
                alert.source_ip, alert.target_user, alert.hostname,
                alert.description, alert.event_count, related_ids
            ))
            conn.commit()
            return cursor.lastrowid
    
    def get_recent_events_by_ip(
        self, 
        source_ip: str, 
        event_type: str,
        window_seconds: int
    ) -> List[Dict]:
        """Get recent events from a specific IP."""
        sql = """
        SELECT * FROM log_events 
        WHERE source_ip = ? 
        AND event_type = ?
        AND timestamp >= datetime('now', ?)
        ORDER BY timestamp DESC
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (source_ip, event_type, f'-{window_seconds} seconds'))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_recent_events_by_user(
        self,
        username: str,
        event_type: str,
        window_seconds: int
    ) -> List[Dict]:
        """Get recent events for a specific user."""
        sql = """
        SELECT * FROM log_events 
        WHERE username = ? 
        AND event_type = ?
        AND timestamp >= datetime('now', ?)
        ORDER BY timestamp DESC
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (username, event_type, f'-{window_seconds} seconds'))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_statistics(self, days: int = 7) -> Dict[str, Any]:
        """Get aggregated statistics for dashboard."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Total events
            cursor.execute("""
                SELECT COUNT(*) as total FROM log_events 
                WHERE timestamp >= datetime('now', ?)
            """, (f'-{days} days',))
            total_events = cursor.fetchone()['total']
            
            # Events by type
            cursor.execute("""
                SELECT event_type, COUNT(*) as count FROM log_events 
                WHERE timestamp >= datetime('now', ?)
                GROUP BY event_type ORDER BY count DESC
            """, (f'-{days} days',))
            events_by_type = {row['event_type']: row['count'] for row in cursor.fetchall()}
            
            # Alerts by severity
            cursor.execute("""
                SELECT severity, COUNT(*) as count FROM threat_alerts 
                WHERE timestamp >= datetime('now', ?)
                GROUP BY severity
            """, (f'-{days} days',))
            alerts_by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}
            
            # Top source IPs
            cursor.execute("""
                SELECT source_ip, COUNT(*) as count FROM log_events 
                WHERE source_ip IS NOT NULL
                AND timestamp >= datetime('now', ?)
                GROUP BY source_ip ORDER BY count DESC LIMIT 10
            """, (f'-{days} days',))
            top_ips = [(row['source_ip'], row['count']) for row in cursor.fetchall()]
            
            # Events per hour (last 24h)
            cursor.execute("""
                SELECT strftime('%H', timestamp) as hour, COUNT(*) as count 
                FROM log_events 
                WHERE timestamp >= datetime('now', '-1 day')
                GROUP BY hour ORDER BY hour
            """)
            events_per_hour = {row['hour']: row['count'] for row in cursor.fetchall()}
            
            # Recent alerts
            cursor.execute("""
                SELECT * FROM threat_alerts 
                WHERE timestamp >= datetime('now', ?)
                ORDER BY timestamp DESC LIMIT 20
            """, (f'-{days} days',))
            recent_alerts = [dict(row) for row in cursor.fetchall()]
            
            return {
                'total_events': total_events,
                'events_by_type': events_by_type,
                'alerts_by_severity': alerts_by_severity,
                'top_source_ips': top_ips,
                'events_per_hour': events_per_hour,
                'recent_alerts': recent_alerts
            }
    
    def get_alerts(
        self, 
        limit: int = 100, 
        unacknowledged_only: bool = False
    ) -> List[Dict]:
        """Get threat alerts."""
        sql = "SELECT * FROM threat_alerts"
        if unacknowledged_only:
            sql += " WHERE acknowledged = FALSE"
        sql += " ORDER BY timestamp DESC LIMIT ?"
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def acknowledge_alert(self, alert_id: int) -> bool:
        """Mark an alert as acknowledged."""
        sql = "UPDATE threat_alerts SET acknowledged = TRUE WHERE id = ?"
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, (alert_id,))
            conn.commit()
            return cursor.rowcount > 0
