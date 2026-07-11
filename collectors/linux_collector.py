import re
import os
from datetime import datetime
from typing import Generator, Optional, Dict, List
from dataclasses import dataclass
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


@dataclass
class LinuxLogEvent:
    """Represents a parsed Linux log event."""
    timestamp: datetime
    hostname: str
    service: str
    pid: Optional[int]
    event_type: str
    username: Optional[str]
    source_ip: Optional[str]
    message: str
    raw_line: str
    log_file: str


class LinuxLogCollector:
    """Collects and parses Linux system logs."""
    
    # Common syslog timestamp formats
    TIMESTAMP_FORMATS = [
        "%b %d %H:%M:%S",  # Standard syslog: "Jun 11 14:30:00"
        "%Y-%m-%dT%H:%M:%S",  # ISO format
        "%Y-%m-%d %H:%M:%S",  # Alternative
    ]
    
    # Patterns for different log types
    PATTERNS = {
        'syslog': re.compile(
            r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<hostname>\S+)\s+'
            r'(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
            r'(?P<message>.+)$'
        ),
        'auth_failed': re.compile(
            r'Failed (?P<method>password|publickey) for '
            r'(?:invalid user )?(?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
        ),
        'auth_success': re.compile(
            r'Accepted (?P<method>password|publickey) for '
            r'(?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
        ),
        'auth_invalid_user': re.compile(
            r'Invalid user (?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
        ),
        'sudo': re.compile(
            r'(?P<username>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)$'
        ),
        'sudo_failed': re.compile(
            r'(?P<username>\S+)\s*:\s*.*authentication failure'
        ),
        'session_opened': re.compile(
            r'session opened for user (?P<username>\S+)'
        ),
        'session_closed': re.compile(
            r'session closed for user (?P<username>\S+)'
        ),
        'ip_address': re.compile(
            r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        ),
    }
    
    def __init__(self, log_paths: List[str] = None):
        self.log_paths = log_paths or [
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/syslog",
        ]
        self._file_positions: Dict[str, int] = {}
        self._current_year = datetime.now().year
    
    def collect_events(self, max_events: int = 100) -> Generator[LinuxLogEvent, None, None]:
        """Collect new events from all configured log files."""
        events_collected = 0
        
        for log_path in self.log_paths:
            if events_collected >= max_events:
                break
            
            if not os.path.exists(log_path):
                continue
            
            try:
                for event in self._read_log_file(log_path, max_events - events_collected):
                    yield event
                    events_collected += 1
            except Exception as e:
                logger.error(f"Error reading {log_path}: {e}")
    
    def _read_log_file(
        self, 
        log_path: str, 
        max_events: int
    ) -> Generator[LinuxLogEvent, None, None]:
        """Read new lines from a log file."""
        # Get last read position
        last_pos = self._file_positions.get(log_path, 0)
        
        # Check if file was rotated (smaller than last position)
        try:
            current_size = os.path.getsize(log_path)
            if current_size < last_pos:
                last_pos = 0
        except OSError:
            return
        
        events_read = 0
        
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            f.seek(last_pos)
            
            for line in f:
                if events_read >= max_events:
                    break
                
                line = line.strip()
                if not line:
                    continue
                
                event = self._parse_line(line, log_path)
                if event:
                    yield event
                    events_read += 1
            
            # Save current position
            self._file_positions[log_path] = f.tell()
    
    def _parse_line(self, line: str, log_path: str) -> Optional[LinuxLogEvent]:
        """Parse a log line into a structured event."""
        # Try to match syslog format
        match = self.PATTERNS['syslog'].match(line)
        if not match:
            return None
        
        groups = match.groupdict()
        
        # Parse timestamp
        timestamp = self._parse_timestamp(groups['timestamp'])
        if not timestamp:
            return None
        
        # Determine event type and extract details
        message = groups['message']
        event_type, username, source_ip = self._classify_event(message)
        
        return LinuxLogEvent(
            timestamp=timestamp,
            hostname=groups['hostname'],
            service=groups['service'],
            pid=int(groups['pid']) if groups['pid'] else None,
            event_type=event_type,
            username=username,
            source_ip=source_ip,
            message=message[:2000],
            raw_line=line,
            log_file=log_path
        )
    
    def _parse_timestamp(self, ts_string: str) -> Optional[datetime]:
        """Parse timestamp string to datetime."""
        for fmt in self.TIMESTAMP_FORMATS:
            try:
                dt = datetime.strptime(ts_string, fmt)
                # Syslog format doesn't include year
                if dt.year == 1900:
                    dt = dt.replace(year=self._current_year)
                return dt
            except ValueError:
                continue
        return None
    
    def _classify_event(self, message: str) -> tuple:
        """Classify event type and extract username/IP."""
        username = None
        source_ip = None
        
        # Check for authentication failures
        match = self.PATTERNS['auth_failed'].search(message)
        if match:
            return (
                "failed_login",
                match.group('username'),
                match.group('ip')
            )
        
        # Check for successful authentication
        match = self.PATTERNS['auth_success'].search(message)
        if match:
            return (
                "successful_login",
                match.group('username'),
                match.group('ip')
            )
        
        # Check for invalid user attempts
        match = self.PATTERNS['auth_invalid_user'].search(message)
        if match:
            return (
                "invalid_user",
                match.group('username'),
                match.group('ip')
            )
        
        # Check for sudo commands
        match = self.PATTERNS['sudo'].search(message)
        if match:
            return (
                "sudo_command",
                match.group('username'),
                None
            )
        
        # Check for sudo failures
        match = self.PATTERNS['sudo_failed'].search(message)
        if match:
            return (
                "sudo_failure",
                match.group('username'),
                None
            )
        
        # Check for session events
        match = self.PATTERNS['session_opened'].search(message)
        if match:
            return ("session_opened", match.group('username'), None)
        
        match = self.PATTERNS['session_closed'].search(message)
        if match:
            return ("session_closed", match.group('username'), None)
        
        # Try to extract IP from message
        ip_match = self.PATTERNS['ip_address'].search(message)
        if ip_match:
            source_ip = ip_match.group(1)
        
        # Generic event
        return ("generic", username, source_ip)
