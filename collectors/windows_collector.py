import re
import platform
from datetime import datetime
from typing import Generator, Optional, Dict, Any
from dataclasses import dataclass
import logging

if platform.system() == "Windows":
    import win32evtlog
    import win32evtlogutil
    import win32con
    import pywintypes
    WINDOWS_AVAILABLE = True
else:
    WINDOWS_AVAILABLE = False

logger = logging.getLogger(__name__)


# Windows Security Event IDs of interest
SECURITY_EVENT_IDS = {
    # Logon events
    4624: "successful_login",
    4625: "failed_login",
    4634: "logoff",
    4647: "user_initiated_logoff",
    4648: "explicit_credentials_logon",
    4672: "special_privileges_assigned",
    
    # Account management
    4720: "user_account_created",
    4722: "user_account_enabled",
    4723: "password_change_attempt",
    4724: "password_reset_attempt",
    4725: "user_account_disabled",
    4726: "user_account_deleted",
    4738: "user_account_changed",
    4740: "user_account_locked",
    
    # Privilege use
    4673: "privileged_service_called",
    4674: "privileged_object_operation",
    
    # Process tracking
    4688: "process_created",
    4689: "process_terminated",
    
    # Object access
    4663: "object_access_attempt",
    4656: "handle_requested",
    
    # System events
    1102: "audit_log_cleared",
    4616: "system_time_changed",
    4697: "service_installed",
}


@dataclass
class WindowsEvent:
    """Represents a parsed Windows event."""
    event_id: int
    event_type: str
    timestamp: datetime
    source_name: str
    computer_name: str
    username: Optional[str]
    domain: Optional[str]
    source_ip: Optional[str]
    logon_type: Optional[int]
    message: str
    raw_xml: str


class WindowsLogCollector:
    """Collects and parses Windows Event Logs."""
    
    # Logon type descriptions
    LOGON_TYPES = {
        2: "Interactive",
        3: "Network",
        4: "Batch",
        5: "Service",
        7: "Unlock",
        8: "NetworkCleartext",
        9: "NewCredentials",
        10: "RemoteInteractive",
        11: "CachedInteractive",
    }
    
    def __init__(self, channels: list = None):
        if not WINDOWS_AVAILABLE:
            raise RuntimeError("Windows Event Log API not available on this platform")
        
        self.channels = channels or ["Security", "System", "Application"]
        self._last_record_numbers: Dict[str, int] = {}
        self.errors: list = []
        
        # Regex patterns for parsing event messages
        self._ip_pattern = re.compile(
            r'Source Network Address:\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
        )
        self._username_pattern = re.compile(
            r'Account Name:\s*(\S+)'
        )
        self._domain_pattern = re.compile(
            r'Account Domain:\s*(\S+)'
        )
        self._logon_type_pattern = re.compile(
            r'Logon Type:\s*(\d+)'
        )
    
    def collect_events(self, max_events: int = 100) -> Generator[WindowsEvent, None, None]:
        """Collect new events from all configured channels."""
        for channel in self.channels:
            try:
                yield from self._collect_from_channel(channel, max_events)
            except Exception as e:
                logger.error(f"Error collecting from channel {channel}: {e}")
    
    def _collect_from_channel(
        self, 
        channel: str, 
        max_events: int
    ) -> Generator[WindowsEvent, None, None]:
        """Collect events from a specific channel."""
        try:
            handle = win32evtlog.OpenEventLog(None, channel)
        except pywintypes.error as e:
            msg = f"Cannot open event log {channel}: {e}"
            logger.error(msg)
            if msg not in self.errors:
                self.errors.append(msg)
            return
        
        try:
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events_read = 0
            
            while events_read < max_events:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events:
                    break
                
                for event in events:
                    if events_read >= max_events:
                        break
                    
                    # Skip if we've already processed this event
                    record_num = event.RecordNumber
                    last_record = self._last_record_numbers.get(channel, 0)
                    
                    if record_num <= last_record:
                        continue
                    
                    self._last_record_numbers[channel] = max(
                        last_record, record_num
                    )
                    
                    parsed = self._parse_event(event, channel)
                    if parsed:
                        yield parsed
                        events_read += 1
        
        finally:
            win32evtlog.CloseEventLog(handle)
    
    def _parse_event(self, event, channel: str) -> Optional[WindowsEvent]:
        """Parse a Windows event into our format."""
        event_id = event.EventID & 0xFFFF  # Mask to get actual event ID
        
        # For Security log, focus on known event IDs
        if channel == "Security" and event_id not in SECURITY_EVENT_IDS:
            return None
        
        # Get event message
        try:
            message = win32evtlogutil.SafeFormatMessage(event, channel)
        except Exception:
            message = str(event.StringInserts) if event.StringInserts else ""
        
        # Extract fields from message
        source_ip = self._extract_ip(message)
        username = self._extract_username(message, event)
        domain = self._extract_domain(message)
        logon_type = self._extract_logon_type(message)
        
        # Determine event type
        event_type = SECURITY_EVENT_IDS.get(event_id, f"event_{event_id}")
        
        return WindowsEvent(
            event_id=event_id,
            event_type=event_type,
            timestamp=datetime.fromtimestamp(event.TimeGenerated.timestamp()),
            source_name=event.SourceName,
            computer_name=event.ComputerName,
            username=username,
            domain=domain,
            source_ip=source_ip,
            logon_type=logon_type,
            message=message[:2000],  # Truncate long messages
            raw_xml=str(event.StringInserts) if event.StringInserts else ""
        )
    
    def _extract_ip(self, message: str) -> Optional[str]:
        """Extract source IP from event message."""
        match = self._ip_pattern.search(message)
        if match:
            ip = match.group(1)
            # Filter out local/invalid IPs
            if ip not in ('-', '127.0.0.1', '::1', '0.0.0.0'):
                return ip
        return None
    
    def _extract_username(self, message: str, event) -> Optional[str]:
        """Extract username from event."""
        # Try string inserts first
        if event.StringInserts and len(event.StringInserts) > 5:
            username = event.StringInserts[5]
            if username and username != '-':
                return username
        
        # Fall back to regex
        match = self._username_pattern.search(message)
        if match:
            username = match.group(1)
            if username not in ('-', 'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'):
                return username
        return None
    
    def _extract_domain(self, message: str) -> Optional[str]:
        """Extract domain from event message."""
        match = self._domain_pattern.search(message)
        return match.group(1) if match else None
    
    def _extract_logon_type(self, message: str) -> Optional[int]:
        """Extract logon type from event message."""
        match = self._logon_type_pattern.search(message)
        return int(match.group(1)) if match else None
    
    def get_logon_type_description(self, logon_type: int) -> str:
        """Get human-readable logon type description."""
        return self.LOGON_TYPES.get(logon_type, f"Unknown ({logon_type})")
