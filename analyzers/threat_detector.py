import re
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from collections import defaultdict
import logging

from storage.database import Database, ThreatAlert, Severity, ThreatType, LogEvent

logger = logging.getLogger(__name__)


@dataclass
class DetectionRule:
    """Represents a threat detection rule."""
    name: str
    threat_type: ThreatType
    severity: Severity
    description_template: str
    
    def format_description(self, **kwargs) -> str:
        return self.description_template.format(**kwargs)


class ThreatDetector:
    """Analyzes events and detects potential security threats."""
    
    # Suspicious process patterns
    SUSPICIOUS_PROCESSES = [
        r'mimikatz',
        r'pwdump',
        r'procdump',
        r'lazagne',
        r'bloodhound',
        r'rubeus',
        r'sharphound',
        r'covenant',
        r'empire',
        r'metasploit',
        r'msfconsole',
        r'nmap',
        r'masscan',
        r'hydra',
        r'medusa',
        r'hashcat',
        r'john',
        r'nc\.exe',
        r'netcat',
        r'psexec',
        r'wmic.*process.*call.*create',
        r'powershell.*-enc',
        r'powershell.*downloadstring',
        r'powershell.*iex',
        r'certutil.*-urlcache',
        r'bitsadmin.*/transfer',
    ]
    
    # Known malicious IP patterns (example - in production, use threat intel feeds)
    MALICIOUS_IP_RANGES = [
        # Add known bad IP ranges here
    ]
    
    def __init__(self, db: Database, config):
        self.db = db
        self.config = config
        self.thresholds = config.thresholds
        
        # Compile regex patterns
        self._suspicious_process_pattern = re.compile(
            '|'.join(self.SUSPICIOUS_PROCESSES),
            re.IGNORECASE
        )
        
        # In-memory tracking for real-time detection
        self._failed_logins: Dict[str, List[datetime]] = defaultdict(list)
        self._connection_attempts: Dict[str, List[datetime]] = defaultdict(list)
    
    def analyze_event(self, event: LogEvent) -> Optional[ThreatAlert]:
        """Analyze a single event for threats."""
        alerts = []
        
        # Check for brute force
        if event.event_type in ('failed_login', 'invalid_user'):
            alert = self._check_brute_force(event)
            if alert:
                alerts.append(alert)
        
        # Check for multiple failed logins (user-based)
        if event.event_type == 'failed_login' and event.username:
            alert = self._check_failed_logins_user(event)
            if alert:
                alerts.append(alert)
        
        # Check for privilege escalation
        if event.event_type in ('sudo_command', 'sudo_failure', 
                                 'special_privileges_assigned', 'privilege_escalation'):
            alert = self._check_privilege_escalation(event)
            if alert:
                alerts.append(alert)
        
        # Check for suspicious processes
        if event.event_type == 'process_created':
            alert = self._check_suspicious_process(event)
            if alert:
                alerts.append(alert)
        
        # Check for audit log tampering
        if event.event_type == 'audit_log_cleared':
            alert = self._create_alert(
                ThreatType.ANOMALY,
                Severity.CRITICAL,
                event,
                f"Audit log cleared on {event.hostname}",
                1
            )
            alerts.append(alert)
        
        # Return the most severe alert if multiple detected
        if alerts:
            return max(alerts, key=lambda a: a.severity.value)
        return None
    
    def _check_brute_force(self, event: LogEvent) -> Optional[ThreatAlert]:
        """Detect brute force attacks based on IP."""
        if not event.source_ip:
            return None
        
        key = event.source_ip
        now = datetime.now()
        window = timedelta(seconds=self.thresholds.brute_force_window_seconds)
        
        # Clean old entries
        self._failed_logins[key] = [
            ts for ts in self._failed_logins[key]
            if now - ts < window
        ]
        
        # Add current event
        self._failed_logins[key].append(now)
        
        count = len(self._failed_logins[key])
        
        if count >= self.thresholds.brute_force_threshold:
            # Reset counter after alerting
            self._failed_logins[key] = []
            
            return self._create_alert(
                ThreatType.BRUTE_FORCE,
                Severity.HIGH,
                event,
                f"Brute force attack detected from {event.source_ip}: "
                f"{count} failed attempts in {self.thresholds.brute_force_window_seconds}s",
                count
            )
        
        return None
    
    def _check_failed_logins_user(self, event: LogEvent) -> Optional[ThreatAlert]:
        """Detect multiple failed logins for a specific user."""
        if not event.username:
            return None
        
        # Query database for recent failures
        recent = self.db.get_recent_events_by_user(
            event.username,
            'failed_login',
            self.thresholds.failed_login_window_seconds
        )
        
        count = len(recent)
        
        if count >= self.thresholds.failed_login_threshold:
            severity = Severity.MEDIUM
            if count >= self.thresholds.failed_login_threshold * 2:
                severity = Severity.HIGH
            
            return self._create_alert(
                ThreatType.FAILED_LOGIN,
                severity,
                event,
                f"Multiple failed login attempts for user '{event.username}': "
                f"{count} failures in {self.thresholds.failed_login_window_seconds}s",
                count,
                [e['id'] for e in recent]
            )
        
        return None
    
    def _check_privilege_escalation(self, event: LogEvent) -> Optional[ThreatAlert]:
        """Detect potential privilege escalation attempts."""
        message_lower = event.message.lower()
        
        # Check for suspicious keywords
        suspicious_keywords = [
            'authentication failure',
            'not in sudoers',
            'incorrect password',
            'permission denied',
        ]
        
        is_failure = any(kw in message_lower for kw in suspicious_keywords)
        
        if is_failure:
            return self._create_alert(
                ThreatType.PRIVILEGE_ESCALATION,
                Severity.MEDIUM,
                event,
                f"Failed privilege escalation attempt by '{event.username or 'unknown'}' "
                f"on {event.hostname}",
                1
            )
        
        # Successful sudo to root from unusual user might also be worth tracking
        if 'USER=root' in event.message:
            # Log for monitoring but lower severity
            return self._create_alert(
                ThreatType.PRIVILEGE_ESCALATION,
                Severity.LOW,
                event,
                f"Privilege escalation to root by '{event.username or 'unknown'}' "
                f"on {event.hostname}",
                1
            )
        
        return None
    
    def _check_suspicious_process(self, event: LogEvent) -> Optional[ThreatAlert]:
        """Detect suspicious process execution."""
        match = self._suspicious_process_pattern.search(event.message)
        
        if match:
            return self._create_alert(
                ThreatType.SUSPICIOUS_PROCESS,
                Severity.CRITICAL,
                event,
                f"Suspicious process detected on {event.hostname}: "
                f"'{match.group()}' - Full command: {event.message[:200]}",
                1
            )
        
        return None
    
    def _check_port_scan(self, event: LogEvent) -> Optional[ThreatAlert]:
        """Detect potential port scanning activity."""
        if not event.source_ip:
            return None
        
        key = f"portscan_{event.source_ip}"
        now = datetime.now()
        window = timedelta(seconds=self.thresholds.port_scan_window_seconds)
        
        self._connection_attempts[key] = [
            ts for ts in self._connection_attempts[key]
            if now - ts < window
        ]
        
        self._connection_attempts[key].append(now)
        
        count = len(self._connection_attempts[key])
        
        if count >= self.thresholds.port_scan_threshold:
            self._connection_attempts[key] = []
            
            return self._create_alert(
                ThreatType.PORT_SCAN,
                Severity.MEDIUM,
                event,
                f"Potential port scan from {event.source_ip}: "
                f"{count} connection attempts in {self.thresholds.port_scan_window_seconds}s",
                count
            )
        
        return None
    
    def _create_alert(
        self,
        threat_type: ThreatType,
        severity: Severity,
        event: LogEvent,
        description: str,
        event_count: int,
        related_ids: List[int] = None
    ) -> ThreatAlert:
        """Create a threat alert."""
        return ThreatAlert(
            id=None,
            timestamp=datetime.now(),
            threat_type=threat_type,
            severity=severity,
            source_ip=event.source_ip,
            target_user=event.username,
            hostname=event.hostname,
            description=description,
            event_count=event_count,
            related_event_ids=related_ids or []
        )
    
    def get_threat_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get summary of threats detected in the specified period."""
        stats = self.db.get_statistics(days=hours // 24 or 1)
        
        return {
            'total_events_analyzed': stats['total_events'],
            'alerts_by_severity': {
                'critical': stats['alerts_by_severity'].get(4, 0),
                'high': stats['alerts_by_severity'].get(3, 0),
                'medium': stats['alerts_by_severity'].get(2, 0),
                'low': stats['alerts_by_severity'].get(1, 0),
            },
            'top_source_ips': stats['top_source_ips'],
            'recent_alerts': stats['recent_alerts'][:10]
        }
