import asyncio
import platform
import signal
import sys
import logging
import socket
from datetime import datetime
from typing import Optional
import threading
import time

import uvicorn

from config.settings import settings, Config
from storage.database import Database, LogEvent
from analyzers.threat_detector import ThreatDetector
from alerts.notifier import AlertNotifier
from api import routes

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('soc_monitor.log')
    ]
)
logger = logging.getLogger(__name__)


def _print_startup_banner(config: Config):
    """Print startup information to console."""
    host = socket.gethostname()
    port = config.api_port
    print()
    print("=" * 58)
    print("  SOC Monitor — Security Operations Center")
    print("=" * 58)
    print(f"  Platform     : {platform.system()}")
    print(f"  Hostname       : {host}")
    print(f"  Database       : {config.database.type}")
    print(f"  Poll Interval  : {config.collector.poll_interval}s")
    print(f"  Batch Size     : {config.collector.batch_size}")
    print("-" * 58)
    print(f"  Dashboard      : http://localhost:{port}/dashboard")
    print(f"  API Docs       : http://localhost:{port}/docs")
    print(f"  Health Check   : http://localhost:{port}/api/health")
    print(f"  System Status  : http://localhost:{port}/api/system/status")
    print("-" * 58)
    notif = config.notifications
    channels = []
    if notif.discord_enabled:
        channels.append("Discord")
    if notif.telegram_enabled:
        channels.append("Telegram")
    if notif.email_enabled:
        channels.append("Email")
    print(f"  Notifications  : {', '.join(channels) if channels else 'None (configure via .env)'}")
    if platform.system() == "Windows":
        print("  Note           : Run as Administrator for Security Event Log")
    print("=" * 58)
    print()


class SOCMonitor:
    """Main SOC Monitoring application."""
    
    def __init__(self, config: Config):
        self.config = config
        self.running = False
        self.started_at = datetime.now()
        self.collector_errors: list = []
        
        # Initialize components
        self.db = Database(config.database)
        self.detector = ThreatDetector(self.db, config)
        self.notifier = AlertNotifier(config)
        
        # Platform-specific collector
        self.collector = None
        self._init_collector()
        
        # Wire up API routes
        routes.db = self.db
        routes.detector = self.detector
        routes.notifier = self.notifier
        self._update_system_state()
    
    def _init_collector(self):
        """Initialize the appropriate log collector for the platform."""
        if platform.system() == "Windows":
            try:
                from collectors.windows_collector import WindowsLogCollector
                self.collector = WindowsLogCollector(
                    channels=self.config.collector.windows_channels
                )
                logger.info("Windows Event Log collector initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Windows collector: {e}")
        else:
            try:
                from collectors.linux_collector import LinuxLogCollector
                self.collector = LinuxLogCollector(
                    log_paths=self.config.collector.linux_log_paths
                )
                logger.info("Linux log collector initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Linux collector: {e}")
    
    def _update_system_state(self):
        """Push runtime state to API for dashboard."""
        collector_type = None
        channels = []
        if platform.system() == "Windows":
            collector_type = "Windows Event Log"
            channels = self.config.collector.windows_channels
        else:
            collector_type = "Linux Syslog"
            channels = self.config.collector.linux_log_paths

        routes.system_state = {
            "started_at": self.started_at,
            "database_type": self.config.database.type,
            "collector_type": collector_type,
            "collector_active": self.collector is not None,
            "collector_channels": channels,
            "collector_errors": (
                getattr(self.collector, "errors", []) + self.collector_errors
            )[-5:],
            "poll_interval": self.config.collector.poll_interval,
            "batch_size": self.config.collector.batch_size,
            "api_host": self.config.api_host,
            "api_port": self.config.api_port,
        }
    
    def collect_and_analyze(self):
        """Main collection and analysis loop."""
        if not self.collector:
            logger.warning("No collector available, skipping collection")
            return
        
        try:
            events_processed = 0
            alerts_generated = 0
            
            for event in self.collector.collect_events(
                max_events=self.config.collector.batch_size
            ):
                # Convert to LogEvent
                log_event = self._convert_event(event)
                
                # Store in database
                event_id = self.db.insert_event(log_event)
                
                if event_id:
                    log_event.id = event_id
                    events_processed += 1
                    
                    # Analyze for threats
                    alert = self.detector.analyze_event(log_event)
                    
                    if alert:
                        # Store alert
                        alert_id = self.db.insert_alert(alert)
                        alert.id = alert_id
                        alerts_generated += 1
                        
                        logger.warning(
                            f"ALERT: {alert.threat_type.value} - "
                            f"{alert.severity.name} - {alert.description}"
                        )
                        
                        # Send notifications asynchronously
                        asyncio.run(self.notifier.send_alert(alert))
            
            if events_processed > 0:
                logger.info(
                    f"Processed {events_processed} events, "
                    f"generated {alerts_generated} alerts"
                )
            
            self._update_system_state()
        
        except Exception as e:
            logger.error(f"Error in collection cycle: {e}", exc_info=True)
            self.collector_errors.append(str(e))
            self._update_system_state()
    
    def _convert_event(self, event) -> LogEvent:
        """Convert platform-specific event to LogEvent."""
        # Handle Windows events
        if hasattr(event, 'event_id'):
            raw = f"{event.timestamp}|{event.event_id}|{event.message}"
            return LogEvent(
                id=None,
                timestamp=event.timestamp,
                source="windows",
                hostname=event.computer_name,
                event_type=event.event_type,
                event_id=event.event_id,
                username=event.username,
                source_ip=event.source_ip,
                message=event.message,
                raw_data=event.raw_xml,
                hash=LogEvent.compute_hash(raw)
            )
        
        # Handle Linux events
        raw = event.raw_line
        return LogEvent(
            id=None,
            timestamp=event.timestamp,
            source="linux",
            hostname=event.hostname,
            event_type=event.event_type,
            event_id=None,
            username=event.username,
            source_ip=event.source_ip,
            message=event.message,
            raw_data=raw,
            hash=LogEvent.compute_hash(raw)
        )
    
    def collection_loop(self):
        """Background collection thread."""
        while self.running:
            self.collect_and_analyze()
            time.sleep(self.config.collector.poll_interval)
    
    def start(self):
        """Start the SOC Monitor."""
        logger.info("Starting SOC Monitor...")
        _print_startup_banner(self.config)
        self.running = True
        
        # Start collection thread
        self.collection_thread = threading.Thread(
            target=self.collection_loop,
            daemon=True
        )
        self.collection_thread.start()
        logger.info("Collection thread started")
        
        # Start API server
        logger.info(f"Starting API server on {self.config.api_host}:{self.config.api_port}")
        uvicorn.run(
            routes.app,
            host=self.config.api_host,
            port=self.config.api_port,
            log_level="info"
        )
    
    def stop(self):
        """Stop the SOC Monitor."""
        logger.info("Stopping SOC Monitor...")
        self.running = False
        try:
            loop = asyncio.new_event_loop()
            loop.run_until_complete(self.notifier.close())
            loop.close()
        except Exception:
            pass


def main():
    """Entry point."""
    monitor = SOCMonitor(settings)
    
    # Handle shutdown signals
    def signal_handler(sig, frame):
        logger.info("Shutdown signal received")
        monitor.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        monitor.start()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        monitor.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
