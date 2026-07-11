import os
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path


@dataclass
class DatabaseConfig:
    """Database configuration settings."""
    type: str = "sqlite"  # "sqlite" or "postgresql"
    sqlite_path: Path = Path("soc_monitor.db")
    pg_host: str = "localhost"
    pg_port: int = 5432
    pg_database: str = "soc_monitor"
    pg_user: str = "soc_user"
    pg_password: str = ""


@dataclass
class AlertThresholds:
    """Thresholds for threat detection."""
    failed_login_threshold: int = 5
    failed_login_window_seconds: int = 300  # 5 minutes
    brute_force_threshold: int = 10
    brute_force_window_seconds: int = 60  # 1 minute
    port_scan_threshold: int = 20
    port_scan_window_seconds: int = 60
    privilege_escalation_keywords: list = field(default_factory=lambda: [
        "sudo", "su ", "runas", "privilege", "admin", "root"
    ])


@dataclass
class NotificationConfig:
    """Notification service configuration."""
    # Discord
    discord_enabled: bool = False
    discord_webhook_url: str = ""
    
    # Telegram
    telegram_enabled: bool = False
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    
    # Email
    email_enabled: bool = False
    smtp_server: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    email_recipients: list = field(default_factory=list)


@dataclass
class CollectorConfig:
    """Log collector configuration."""
    # Windows Event Log channels to monitor
    windows_channels: list = field(default_factory=lambda: [
        "Security",
        "System",
        "Application"
    ])
    
    # Linux log files to monitor
    linux_log_paths: list = field(default_factory=lambda: [
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/secure"
    ])
    
    # Collection interval in seconds
    poll_interval: int = 10
    
    # Maximum events per batch
    batch_size: int = 100


@dataclass
class Config:
    """Main configuration container."""
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    thresholds: AlertThresholds = field(default_factory=AlertThresholds)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    collector: CollectorConfig = field(default_factory=CollectorConfig)
    api_host: str = "0.0.0.0"
    api_port: int = 8080
    debug: bool = False
    log_level: str = "INFO"


def load_config_from_env() -> Config:
    """Load configuration from environment variables."""
    config = Config()
    
    # Database
    config.database.type = os.getenv("DB_TYPE", "sqlite")
    config.database.pg_host = os.getenv("PG_HOST", "localhost")
    config.database.pg_password = os.getenv("PG_PASSWORD", "")
    
    # Discord
    config.notifications.discord_enabled = os.getenv("DISCORD_ENABLED", "").lower() == "true"
    config.notifications.discord_webhook_url = os.getenv("DISCORD_WEBHOOK", "")
    
    # Telegram
    config.notifications.telegram_enabled = os.getenv("TELEGRAM_ENABLED", "").lower() == "true"
    config.notifications.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    config.notifications.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
    
    # Email
    config.notifications.email_enabled = os.getenv("EMAIL_ENABLED", "").lower() == "true"
    config.notifications.smtp_user = os.getenv("SMTP_USER", "")
    config.notifications.smtp_password = os.getenv("SMTP_PASSWORD", "")
    
    return config


# Global config instance
settings = load_config_from_env()
