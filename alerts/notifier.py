import asyncio
import aiohttp
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional
import logging

from storage.database import ThreatAlert, Severity

logger = logging.getLogger(__name__)


class AlertNotifier:
    """Sends alerts via Discord, Telegram, and Email."""
    
    SEVERITY_COLORS = {
        Severity.LOW: 0x3498db,      # Blue
        Severity.MEDIUM: 0xf1c40f,   # Yellow
        Severity.HIGH: 0xe67e22,     # Orange
        Severity.CRITICAL: 0xe74c3c, # Red
    }
    
    SEVERITY_EMOJIS = {
        Severity.LOW: "ℹ️",
        Severity.MEDIUM: "⚠️",
        Severity.HIGH: "🔶",
        Severity.CRITICAL: "🚨",
    }
    
    def __init__(self, config):
        self.config = config.notifications
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session
    
    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def send_alert(self, alert: ThreatAlert) -> dict:
        """Send alert to all configured notification channels."""
        results = {}
        
        if self.config.discord_enabled:
            results['discord'] = await self._send_discord(alert)
        
        if self.config.telegram_enabled:
            results['telegram'] = await self._send_telegram(alert)
        
        if self.config.email_enabled:
            results['email'] = await self._send_email(alert)
        
        return results
    
    async def _send_discord(self, alert: ThreatAlert) -> bool:
        """Send alert to Discord webhook."""
        if not self.config.discord_webhook_url:
            return False
        
        severity = alert.severity
        emoji = self.SEVERITY_EMOJIS.get(severity, "⚠️")
        color = self.SEVERITY_COLORS.get(severity, 0xffffff)
        
        embed = {
            "title": f"{emoji} Security Alert: {alert.threat_type.value.replace('_', ' ').title()}",
            "description": alert.description,
            "color": color,
            "fields": [
                {
                    "name": "Severity",
                    "value": severity.name,
                    "inline": True
                },
                {
                    "name": "Hostname",
                    "value": alert.hostname,
                    "inline": True
                },
                {
                    "name": "Timestamp",
                    "value": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "inline": True
                }
            ],
            "footer": {
                "text": "SOC Monitor"
            }
        }
        
        if alert.source_ip:
            embed["fields"].append({
                "name": "Source IP",
                "value": alert.source_ip,
                "inline": True
            })
        
        if alert.target_user:
            embed["fields"].append({
                "name": "Target User",
                "value": alert.target_user,
                "inline": True
            })
        
        embed["fields"].append({
            "name": "Event Count",
            "value": str(alert.event_count),
            "inline": True
        })
        
        payload = {"embeds": [embed]}
        
        try:
            session = await self._get_session()
            async with session.post(
                self.config.discord_webhook_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status in (200, 204):
                    logger.info(f"Discord alert sent successfully")
                    return True
                else:
                    logger.error(f"Discord webhook failed: {response.status}")
                    return False
        except Exception as e:
            logger.error(f"Discord notification error: {e}")
            return False
    
    async def _send_telegram(self, alert: ThreatAlert) -> bool:
        """Send alert to Telegram."""
        if not self.config.telegram_bot_token or not self.config.telegram_chat_id:
            return False
        
        severity = alert.severity
        emoji = self.SEVERITY_EMOJIS.get(severity, "⚠️")
        
        message = f"""
{emoji} <b>Security Alert</b>

<b>Type:</b> {alert.threat_type.value.replace('_', ' ').title()}
<b>Severity:</b> {severity.name}
<b>Host:</b> {alert.hostname}
<b>Time:</b> {alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")}

<b>Description:</b>
{alert.description}
"""
        
        if alert.source_ip:
            message += f"\n<b>Source IP:</b> {alert.source_ip}"
        
        if alert.target_user:
            message += f"\n<b>Target User:</b> {alert.target_user}"
        
        url = f"[api.telegram.org](https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage)"
        payload = {
            "chat_id": self.config.telegram_chat_id,
            "text": message,
            "parse_mode": "HTML"
        }
        
        try:
            session = await self._get_session()
            async with session.post(
                url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    logger.info("Telegram alert sent successfully")
                    return True
                else:
                    logger.error(f"Telegram API failed: {response.status}")
                    return False
        except Exception as e:
            logger.error(f"Telegram notification error: {e}")
            return False
    
    async def _send_email(self, alert: ThreatAlert) -> bool:
        """Send alert via email."""
        if not self.config.smtp_user or not self.config.email_recipients:
            return False
        
        severity = alert.severity
        
        subject = f"[{severity.name}] Security Alert: {alert.threat_type.value.replace('_', ' ').title()}"
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <div style="background-color: {'#e74c3c' if severity == Severity.CRITICAL else '#f39c12' if severity == Severity.HIGH else '#3498db'}; 
                        color: white; padding: 20px; border-radius: 5px;">
                <h2>🚨 Security Alert</h2>
            </div>
            <div style="padding: 20px;">
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 10px; border-bottom: 1px solid #ddd;"><strong>Type:</strong></td>
                        <td style="padding: 10px; border-bottom: 1px solid #ddd;">{alert.threat_type.value.replace('_', ' ').title()}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border-bottom: 1px solid #ddd;"><strong>Severity:</strong></td>
                        <td style="padding: 10px; border-bottom: 1px solid #ddd;">{severity.name}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border-bottom: 1px solid #ddd;"><strong>Hostname:</strong></td>
                        <td style="padding: 10px; border-bottom: 1px solid #ddd;">{alert.hostname}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border-bottom: 1px solid #ddd;"><strong>Timestamp:</strong></td>
                        <td style="padding: 10px; border-bottom: 1px solid #ddd;">{alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border-bottom: 1px solid #ddd;"><strong>Source IP:</strong></td>
                        <td style="padding: 10px; border-bottom: 1px solid #ddd;">{alert.source_ip or 'N/A'}</td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border-bottom: 1px solid #ddd;"><strong>Target User:</strong></td>
                        <td style="padding: 10px; border-bottom: 1px solid #ddd;">{alert.target_user or 'N/A'}</td>
                    </tr>
                </table>
                <div style="margin-top: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 5px;">
                    <strong>Description:</strong><br>
                    {alert.description}
                </div>
            </div>
            <div style="padding: 20px; color: #666; font-size: 12px;">
                Generated by SOC Monitor
            </div>
        </body>
        </html>
        """
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.config.smtp_user
            msg['To'] = ', '.join(self.config.email_recipients)
            
            msg.attach(MIMEText(alert.description, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
            
            context = ssl.create_default_context()
            
            with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port) as server:
                server.starttls(context=context)
                server.login(self.config.smtp_user, self.config.smtp_password)
                server.sendmail(
                    self.config.smtp_user,
                    self.config.email_recipients,
                    msg.as_string()
                )
            
            logger.info("Email alert sent successfully")
            return True
        
        except Exception as e:
            logger.error(f"Email notification error: {e}")
            return False
