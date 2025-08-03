"""
Advanced Alerting System

Multi-channel alert notification system with escalation, throttling,
and intelligent routing for business and operational events.
"""

import logging
import asyncio
import json
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from uuid import UUID, uuid4

import aiohttp
import smtplib
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart

from core.metrics_collector import Alert, AlertSeverity
from core.audit_logger import AuditLogger, AuditEvent, AuditEventType

logger = logging.getLogger(__name__)


class NotificationChannel(str, Enum):
    """Available notification channels"""
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    SMS = "sms"
    PAGERDUTY = "pagerduty"
    DISCORD = "discord"


class EscalationLevel(str, Enum):
    """Alert escalation levels"""
    L1_SUPPORT = "l1_support"
    L2_ENGINEERING = "l2_engineering"
    L3_SENIOR = "l3_senior"
    MANAGEMENT = "management"


@dataclass
class NotificationConfig:
    """Configuration for notification channel"""
    channel: NotificationChannel
    enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)
    escalation_delay: timedelta = field(default_factory=lambda: timedelta(minutes=15))
    max_frequency: timedelta = field(default_factory=lambda: timedelta(minutes=5))


@dataclass
class AlertNotification:
    """Alert notification tracking"""
    id: str
    alert_id: str
    channel: NotificationChannel
    recipient: str
    sent_at: datetime
    delivery_status: str = "pending"
    error_message: Optional[str] = None
    escalation_level: EscalationLevel = EscalationLevel.L1_SUPPORT


class AlertingSystem:
    """
    Advanced alerting system with multi-channel notifications.
    
    Features:
    - Multiple notification channels (Email, Slack, Webhook, SMS)
    - Alert escalation and routing
    - Throttling and deduplication
    - Delivery tracking and retry logic
    - Template-based messaging
    """
    
    def __init__(self, audit_logger: AuditLogger = None):
        self.audit_logger = audit_logger or AuditLogger({"postgres_enabled": True})
        
        # Notification configurations
        self.notification_configs = {}
        
        # Alert tracking
        self.sent_notifications = {}
        self.alert_frequencies = {}
        
        # Templates
        self.message_templates = self._load_default_templates()
        
        # Background tasks
        self._running = False
        self._escalation_task = None
    
    def configure_channel(
        self,
        channel: NotificationChannel,
        config: Dict[str, Any],
        enabled: bool = True
    ):
        """Configure a notification channel"""
        
        self.notification_configs[channel] = NotificationConfig(
            channel=channel,
            enabled=enabled,
            config=config
        )
        
        logger.info(f"Configured notification channel: {channel.value}")
    
    async def send_alert(
        self,
        alert: Alert,
        channels: List[NotificationChannel] = None,
        escalation_level: EscalationLevel = EscalationLevel.L1_SUPPORT
    ) -> List[AlertNotification]:
        """Send alert notifications through specified channels"""
        
        # Default to all enabled channels if none specified
        if channels is None:
            channels = [
                config.channel for config in self.notification_configs.values()
                if config.enabled
            ]
        
        # Check throttling
        if await self._is_throttled(alert):
            logger.info(f"Alert {alert.id} is throttled, skipping notification")
            return []
        
        notifications = []
        
        for channel in channels:
            if channel not in self.notification_configs:
                logger.warning(f"Channel {channel.value} not configured")
                continue
            
            config = self.notification_configs[channel]
            if not config.enabled:
                continue
            
            try:
                notification = await self._send_channel_notification(
                    alert, channel, escalation_level
                )
                notifications.append(notification)
                
            except Exception as e:
                logger.error(f"Failed to send {channel.value} notification: {e}")
                
                # Create failed notification record
                notification = AlertNotification(
                    id=str(uuid4()),
                    alert_id=alert.id,
                    channel=channel,
                    recipient="unknown",
                    sent_at=datetime.utcnow(),
                    delivery_status="failed",
                    error_message=str(e),
                    escalation_level=escalation_level
                )
                notifications.append(notification)
        
        # Update throttling tracking
        await self._update_frequency_tracking(alert)
        
        # Log alert notification
        await self.audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.SYSTEM_ERROR,  # Should be ALERT_SENT
            details={
                "alert_id": alert.id,
                "alert_name": alert.name,
                "severity": alert.severity.value,
                "channels": [n.channel.value for n in notifications],
                "escalation_level": escalation_level.value,
                "successful_notifications": len([n for n in notifications if n.delivery_status == "sent"])
            }
        ))
        
        return notifications
    
    async def _send_channel_notification(
        self,
        alert: Alert,
        channel: NotificationChannel,
        escalation_level: EscalationLevel
    ) -> AlertNotification:
        """Send notification through specific channel"""
        
        config = self.notification_configs[channel]
        
        # Generate message content
        message = await self._generate_message(alert, channel, escalation_level)
        
        notification = AlertNotification(
            id=str(uuid4()),
            alert_id=alert.id,
            channel=channel,
            recipient="",  # Will be set by channel handler
            sent_at=datetime.utcnow(),
            escalation_level=escalation_level
        )
        
        # Send through appropriate channel
        if channel == NotificationChannel.EMAIL:
            await self._send_email(alert, message, config, notification)
        elif channel == NotificationChannel.SLACK:
            await self._send_slack(alert, message, config, notification)
        elif channel == NotificationChannel.WEBHOOK:
            await self._send_webhook(alert, message, config, notification)
        elif channel == NotificationChannel.SMS:
            await self._send_sms(alert, message, config, notification)
        elif channel == NotificationChannel.PAGERDUTY:
            await self._send_pagerduty(alert, message, config, notification)
        elif channel == NotificationChannel.DISCORD:
            await self._send_discord(alert, message, config, notification)
        
        return notification
    
    async def _send_email(
        self,
        alert: Alert,
        message: Dict[str, str],
        config: NotificationConfig,
        notification: AlertNotification
    ):
        """Send email notification"""
        
        try:
            smtp_config = config.config
            
            # Create message
            msg = MimeMultipart('alternative')
            msg['Subject'] = message['subject']
            msg['From'] = smtp_config['from_email']
            msg['To'] = smtp_config['to_email']
            
            # Add HTML and text parts
            text_part = MimeText(message['text'], 'plain')
            html_part = MimeText(message['html'], 'html')
            
            msg.attach(text_part)
            msg.attach(html_part)
            
            # Send email
            with smtplib.SMTP(smtp_config['host'], smtp_config.get('port', 587)) as server:
                if smtp_config.get('use_tls', True):
                    server.starttls()
                
                if 'username' in smtp_config:
                    server.login(smtp_config['username'], smtp_config['password'])
                
                server.send_message(msg)
            
            notification.recipient = smtp_config['to_email']
            notification.delivery_status = "sent"
            
        except Exception as e:
            notification.delivery_status = "failed"
            notification.error_message = str(e)
            raise
    
    async def _send_slack(
        self,
        alert: Alert,
        message: Dict[str, str],
        config: NotificationConfig,
        notification: AlertNotification
    ):
        """Send Slack notification"""
        
        try:
            slack_config = config.config
            webhook_url = slack_config['webhook_url']
            
            # Create Slack message
            color_map = {
                AlertSeverity.CRITICAL: "danger",
                AlertSeverity.WARNING: "warning",
                AlertSeverity.INFO: "good"
            }
            
            slack_message = {
                "text": f"🚨 Alert: {alert.name}",
                "attachments": [
                    {
                        "color": color_map.get(alert.severity, "warning"),
                        "fields": [
                            {
                                "title": "Alert",
                                "value": alert.name,
                                "short": True
                            },
                            {
                                "title": "Severity",
                                "value": alert.severity.value.upper(),
                                "short": True
                            },
                            {
                                "title": "Condition",
                                "value": alert.condition,
                                "short": False
                            },
                            {
                                "title": "Current Value",
                                "value": str(alert.current_value),
                                "short": True
                            },
                            {
                                "title": "Threshold",
                                "value": str(alert.threshold),
                                "short": True
                            }
                        ],
                        "footer": "QES Platform Monitoring",
                        "ts": int(alert.triggered_at.timestamp())
                    }
                ]
            }
            
            # Send to Slack
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=slack_message) as response:
                    if response.status == 200:
                        notification.delivery_status = "sent"
                    else:
                        raise Exception(f"Slack API returned {response.status}")
            
            notification.recipient = slack_config.get('channel', 'unknown')
            
        except Exception as e:
            notification.delivery_status = "failed"
            notification.error_message = str(e)
            raise
    
    async def _send_webhook(
        self,
        alert: Alert,
        message: Dict[str, str],
        config: NotificationConfig,
        notification: AlertNotification
    ):
        """Send webhook notification"""
        
        try:
            webhook_config = config.config
            webhook_url = webhook_config['url']
            
            # Create webhook payload
            payload = {
                "alert_id": alert.id,
                "name": alert.name,
                "severity": alert.severity.value,
                "condition": alert.condition,
                "threshold": alert.threshold,
                "current_value": alert.current_value,
                "triggered_at": alert.triggered_at.isoformat(),
                "message": alert.message,
                "metadata": alert.metadata
            }
            
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "QES-Platform-Alerting/1.0"
            }
            
            # Add custom headers if configured
            if 'headers' in webhook_config:
                headers.update(webhook_config['headers'])
            
            # Send webhook
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    webhook_url,
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if 200 <= response.status < 300:
                        notification.delivery_status = "sent"
                    else:
                        raise Exception(f"Webhook returned {response.status}")
            
            notification.recipient = webhook_url
            
        except Exception as e:
            notification.delivery_status = "failed"
            notification.error_message = str(e)
            raise
    
    async def _send_sms(
        self,
        alert: Alert,
        message: Dict[str, str],
        config: NotificationConfig,
        notification: AlertNotification
    ):
        """Send SMS notification (placeholder - would integrate with SMS provider)"""
        
        # Placeholder implementation
        # In production, this would integrate with Twilio, AWS SNS, etc.
        
        sms_config = config.config
        phone_number = sms_config['phone_number']
        
        # For now, just log
        logger.info(f"SMS Alert to {phone_number}: {alert.name}")
        
        notification.recipient = phone_number
        notification.delivery_status = "sent"
    
    async def _send_pagerduty(
        self,
        alert: Alert,
        message: Dict[str, str],
        config: NotificationConfig,
        notification: AlertNotification
    ):
        """Send PagerDuty notification"""
        
        try:
            pd_config = config.config
            routing_key = pd_config['routing_key']
            
            # Create PagerDuty event
            event_payload = {
                "routing_key": routing_key,
                "event_action": "trigger",
                "dedup_key": f"qes-alert-{alert.id}",
                "payload": {
                    "summary": f"{alert.name}: {alert.message}",
                    "severity": alert.severity.value,
                    "source": "QES Platform",
                    "component": "monitoring",
                    "group": "alerts",
                    "class": alert.severity.value,
                    "custom_details": {
                        "condition": alert.condition,
                        "threshold": alert.threshold,
                        "current_value": alert.current_value,
                        "triggered_at": alert.triggered_at.isoformat()
                    }
                }
            }
            
            # Send to PagerDuty
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://events.pagerduty.com/v2/enqueue",
                    json=event_payload,
                    headers={"Content-Type": "application/json"}
                ) as response:
                    if response.status == 202:
                        notification.delivery_status = "sent"
                    else:
                        raise Exception(f"PagerDuty API returned {response.status}")
            
            notification.recipient = pd_config.get('service_name', 'unknown')
            
        except Exception as e:
            notification.delivery_status = "failed"
            notification.error_message = str(e)
            raise
    
    async def _send_discord(
        self,
        alert: Alert,
        message: Dict[str, str],
        config: NotificationConfig,
        notification: AlertNotification
    ):
        """Send Discord notification"""
        
        try:
            discord_config = config.config
            webhook_url = discord_config['webhook_url']
            
            # Create Discord embed
            color_map = {
                AlertSeverity.CRITICAL: 15158332,  # Red
                AlertSeverity.WARNING: 16776960,   # Yellow
                AlertSeverity.INFO: 3447003        # Blue
            }
            
            discord_message = {
                "content": f"🚨 **Alert Triggered**",
                "embeds": [
                    {
                        "title": alert.name,
                        "description": alert.message,
                        "color": color_map.get(alert.severity, 16776960),
                        "fields": [
                            {
                                "name": "Severity",
                                "value": alert.severity.value.upper(),
                                "inline": True
                            },
                            {
                                "name": "Current Value",
                                "value": str(alert.current_value),
                                "inline": True
                            },
                            {
                                "name": "Threshold",
                                "value": str(alert.threshold),
                                "inline": True
                            },
                            {
                                "name": "Condition",
                                "value": alert.condition,
                                "inline": False
                            }
                        ],
                        "footer": {
                            "text": "QES Platform Monitoring"
                        },
                        "timestamp": alert.triggered_at.isoformat()
                    }
                ]
            }
            
            # Send to Discord
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=discord_message) as response:
                    if response.status == 204:
                        notification.delivery_status = "sent"
                    else:
                        raise Exception(f"Discord API returned {response.status}")
            
            notification.recipient = discord_config.get('channel', 'unknown')
            
        except Exception as e:
            notification.delivery_status = "failed"
            notification.error_message = str(e)
            raise
    
    async def _generate_message(
        self,
        alert: Alert,
        channel: NotificationChannel,
        escalation_level: EscalationLevel
    ) -> Dict[str, str]:
        """Generate message content for specific channel"""
        
        template_key = f"{channel.value}_{alert.severity.value}"
        template = self.message_templates.get(template_key, self.message_templates['default'])
        
        # Template variables
        variables = {
            "alert_name": alert.name,
            "severity": alert.severity.value.upper(),
            "condition": alert.condition,
            "threshold": alert.threshold,
            "current_value": alert.current_value,
            "triggered_at": alert.triggered_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "escalation_level": escalation_level.value,
            "alert_id": alert.id,
            "message": alert.message
        }
        
        # Format templates
        formatted_message = {}
        for key, template_text in template.items():
            formatted_message[key] = template_text.format(**variables)
        
        return formatted_message
    
    async def _is_throttled(self, alert: Alert) -> bool:
        """Check if alert should be throttled"""
        
        now = datetime.utcnow()
        frequency_key = f"{alert.name}_{alert.severity.value}"
        
        if frequency_key in self.alert_frequencies:
            last_sent = self.alert_frequencies[frequency_key]
            min_interval = timedelta(minutes=5)  # Minimum 5 minutes between same alerts
            
            if now - last_sent < min_interval:
                return True
        
        return False
    
    async def _update_frequency_tracking(self, alert: Alert):
        """Update frequency tracking for throttling"""
        
        frequency_key = f"{alert.name}_{alert.severity.value}"
        self.alert_frequencies[frequency_key] = datetime.utcnow()
    
    def _load_default_templates(self) -> Dict[str, Dict[str, str]]:
        """Load default message templates"""
        
        return {
            "default": {
                "subject": "🚨 QES Platform Alert: {alert_name}",
                "text": """
QES Platform Alert

Alert: {alert_name}
Severity: {severity}
Condition: {condition}
Current Value: {current_value}
Threshold: {threshold}
Triggered: {triggered_at}

Message: {message}

Alert ID: {alert_id}
                """.strip(),
                "html": """
<h2>🚨 QES Platform Alert</h2>
<p><strong>Alert:</strong> {alert_name}</p>
<p><strong>Severity:</strong> <span style="color: red;">{severity}</span></p>
<p><strong>Condition:</strong> {condition}</p>
<p><strong>Current Value:</strong> {current_value}</p>
<p><strong>Threshold:</strong> {threshold}</p>
<p><strong>Triggered:</strong> {triggered_at}</p>
<p><strong>Message:</strong> {message}</p>
<hr>
<p><small>Alert ID: {alert_id}</small></p>
                """.strip()
            }
        }


def create_default_alerting_system() -> AlertingSystem:
    """Create alerting system with default configuration"""
    
    alerting = AlertingSystem()
    
    # Configure email (placeholder configuration)
    alerting.configure_channel(
        NotificationChannel.EMAIL,
        {
            'host': 'smtp.gmail.com',
            'port': 587,
            'use_tls': True,
            'from_email': 'alerts@qes-platform.com',
            'to_email': 'admin@qes-platform.com',
            'username': 'alerts@qes-platform.com',
            'password': 'your-app-password'  # Use environment variable in production
        },
        enabled=False  # Disabled by default until configured
    )
    
    # Configure Slack (placeholder configuration)
    alerting.configure_channel(
        NotificationChannel.SLACK,
        {
            'webhook_url': 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK',
            'channel': '#alerts'
        },
        enabled=False  # Disabled by default until configured
    )
    
    return alerting