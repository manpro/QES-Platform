"""
Business Metrics Collection System

Comprehensive metrics collection for business intelligence, performance monitoring,
and operational alerting with integration to Prometheus, Grafana, and custom dashboards.
"""

import logging
import time
import asyncio
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from uuid import UUID
import json

from prometheus_client import Counter, Histogram, Gauge, Summary, start_http_server
import redis

from core.audit_logger import AuditLogger, AuditEvent, AuditEventType
from billing.usage_tracker import UsageTracker
from billing.models import UsageMetricType

logger = logging.getLogger(__name__)


class MetricType(str, Enum):
    """Types of metrics to collect"""
    # Business metrics
    REVENUE = "revenue"
    SUBSCRIPTION_COUNT = "subscription_count"
    USER_ACTIVITY = "user_activity"
    FEATURE_USAGE = "feature_usage"
    
    # Performance metrics
    REQUEST_LATENCY = "request_latency"
    ERROR_RATE = "error_rate"
    THROUGHPUT = "throughput"
    RESOURCE_UTILIZATION = "resource_utilization"
    
    # Operational metrics
    SYSTEM_HEALTH = "system_health"
    DATABASE_PERFORMANCE = "database_performance"
    EXTERNAL_API_HEALTH = "external_api_health"
    SECURITY_EVENTS = "security_events"


class AlertSeverity(str, Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


@dataclass
class MetricPoint:
    """Individual metric data point"""
    metric_type: MetricType
    name: str
    value: float
    timestamp: datetime
    labels: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Alert:
    """Alert definition and state"""
    id: str
    name: str
    severity: AlertSeverity
    condition: str
    threshold: float
    current_value: float
    triggered_at: datetime
    resolved_at: Optional[datetime] = None
    message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class PrometheusMetrics:
    """Prometheus metrics definitions"""
    
    def __init__(self):
        # Business metrics
        self.revenue_total = Counter(
            'qes_revenue_total',
            'Total revenue generated',
            ['plan_type', 'currency']
        )
        
        self.subscriptions_active = Gauge(
            'qes_subscriptions_active',
            'Number of active subscriptions',
            ['plan_type']
        )
        
        self.users_active = Gauge(
            'qes_users_active',
            'Number of active users',
            ['time_period']
        )
        
        # Performance metrics
        self.request_duration = Histogram(
            'qes_request_duration_seconds',
            'Request duration in seconds',
            ['method', 'endpoint', 'status']
        )
        
        self.request_count = Counter(
            'qes_requests_total',
            'Total number of requests',
            ['method', 'endpoint', 'status']
        )
        
        self.error_rate = Gauge(
            'qes_error_rate',
            'Error rate percentage',
            ['service', 'error_type']
        )
        
        # Usage metrics
        self.usage_total = Counter(
            'qes_usage_total',
            'Total usage by metric type',
            ['tenant_id', 'metric_type']
        )
        
        self.quota_utilization = Gauge(
            'qes_quota_utilization',
            'Quota utilization percentage',
            ['tenant_id', 'metric_type']
        )
        
        # System health
        self.database_connections = Gauge(
            'qes_database_connections',
            'Number of database connections',
            ['database']
        )
        
        self.external_api_response_time = Histogram(
            'qes_external_api_response_time_seconds',
            'External API response time',
            ['provider', 'operation']
        )
        
        # Security metrics
        self.authentication_attempts = Counter(
            'qes_authentication_attempts_total',
            'Total authentication attempts',
            ['result', 'method']
        )
        
        self.security_violations = Counter(
            'qes_security_violations_total',
            'Security violations detected',
            ['violation_type', 'severity']
        )


class MetricsCollector:
    """
    Central metrics collection and aggregation system.
    
    Features:
    - Real-time metrics collection
    - Business intelligence analytics
    - Performance monitoring
    - Automated alerting
    - Integration with Prometheus/Grafana
    """
    
    def __init__(
        self,
        redis_client: redis.Redis = None,
        usage_tracker: UsageTracker = None,
        audit_logger: AuditLogger = None
    ):
        self.redis_client = redis_client or redis.Redis(host='localhost', port=6380, db=0)
        self.usage_tracker = usage_tracker or UsageTracker()
        self.audit_logger = audit_logger or AuditLogger({"postgres_enabled": True})
        
        # Initialize Prometheus metrics
        self.prometheus_metrics = PrometheusMetrics()
        
        # Metrics storage
        self.metrics_buffer = []
        self.alerts = {}
        
        # Alert handlers
        self.alert_handlers = []
        
        # Background tasks
        self._running = False
        self._collection_task = None
        self._aggregation_task = None
    
    async def start(self):
        """Start metrics collection background tasks"""
        if self._running:
            return
        
        self._running = True
        
        # Start background tasks
        self._collection_task = asyncio.create_task(self._collection_loop())
        self._aggregation_task = asyncio.create_task(self._aggregation_loop())
        
        # Start Prometheus metrics server
        start_http_server(8001)  # Expose on port 8001
        
        logger.info("Metrics collection system started")
    
    async def stop(self):
        """Stop metrics collection"""
        self._running = False
        
        if self._collection_task:
            self._collection_task.cancel()
        if self._aggregation_task:
            self._aggregation_task.cancel()
        
        logger.info("Metrics collection system stopped")
    
    async def record_metric(
        self,
        metric_type: MetricType,
        name: str,
        value: float,
        labels: Dict[str, str] = None,
        metadata: Dict[str, Any] = None
    ):
        """Record a metric data point"""
        
        metric_point = MetricPoint(
            metric_type=metric_type,
            name=name,
            value=value,
            timestamp=datetime.utcnow(),
            labels=labels or {},
            metadata=metadata or {}
        )
        
        # Add to buffer
        self.metrics_buffer.append(metric_point)
        
        # Update Prometheus metrics
        await self._update_prometheus_metrics(metric_point)
        
        # Store in Redis for real-time queries
        await self._store_in_redis(metric_point)
        
        logger.debug(f"Recorded metric: {name}={value} ({metric_type.value})")
    
    async def record_business_event(
        self,
        event_type: str,
        tenant_id: UUID,
        value: float,
        metadata: Dict[str, Any] = None
    ):
        """Record business event for analytics"""
        
        await self.record_metric(
            metric_type=MetricType.FEATURE_USAGE,
            name=f"business_event_{event_type}",
            value=value,
            labels={
                "tenant_id": str(tenant_id),
                "event_type": event_type
            },
            metadata=metadata
        )
        
        # Update business intelligence metrics
        await self._update_business_metrics(event_type, tenant_id, value, metadata)
    
    async def record_performance_metric(
        self,
        operation: str,
        duration: float,
        success: bool = True,
        metadata: Dict[str, Any] = None
    ):
        """Record performance metric"""
        
        await self.record_metric(
            metric_type=MetricType.REQUEST_LATENCY,
            name=f"operation_{operation}_duration",
            value=duration,
            labels={
                "operation": operation,
                "success": str(success)
            },
            metadata=metadata
        )
        
        # Update Prometheus histogram
        status = "success" if success else "error"
        self.prometheus_metrics.request_duration.labels(
            method="POST",  # Could be extracted from metadata
            endpoint=operation,
            status=status
        ).observe(duration)
    
    async def get_metrics_summary(
        self,
        metric_type: MetricType = None,
        time_range: timedelta = None
    ) -> Dict[str, Any]:
        """Get metrics summary for dashboard"""
        
        time_range = time_range or timedelta(hours=24)
        cutoff_time = datetime.utcnow() - time_range
        
        # Filter metrics by type and time
        filtered_metrics = [
            m for m in self.metrics_buffer
            if (not metric_type or m.metric_type == metric_type) and
               m.timestamp >= cutoff_time
        ]
        
        if not filtered_metrics:
            return {"message": "No metrics found", "count": 0}
        
        # Aggregate metrics
        summary = {
            "time_range": {
                "start": cutoff_time.isoformat(),
                "end": datetime.utcnow().isoformat(),
                "duration_hours": time_range.total_seconds() / 3600
            },
            "total_points": len(filtered_metrics),
            "metrics_by_type": {},
            "top_metrics": [],
            "alerts_active": len([a for a in self.alerts.values() if not a.resolved_at])
        }
        
        # Group by metric type
        type_groups = {}
        for metric in filtered_metrics:
            metric_type_key = metric.metric_type.value
            if metric_type_key not in type_groups:
                type_groups[metric_type_key] = []
            type_groups[metric_type_key].append(metric)
        
        # Summarize each type
        for type_key, metrics in type_groups.items():
            values = [m.value for m in metrics]
            summary["metrics_by_type"][type_key] = {
                "count": len(metrics),
                "total": sum(values),
                "average": sum(values) / len(values),
                "min": min(values),
                "max": max(values)
            }
        
        return summary
    
    async def get_business_intelligence(
        self,
        tenant_id: UUID = None,
        days: int = 30
    ) -> Dict[str, Any]:
        """Get business intelligence dashboard data"""
        
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Get usage analytics
        usage_analytics = {}
        if tenant_id:
            usage_analytics = await self.usage_tracker.get_usage_analytics(tenant_id, days)
        
        # Get revenue metrics from Redis
        revenue_data = await self._get_revenue_metrics(start_date, end_date, tenant_id)
        
        # Get user activity metrics
        activity_data = await self._get_activity_metrics(start_date, end_date, tenant_id)
        
        # Get system performance
        performance_data = await self._get_performance_metrics(start_date, end_date)
        
        return {
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
                "days": days
            },
            "tenant_id": str(tenant_id) if tenant_id else "all",
            "revenue": revenue_data,
            "usage": usage_analytics,
            "activity": activity_data,
            "performance": performance_data,
            "generated_at": datetime.utcnow().isoformat()
        }
    
    async def check_alerts(self):
        """Check alert conditions and trigger notifications"""
        
        # Define alert conditions
        alert_conditions = [
            {
                "id": "high_error_rate",
                "name": "High Error Rate",
                "severity": AlertSeverity.CRITICAL,
                "condition": "error_rate > 5",
                "threshold": 5.0,
                "metric": "qes_error_rate"
            },
            {
                "id": "low_disk_space",
                "name": "Low Disk Space",
                "severity": AlertSeverity.WARNING,
                "condition": "disk_usage > 80",
                "threshold": 80.0,
                "metric": "system_disk_usage"
            },
            {
                "id": "high_response_time",
                "name": "High Response Time",
                "severity": AlertSeverity.WARNING,
                "condition": "avg_response_time > 2",
                "threshold": 2.0,
                "metric": "qes_request_duration_seconds"
            },
            {
                "id": "quota_exceeded",
                "name": "Quota Exceeded",
                "severity": AlertSeverity.INFO,
                "condition": "quota_utilization > 90",
                "threshold": 90.0,
                "metric": "qes_quota_utilization"
            }
        ]
        
        for condition in alert_conditions:
            current_value = await self._evaluate_metric(condition["metric"])
            
            if current_value > condition["threshold"]:
                await self._trigger_alert(condition, current_value)
            else:
                await self._resolve_alert(condition["id"])
    
    async def _collection_loop(self):
        """Background metrics collection loop"""
        
        while self._running:
            try:
                # Collect system metrics
                await self._collect_system_metrics()
                
                # Collect business metrics
                await self._collect_business_metrics()
                
                # Check alerts
                await self.check_alerts()
                
                # Sleep for collection interval
                await asyncio.sleep(60)  # Collect every minute
                
            except Exception as e:
                logger.error(f"Metrics collection error: {e}")
                await asyncio.sleep(10)  # Short sleep on error
    
    async def _aggregation_loop(self):
        """Background metrics aggregation loop"""
        
        while self._running:
            try:
                # Flush metrics buffer to permanent storage
                if self.metrics_buffer:
                    await self._flush_metrics_buffer()
                
                # Aggregate hourly/daily metrics
                await self._aggregate_metrics()
                
                # Cleanup old metrics
                await self._cleanup_old_metrics()
                
                # Sleep for aggregation interval
                await asyncio.sleep(300)  # Aggregate every 5 minutes
                
            except Exception as e:
                logger.error(f"Metrics aggregation error: {e}")
                await asyncio.sleep(30)
    
    async def _update_prometheus_metrics(self, metric_point: MetricPoint):
        """Update Prometheus metrics"""
        
        try:
            if metric_point.metric_type == MetricType.REQUEST_LATENCY:
                # Update request duration histogram
                labels = metric_point.labels
                self.prometheus_metrics.request_duration.labels(
                    method=labels.get("method", "unknown"),
                    endpoint=labels.get("endpoint", "unknown"),
                    status=labels.get("status", "unknown")
                ).observe(metric_point.value)
            
            elif metric_point.metric_type == MetricType.FEATURE_USAGE:
                # Update usage counter
                tenant_id = metric_point.labels.get("tenant_id", "unknown")
                metric_type = metric_point.labels.get("metric_type", "unknown")
                self.prometheus_metrics.usage_total.labels(
                    tenant_id=tenant_id,
                    metric_type=metric_type
                ).inc(metric_point.value)
            
            # Add more metric type handlers as needed
            
        except Exception as e:
            logger.error(f"Failed to update Prometheus metrics: {e}")
    
    async def _store_in_redis(self, metric_point: MetricPoint):
        """Store metric in Redis for real-time queries"""
        
        try:
            key = f"metrics:{metric_point.metric_type.value}:{metric_point.name}"
            data = {
                "value": metric_point.value,
                "timestamp": metric_point.timestamp.isoformat(),
                "labels": metric_point.labels,
                "metadata": metric_point.metadata
            }
            
            # Store with TTL of 7 days
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.redis_client.setex(
                    key,
                    7 * 24 * 3600,  # 7 days
                    json.dumps(data, default=str)
                )
            )
            
        except Exception as e:
            logger.error(f"Failed to store metric in Redis: {e}")
    
    async def _collect_system_metrics(self):
        """Collect system health metrics"""
        
        import psutil
        
        # CPU usage
        cpu_percent = psutil.cpu_percent()
        await self.record_metric(
            MetricType.RESOURCE_UTILIZATION,
            "cpu_usage_percent",
            cpu_percent
        )
        
        # Memory usage
        memory = psutil.virtual_memory()
        await self.record_metric(
            MetricType.RESOURCE_UTILIZATION,
            "memory_usage_percent",
            memory.percent
        )
        
        # Disk usage
        disk = psutil.disk_usage('/')
        disk_percent = (disk.used / disk.total) * 100
        await self.record_metric(
            MetricType.RESOURCE_UTILIZATION,
            "disk_usage_percent",
            disk_percent
        )
    
    async def _collect_business_metrics(self):
        """Collect business metrics"""
        
        # This would integrate with your billing system
        # For now, placeholder implementation
        pass
    
    async def _flush_metrics_buffer(self):
        """Flush metrics buffer to permanent storage"""
        
        if not self.metrics_buffer:
            return
        
        # In production, this would write to a time-series database
        # For now, just log the count
        logger.info(f"Flushing {len(self.metrics_buffer)} metrics to storage")
        
        # Clear buffer
        self.metrics_buffer.clear()
    
    async def _aggregate_metrics(self):
        """Aggregate metrics for reporting"""
        
        # Placeholder for metric aggregation logic
        logger.debug("Aggregating metrics")
    
    async def _cleanup_old_metrics(self):
        """Clean up old metrics to save space"""
        
        # Placeholder for cleanup logic
        logger.debug("Cleaning up old metrics")
    
    async def _get_revenue_metrics(self, start_date, end_date, tenant_id=None):
        """Get revenue metrics from data sources"""
        
        # Placeholder - would integrate with billing system
        return {
            "total_revenue": 0.0,
            "new_revenue": 0.0,
            "recurring_revenue": 0.0,
            "churn_rate": 0.0
        }
    
    async def _get_activity_metrics(self, start_date, end_date, tenant_id=None):
        """Get user activity metrics"""
        
        # Placeholder - would query user activity data
        return {
            "active_users": 0,
            "new_users": 0,
            "user_sessions": 0,
            "avg_session_duration": 0.0
        }
    
    async def _get_performance_metrics(self, start_date, end_date):
        """Get system performance metrics"""
        
        # Placeholder - would aggregate performance data
        return {
            "avg_response_time": 0.0,
            "error_rate": 0.0,
            "throughput": 0.0,
            "uptime": 99.9
        }
    
    async def _evaluate_metric(self, metric_name: str) -> float:
        """Evaluate current value of a metric"""
        
        # Placeholder - would query current metric value
        return 0.0
    
    async def _trigger_alert(self, condition: Dict[str, Any], current_value: float):
        """Trigger an alert"""
        
        alert_id = condition["id"]
        
        # Check if alert already exists
        if alert_id in self.alerts and not self.alerts[alert_id].resolved_at:
            return  # Alert already active
        
        alert = Alert(
            id=alert_id,
            name=condition["name"],
            severity=AlertSeverity(condition["severity"]),
            condition=condition["condition"],
            threshold=condition["threshold"],
            current_value=current_value,
            triggered_at=datetime.utcnow(),
            message=f"{condition['name']}: {current_value} > {condition['threshold']}"
        )
        
        self.alerts[alert_id] = alert
        
        # Send notifications
        await self._send_alert_notifications(alert)
        
        logger.warning(f"Alert triggered: {alert.name} - {alert.message}")
    
    async def _resolve_alert(self, alert_id: str):
        """Resolve an alert"""
        
        if alert_id in self.alerts and not self.alerts[alert_id].resolved_at:
            self.alerts[alert_id].resolved_at = datetime.utcnow()
            
            logger.info(f"Alert resolved: {self.alerts[alert_id].name}")
    
    async def _send_alert_notifications(self, alert: Alert):
        """Send alert notifications"""
        
        # Send to configured alert handlers
        for handler in self.alert_handlers:
            try:
                await handler(alert)
            except Exception as e:
                logger.error(f"Alert handler failed: {e}")
    
    def add_alert_handler(self, handler: Callable):
        """Add alert notification handler"""
        self.alert_handlers.append(handler)


# Global metrics collector instance
metrics_collector = None


def get_metrics_collector() -> MetricsCollector:
    """Get global metrics collector instance"""
    global metrics_collector
    
    if metrics_collector is None:
        metrics_collector = MetricsCollector()
    
    return metrics_collector


async def initialize_metrics():
    """Initialize metrics collection system"""
    collector = get_metrics_collector()
    await collector.start()
    
    logger.info("Metrics system initialized")


async def shutdown_metrics():
    """Shutdown metrics collection system"""
    collector = get_metrics_collector()
    await collector.stop()
    
    logger.info("Metrics system shutdown")