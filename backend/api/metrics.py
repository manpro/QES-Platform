"""
Metrics and Business Intelligence API

Comprehensive metrics API for business intelligence, performance monitoring,
and operational insights with real-time dashboards and alerting.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Depends, status, Query, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from auth.jwt_auth import get_current_user
from models.user import User
from core.metrics_collector import MetricsCollector, MetricType, get_metrics_collector
from core.alerting_system import AlertingSystem, create_default_alerting_system, NotificationChannel
from core.audit_logger import AuditLogger, AuditEvent, AuditEventType

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/metrics", tags=["metrics"])


class MetricRequest(BaseModel):
    """Request to record a custom metric"""
    metric_type: str = Field(..., description="Type of metric")
    name: str = Field(..., description="Metric name")
    value: float = Field(..., description="Metric value")
    labels: Optional[Dict[str, str]] = Field(None, description="Metric labels")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")


class BusinessIntelligenceRequest(BaseModel):
    """Request for business intelligence data"""
    tenant_id: Optional[str] = Field(None, description="Specific tenant ID (admin only)")
    days: int = Field(30, ge=1, le=365, description="Number of days to analyze")
    include_projections: bool = Field(True, description="Include usage projections")
    include_comparisons: bool = Field(True, description="Include period comparisons")


class AlertConfigRequest(BaseModel):
    """Request to configure alert settings"""
    channel: str = Field(..., description="Notification channel")
    enabled: bool = Field(True, description="Enable/disable channel")
    config: Dict[str, Any] = Field(..., description="Channel configuration")


class DashboardResponse(BaseModel):
    """Dashboard data response"""
    tenant_id: str
    period: Dict[str, str]
    business_metrics: Dict[str, Any]
    performance_metrics: Dict[str, Any]
    usage_metrics: Dict[str, Any]
    alerts: Dict[str, Any]
    recommendations: List[str]


def get_metrics_services():
    """Get metrics service dependencies"""
    metrics_collector = get_metrics_collector()
    alerting_system = create_default_alerting_system()
    audit_logger = AuditLogger({"postgres_enabled": True, "loki_enabled": True})
    
    return metrics_collector, alerting_system, audit_logger


@router.get("/dashboard")
async def get_dashboard_data(
    days: int = Query(7, ge=1, le=90, description="Number of days for dashboard"),
    current_user: User = Depends(get_current_user)
):
    """
    Get comprehensive dashboard data for the current user's tenant.
    
    Returns business metrics, performance data, usage statistics, and alerts.
    """
    try:
        metrics_collector, alerting_system, _ = get_metrics_services()
        
        # Get business intelligence data
        bi_data = await metrics_collector.get_business_intelligence(
            current_user.tenant_id,
            days
        )
        
        # Get metrics summary
        metrics_summary = await metrics_collector.get_metrics_summary(
            time_range=timedelta(days=days)
        )
        
        # Get active alerts
        active_alerts = [
            {
                "id": alert.id,
                "name": alert.name,
                "severity": alert.severity.value,
                "triggered_at": alert.triggered_at.isoformat(),
                "message": alert.message
            }
            for alert in alerting_system.alerts.values()
            if not alert.resolved_at
        ]
        
        # Generate recommendations
        recommendations = await _generate_recommendations(
            current_user.tenant_id, bi_data, metrics_summary
        )
        
        return DashboardResponse(
            tenant_id=str(current_user.tenant_id),
            period={
                "start": (datetime.utcnow() - timedelta(days=days)).isoformat(),
                "end": datetime.utcnow().isoformat(),
                "days": days
            },
            business_metrics=bi_data,
            performance_metrics=metrics_summary,
            usage_metrics=bi_data.get("usage", {}),
            alerts={
                "active_count": len(active_alerts),
                "alerts": active_alerts[:5]  # Limit to 5 most recent
            },
            recommendations=recommendations
        )
        
    except Exception as e:
        logger.error(f"Failed to get dashboard data: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dashboard data"
        )


@router.post("/record")
async def record_custom_metric(
    request: MetricRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Record a custom metric (admin only).
    
    Allows manual recording of business or operational metrics.
    """
    try:
        # Check admin access
        if current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        
        metrics_collector, _, audit_logger = get_metrics_services()
        
        # Parse metric type
        try:
            metric_type = MetricType(request.metric_type)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid metric type: {request.metric_type}"
            )
        
        # Record metric
        await metrics_collector.record_metric(
            metric_type=metric_type,
            name=request.name,
            value=request.value,
            labels=request.labels or {},
            metadata=request.metadata or {}
        )
        
        # Log metric recording
        await audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.SYSTEM_ERROR,  # Should be METRIC_RECORDED
            user_id=str(current_user.id),
            details={
                "metric_type": request.metric_type,
                "metric_name": request.name,
                "value": request.value,
                "labels": request.labels
            }
        ))
        
        return {
            "success": True,
            "metric_type": request.metric_type,
            "name": request.name,
            "value": request.value,
            "recorded_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to record metric: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to record metric"
        )


@router.get("/business-intelligence")
async def get_business_intelligence(
    request: BusinessIntelligenceRequest = Depends(),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive business intelligence data"""
    
    try:
        metrics_collector, _, _ = get_metrics_services()
        
        # Determine tenant ID
        tenant_id = current_user.tenant_id
        if request.tenant_id:
            # Only admins can view other tenants
            if current_user.role != "admin":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Admin access required to view other tenants"
                )
            tenant_id = request.tenant_id
        
        # Get business intelligence data
        bi_data = await metrics_collector.get_business_intelligence(
            tenant_id, request.days
        )
        
        # Add projections if requested
        if request.include_projections:
            bi_data["projections"] = await _get_usage_projections(
                tenant_id, 30  # 30-day projections
            )
        
        # Add period comparisons if requested
        if request.include_comparisons:
            bi_data["comparisons"] = await _get_period_comparisons(
                tenant_id, request.days
            )
        
        return bi_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get business intelligence: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve business intelligence data"
        )


@router.get("/performance")
async def get_performance_metrics(
    hours: int = Query(24, ge=1, le=168, description="Hours to analyze"),
    metric_type: Optional[str] = Query(None, description="Specific metric type"),
    current_user: User = Depends(get_current_user)
):
    """Get system performance metrics"""
    
    try:
        metrics_collector, _, _ = get_metrics_services()
        
        # Parse metric type if provided
        parsed_metric_type = None
        if metric_type:
            try:
                parsed_metric_type = MetricType(metric_type)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid metric type: {metric_type}"
                )
        
        # Get metrics summary
        metrics_summary = await metrics_collector.get_metrics_summary(
            metric_type=parsed_metric_type,
            time_range=timedelta(hours=hours)
        )
        
        return {
            "tenant_id": str(current_user.tenant_id),
            "time_period_hours": hours,
            "metric_type_filter": metric_type,
            "performance_data": metrics_summary,
            "generated_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get performance metrics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve performance metrics"
        )


@router.get("/alerts")
async def get_alerts(
    active_only: bool = Query(True, description="Show only active alerts"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    current_user: User = Depends(get_current_user)
):
    """Get alerts for the current tenant"""
    
    try:
        _, alerting_system, _ = get_metrics_services()
        
        # Filter alerts
        alerts = []
        for alert in alerting_system.alerts.values():
            # Skip resolved alerts if only active requested
            if active_only and alert.resolved_at:
                continue
            
            # Filter by severity if specified
            if severity and alert.severity.value != severity:
                continue
            
            alerts.append({
                "id": alert.id,
                "name": alert.name,
                "severity": alert.severity.value,
                "condition": alert.condition,
                "threshold": alert.threshold,
                "current_value": alert.current_value,
                "triggered_at": alert.triggered_at.isoformat(),
                "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
                "message": alert.message,
                "metadata": alert.metadata
            })
        
        return {
            "tenant_id": str(current_user.tenant_id),
            "filters": {
                "active_only": active_only,
                "severity": severity
            },
            "total_alerts": len(alerts),
            "alerts": alerts
        }
        
    except Exception as e:
        logger.error(f"Failed to get alerts: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve alerts"
        )


@router.post("/alerts/configure")
async def configure_alert_channel(
    request: AlertConfigRequest,
    current_user: User = Depends(get_current_user)
):
    """Configure alert notification channel (admin only)"""
    
    try:
        # Check admin access
        if current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        
        _, alerting_system, audit_logger = get_metrics_services()
        
        # Parse notification channel
        try:
            channel = NotificationChannel(request.channel)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid notification channel: {request.channel}"
            )
        
        # Configure channel
        alerting_system.configure_channel(
            channel=channel,
            config=request.config,
            enabled=request.enabled
        )
        
        # Log configuration change
        await audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.SYSTEM_ERROR,  # Should be ALERT_CONFIG_CHANGED
            user_id=str(current_user.id),
            details={
                "channel": request.channel,
                "enabled": request.enabled,
                "config_keys": list(request.config.keys())
            }
        ))
        
        return {
            "success": True,
            "channel": request.channel,
            "enabled": request.enabled,
            "configured_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to configure alert channel: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to configure alert channel"
        )


@router.post("/alerts/test")
async def test_alert_system(
    channel: str = Query(..., description="Channel to test"),
    current_user: User = Depends(get_current_user)
):
    """Test alert notification system (admin only)"""
    
    try:
        # Check admin access
        if current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        
        from core.metrics_collector import Alert, AlertSeverity
        
        _, alerting_system, _ = get_metrics_services()
        
        # Parse notification channel
        try:
            notification_channel = NotificationChannel(channel)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid notification channel: {channel}"
            )
        
        # Create test alert
        test_alert = Alert(
            id="test-alert",
            name="Test Alert",
            severity=AlertSeverity.INFO,
            condition="test condition",
            threshold=100.0,
            current_value=150.0,
            triggered_at=datetime.utcnow(),
            message="This is a test alert from QES Platform monitoring system"
        )
        
        # Send test notification
        notifications = await alerting_system.send_alert(
            test_alert,
            channels=[notification_channel]
        )
        
        return {
            "success": True,
            "channel": channel,
            "test_alert_id": test_alert.id,
            "notifications_sent": len(notifications),
            "delivery_status": [
                {
                    "notification_id": n.id,
                    "status": n.delivery_status,
                    "recipient": n.recipient,
                    "error": n.error_message
                }
                for n in notifications
            ]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to test alert system: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to test alert system"
        )


@router.get("/health")
async def metrics_service_health():
    """Health check for metrics and monitoring system"""
    
    try:
        metrics_collector, alerting_system, _ = get_metrics_services()
        
        # Check metrics collector status
        metrics_healthy = hasattr(metrics_collector, '_running') and metrics_collector._running
        
        # Check alert system status
        alerts_healthy = len(alerting_system.notification_configs) > 0
        
        # Get system stats
        buffer_size = len(metrics_collector.metrics_buffer)
        active_alerts = len([a for a in alerting_system.alerts.values() if not a.resolved_at])
        
        overall_status = "healthy" if (metrics_healthy and alerts_healthy) else "degraded"
        
        return {
            "status": overall_status,
            "service": "metrics_monitoring",
            "components": {
                "metrics_collector": {
                    "status": "healthy" if metrics_healthy else "unhealthy",
                    "buffer_size": buffer_size,
                    "running": metrics_healthy
                },
                "alerting_system": {
                    "status": "healthy" if alerts_healthy else "unhealthy",
                    "configured_channels": len(alerting_system.notification_configs),
                    "active_alerts": active_alerts
                }
            },
            "prometheus_metrics_port": 8001
        }
        
    except Exception as e:
        logger.error(f"Metrics service health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Metrics service unhealthy: {str(e)}"
        )


async def _generate_recommendations(
    tenant_id: str,
    bi_data: Dict[str, Any],
    metrics_summary: Dict[str, Any]
) -> List[str]:
    """Generate actionable recommendations based on metrics"""
    
    recommendations = []
    
    # Analyze usage patterns
    usage = bi_data.get("usage", {})
    if usage:
        summary = usage.get("summary", {})
        for metric_type, data in summary.items():
            total_usage = data.get("total_quantity", 0)
            if total_usage > 1000:  # High usage threshold
                recommendations.append(f"Consider optimizing {metric_type} usage - current: {total_usage}")
    
    # Analyze performance
    if metrics_summary.get("total_points", 0) == 0:
        recommendations.append("No recent metrics data - consider enabling more monitoring")
    
    # Check error rates
    error_metrics = metrics_summary.get("metrics_by_type", {}).get("error_rate", {})
    if error_metrics and error_metrics.get("average", 0) > 1:
        recommendations.append("Error rate is elevated - investigate system issues")
    
    # Add generic recommendations if none specific
    if not recommendations:
        recommendations.extend([
            "System appears to be running smoothly",
            "Consider enabling additional monitoring for better insights",
            "Review usage patterns regularly for optimization opportunities"
        ])
    
    return recommendations


async def _get_usage_projections(tenant_id: str, days: int) -> Dict[str, Any]:
    """Get usage projections for business intelligence"""
    
    # Placeholder implementation
    return {
        "projection_period_days": days,
        "projected_metrics": {},
        "confidence_score": 85.0
    }


async def _get_period_comparisons(tenant_id: str, days: int) -> Dict[str, Any]:
    """Get period-over-period comparisons"""
    
    # Placeholder implementation
    return {
        "current_period": {"days": days},
        "previous_period": {"days": days},
        "comparison_metrics": {},
        "trends": []
    }