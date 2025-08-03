"""
Usage Tracking API Endpoints

Real-time usage analytics, quota management, and billing integration
with comprehensive reporting and enforcement capabilities.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Depends, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from auth.jwt_auth import get_current_user
from models.user import User
from billing.usage_tracker import UsageTracker
from billing.models import UsageMetricType
from core.usage_enforcement import UsageEnforcement
from core.usage_middleware import UsageAnalytics
from billing.subscription_manager import SubscriptionManager
from billing.stripe_client import StripeClient
from core.audit_logger import AuditLogger, AuditEvent, AuditEventType

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/usage", tags=["usage"])


class UsageStatsResponse(BaseModel):
    """Usage statistics response"""
    tenant_id: str
    current_period: Dict[str, Any]
    usage_by_metric: Dict[str, Any]
    billing_period: Dict[str, str]
    subscription_info: Dict[str, Any]


class QuotaStatusResponse(BaseModel):
    """Quota status response"""
    tenant_id: str
    metrics: Dict[str, Dict[str, Any]]
    overall_status: str
    warnings: List[str]
    recommendations: List[str]


class UsageProjectionRequest(BaseModel):
    """Request for usage projection"""
    days_ahead: int = Field(30, ge=1, le=365, description="Days to project ahead")
    metric_types: Optional[List[str]] = Field(None, description="Specific metrics to project")


class ExportUsageRequest(BaseModel):
    """Request to export usage data"""
    start_date: datetime = Field(..., description="Start date for export")
    end_date: datetime = Field(..., description="End date for export")
    format: str = Field("json", description="Export format (json/csv)")
    include_metadata: bool = Field(True, description="Include metadata in export")


def get_usage_services():
    """Get usage tracking service dependencies"""
    stripe_client = StripeClient()
    usage_tracker = UsageTracker()
    subscription_manager = SubscriptionManager(stripe_client, usage_tracker)
    audit_logger = AuditLogger({"postgres_enabled": True, "loki_enabled": True})
    
    usage_enforcement = UsageEnforcement(usage_tracker, subscription_manager, audit_logger)
    usage_analytics = UsageAnalytics(usage_tracker)
    
    return usage_tracker, usage_enforcement, usage_analytics, subscription_manager


@router.get("/stats", response_model=UsageStatsResponse)
async def get_usage_stats(
    current_user: User = Depends(get_current_user)
):
    """
    Get comprehensive usage statistics for the current user's tenant.
    
    Returns current usage, limits, and subscription information.
    """
    try:
        usage_tracker, usage_enforcement, _, subscription_manager = get_usage_services()
        
        # Get usage summary
        usage_summary = await usage_enforcement.get_usage_summary(current_user.tenant_id)
        
        if "error" in usage_summary:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=usage_summary["error"]
            )
        
        # Get current subscription
        subscription = subscription_manager.get_tenant_subscription(current_user.tenant_id)
        
        return UsageStatsResponse(
            tenant_id=str(current_user.tenant_id),
            current_period={
                "start": usage_summary["billing_period"]["start"],
                "end": usage_summary["billing_period"]["end"]
            },
            usage_by_metric=usage_summary["metrics"],
            billing_period=usage_summary["billing_period"],
            subscription_info={
                "plan_name": usage_summary["plan"]["name"],
                "plan_type": usage_summary["plan"]["type"],
                "subscription_id": usage_summary["subscription_id"]
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get usage stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve usage statistics"
        )


@router.get("/quota-status", response_model=QuotaStatusResponse)
async def get_quota_status(
    current_user: User = Depends(get_current_user)
):
    """
    Get current quota status and enforcement information.
    
    Returns quota limits, current usage, and any warnings or recommendations.
    """
    try:
        usage_tracker, usage_enforcement, _, _ = get_usage_services()
        
        # Get usage summary
        usage_summary = await usage_enforcement.get_usage_summary(current_user.tenant_id)
        
        if "error" in usage_summary:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=usage_summary["error"]
            )
        
        # Determine overall status
        overall_status = "normal"
        warnings = []
        recommendations = []
        
        for metric_name, metric_data in usage_summary["metrics"].items():
            if metric_data["status"] == "exceeded":
                overall_status = "exceeded"
                warnings.append(f"{metric_name} quota exceeded ({metric_data['percentage']}%)")
            elif metric_data["status"] == "warning" and overall_status == "normal":
                overall_status = "warning"
                warnings.append(f"{metric_name} approaching limit ({metric_data['percentage']}%)")
        
        # Generate recommendations
        if overall_status in ["warning", "exceeded"]:
            recommendations.append("Consider upgrading your plan for higher limits")
            recommendations.append("Review usage patterns to optimize consumption")
        
        return QuotaStatusResponse(
            tenant_id=str(current_user.tenant_id),
            metrics=usage_summary["metrics"],
            overall_status=overall_status,
            warnings=warnings,
            recommendations=recommendations
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get quota status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve quota status"
        )


@router.get("/analytics")
async def get_usage_analytics(
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
    current_user: User = Depends(get_current_user)
):
    """Get detailed usage analytics and trends"""
    
    try:
        usage_tracker, _, usage_analytics, _ = get_usage_services()
        
        # Get comprehensive analytics
        analytics = await usage_tracker.get_usage_analytics(current_user.tenant_id, days)
        
        # Get usage trends
        trends = await usage_analytics.get_usage_trends(current_user.tenant_id, days)
        
        # Get performance metrics
        performance = await usage_analytics.get_performance_metrics(current_user.tenant_id, 24)
        
        return {
            "tenant_id": str(current_user.tenant_id),
            "analytics": analytics,
            "trends": trends,
            "performance": performance
        }
        
    except Exception as e:
        logger.error(f"Failed to get usage analytics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve usage analytics"
        )


@router.post("/projections")
async def get_usage_projections(
    request: UsageProjectionRequest,
    current_user: User = Depends(get_current_user)
):
    """Get usage projections based on current trends"""
    
    try:
        usage_tracker, usage_enforcement, _, _ = get_usage_services()
        
        # Get usage projections
        projections = await usage_enforcement.project_usage(
            current_user.tenant_id, 
            request.days_ahead
        )
        
        # If specific metrics requested, filter
        if request.metric_types:
            filtered_projections = {}
            for metric_type in request.metric_types:
                if metric_type in projections["projections"]:
                    filtered_projections[metric_type] = projections["projections"][metric_type]
            projections["projections"] = filtered_projections
        
        return projections
        
    except Exception as e:
        logger.error(f"Failed to get usage projections: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate usage projections"
        )


@router.get("/real-time")
async def get_real_time_usage(
    hours: int = Query(1, ge=1, le=24, description="Hours to analyze"),
    metric_type: Optional[str] = Query(None, description="Specific metric to filter"),
    current_user: User = Depends(get_current_user)
):
    """Get real-time usage statistics"""
    
    try:
        usage_tracker, _, _, _ = get_usage_services()
        
        # Parse metric type if provided
        parsed_metric_type = None
        if metric_type:
            try:
                parsed_metric_type = UsageMetricType(metric_type)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid metric type: {metric_type}"
                )
        
        # Get real-time usage
        real_time_data = await usage_tracker.get_real_time_usage(
            current_user.tenant_id,
            parsed_metric_type,
            hours
        )
        
        return real_time_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get real-time usage: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve real-time usage"
        )


@router.get("/violations")
async def get_quota_violations(
    days: int = Query(30, ge=1, le=90, description="Days to look back"),
    current_user: User = Depends(get_current_user)
):
    """Get recent quota violations and enforcement actions"""
    
    try:
        usage_tracker, usage_enforcement, _, _ = get_usage_services()
        
        # Get quota violations
        violations = await usage_enforcement.get_quota_violations(
            current_user.tenant_id,
            days
        )
        
        return {
            "tenant_id": str(current_user.tenant_id),
            "period_days": days,
            "violations": violations,
            "total_violations": len(violations)
        }
        
    except Exception as e:
        logger.error(f"Failed to get quota violations: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve quota violations"
        )


@router.post("/export")
async def export_usage_data(
    request: ExportUsageRequest,
    current_user: User = Depends(get_current_user)
):
    """Export usage data for reporting or backup"""
    
    try:
        usage_tracker, _, _, _ = get_usage_services()
        
        # Validate date range
        if request.start_date >= request.end_date:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Start date must be before end date"
            )
        
        # Limit export range to prevent large exports
        max_days = 365
        if (request.end_date - request.start_date).days > max_days:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Export range cannot exceed {max_days} days"
            )
        
        # Export usage data
        export_data = await usage_tracker.export_usage_data(
            current_user.tenant_id,
            request.start_date,
            request.end_date,
            request.format
        )
        
        # Log export for audit trail
        audit_logger = AuditLogger({"postgres_enabled": True})
        await audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.SYSTEM_ERROR,  # Should be USAGE_EXPORT
            user_id=str(current_user.id),
            details={
                "export_period_start": request.start_date.isoformat(),
                "export_period_end": request.end_date.isoformat(),
                "format": request.format,
                "record_count": export_data["record_count"],
                "tenant_id": str(current_user.tenant_id)
            }
        ))
        
        return export_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to export usage data: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export usage data"
        )


@router.get("/patterns")
async def analyze_usage_patterns(
    days: int = Query(30, ge=7, le=90, description="Days to analyze"),
    current_user: User = Depends(get_current_user)
):
    """Analyze usage patterns and identify trends"""
    
    try:
        from core.usage_enforcement import UsagePrediction
        
        usage_tracker, _, _, _ = get_usage_services()
        usage_prediction = UsagePrediction(usage_tracker)
        
        # Get pattern analysis
        patterns = await usage_prediction.analyze_usage_patterns(
            current_user.tenant_id,
            days
        )
        
        # Get predictions for each metric type
        predictions = {}
        for metric_type in UsageMetricType:
            try:
                prediction = await usage_prediction.predict_monthly_usage(
                    current_user.tenant_id,
                    metric_type
                )
                predictions[metric_type.value] = prediction
            except Exception as e:
                logger.warning(f"Failed to predict {metric_type.value}: {e}")
                continue
        
        return {
            "tenant_id": str(current_user.tenant_id),
            "patterns": patterns,
            "predictions": predictions
        }
        
    except Exception as e:
        logger.error(f"Failed to analyze usage patterns: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to analyze usage patterns"
        )


@router.post("/test-enforcement")
async def test_quota_enforcement(
    metric_type: str,
    quantity: int = 1,
    current_user: User = Depends(get_current_user)
):
    """
    Test quota enforcement for a specific metric (admin only).
    
    This endpoint allows testing the quota enforcement system
    without actually consuming resources.
    """
    try:
        # Check if user has admin access
        if current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        
        # Parse metric type
        try:
            parsed_metric_type = UsageMetricType(metric_type)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid metric type: {metric_type}"
            )
        
        usage_tracker, usage_enforcement, _, _ = get_usage_services()
        
        # Test quota enforcement
        allowance = await usage_enforcement.check_usage_allowance(
            current_user.tenant_id,
            parsed_metric_type,
            quantity
        )
        
        return {
            "tenant_id": str(current_user.tenant_id),
            "metric_type": metric_type,
            "requested_quantity": quantity,
            "enforcement_result": allowance
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to test quota enforcement: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to test quota enforcement"
        )


@router.get("/health")
async def usage_service_health():
    """Health check for usage tracking service"""
    
    try:
        usage_tracker, _, _, _ = get_usage_services()
        
        # Test database connectivity
        test_tenant_id = "test-tenant-id"
        current_usage = usage_tracker.get_current_month_usage(test_tenant_id)
        
        # Check if batch buffer is functioning
        batch_buffer_size = len(usage_tracker._batch_buffer) if hasattr(usage_tracker, '_batch_buffer') else 0
        
        return {
            "status": "healthy",
            "service": "usage_tracking",
            "database_accessible": True,
            "batch_buffer_size": batch_buffer_size,
            "last_flush": usage_tracker._last_flush.isoformat() if hasattr(usage_tracker, '_last_flush') else None
        }
        
    except Exception as e:
        logger.error(f"Usage service health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Usage tracking service unhealthy: {str(e)}"
        )