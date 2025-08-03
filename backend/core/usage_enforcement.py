"""
Usage Enforcement and Quota Management

Advanced usage enforcement with soft/hard limits, grace periods,
and automated notifications for quota management.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from decimal import Decimal
from uuid import UUID
from enum import Enum

from billing.usage_tracker import UsageTracker
from billing.models import UsageMetricType, BillingPlan
from billing.subscription_manager import SubscriptionManager
from core.audit_logger import AuditLogger, AuditEvent, AuditEventType

logger = logging.getLogger(__name__)


class QuotaViolationType(str, Enum):
    """Types of quota violations"""
    SOFT_LIMIT = "soft_limit"      # Warning threshold reached
    HARD_LIMIT = "hard_limit"      # Usage blocked
    OVERAGE = "overage"            # Billable overage usage
    RATE_LIMIT = "rate_limit"      # Too many requests


class QuotaAction(str, Enum):
    """Actions to take on quota violations"""
    WARN = "warn"                  # Send warning notification
    THROTTLE = "throttle"          # Reduce rate limits
    BLOCK = "block"                # Block further usage
    CHARGE_OVERAGE = "charge_overage"  # Allow with overage charges


class QuotaPolicy:
    """Configuration for usage quota enforcement"""
    
    def __init__(
        self,
        metric_type: UsageMetricType,
        soft_limit_percentage: float = 0.8,
        hard_limit_percentage: float = 1.0,
        overage_allowed: bool = False,
        overage_price: Decimal = Decimal("0"),
        grace_period_hours: int = 24,
        notification_thresholds: List[float] = None
    ):
        self.metric_type = metric_type
        self.soft_limit_percentage = soft_limit_percentage
        self.hard_limit_percentage = hard_limit_percentage
        self.overage_allowed = overage_allowed
        self.overage_price = overage_price
        self.grace_period_hours = grace_period_hours
        self.notification_thresholds = notification_thresholds or [0.5, 0.8, 0.9, 1.0]


class UsageEnforcement:
    """
    Advanced usage enforcement with configurable policies.
    
    Features:
    - Soft and hard quota limits
    - Overage billing support
    - Grace periods for trial users
    - Automated notifications
    - Usage analytics and projections
    """
    
    def __init__(
        self,
        usage_tracker: UsageTracker,
        subscription_manager: SubscriptionManager,
        audit_logger: AuditLogger
    ):
        self.usage_tracker = usage_tracker
        self.subscription_manager = subscription_manager
        self.audit_logger = audit_logger
        
        # Default quota policies
        self.quota_policies = {
            UsageMetricType.SIGNATURES: QuotaPolicy(
                metric_type=UsageMetricType.SIGNATURES,
                overage_allowed=True,
                overage_price=Decimal("0.50")  # $0.50 per extra signature
            ),
            UsageMetricType.DOCUMENTS: QuotaPolicy(
                metric_type=UsageMetricType.DOCUMENTS,
                overage_allowed=True,
                overage_price=Decimal("0.10")  # $0.10 per extra document
            ),
            UsageMetricType.API_CALLS: QuotaPolicy(
                metric_type=UsageMetricType.API_CALLS,
                overage_allowed=True,
                overage_price=Decimal("0.001")  # $0.001 per extra API call
            ),
            UsageMetricType.STORAGE_GB: QuotaPolicy(
                metric_type=UsageMetricType.STORAGE_GB,
                overage_allowed=False,  # Hard limit on storage
                hard_limit_percentage=1.0
            )
        }
    
    async def check_usage_allowance(
        self,
        tenant_id: UUID,
        metric_type: UsageMetricType,
        requested_quantity: int = 1
    ) -> Dict[str, Any]:
        """
        Check if usage is allowed and what action to take.
        
        Args:
            tenant_id: Tenant identifier
            metric_type: Type of usage metric
            requested_quantity: Amount of usage being requested
            
        Returns:
            Dictionary with allowance decision and metadata
        """
        try:
            # Get current subscription
            subscription = self.subscription_manager.get_tenant_subscription(tenant_id)
            if not subscription:
                return {
                    "allowed": False,
                    "reason": "no_subscription",
                    "message": "No active subscription found"
                }
            
            # Get quota policy
            policy = self.quota_policies.get(metric_type)
            if not policy:
                # No policy defined - allow usage
                return {"allowed": True, "reason": "no_policy"}
            
            # Get current usage and limits
            current_usage = self.usage_tracker.get_current_month_usage(tenant_id)
            metric_usage = current_usage.get(metric_type.value, 0)
            plan_limit = self._get_plan_limit(subscription.plan, metric_type)
            
            # Calculate usage after this request
            projected_usage = metric_usage + requested_quantity
            
            # Check limits
            soft_limit = int(plan_limit * policy.soft_limit_percentage)
            hard_limit = int(plan_limit * policy.hard_limit_percentage)
            
            # Determine action
            if projected_usage <= soft_limit:
                # Within normal usage
                return {
                    "allowed": True,
                    "reason": "within_limits",
                    "current_usage": metric_usage,
                    "limit": plan_limit,
                    "usage_percentage": (metric_usage / plan_limit * 100) if plan_limit > 0 else 0
                }
            
            elif projected_usage <= hard_limit:
                # Soft limit exceeded - warn but allow
                await self._handle_quota_violation(
                    tenant_id, metric_type, QuotaViolationType.SOFT_LIMIT,
                    metric_usage, plan_limit
                )
                
                return {
                    "allowed": True,
                    "reason": "soft_limit_exceeded",
                    "warning": True,
                    "current_usage": metric_usage,
                    "limit": plan_limit,
                    "usage_percentage": (metric_usage / plan_limit * 100) if plan_limit > 0 else 0
                }
            
            elif policy.overage_allowed:
                # Hard limit exceeded but overage allowed
                overage_quantity = projected_usage - hard_limit
                overage_charge = overage_quantity * policy.overage_price
                
                await self._handle_quota_violation(
                    tenant_id, metric_type, QuotaViolationType.OVERAGE,
                    metric_usage, plan_limit, overage_charge
                )
                
                return {
                    "allowed": True,
                    "reason": "overage_billing",
                    "overage": True,
                    "overage_quantity": overage_quantity,
                    "overage_charge": float(overage_charge),
                    "current_usage": metric_usage,
                    "limit": plan_limit
                }
            
            else:
                # Hard limit exceeded and no overage allowed
                await self._handle_quota_violation(
                    tenant_id, metric_type, QuotaViolationType.HARD_LIMIT,
                    metric_usage, plan_limit
                )
                
                return {
                    "allowed": False,
                    "reason": "hard_limit_exceeded",
                    "current_usage": metric_usage,
                    "limit": plan_limit,
                    "message": f"Monthly {metric_type.value} limit exceeded. Please upgrade your plan."
                }
        
        except Exception as e:
            logger.error(f"Usage allowance check failed: {e}")
            # Allow usage if checking fails (fail open)
            return {"allowed": True, "reason": "check_failed", "error": str(e)}
    
    async def get_usage_summary(self, tenant_id: UUID) -> Dict[str, Any]:
        """Get comprehensive usage summary for a tenant"""
        
        try:
            subscription = self.subscription_manager.get_tenant_subscription(tenant_id)
            if not subscription:
                return {"error": "No subscription found"}
            
            current_usage = self.usage_tracker.get_current_month_usage(tenant_id)
            
            summary = {
                "tenant_id": str(tenant_id),
                "subscription_id": str(subscription.id),
                "plan": {
                    "id": subscription.plan.id,
                    "name": subscription.plan.name,
                    "type": subscription.plan.type.value
                },
                "billing_period": {
                    "start": subscription.current_period_start.isoformat(),
                    "end": subscription.current_period_end.isoformat()
                },
                "metrics": {}
            }
            
            # Analyze each metric type
            for metric_type in UsageMetricType:
                usage_count = current_usage.get(metric_type.value, 0)
                limit = self._get_plan_limit(subscription.plan, metric_type)
                
                usage_percentage = (usage_count / limit * 100) if limit > 0 else 0
                remaining = max(0, limit - usage_count)
                
                # Determine status
                policy = self.quota_policies.get(metric_type)
                if policy:
                    soft_limit = int(limit * policy.soft_limit_percentage)
                    if usage_count >= limit:
                        status = "exceeded"
                    elif usage_count >= soft_limit:
                        status = "warning"
                    else:
                        status = "normal"
                else:
                    status = "normal"
                
                summary["metrics"][metric_type.value] = {
                    "usage": usage_count,
                    "limit": limit,
                    "remaining": remaining,
                    "percentage": round(usage_percentage, 2),
                    "status": status,
                    "overage_allowed": policy.overage_allowed if policy else False
                }
            
            return summary
            
        except Exception as e:
            logger.error(f"Failed to get usage summary: {e}")
            raise
    
    async def project_usage(
        self,
        tenant_id: UUID,
        days_ahead: int = 30
    ) -> Dict[str, Any]:
        """Project future usage based on current trends"""
        
        try:
            # Get historical usage for trend analysis
            history_days = min(30, days_ahead)  # Use up to 30 days of history
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=history_days)
            
            historical_usage = self.usage_tracker.get_period_usage(tenant_id, start_date, end_date)
            
            projections = {}
            
            for metric_type, historical_count in historical_usage.items():
                # Calculate daily average
                daily_average = historical_count / history_days
                
                # Project future usage
                projected_total = daily_average * days_ahead
                
                projections[metric_type] = {
                    "historical_usage": historical_count,
                    "historical_days": history_days,
                    "daily_average": round(daily_average, 2),
                    "projected_usage": round(projected_total, 0),
                    "projection_period_days": days_ahead
                }
            
            return {
                "tenant_id": str(tenant_id),
                "projection_date": datetime.utcnow().isoformat(),
                "historical_period": {
                    "start": start_date.isoformat(),
                    "end": end_date.isoformat(),
                    "days": history_days
                },
                "projections": projections
            }
            
        except Exception as e:
            logger.error(f"Failed to project usage: {e}")
            raise
    
    async def get_quota_violations(
        self,
        tenant_id: UUID,
        days: int = 30
    ) -> List[Dict[str, Any]]:
        """Get recent quota violations for a tenant"""
        
        try:
            # This would query a quota_violations table in a real implementation
            # For now, return a placeholder structure
            
            violations = []
            
            # Example violation (would come from database)
            # violations.append({
            #     "id": "violation_id",
            #     "timestamp": datetime.utcnow().isoformat(),
            #     "metric_type": "signatures",
            #     "violation_type": "soft_limit",
            #     "usage_count": 85,
            #     "limit": 100,
            #     "action_taken": "warning_sent"
            # })
            
            return violations
            
        except Exception as e:
            logger.error(f"Failed to get quota violations: {e}")
            raise
    
    def _get_plan_limit(self, plan: BillingPlan, metric_type: UsageMetricType) -> int:
        """Get plan limit for a specific metric type"""
        
        if metric_type == UsageMetricType.SIGNATURES:
            return plan.signatures_included
        elif metric_type == UsageMetricType.DOCUMENTS:
            return plan.documents_included
        elif metric_type == UsageMetricType.API_CALLS:
            return plan.api_calls_included
        elif metric_type == UsageMetricType.STORAGE_GB:
            return plan.storage_gb_included
        else:
            return 0
    
    async def _handle_quota_violation(
        self,
        tenant_id: UUID,
        metric_type: UsageMetricType,
        violation_type: QuotaViolationType,
        current_usage: int,
        limit: int,
        overage_charge: Decimal = None
    ):
        """Handle quota violation by logging and triggering notifications"""
        
        try:
            # Log the violation
            await self.audit_logger.log_event(AuditEvent(
                event_type=AuditEventType.SYSTEM_ERROR,  # Should be QUOTA_VIOLATION
                details={
                    "tenant_id": str(tenant_id),
                    "metric_type": metric_type.value,
                    "violation_type": violation_type.value,
                    "current_usage": current_usage,
                    "limit": limit,
                    "overage_charge": float(overage_charge) if overage_charge else None,
                    "timestamp": datetime.utcnow().isoformat()
                }
            ))
            
            # In a real implementation, this would trigger notifications
            # to the tenant about the quota violation
            logger.info(
                f"Quota violation: tenant={tenant_id}, "
                f"metric={metric_type.value}, type={violation_type.value}, "
                f"usage={current_usage}, limit={limit}"
            )
            
        except Exception as e:
            logger.error(f"Failed to handle quota violation: {e}")


class UsagePrediction:
    """Predictive analytics for usage patterns"""
    
    def __init__(self, usage_tracker: UsageTracker):
        self.usage_tracker = usage_tracker
    
    async def predict_monthly_usage(
        self,
        tenant_id: UUID,
        metric_type: UsageMetricType
    ) -> Dict[str, Any]:
        """Predict end-of-month usage based on current trends"""
        
        try:
            # Get current month usage
            now = datetime.utcnow()
            month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            
            current_usage = self.usage_tracker.get_period_usage(tenant_id, month_start, now)
            metric_usage = current_usage.get(metric_type.value, 0)
            
            # Calculate days elapsed and remaining in month
            days_elapsed = (now - month_start).days + 1
            
            # Calculate days in current month
            if month_start.month == 12:
                next_month = month_start.replace(year=month_start.year + 1, month=1)
            else:
                next_month = month_start.replace(month=month_start.month + 1)
            
            days_in_month = (next_month - month_start).days
            days_remaining = days_in_month - days_elapsed
            
            # Calculate daily average and project
            daily_average = metric_usage / days_elapsed if days_elapsed > 0 else 0
            projected_monthly = daily_average * days_in_month
            
            return {
                "metric_type": metric_type.value,
                "current_usage": metric_usage,
                "days_elapsed": days_elapsed,
                "days_remaining": days_remaining,
                "daily_average": round(daily_average, 2),
                "projected_monthly": round(projected_monthly, 0),
                "confidence": min(100, days_elapsed * 3.33)  # Higher confidence with more data
            }
            
        except Exception as e:
            logger.error(f"Failed to predict monthly usage: {e}")
            raise
    
    async def analyze_usage_patterns(
        self,
        tenant_id: UUID,
        days: int = 30
    ) -> Dict[str, Any]:
        """Analyze usage patterns and identify trends"""
        
        try:
            # Get usage history
            records = self.usage_tracker.get_usage_history(tenant_id, days=days, limit=1000)
            
            if not records:
                return {"message": "No usage data available"}
            
            # Group by day and metric type
            daily_usage = {}
            for record in records:
                day_key = record.timestamp.strftime("%Y-%m-%d")
                metric_key = record.metric_type.value
                
                if day_key not in daily_usage:
                    daily_usage[day_key] = {}
                if metric_key not in daily_usage[day_key]:
                    daily_usage[day_key][metric_key] = 0
                
                daily_usage[day_key][metric_key] += record.quantity
            
            # Analyze patterns
            patterns = {
                "peak_usage_days": {},
                "average_daily_usage": {},
                "usage_trends": {},
                "weekly_patterns": {}
            }
            
            # Calculate averages and find peaks
            for metric_type in UsageMetricType:
                metric_key = metric_type.value
                daily_counts = []
                
                for day_data in daily_usage.values():
                    daily_counts.append(day_data.get(metric_key, 0))
                
                if daily_counts:
                    avg_daily = sum(daily_counts) / len(daily_counts)
                    max_daily = max(daily_counts)
                    
                    patterns["average_daily_usage"][metric_key] = round(avg_daily, 2)
                    patterns["peak_usage_days"][metric_key] = max_daily
            
            return {
                "tenant_id": str(tenant_id),
                "analysis_period_days": days,
                "total_records_analyzed": len(records),
                "patterns": patterns,
                "daily_breakdown": daily_usage
            }
            
        except Exception as e:
            logger.error(f"Failed to analyze usage patterns: {e}")
            raise