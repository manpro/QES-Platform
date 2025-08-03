"""
Real-time Usage Tracking Middleware

Automatically tracks usage metrics for all API endpoints with configurable
rate limiting, quota enforcement, and real-time analytics.
"""

import logging
import time
import asyncio
from typing import Dict, Any, Optional, Callable
from datetime import datetime
from uuid import UUID

from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from billing.usage_tracker import UsageTracker
from billing.models import UsageMetricType
from billing.subscription_manager import SubscriptionManager
from core.audit_logger import AuditLogger, AuditEvent, AuditEventType
from auth.jwt_auth import get_current_user_from_token

logger = logging.getLogger(__name__)


class UsageTrackingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for real-time usage tracking and quota enforcement.
    
    Features:
    - Automatic usage recording for API endpoints
    - Real-time quota enforcement
    - Rate limiting per tenant
    - Performance analytics
    - Usage-based access control
    """
    
    def __init__(
        self, 
        app,
        usage_tracker: UsageTracker = None,
        subscription_manager: SubscriptionManager = None,
        audit_logger: AuditLogger = None
    ):
        super().__init__(app)
        self.usage_tracker = usage_tracker or UsageTracker()
        self.subscription_manager = subscription_manager
        self.audit_logger = audit_logger or AuditLogger({"postgres_enabled": True})
        
        # Define endpoint patterns and their corresponding usage metrics
        self.endpoint_metrics = {
            "/api/v1/documents": UsageMetricType.DOCUMENTS,
            "/api/v1/signatures": UsageMetricType.SIGNATURES,
            "/api/v1/blockchain": UsageMetricType.API_CALLS,
            "/api/v1/biometric": UsageMetricType.API_CALLS,
            "/api/v1/document-verification": UsageMetricType.API_CALLS,
            "/api/v1/tsa": UsageMetricType.API_CALLS,
        }
        
        # Rate limiting configuration (requests per minute)
        self.rate_limits = {
            "free": 100,
            "professional": 500,
            "enterprise": 2000
        }
        
        # In-memory rate limiting cache (in production, use Redis)
        self.rate_limit_cache = {}
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with usage tracking and quota enforcement"""
        
        start_time = time.time()
        
        # Skip tracking for non-API endpoints
        if not request.url.path.startswith("/api/"):
            return await call_next(request)
        
        try:
            # Extract user and tenant information
            user_info = await self._extract_user_info(request)
            
            if not user_info:
                # No authentication required for this endpoint
                return await call_next(request)
            
            tenant_id = user_info.get("tenant_id")
            user_id = user_info.get("user_id")
            subscription_id = user_info.get("subscription_id")
            
            # Check rate limits
            rate_limit_result = await self._check_rate_limit(request, tenant_id, user_info.get("plan_type"))
            
            if not rate_limit_result["allowed"]:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "error": "Rate limit exceeded",
                        "limit": rate_limit_result["limit"],
                        "reset_time": rate_limit_result["reset_time"],
                        "message": "Too many requests. Please try again later."
                    }
                )
            
            # Check usage quotas before processing request
            quota_check = await self._check_usage_quota(request, tenant_id, subscription_id)
            
            if not quota_check["allowed"]:
                return JSONResponse(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    content={
                        "error": "Usage quota exceeded",
                        "metric_type": quota_check["metric_type"],
                        "current_usage": quota_check["current_usage"],
                        "limit": quota_check["limit"],
                        "message": "Usage quota exceeded. Please upgrade your plan or wait for the next billing cycle."
                    }
                )
            
            # Process the request
            response = await call_next(request)
            
            # Record usage after successful request
            if response.status_code < 400:  # Only count successful requests
                await self._record_usage(request, response, tenant_id, user_id, subscription_id)
            
            # Add usage information to response headers
            response.headers["X-Usage-Recorded"] = "true"
            response.headers["X-Processing-Time"] = str(int((time.time() - start_time) * 1000))
            
            return response
            
        except Exception as e:
            logger.error(f"Usage tracking middleware error: {e}")
            # Don't block requests due to usage tracking errors
            return await call_next(request)
    
    async def _extract_user_info(self, request: Request) -> Optional[Dict[str, Any]]:
        """Extract user and tenant information from request"""
        try:
            # Try to get JWT token from Authorization header
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return None
            
            token = auth_header[7:]  # Remove "Bearer " prefix
            user = await get_current_user_from_token(token)
            
            if not user:
                return None
            
            # Get subscription information
            subscription = None
            if self.subscription_manager and user.tenant_id:
                subscription = self.subscription_manager.get_tenant_subscription(user.tenant_id)
            
            return {
                "user_id": user.id,
                "tenant_id": user.tenant_id,
                "subscription_id": subscription.id if subscription else None,
                "plan_type": subscription.plan.type.value if subscription else "free"
            }
            
        except Exception as e:
            logger.debug(f"Could not extract user info: {e}")
            return None
    
    async def _check_rate_limit(
        self, 
        request: Request, 
        tenant_id: UUID, 
        plan_type: str
    ) -> Dict[str, Any]:
        """Check if request is within rate limits"""
        
        try:
            current_time = datetime.utcnow()
            minute_key = current_time.strftime("%Y-%m-%d-%H-%M")
            cache_key = f"rate_limit:{tenant_id}:{minute_key}"
            
            # Get current count from cache
            current_count = self.rate_limit_cache.get(cache_key, 0)
            limit = self.rate_limits.get(plan_type, self.rate_limits["free"])
            
            if current_count >= limit:
                return {
                    "allowed": False,
                    "limit": limit,
                    "current": current_count,
                    "reset_time": (current_time.replace(second=0, microsecond=0).timestamp() + 60)
                }
            
            # Increment counter
            self.rate_limit_cache[cache_key] = current_count + 1
            
            # Clean old entries (keep only current and previous minute)
            self._cleanup_rate_limit_cache(current_time)
            
            return {
                "allowed": True,
                "limit": limit,
                "current": current_count + 1,
                "reset_time": (current_time.replace(second=0, microsecond=0).timestamp() + 60)
            }
            
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            # Allow request if rate limiting fails
            return {"allowed": True, "limit": 0, "current": 0}
    
    async def _check_usage_quota(
        self, 
        request: Request, 
        tenant_id: UUID, 
        subscription_id: UUID
    ) -> Dict[str, Any]:
        """Check if request would exceed usage quotas"""
        
        try:
            if not subscription_id:
                # No subscription - allow limited free usage
                return {"allowed": True}
            
            # Determine metric type based on endpoint
            metric_type = self._get_metric_type(request.url.path, request.method)
            
            if not metric_type:
                # No usage tracking for this endpoint
                return {"allowed": True}
            
            # Get current month usage
            current_usage = self.usage_tracker.get_current_month_usage(tenant_id)
            metric_usage = current_usage.get(metric_type.value, 0)
            
            # Get subscription limits
            if self.subscription_manager:
                subscription = self.subscription_manager.get_tenant_subscription(tenant_id)
                if subscription:
                    limits = self._get_plan_limits(subscription.plan)
                    limit = limits.get(metric_type.value, 0)
                    
                    if limit > 0 and metric_usage >= limit:
                        return {
                            "allowed": False,
                            "metric_type": metric_type.value,
                            "current_usage": metric_usage,
                            "limit": limit
                        }
            
            return {"allowed": True}
            
        except Exception as e:
            logger.error(f"Usage quota check failed: {e}")
            # Allow request if quota checking fails
            return {"allowed": True}
    
    async def _record_usage(
        self,
        request: Request,
        response: Response,
        tenant_id: UUID,
        user_id: UUID,
        subscription_id: UUID
    ):
        """Record usage for the processed request"""
        
        try:
            if not subscription_id:
                return  # No subscription to track usage against
            
            # Determine metric type and quantity
            metric_type = self._get_metric_type(request.url.path, request.method)
            
            if not metric_type:
                return  # No usage tracking for this endpoint
            
            # Calculate quantity based on endpoint and response
            quantity = await self._calculate_usage_quantity(request, response)
            
            # Extract resource ID from request/response
            resource_id = await self._extract_resource_id(request, response)
            
            # Record the usage
            usage_record = self.usage_tracker.record_usage(
                tenant_id=tenant_id,
                subscription_id=subscription_id,
                metric_type=metric_type,
                quantity=quantity,
                resource_id=resource_id,
                user_id=user_id,
                metadata={
                    "endpoint": request.url.path,
                    "method": request.method,
                    "user_agent": request.headers.get("User-Agent", ""),
                    "ip_address": request.client.host if request.client else "",
                    "response_status": response.status_code,
                    "response_size": len(response.body) if hasattr(response, 'body') else 0
                }
            )
            
            # Log usage for audit trail
            await self.audit_logger.log_event(AuditEvent(
                event_type=AuditEventType.SYSTEM_ERROR,  # Should be USAGE_RECORDED
                user_id=str(user_id),
                resource_id=resource_id,
                details={
                    "usage_record_id": str(usage_record.id),
                    "metric_type": metric_type.value,
                    "quantity": quantity,
                    "endpoint": request.url.path,
                    "tenant_id": str(tenant_id)
                }
            ))
            
        except Exception as e:
            logger.error(f"Failed to record usage: {e}")
            # Don't fail the request if usage recording fails
    
    def _get_metric_type(self, path: str, method: str) -> Optional[UsageMetricType]:
        """Determine usage metric type based on endpoint"""
        
        # Document operations
        if "/documents" in path:
            if method == "POST":
                return UsageMetricType.DOCUMENTS
            return UsageMetricType.API_CALLS
        
        # Signature operations
        elif "/signatures" in path:
            if method == "POST":
                return UsageMetricType.SIGNATURES
            return UsageMetricType.API_CALLS
        
        # Other API calls
        elif any(pattern in path for pattern in ["/blockchain", "/biometric", "/document-verification", "/tsa"]):
            return UsageMetricType.API_CALLS
        
        # File storage (calculated based on file size)
        elif "/upload" in path or "/download" in path:
            return UsageMetricType.STORAGE_GB
        
        return None
    
    async def _calculate_usage_quantity(self, request: Request, response: Response) -> int:
        """Calculate usage quantity based on request and response"""
        
        # For storage operations, use file size
        if "/upload" in request.url.path:
            content_length = request.headers.get("content-length")
            if content_length:
                # Convert bytes to GB (rounded up)
                bytes_size = int(content_length)
                gb_size = max(1, (bytes_size + 1024**3 - 1) // 1024**3)  # Round up to nearest GB
                return gb_size
        
        # For most operations, count as 1 unit
        return 1
    
    async def _extract_resource_id(self, request: Request, response: Response) -> Optional[str]:
        """Extract resource ID from request or response"""
        
        try:
            # Extract from URL path parameters
            path_parts = request.url.path.split('/')
            
            # Look for UUID-like patterns in path
            for part in path_parts:
                if len(part) == 36 and part.count('-') == 4:  # Simple UUID check
                    return part
            
            # Could also extract from response body if needed
            # response_data = await response.json() if hasattr(response, 'json') else None
            # if response_data and 'id' in response_data:
            #     return response_data['id']
            
            return None
            
        except Exception:
            return None
    
    def _get_plan_limits(self, plan) -> Dict[str, int]:
        """Get usage limits for a billing plan"""
        
        return {
            UsageMetricType.SIGNATURES.value: plan.signatures_included,
            UsageMetricType.DOCUMENTS.value: plan.documents_included,
            UsageMetricType.API_CALLS.value: plan.api_calls_included,
            UsageMetricType.STORAGE_GB.value: plan.storage_gb_included
        }
    
    def _cleanup_rate_limit_cache(self, current_time: datetime):
        """Clean up old rate limit cache entries"""
        
        try:
            current_minute = current_time.strftime("%Y-%m-%d-%H-%M")
            
            # Keep only current and previous minute
            keys_to_remove = []
            for key in self.rate_limit_cache.keys():
                if not key.endswith(current_minute):
                    # Check if it's the previous minute
                    prev_minute = (current_time.replace(second=0, microsecond=0) - 
                                 timedelta(minutes=1)).strftime("%Y-%m-%d-%H-%M")
                    if not key.endswith(prev_minute):
                        keys_to_remove.append(key)
            
            for key in keys_to_remove:
                del self.rate_limit_cache[key]
                
        except Exception as e:
            logger.debug(f"Cache cleanup error: {e}")


class UsageAnalytics:
    """Advanced usage analytics and reporting"""
    
    def __init__(self, usage_tracker: UsageTracker):
        self.usage_tracker = usage_tracker
    
    async def get_usage_trends(
        self,
        tenant_id: UUID,
        days: int = 30
    ) -> Dict[str, Any]:
        """Get usage trends over time"""
        
        try:
            from datetime import timedelta
            
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            
            # Get daily usage breakdown
            daily_usage = {}
            current_date = start_date
            
            while current_date <= end_date:
                day_start = current_date.replace(hour=0, minute=0, second=0, microsecond=0)
                day_end = day_start + timedelta(days=1)
                
                day_usage = self.usage_tracker.get_period_usage(tenant_id, day_start, day_end)
                daily_usage[day_start.strftime("%Y-%m-%d")] = day_usage
                
                current_date += timedelta(days=1)
            
            # Calculate trends
            total_usage = {}
            for day_data in daily_usage.values():
                for metric, count in day_data.items():
                    total_usage[metric] = total_usage.get(metric, 0) + count
            
            return {
                "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
                "daily_usage": daily_usage,
                "total_usage": total_usage,
                "average_daily": {
                    metric: total / days for metric, total in total_usage.items()
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get usage trends: {e}")
            raise
    
    async def get_cost_analysis(
        self,
        tenant_id: UUID,
        subscription_id: UUID
    ) -> Dict[str, Any]:
        """Analyze usage costs and projections"""
        
        try:
            # Get current month usage
            current_usage = self.usage_tracker.get_current_month_usage(tenant_id)
            
            # Get subscription details (would need subscription manager)
            # subscription = self.subscription_manager.get_subscription(subscription_id)
            
            # Calculate overage costs (placeholder)
            overage_costs = {
                "signatures": 0.10,  # $0.10 per extra signature
                "documents": 0.05,   # $0.05 per extra document
                "api_calls": 0.001,  # $0.001 per extra API call
                "storage_gb": 1.00   # $1.00 per extra GB
            }
            
            return {
                "current_usage": current_usage,
                "overage_costs": overage_costs,
                "projected_monthly_cost": 0.0  # Calculate based on current usage
            }
            
        except Exception as e:
            logger.error(f"Failed to get cost analysis: {e}")
            raise
    
    async def get_performance_metrics(
        self,
        tenant_id: UUID,
        hours: int = 24
    ) -> Dict[str, Any]:
        """Get performance metrics for usage tracking"""
        
        try:
            from datetime import timedelta
            
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=hours)
            
            # Get usage records for the period
            records = self.usage_tracker.get_usage_history(
                tenant_id=tenant_id,
                days=hours // 24 or 1,
                limit=1000
            )
            
            # Filter records to the exact time period
            period_records = [
                r for r in records 
                if start_time <= r.timestamp <= end_time
            ]
            
            # Calculate metrics
            total_requests = len(period_records)
            unique_users = len(set(r.user_id for r in period_records if r.user_id))
            
            # Group by hour
            hourly_breakdown = {}
            for record in period_records:
                hour_key = record.timestamp.strftime("%Y-%m-%d-%H")
                if hour_key not in hourly_breakdown:
                    hourly_breakdown[hour_key] = 0
                hourly_breakdown[hour_key] += record.quantity
            
            return {
                "period": {"start": start_time.isoformat(), "end": end_time.isoformat()},
                "total_requests": total_requests,
                "unique_users": unique_users,
                "average_requests_per_hour": total_requests / hours if hours > 0 else 0,
                "hourly_breakdown": hourly_breakdown
            }
            
        except Exception as e:
            logger.error(f"Failed to get performance metrics: {e}")
            raise