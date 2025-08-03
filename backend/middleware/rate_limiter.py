"""
Rate Limiting and Quota Management Middleware

Implements per-tenant rate limiting and quota management for QES operations
using Redis-based sliding window counters and configurable limits.
"""

import asyncio
import time
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import json

from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
import redis.asyncio as redis
import structlog

from .tenant_resolver import get_current_tenant, TenantContext

logger = structlog.get_logger(__name__)


class LimitType(Enum):
    """Types of rate limits and quotas."""
    REQUESTS_PER_MINUTE = "requests_per_minute"
    REQUESTS_PER_HOUR = "requests_per_hour"
    REQUESTS_PER_DAY = "requests_per_day"
    SIGNATURES_PER_HOUR = "signatures_per_hour"
    SIGNATURES_PER_DAY = "signatures_per_day"
    SIGNATURES_PER_MONTH = "signatures_per_month"
    STORAGE_QUOTA_MB = "storage_quota_mb"
    CONCURRENT_SESSIONS = "concurrent_sessions"


class QuotaExceededError(HTTPException):
    """Raised when quota limit is exceeded."""
    def __init__(self, limit_type: LimitType, limit: int, current: int, reset_time: int):
        self.limit_type = limit_type
        self.limit = limit
        self.current = current
        self.reset_time = reset_time
        
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Quota exceeded for {limit_type.value}: {current}/{limit}",
            headers={
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": str(max(0, limit - current)),
                "X-RateLimit-Reset": str(reset_time),
                "Retry-After": str(max(1, reset_time - int(time.time())))
            }
        )


@dataclass
class RateLimit:
    """Rate limit configuration."""
    limit_type: LimitType
    limit: int
    window_seconds: int
    
    
@dataclass
class TenantLimits:
    """Tenant-specific limits configuration."""
    tenant_id: str
    rate_limits: Dict[LimitType, RateLimit]
    is_enabled: bool = True
    
    def get_limit(self, limit_type: LimitType) -> Optional[RateLimit]:
        """Get rate limit for specific type."""
        return self.rate_limits.get(limit_type)


class RateLimiter:
    """
    Redis-based rate limiter with sliding window algorithm.
    
    Implements per-tenant rate limiting with configurable limits
    and automatic quota management.
    """
    
    def __init__(self, redis_client: redis.Redis, 
                 default_limits: Dict[LimitType, RateLimit]):
        self.redis = redis_client
        self.default_limits = default_limits
        self._tenant_limits_cache: Dict[str, TenantLimits] = {}
        self._cache_timestamps: Dict[str, float] = {}
        self.cache_ttl = 300  # 5 minutes
        
    async def check_rate_limit(self, 
                             tenant: TenantContext,
                             limit_type: LimitType,
                             increment: int = 1) -> Tuple[bool, int, int, int]:
        """
        Check if request is within rate limits.
        
        Args:
            tenant: Tenant context
            limit_type: Type of limit to check
            increment: Amount to increment counter by
            
        Returns:
            Tuple of (allowed, current_count, limit, reset_time)
            
        Raises:
            QuotaExceededError: If limit is exceeded
        """
        # Get tenant limits
        tenant_limits = await self._get_tenant_limits(tenant)
        rate_limit = tenant_limits.get_limit(limit_type)
        
        if not rate_limit:
            # No limit configured, allow request
            return True, 0, -1, 0
            
        # Generate Redis key
        key = self._generate_key(tenant.tenant_id, limit_type, rate_limit.window_seconds)
        
        # Use sliding window algorithm
        current_time = int(time.time())
        window_start = current_time - rate_limit.window_seconds
        
        # Redis pipeline for atomic operations
        pipe = self.redis.pipeline()
        
        # Remove expired entries
        pipe.zremrangebyscore(key, 0, window_start)
        
        # Count current requests in window
        pipe.zcard(key)
        
        # Add current request
        pipe.zadd(key, {f"{current_time}:{asyncio.get_event_loop().time()}": current_time})
        
        # Set expiration
        pipe.expire(key, rate_limit.window_seconds + 60)
        
        # Execute pipeline
        results = await pipe.execute()
        current_count = results[1]
        
        # Calculate reset time (next window)
        reset_time = current_time + rate_limit.window_seconds
        
        # Check if limit exceeded
        if current_count > rate_limit.limit:
            logger.warning("Rate limit exceeded",
                         tenant_id=tenant.tenant_id,
                         limit_type=limit_type.value,
                         current=current_count,
                         limit=rate_limit.limit)
            
            # Remove the request we just added since it's rejected
            await self.redis.zrem(key, f"{current_time}:{asyncio.get_event_loop().time()}")
            
            raise QuotaExceededError(
                limit_type=limit_type,
                limit=rate_limit.limit,
                current=current_count,
                reset_time=reset_time
            )
            
        logger.debug("Rate limit check passed",
                    tenant_id=tenant.tenant_id,
                    limit_type=limit_type.value,
                    current=current_count,
                    limit=rate_limit.limit)
        
        return True, current_count, rate_limit.limit, reset_time
        
    async def get_usage_stats(self, 
                            tenant: TenantContext) -> Dict[str, Dict[str, Any]]:
        """Get current usage statistics for tenant."""
        tenant_limits = await self._get_tenant_limits(tenant)
        stats = {}
        
        for limit_type, rate_limit in tenant_limits.rate_limits.items():
            key = self._generate_key(tenant.tenant_id, limit_type, rate_limit.window_seconds)
            
            current_time = int(time.time())
            window_start = current_time - rate_limit.window_seconds
            
            # Count requests in current window
            current_count = await self.redis.zcount(key, window_start, current_time)
            
            # Calculate reset time
            reset_time = current_time + rate_limit.window_seconds
            
            stats[limit_type.value] = {
                "current": current_count,
                "limit": rate_limit.limit,
                "remaining": max(0, rate_limit.limit - current_count),
                "reset_time": reset_time,
                "window_seconds": rate_limit.window_seconds
            }
            
        return stats
        
    async def reset_quota(self, 
                        tenant: TenantContext,
                        limit_type: LimitType) -> bool:
        """Reset quota for specific limit type."""
        tenant_limits = await self._get_tenant_limits(tenant)
        rate_limit = tenant_limits.get_limit(limit_type)
        
        if not rate_limit:
            return False
            
        key = self._generate_key(tenant.tenant_id, limit_type, rate_limit.window_seconds)
        await self.redis.delete(key)
        
        logger.info("Quota reset",
                   tenant_id=tenant.tenant_id,
                   limit_type=limit_type.value)
        
        return True
        
    def _generate_key(self, tenant_id: str, limit_type: LimitType, window: int) -> str:
        """Generate Redis key for rate limit counter."""
        current_time = int(time.time())
        window_start = (current_time // window) * window
        return f"qes:ratelimit:{tenant_id}:{limit_type.value}:{window_start}"
        
    async def _get_tenant_limits(self, tenant: TenantContext) -> TenantLimits:
        """Get tenant-specific limits with caching."""
        # Check cache first
        if tenant.tenant_id in self._tenant_limits_cache:
            if self._is_cache_valid(tenant.tenant_id):
                return self._tenant_limits_cache[tenant.tenant_id]
            else:
                # Remove expired cache
                del self._tenant_limits_cache[tenant.tenant_id]
                del self._cache_timestamps[tenant.tenant_id]
                
        # Get limits from tenant settings
        tenant_limits = self._parse_tenant_limits(tenant)
        
        # Cache the result
        self._tenant_limits_cache[tenant.tenant_id] = tenant_limits
        self._cache_timestamps[tenant.tenant_id] = time.time()
        
        return tenant_limits
        
    def _parse_tenant_limits(self, tenant: TenantContext) -> TenantLimits:
        """Parse tenant settings to extract rate limits."""
        limits_config = tenant.get_setting("rate_limits", {})
        rate_limits = {}
        
        # Parse configured limits
        for limit_type_str, config in limits_config.items():
            try:
                limit_type = LimitType(limit_type_str)
                rate_limits[limit_type] = RateLimit(
                    limit_type=limit_type,
                    limit=config.get("limit", 0),
                    window_seconds=config.get("window_seconds", 3600)
                )
            except ValueError:
                logger.warning("Unknown limit type in tenant config",
                             tenant_id=tenant.tenant_id,
                             limit_type=limit_type_str)
                
        # Apply default limits for missing configurations
        for limit_type, default_limit in self.default_limits.items():
            if limit_type not in rate_limits:
                rate_limits[limit_type] = default_limit
                
        return TenantLimits(
            tenant_id=tenant.tenant_id,
            rate_limits=rate_limits,
            is_enabled=tenant.get_setting("rate_limiting_enabled", True)
        )
        
    def _is_cache_valid(self, tenant_id: str) -> bool:
        """Check if cached limits are still valid."""
        if tenant_id not in self._cache_timestamps:
            return False
            
        age = time.time() - self._cache_timestamps[tenant_id]
        return age < self.cache_ttl


class RateLimitingMiddleware:
    """
    FastAPI middleware for rate limiting and quota management.
    """
    
    def __init__(self, rate_limiter: RateLimiter):
        self.rate_limiter = rate_limiter
        
    async def __call__(self, request: Request, call_next):
        """Apply rate limiting to requests."""
        try:
            # Skip rate limiting for certain paths
            if self._should_skip_rate_limiting(request.url.path):
                return await call_next(request)
                
            # Get tenant context
            if not hasattr(request.state, 'tenant'):
                # Tenant not resolved, skip rate limiting
                return await call_next(request)
                
            tenant = request.state.tenant
            
            # Determine limit type based on endpoint
            limit_type = self._get_limit_type_for_request(request)
            
            # Check rate limit
            allowed, current, limit, reset_time = await self.rate_limiter.check_rate_limit(
                tenant=tenant,
                limit_type=limit_type
            )
            
            # Process request
            response = await call_next(request)
            
            # Add rate limit headers
            if limit > 0:  # Only add headers if limit is configured
                response.headers["X-RateLimit-Limit"] = str(limit)
                response.headers["X-RateLimit-Remaining"] = str(max(0, limit - current))
                response.headers["X-RateLimit-Reset"] = str(reset_time)
                
            return response
            
        except QuotaExceededError as e:
            # Return rate limit exceeded response
            return JSONResponse(
                status_code=e.status_code,
                content={
                    "error": "quota_exceeded",
                    "message": e.detail,
                    "limit_type": e.limit_type.value,
                    "current": e.current,
                    "limit": e.limit,
                    "reset_time": e.reset_time,
                    "timestamp": int(time.time())
                },
                headers=dict(e.headers) if e.headers else {}
            )
            
        except Exception as e:
            # Log unexpected errors but don't block requests
            logger.error("Rate limiting error", error=str(e))
            return await call_next(request)
            
    def _should_skip_rate_limiting(self, path: str) -> bool:
        """Check if path should skip rate limiting."""
        skip_paths = [
            '/health',
            '/metrics',
            '/favicon.ico',
            '/robots.txt',
            '/docs',
            '/redoc',
            '/openapi.json'
        ]
        
        return any(path.startswith(skip_path) for skip_path in skip_paths)
        
    def _get_limit_type_for_request(self, request: Request) -> LimitType:
        """Determine appropriate limit type for request."""
        path = request.url.path
        method = request.method
        
        # Signature operations have stricter limits
        if '/api/v1/sign' in path and method == 'POST':
            return LimitType.SIGNATURES_PER_HOUR
            
        # Authentication endpoints
        if '/api/v1/auth' in path:
            return LimitType.REQUESTS_PER_MINUTE
            
        # General API requests
        return LimitType.REQUESTS_PER_HOUR


# Default rate limits for different tenant tiers
DEFAULT_RATE_LIMITS = {
    # Free tier limits
    "free": {
        LimitType.REQUESTS_PER_MINUTE: RateLimit(LimitType.REQUESTS_PER_MINUTE, 10, 60),
        LimitType.REQUESTS_PER_HOUR: RateLimit(LimitType.REQUESTS_PER_HOUR, 100, 3600),
        LimitType.SIGNATURES_PER_HOUR: RateLimit(LimitType.SIGNATURES_PER_HOUR, 5, 3600),
        LimitType.SIGNATURES_PER_DAY: RateLimit(LimitType.SIGNATURES_PER_DAY, 20, 86400),
        LimitType.SIGNATURES_PER_MONTH: RateLimit(LimitType.SIGNATURES_PER_MONTH, 100, 2592000),
        LimitType.STORAGE_QUOTA_MB: RateLimit(LimitType.STORAGE_QUOTA_MB, 100, 0),
        LimitType.CONCURRENT_SESSIONS: RateLimit(LimitType.CONCURRENT_SESSIONS, 2, 0)
    },
    
    # Professional tier limits
    "professional": {
        LimitType.REQUESTS_PER_MINUTE: RateLimit(LimitType.REQUESTS_PER_MINUTE, 60, 60),
        LimitType.REQUESTS_PER_HOUR: RateLimit(LimitType.REQUESTS_PER_HOUR, 1000, 3600),
        LimitType.SIGNATURES_PER_HOUR: RateLimit(LimitType.SIGNATURES_PER_HOUR, 100, 3600),
        LimitType.SIGNATURES_PER_DAY: RateLimit(LimitType.SIGNATURES_PER_DAY, 500, 86400),
        LimitType.SIGNATURES_PER_MONTH: RateLimit(LimitType.SIGNATURES_PER_MONTH, 5000, 2592000),
        LimitType.STORAGE_QUOTA_MB: RateLimit(LimitType.STORAGE_QUOTA_MB, 1000, 0),
        LimitType.CONCURRENT_SESSIONS: RateLimit(LimitType.CONCURRENT_SESSIONS, 10, 0)
    },
    
    # Enterprise tier limits
    "enterprise": {
        LimitType.REQUESTS_PER_MINUTE: RateLimit(LimitType.REQUESTS_PER_MINUTE, 300, 60),
        LimitType.REQUESTS_PER_HOUR: RateLimit(LimitType.REQUESTS_PER_HOUR, 10000, 3600),
        LimitType.SIGNATURES_PER_HOUR: RateLimit(LimitType.SIGNATURES_PER_HOUR, 1000, 3600),
        LimitType.SIGNATURES_PER_DAY: RateLimit(LimitType.SIGNATURES_PER_DAY, 10000, 86400),
        LimitType.SIGNATURES_PER_MONTH: RateLimit(LimitType.SIGNATURES_PER_MONTH, 100000, 2592000),
        LimitType.STORAGE_QUOTA_MB: RateLimit(LimitType.STORAGE_QUOTA_MB, 10000, 0),
        LimitType.CONCURRENT_SESSIONS: RateLimit(LimitType.CONCURRENT_SESSIONS, 50, 0)
    }
}


# Utility functions
def get_rate_limiter(redis_client: redis.Redis, 
                    tier: str = "professional") -> RateLimiter:
    """Create rate limiter with default limits for tier."""
    default_limits = DEFAULT_RATE_LIMITS.get(tier, DEFAULT_RATE_LIMITS["professional"])
    return RateLimiter(redis_client, default_limits)


async def check_quota_before_operation(tenant: TenantContext,
                                     rate_limiter: RateLimiter,
                                     operation_type: str) -> bool:
    """
    Check quota before performing expensive operations.
    
    Args:
        tenant: Tenant context
        rate_limiter: Rate limiter instance
        operation_type: Type of operation (sign, verify, etc.)
        
    Returns:
        True if operation is allowed
        
    Raises:
        QuotaExceededError: If quota is exceeded
    """
    limit_type_map = {
        "sign": LimitType.SIGNATURES_PER_HOUR,
        "verify": LimitType.REQUESTS_PER_HOUR,
        "auth": LimitType.REQUESTS_PER_MINUTE
    }
    
    limit_type = limit_type_map.get(operation_type, LimitType.REQUESTS_PER_HOUR)
    
    allowed, _, _, _ = await rate_limiter.check_rate_limit(
        tenant=tenant,
        limit_type=limit_type
    )
    
    return allowed