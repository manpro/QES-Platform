"""
Middleware package for QES Platform.

Contains middleware components for cross-cutting concerns like
tenant resolution, rate limiting, and request processing.
"""

from .tenant_resolver import (
    TenantResolver,
    TenantMiddleware, 
    TenantContext,
    TenantNotFoundError,
    InvalidSubdomainError,
    get_current_tenant,
    get_tenant_database_url,
    get_tenant_setting,
    tenant_dependency
)

from .rate_limiter import (
    RateLimiter,
    RateLimitingMiddleware,
    LimitType,
    RateLimit,
    TenantLimits,
    QuotaExceededError,
    DEFAULT_RATE_LIMITS,
    get_rate_limiter,
    check_quota_before_operation
)

__all__ = [
    # Tenant resolution
    "TenantResolver",
    "TenantMiddleware",
    "TenantContext", 
    "TenantNotFoundError",
    "InvalidSubdomainError",
    "get_current_tenant",
    "get_tenant_database_url",
    "get_tenant_setting",
    "tenant_dependency",
    
    # Rate limiting
    "RateLimiter",
    "RateLimitingMiddleware",
    "LimitType",
    "RateLimit",
    "TenantLimits",
    "QuotaExceededError",
    "DEFAULT_RATE_LIMITS",
    "get_rate_limiter",
    "check_quota_before_operation"
]