"""
Tenant Resolver Middleware

Implements multi-tenant resolution based on subdomain routing,
providing database schema isolation and tenant-specific configuration.
"""

import asyncio
import re
from typing import Dict, Any, Optional
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

logger = structlog.get_logger(__name__)


class TenantNotFoundError(HTTPException):
    """Raised when tenant cannot be resolved."""
    def __init__(self, subdomain: str):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant not found for subdomain: {subdomain}"
        )


class InvalidSubdomainError(HTTPException):
    """Raised when subdomain format is invalid."""
    def __init__(self, subdomain: str):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid subdomain format: {subdomain}"
        )


class TenantContext:
    """Container for tenant-specific context information."""
    
    def __init__(self, 
                 tenant_id: str,
                 name: str,
                 subdomain: str,
                 schema_name: str,
                 settings: Dict[str, Any],
                 is_active: bool = True):
        self.tenant_id = tenant_id
        self.name = name
        self.subdomain = subdomain
        self.schema_name = schema_name
        self.settings = settings
        self.is_active = is_active
        
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get tenant-specific setting value."""
        return self.settings.get(key, default)
        
    def get_database_url(self, base_url: str) -> str:
        """Get tenant-specific database URL with schema."""
        if "postgresql" in base_url:
            # Add search_path for PostgreSQL schema isolation
            separator = "&" if "?" in base_url else "?"
            return f"{base_url}{separator}options=-csearch_path%3D{self.schema_name}"
        return base_url
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert tenant context to dictionary."""
        return {
            "tenant_id": self.tenant_id,
            "name": self.name,
            "subdomain": self.subdomain,
            "schema_name": self.schema_name,
            "settings": self.settings,
            "is_active": self.is_active
        }


class TenantResolver:
    """
    Resolves tenant information from HTTP requests.
    
    Supports multiple resolution strategies:
    1. Subdomain-based (primary): tenant.qes-platform.com
    2. Header-based (API): X-Tenant-ID header
    3. Path-based (fallback): /tenant/{tenant_id}/api/...
    """
    
    def __init__(self, 
                 db_session_factory,
                 cache_ttl: int = 300,
                 enable_cache: bool = True):
        self.db_session_factory = db_session_factory
        self.cache_ttl = cache_ttl
        self.enable_cache = enable_cache
        self._tenant_cache: Dict[str, TenantContext] = {}
        self._cache_timestamps: Dict[str, float] = {}
        
        # Subdomain validation pattern
        self.subdomain_pattern = re.compile(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$')
        
        # Reserved subdomains that cannot be used for tenants
        self.reserved_subdomains = {
            'www', 'api', 'admin', 'app', 'mail', 'ftp', 'ssh',
            'staging', 'test', 'dev', 'prod', 'production',
            'support', 'help', 'docs', 'blog', 'status'
        }
        
    async def resolve_tenant(self, request: Request) -> TenantContext:
        """
        Resolve tenant from HTTP request.
        
        Args:
            request: FastAPI request object
            
        Returns:
            TenantContext with tenant information
            
        Raises:
            TenantNotFoundError: If tenant cannot be found
            InvalidSubdomainError: If subdomain format is invalid
        """
        # Strategy 1: Subdomain-based resolution (primary)
        subdomain = self._extract_subdomain(request)
        if subdomain:
            return await self._resolve_by_subdomain(subdomain)
            
        # Strategy 2: Header-based resolution (for API clients)
        tenant_id = request.headers.get('X-Tenant-ID')
        if tenant_id:
            return await self._resolve_by_tenant_id(tenant_id)
            
        # Strategy 3: Path-based resolution (fallback)
        tenant_from_path = self._extract_tenant_from_path(request.url.path)
        if tenant_from_path:
            return await self._resolve_by_tenant_id(tenant_from_path)
            
        # Default tenant for development/testing
        if self._is_development_request(request):
            return await self._get_default_tenant()
            
        raise TenantNotFoundError("unknown")
        
    def _extract_subdomain(self, request: Request) -> Optional[str]:
        """Extract subdomain from request host."""
        host = request.headers.get('host', '').lower()
        
        # Remove port if present
        host = host.split(':')[0]
        
        # Split host into parts
        parts = host.split('.')
        
        # Need at least 3 parts for subdomain.domain.tld
        if len(parts) < 3:
            return None
            
        # Extract subdomain (first part)
        subdomain = parts[0]
        
        # Validate subdomain format
        if not self.subdomain_pattern.match(subdomain):
            return None
            
        # Check if subdomain is reserved
        if subdomain in self.reserved_subdomains:
            return None
            
        return subdomain
        
    def _extract_tenant_from_path(self, path: str) -> Optional[str]:
        """Extract tenant ID from URL path."""
        # Pattern: /tenant/{tenant_id}/...
        path_pattern = re.compile(r'^/tenant/([a-f0-9\-]{36})/.*')
        match = path_pattern.match(path)
        return match.group(1) if match else None
        
    def _is_development_request(self, request: Request) -> bool:
        """Check if request is from development environment."""
        host = request.headers.get('host', '').lower()
        return (
            host.startswith('localhost') or
            host.startswith('127.0.0.1') or
            host.startswith('0.0.0.0') or
            '::1' in host
        )
        
    async def _resolve_by_subdomain(self, subdomain: str) -> TenantContext:
        """Resolve tenant by subdomain."""
        # Check cache first
        if self.enable_cache and subdomain in self._tenant_cache:
            if self._is_cache_valid(subdomain):
                logger.debug("Tenant resolved from cache", subdomain=subdomain)
                return self._tenant_cache[subdomain]
            else:
                # Remove expired cache entry
                del self._tenant_cache[subdomain]
                del self._cache_timestamps[subdomain]
                
        # Query database
        async with self.db_session_factory() as session:
            query = text("""
                SELECT id, name, subdomain, schema_name, settings, is_active
                FROM platform.tenants 
                WHERE subdomain = :subdomain AND is_active = true
            """)
            
            result = await session.execute(query, {"subdomain": subdomain})
            row = result.fetchone()
            
            if not row:
                logger.warning("Tenant not found", subdomain=subdomain)
                raise TenantNotFoundError(subdomain)
                
            tenant = TenantContext(
                tenant_id=str(row.id),
                name=row.name,
                subdomain=row.subdomain,
                schema_name=row.schema_name,
                settings=row.settings or {},
                is_active=row.is_active
            )
            
            # Cache the result
            if self.enable_cache:
                self._tenant_cache[subdomain] = tenant
                self._cache_timestamps[subdomain] = asyncio.get_event_loop().time()
                
            logger.info("Tenant resolved", 
                       tenant_id=tenant.tenant_id,
                       subdomain=subdomain,
                       schema=tenant.schema_name)
            
            return tenant
            
    async def _resolve_by_tenant_id(self, tenant_id: str) -> TenantContext:
        """Resolve tenant by tenant ID."""
        # Check cache by tenant ID
        cache_key = f"id:{tenant_id}"
        if self.enable_cache and cache_key in self._tenant_cache:
            if self._is_cache_valid(cache_key):
                return self._tenant_cache[cache_key]
            else:
                del self._tenant_cache[cache_key]
                del self._cache_timestamps[cache_key]
                
        # Query database
        async with self.db_session_factory() as session:
            query = text("""
                SELECT id, name, subdomain, schema_name, settings, is_active
                FROM platform.tenants 
                WHERE id = :tenant_id AND is_active = true
            """)
            
            result = await session.execute(query, {"tenant_id": tenant_id})
            row = result.fetchone()
            
            if not row:
                raise TenantNotFoundError(tenant_id)
                
            tenant = TenantContext(
                tenant_id=str(row.id),
                name=row.name,
                subdomain=row.subdomain,
                schema_name=row.schema_name,
                settings=row.settings or {},
                is_active=row.is_active
            )
            
            # Cache the result
            if self.enable_cache:
                self._tenant_cache[cache_key] = tenant
                self._cache_timestamps[cache_key] = asyncio.get_event_loop().time()
                
            return tenant
            
    async def _get_default_tenant(self) -> TenantContext:
        """Get default tenant for development."""
        # Return development tenant
        async with self.db_session_factory() as session:
            query = text("""
                SELECT id, name, subdomain, schema_name, settings, is_active
                FROM platform.tenants 
                WHERE subdomain = 'dev' 
                LIMIT 1
            """)
            
            result = await session.execute(query)
            row = result.fetchone()
            
            if row:
                return TenantContext(
                    tenant_id=str(row.id),
                    name=row.name,
                    subdomain=row.subdomain,
                    schema_name=row.schema_name,
                    settings=row.settings or {},
                    is_active=row.is_active
                )
            
        # Fallback: create minimal default tenant context
        return TenantContext(
            tenant_id="default",
            name="Default Development Tenant",
            subdomain="dev",
            schema_name="tenant_dev",
            settings={},
            is_active=True
        )
        
    def _is_cache_valid(self, key: str) -> bool:
        """Check if cached entry is still valid."""
        if key not in self._cache_timestamps:
            return False
            
        age = asyncio.get_event_loop().time() - self._cache_timestamps[key]
        return age < self.cache_ttl
        
    async def invalidate_tenant_cache(self, tenant_id: str = None, 
                                    subdomain: str = None):
        """Invalidate tenant cache entries."""
        if tenant_id:
            cache_key = f"id:{tenant_id}"
            self._tenant_cache.pop(cache_key, None)
            self._cache_timestamps.pop(cache_key, None)
            
        if subdomain:
            self._tenant_cache.pop(subdomain, None)
            self._cache_timestamps.pop(subdomain, None)
            
        logger.info("Tenant cache invalidated", 
                   tenant_id=tenant_id, 
                   subdomain=subdomain)


class TenantMiddleware:
    """
    FastAPI middleware for tenant resolution and context injection.
    """
    
    def __init__(self, tenant_resolver: TenantResolver):
        self.tenant_resolver = tenant_resolver
        
    async def __call__(self, request: Request, call_next):
        """Process request with tenant resolution."""
        try:
            # Skip tenant resolution for health checks and metrics
            if self._should_skip_tenant_resolution(request.url.path):
                return await call_next(request)
                
            # Resolve tenant from request
            tenant = await self.tenant_resolver.resolve_tenant(request)
            
            # Add tenant context to request state
            request.state.tenant = tenant
            
            # Add tenant info to request headers for downstream services
            request.headers.__dict__['_list'].append((
                b'x-tenant-id', 
                tenant.tenant_id.encode()
            ))
            request.headers.__dict__['_list'].append((
                b'x-tenant-schema', 
                tenant.schema_name.encode()
            ))
            
            # Log tenant resolution
            logger.bind(
                tenant_id=tenant.tenant_id,
                subdomain=tenant.subdomain,
                schema=tenant.schema_name
            ).info("Request processed for tenant")
            
            # Process request
            response = await call_next(request)
            
            # Add tenant info to response headers
            response.headers["X-Tenant-ID"] = tenant.tenant_id
            response.headers["X-Tenant-Name"] = tenant.name
            
            return response
            
        except (TenantNotFoundError, InvalidSubdomainError) as e:
            # Return tenant-specific error response
            return JSONResponse(
                status_code=e.status_code,
                content={
                    "error": "tenant_resolution_failed",
                    "message": e.detail,
                    "timestamp": str(asyncio.get_event_loop().time())
                }
            )
            
        except Exception as e:
            # Log unexpected errors
            logger.error("Tenant resolution failed", error=str(e))
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "error": "internal_server_error",
                    "message": "Tenant resolution failed",
                    "timestamp": str(asyncio.get_event_loop().time())
                }
            )
            
    def _should_skip_tenant_resolution(self, path: str) -> bool:
        """Check if path should skip tenant resolution."""
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


# Utility functions for tenant context access
def get_current_tenant(request: Request) -> TenantContext:
    """Get current tenant from request state."""
    if not hasattr(request.state, 'tenant'):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Tenant context not available"
        )
    return request.state.tenant


def get_tenant_database_url(request: Request, base_url: str) -> str:
    """Get tenant-specific database URL."""
    tenant = get_current_tenant(request)
    return tenant.get_database_url(base_url)


def get_tenant_setting(request: Request, key: str, default: Any = None) -> Any:
    """Get tenant-specific setting."""
    tenant = get_current_tenant(request)
    return tenant.get_setting(key, default)


# Dependency for FastAPI dependency injection
async def tenant_dependency(request: Request) -> TenantContext:
    """FastAPI dependency to inject tenant context."""
    return get_current_tenant(request)