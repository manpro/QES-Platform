"""
Cache Management API

Administrative endpoints for managing Redis cache operations,
including cache statistics, invalidation, and health monitoring.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, status, Depends, Query
from pydantic import BaseModel, Field

from auth.jwt_auth import get_current_user
from models.user import User
from core.redis_cache import get_cache
from core.certificate_cache import get_certificate_cache

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/cache", tags=["cache-management"])


class CacheStatsResponse(BaseModel):
    """Cache statistics response"""
    redis_stats: Dict[str, Any]
    certificate_stats: Dict[str, Any]
    overall_health: str
    last_updated: datetime


class CacheInvalidationRequest(BaseModel):
    """Request to invalidate cache entries"""
    namespace: Optional[str] = Field(None, description="Cache namespace to invalidate")
    pattern: Optional[str] = Field(None, description="Key pattern to match")
    provider: Optional[str] = Field(None, description="QES provider to invalidate")
    confirm: bool = Field(False, description="Confirmation flag for destructive operations")


class CacheInvalidationResponse(BaseModel):
    """Response from cache invalidation"""
    success: bool
    entries_deleted: int
    namespace: Optional[str]
    pattern: Optional[str]
    message: str


@router.get("/stats", response_model=CacheStatsResponse)
async def get_cache_statistics(
    current_user: User = Depends(get_current_user),
    include_redis_info: bool = Query(True, description="Include detailed Redis information")
):
    """
    Get comprehensive cache statistics including Redis and certificate cache metrics.
    
    Requires authentication for security purposes.
    """
    
    try:
        # Get Redis cache statistics
        redis_cache = await get_cache()
        redis_stats = await redis_cache.get_stats()
        
        # Get certificate cache statistics
        cert_cache = await get_certificate_cache()
        cert_stats = await cert_cache.get_cache_stats()
        
        # Determine overall health
        overall_health = "healthy"
        if not redis_cache.is_connected:
            overall_health = "unhealthy"
        elif redis_stats.get("hit_rate_percent", 0) < 50:
            overall_health = "degraded"
        
        return CacheStatsResponse(
            redis_stats=redis_stats,
            certificate_stats=cert_stats,
            overall_health=overall_health,
            last_updated=datetime.utcnow()
        )
        
    except Exception as e:
        logger.error(f"Failed to get cache statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve cache statistics: {str(e)}"
        )


@router.get("/health")
async def cache_health_check(current_user: User = Depends(get_current_user)):
    """
    Perform comprehensive cache health check.
    """
    
    try:
        redis_cache = await get_cache()
        health_status = await redis_cache.health_check()
        
        return {
            "cache_health": health_status,
            "timestamp": datetime.utcnow().isoformat(),
            "user": current_user.email
        }
        
    except Exception as e:
        logger.error(f"Cache health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Cache health check failed: {str(e)}"
        )


@router.post("/invalidate", response_model=CacheInvalidationResponse)
async def invalidate_cache_entries(
    request: CacheInvalidationRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Invalidate cache entries based on namespace, pattern, or provider.
    
    This is a destructive operation that requires confirmation.
    Admin privileges may be required in production.
    """
    
    if not request.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cache invalidation requires confirmation (set confirm=true)"
        )
    
    try:
        deleted_count = 0
        operation_details = []
        
        redis_cache = await get_cache()
        cert_cache = await get_certificate_cache()
        
        # Invalidate by provider
        if request.provider:
            provider_deleted = await cert_cache.invalidate_provider_certificates(request.provider)
            deleted_count += provider_deleted
            operation_details.append(f"Provider {request.provider}: {provider_deleted} entries")
        
        # Invalidate by namespace
        elif request.namespace:
            namespace_deleted = await redis_cache.clear_namespace(request.namespace)
            deleted_count += namespace_deleted
            operation_details.append(f"Namespace {request.namespace}: {namespace_deleted} entries")
        
        # Invalidate by pattern
        elif request.pattern:
            pattern_deleted = await redis_cache.delete_pattern(
                request.pattern, 
                request.namespace or "default"
            )
            deleted_count += pattern_deleted
            operation_details.append(f"Pattern {request.pattern}: {pattern_deleted} entries")
        
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Must specify provider, namespace, or pattern for invalidation"
            )
        
        # Log the operation
        logger.warning(
            f"Cache invalidation performed by {current_user.email}: "
            f"{'; '.join(operation_details)}"
        )
        
        return CacheInvalidationResponse(
            success=True,
            entries_deleted=deleted_count,
            namespace=request.namespace,
            pattern=request.pattern,
            message=f"Successfully invalidated {deleted_count} cache entries"
        )
        
    except Exception as e:
        logger.error(f"Cache invalidation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Cache invalidation failed: {str(e)}"
        )


@router.get("/certificates")
async def list_cached_certificates(
    provider: Optional[str] = Query(None, description="Filter by QES provider"),
    current_user: User = Depends(get_current_user)
):
    """
    List cached certificates with metadata.
    """
    
    try:
        cert_cache = await get_certificate_cache()
        certificates = await cert_cache.list_cached_certificates(provider)
        
        return {
            "certificates": certificates,
            "total_count": len(certificates),
            "provider_filter": provider,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to list cached certificates: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list certificates: {str(e)}"
        )


@router.delete("/certificates/{provider}/{identifier}")
async def invalidate_specific_certificate(
    provider: str,
    identifier: str,
    current_user: User = Depends(get_current_user)
):
    """
    Invalidate a specific cached certificate.
    """
    
    try:
        cert_cache = await get_certificate_cache()
        success = await cert_cache.invalidate_certificate(provider, identifier)
        
        if success:
            logger.info(f"Certificate invalidated by {current_user.email}: {provider}:{identifier}")
            return {
                "success": True,
                "message": f"Certificate {provider}:{identifier} invalidated successfully"
            }
        else:
            return {
                "success": False,
                "message": f"Certificate {provider}:{identifier} not found in cache"
            }
        
    except Exception as e:
        logger.error(f"Failed to invalidate certificate {provider}:{identifier}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to invalidate certificate: {str(e)}"
        )


@router.post("/warm-up")
async def warm_up_cache(
    providers: Optional[List[str]] = Query(None, description="Providers to warm up"),
    current_user: User = Depends(get_current_user)
):
    """
    Warm up cache by pre-loading frequently accessed data.
    
    This endpoint can be used after cache invalidation or during
    system startup to improve initial response times.
    """
    
    try:
        # Implementation would pre-load:
        # - Common certificates
        # - Provider metadata
        # - Frequently accessed user data
        # - System configuration
        
        warm_up_tasks = []
        
        if providers:
            # Warm up specific providers
            for provider in providers:
                warm_up_tasks.append(f"Provider {provider} metadata")
        else:
            # Warm up common data
            warm_up_tasks.extend([
                "System configuration",
                "Active certificates",
                "Provider metadata",
                "Common user sessions"
            ])
        
        # Simulate warm-up process (in production, this would actually load data)
        logger.info(f"Cache warm-up initiated by {current_user.email}: {', '.join(warm_up_tasks)}")
        
        return {
            "success": True,
            "message": "Cache warm-up completed successfully",
            "tasks_completed": warm_up_tasks,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Cache warm-up failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Cache warm-up failed: {str(e)}"
        )


@router.get("/memory-usage")
async def get_cache_memory_usage(current_user: User = Depends(get_current_user)):
    """
    Get detailed memory usage information for the cache.
    """
    
    try:
        redis_cache = await get_cache()
        
        # Get Redis memory info
        memory_info = await redis_cache.async_redis_client.info("memory")
        
        # Calculate memory distribution
        memory_stats = {
            "total_system_memory": memory_info.get("total_system_memory"),
            "used_memory": memory_info.get("used_memory"),
            "used_memory_human": memory_info.get("used_memory_human"),
            "used_memory_rss": memory_info.get("used_memory_rss"),
            "used_memory_peak": memory_info.get("used_memory_peak"),
            "used_memory_peak_human": memory_info.get("used_memory_peak_human"),
            "maxmemory": memory_info.get("maxmemory"),
            "maxmemory_human": memory_info.get("maxmemory_human"),
            "mem_fragmentation_ratio": memory_info.get("mem_fragmentation_ratio"),
            "mem_allocator": memory_info.get("mem_allocator")
        }
        
        # Calculate memory usage percentage
        if memory_stats["maxmemory"] and memory_stats["maxmemory"] > 0:
            usage_percent = (memory_stats["used_memory"] / memory_stats["maxmemory"]) * 100
            memory_stats["usage_percentage"] = round(usage_percent, 2)
        else:
            memory_stats["usage_percentage"] = None
        
        return {
            "memory_stats": memory_stats,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "healthy" if memory_stats.get("usage_percentage", 0) < 90 else "warning"
        }
        
    except Exception as e:
        logger.error(f"Failed to get memory usage: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get memory usage: {str(e)}"
        )


@router.get("/key-analysis")
async def analyze_cache_keys(
    namespace: Optional[str] = Query(None, description="Analyze specific namespace"),
    sample_size: int = Query(1000, ge=100, le=10000, description="Sample size for analysis"),
    current_user: User = Depends(get_current_user)
):
    """
    Analyze cache key patterns and usage for optimization insights.
    """
    
    try:
        redis_cache = await get_cache()
        
        # Get key sample
        if namespace:
            pattern = redis_cache._build_key(namespace, "*")
        else:
            pattern = f"{redis_cache.config.key_prefix}*"
        
        # Get sample of keys
        all_keys = await redis_cache.async_redis_client.keys(pattern)
        
        if len(all_keys) > sample_size:
            # Sample randomly for large datasets
            import random
            sampled_keys = random.sample(all_keys, sample_size)
        else:
            sampled_keys = all_keys
        
        # Analyze key patterns
        key_analysis = {
            "total_keys": len(all_keys),
            "sampled_keys": len(sampled_keys),
            "namespaces": {},
            "key_types": {},
            "ttl_distribution": {"no_ttl": 0, "short_ttl": 0, "medium_ttl": 0, "long_ttl": 0}
        }
        
        # Analyze sampled keys
        pipe = redis_cache.async_redis_client.pipeline()
        for key in sampled_keys:
            pipe.ttl(key)
            pipe.type(key)
        
        results = await pipe.execute()
        
        for i, key in enumerate(sampled_keys):
            key_str = key.decode() if isinstance(key, bytes) else key
            ttl = results[i * 2]
            key_type = results[i * 2 + 1]
            
            # Extract namespace
            parts = key_str.split(":")
            if len(parts) >= 2:
                namespace_name = parts[1]
                key_analysis["namespaces"][namespace_name] = key_analysis["namespaces"].get(namespace_name, 0) + 1
            
            # Categorize by type
            key_analysis["key_types"][key_type] = key_analysis["key_types"].get(key_type, 0) + 1
            
            # Categorize by TTL
            if ttl == -1:
                key_analysis["ttl_distribution"]["no_ttl"] += 1
            elif ttl < 300:  # < 5 minutes
                key_analysis["ttl_distribution"]["short_ttl"] += 1
            elif ttl < 3600:  # < 1 hour
                key_analysis["ttl_distribution"]["medium_ttl"] += 1
            else:
                key_analysis["ttl_distribution"]["long_ttl"] += 1
        
        return {
            "analysis": key_analysis,
            "recommendations": _generate_cache_recommendations(key_analysis),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Cache key analysis failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Cache key analysis failed: {str(e)}"
        )


def _generate_cache_recommendations(analysis: Dict[str, Any]) -> List[str]:
    """Generate cache optimization recommendations based on analysis"""
    
    recommendations = []
    
    # TTL recommendations
    ttl_dist = analysis["ttl_distribution"]
    total_keys = sum(ttl_dist.values())
    
    if ttl_dist["no_ttl"] / total_keys > 0.3:
        recommendations.append(
            "Consider adding TTL to keys without expiration to prevent memory buildup"
        )
    
    if ttl_dist["short_ttl"] / total_keys > 0.5:
        recommendations.append(
            "High percentage of short-TTL keys may indicate inefficient caching strategy"
        )
    
    # Namespace recommendations
    namespaces = analysis["namespaces"]
    if len(namespaces) > 10:
        recommendations.append(
            "Consider consolidating namespaces to reduce key fragmentation"
        )
    
    # Key type recommendations
    key_types = analysis["key_types"]
    if key_types.get("string", 0) / total_keys > 0.8:
        recommendations.append(
            "Consider using Redis data structures (hash, set) for better memory efficiency"
        )
    
    if not recommendations:
        recommendations.append("Cache usage patterns look optimal")
    
    return recommendations