"""
Redis Cache Service

Advanced Redis caching implementation for QES Platform with support for:
- Certificate caching with TTL management
- Provider metadata caching
- Session management
- Cache invalidation strategies
- High availability with Redis Cluster support
"""

import logging
import json
import hashlib
import pickle
import gzip
from typing import Any, Dict, List, Optional, Union, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import asyncio

import redis
import aioredis
from redis.exceptions import RedisError, ConnectionError as RedisConnectionError

logger = logging.getLogger(__name__)


class CacheStrategy(str, Enum):
    """Cache eviction and management strategies"""
    LRU = "allkeys-lru"           # Least Recently Used
    LFU = "allkeys-lfu"           # Least Frequently Used  
    TTL = "volatile-ttl"          # TTL-based eviction
    RANDOM = "allkeys-random"     # Random eviction
    NO_EVICTION = "noeviction"    # No automatic eviction


class SerializationFormat(str, Enum):
    """Supported serialization formats"""
    JSON = "json"
    PICKLE = "pickle"
    GZIP_JSON = "gzip_json"
    GZIP_PICKLE = "gzip_pickle"


@dataclass
class CacheConfig:
    """Redis cache configuration"""
    
    # Connection settings
    host: str = "localhost"
    port: int = 6379
    password: Optional[str] = None
    database: int = 0
    
    # Cluster settings
    cluster_enabled: bool = False
    cluster_nodes: List[Dict[str, Any]] = field(default_factory=list)
    
    # Connection pool settings
    max_connections: int = 50
    socket_timeout: float = 5.0
    socket_connect_timeout: float = 5.0
    retry_on_timeout: bool = True
    health_check_interval: int = 30
    
    # Cache behavior
    default_ttl: int = 3600  # 1 hour
    max_memory: str = "256mb"
    eviction_policy: CacheStrategy = CacheStrategy.LRU
    
    # Serialization
    default_serialization: SerializationFormat = SerializationFormat.JSON
    compression_threshold: int = 1024  # Compress data larger than 1KB
    
    # Namespace settings
    key_prefix: str = "qes:"
    namespace_separator: str = ":"
    
    # Performance settings
    pipeline_size: int = 100
    enable_clustering: bool = False
    enable_ssl: bool = False
    ssl_cert_reqs: str = "required"


@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    key: str
    value: Any
    ttl: Optional[int] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_accessed: datetime = field(default_factory=datetime.utcnow)
    access_count: int = 0
    serialization_format: SerializationFormat = SerializationFormat.JSON
    compressed: bool = False
    size_bytes: int = 0


class QESRedisCache:
    """
    Advanced Redis cache implementation for QES Platform
    
    Features:
    - Multi-format serialization (JSON, Pickle, compressed)
    - Automatic TTL management with renewal strategies
    - Namespace-based key organization
    - Pipeline operations for bulk operations
    - Health monitoring and failover
    - Certificate-specific caching with validation
    """
    
    def __init__(self, config: CacheConfig):
        self.config = config
        self.redis_client: Optional[redis.Redis] = None
        self.async_redis_client: Optional[aioredis.Redis] = None
        self.cluster_client: Optional[redis.RedisCluster] = None
        self.is_connected = False
        self.connection_retries = 0
        self.max_retries = 3
        
        # Cache statistics
        self.stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "deletes": 0,
            "errors": 0,
            "bytes_stored": 0,
            "keys_count": 0
        }
        
        # Namespace definitions
        self.namespaces = {
            "certificates": "cert",
            "provider_metadata": "provider",
            "session_data": "session",
            "user_cache": "user",
            "signing_jobs": "jobs",
            "audit_cache": "audit",
            "metrics_cache": "metrics",
            "document_cache": "docs",
            "tsa_cache": "tsa",
            "blockchain_cache": "chain"
        }
    
    async def initialize(self) -> bool:
        """Initialize Redis connection(s)"""
        try:
            if self.config.cluster_enabled and self.config.cluster_nodes:
                await self._initialize_cluster_client()
            else:
                await self._initialize_single_client()
            
            # Configure Redis settings
            await self._configure_redis_settings()
            
            # Test connection
            await self._test_connection()
            
            self.is_connected = True
            logger.info("Redis cache initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Redis cache initialization failed: {e}")
            self.is_connected = False
            return False
    
    async def _initialize_single_client(self):
        """Initialize single Redis instance client"""
        
        connection_kwargs = {
            "host": self.config.host,
            "port": self.config.port,
            "password": self.config.password,
            "db": self.config.database,
            "socket_timeout": self.config.socket_timeout,
            "socket_connect_timeout": self.config.socket_connect_timeout,
            "retry_on_timeout": self.config.retry_on_timeout,
            "max_connections": self.config.max_connections,
            "health_check_interval": self.config.health_check_interval
        }
        
        if self.config.enable_ssl:
            connection_kwargs.update({
                "ssl": True,
                "ssl_cert_reqs": self.config.ssl_cert_reqs
            })
        
        # Synchronous client
        self.redis_client = redis.Redis(**connection_kwargs)
        
        # Asynchronous client
        self.async_redis_client = aioredis.from_url(
            f"redis://{self.config.host}:{self.config.port}/{self.config.database}",
            password=self.config.password,
            encoding="utf-8",
            decode_responses=False  # We handle encoding ourselves
        )
    
    async def _initialize_cluster_client(self):
        """Initialize Redis Cluster client"""
        
        startup_nodes = [
            {"host": node["host"], "port": node["port"]} 
            for node in self.config.cluster_nodes
        ]
        
        self.cluster_client = redis.RedisCluster(
            startup_nodes=startup_nodes,
            password=self.config.password,
            socket_timeout=self.config.socket_timeout,
            socket_connect_timeout=self.config.socket_connect_timeout,
            retry_on_timeout=self.config.retry_on_timeout,
            max_connections=self.config.max_connections
        )
    
    async def _configure_redis_settings(self):
        """Configure Redis memory and eviction policies"""
        
        client = self._get_client()
        
        try:
            # Set memory limit
            await self._execute_command("CONFIG", "SET", "maxmemory", self.config.max_memory)
            
            # Set eviction policy
            await self._execute_command("CONFIG", "SET", "maxmemory-policy", self.config.eviction_policy.value)
            
            # Enable keyspace notifications for expiration events
            await self._execute_command("CONFIG", "SET", "notify-keyspace-events", "Ex")
            
            logger.info(f"Redis configured: maxmemory={self.config.max_memory}, policy={self.config.eviction_policy.value}")
            
        except Exception as e:
            logger.warning(f"Redis configuration failed (non-critical): {e}")
    
    async def _test_connection(self):
        """Test Redis connection"""
        test_key = self._build_key("system", "health_check")
        test_value = "ok"
        
        await self.set(test_key, test_value, ttl=10)
        result = await self.get(test_key)
        
        if result != test_value:
            raise Exception("Redis connection test failed")
        
        await self.delete(test_key)
    
    def _get_client(self) -> Union[redis.Redis, redis.RedisCluster]:
        """Get appropriate Redis client"""
        if self.config.cluster_enabled and self.cluster_client:
            return self.cluster_client
        return self.redis_client
    
    async def _execute_command(self, *args) -> Any:
        """Execute Redis command with error handling"""
        try:
            if self.async_redis_client:
                return await self.async_redis_client.execute_command(*args)
            else:
                client = self._get_client()
                return client.execute_command(*args)
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Redis command failed: {args[0]} - {e}")
            raise
    
    def _build_key(self, namespace: str, key: str) -> str:
        """Build namespaced cache key"""
        namespace_prefix = self.namespaces.get(namespace, namespace)
        return f"{self.config.key_prefix}{namespace_prefix}{self.config.namespace_separator}{key}"
    
    def _serialize_value(self, value: Any, format_type: SerializationFormat = None) -> bytes:
        """Serialize value using specified format"""
        format_type = format_type or self.config.default_serialization
        
        try:
            if format_type == SerializationFormat.JSON:
                serialized = json.dumps(value, default=str).encode('utf-8')
            elif format_type == SerializationFormat.PICKLE:
                serialized = pickle.dumps(value)
            elif format_type == SerializationFormat.GZIP_JSON:
                json_data = json.dumps(value, default=str).encode('utf-8')
                serialized = gzip.compress(json_data)
            elif format_type == SerializationFormat.GZIP_PICKLE:
                pickle_data = pickle.dumps(value)
                serialized = gzip.compress(pickle_data)
            else:
                raise ValueError(f"Unsupported serialization format: {format_type}")
            
            # Auto-compress if above threshold
            if (len(serialized) > self.config.compression_threshold and 
                format_type in [SerializationFormat.JSON, SerializationFormat.PICKLE]):
                if format_type == SerializationFormat.JSON:
                    return gzip.compress(serialized), SerializationFormat.GZIP_JSON
                else:
                    return gzip.compress(serialized), SerializationFormat.GZIP_PICKLE
            
            return serialized, format_type
            
        except Exception as e:
            logger.error(f"Serialization failed: {e}")
            raise
    
    def _deserialize_value(self, data: bytes, format_type: SerializationFormat) -> Any:
        """Deserialize value from bytes"""
        
        try:
            if format_type == SerializationFormat.JSON:
                return json.loads(data.decode('utf-8'))
            elif format_type == SerializationFormat.PICKLE:
                return pickle.loads(data)
            elif format_type == SerializationFormat.GZIP_JSON:
                decompressed = gzip.decompress(data)
                return json.loads(decompressed.decode('utf-8'))
            elif format_type == SerializationFormat.GZIP_PICKLE:
                decompressed = gzip.decompress(data)
                return pickle.loads(decompressed)
            else:
                raise ValueError(f"Unsupported deserialization format: {format_type}")
                
        except Exception as e:
            logger.error(f"Deserialization failed: {e}")
            raise
    
    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        namespace: str = "default",
        serialization_format: SerializationFormat = None
    ) -> bool:
        """Set cache value with optional TTL"""
        
        if not self.is_connected:
            return False
        
        try:
            full_key = self._build_key(namespace, key)
            ttl = ttl or self.config.default_ttl
            
            # Serialize value
            serialized_data, actual_format = self._serialize_value(value, serialization_format)
            
            # Create metadata
            metadata = {
                "format": actual_format.value,
                "created_at": datetime.utcnow().isoformat(),
                "size": len(serialized_data)
            }
            
            # Store data and metadata
            pipe = self.async_redis_client.pipeline()
            pipe.setex(full_key, ttl, serialized_data)
            pipe.setex(f"{full_key}:meta", ttl, json.dumps(metadata))
            await pipe.execute()
            
            # Update statistics
            self.stats["sets"] += 1
            self.stats["bytes_stored"] += len(serialized_data)
            
            logger.debug(f"Cache SET: {full_key} ({len(serialized_data)} bytes, TTL: {ttl}s)")
            return True
            
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Cache SET failed for {key}: {e}")
            return False
    
    async def get(self, key: str, namespace: str = "default") -> Optional[Any]:
        """Get cache value"""
        
        if not self.is_connected:
            return None
        
        try:
            full_key = self._build_key(namespace, key)
            
            # Get data and metadata
            pipe = self.async_redis_client.pipeline()
            pipe.get(full_key)
            pipe.get(f"{full_key}:meta")
            results = await pipe.execute()
            
            data, metadata_json = results
            
            if data is None:
                self.stats["misses"] += 1
                return None
            
            # Parse metadata
            if metadata_json:
                metadata = json.loads(metadata_json)
                format_type = SerializationFormat(metadata["format"])
            else:
                # Fallback to default format
                format_type = self.config.default_serialization
            
            # Deserialize value
            value = self._deserialize_value(data, format_type)
            
            # Update statistics
            self.stats["hits"] += 1
            
            logger.debug(f"Cache HIT: {full_key}")
            return value
            
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Cache GET failed for {key}: {e}")
            return None
    
    async def delete(self, key: str, namespace: str = "default") -> bool:
        """Delete cache entry"""
        
        if not self.is_connected:
            return False
        
        try:
            full_key = self._build_key(namespace, key)
            
            # Delete data and metadata
            pipe = self.async_redis_client.pipeline()
            pipe.delete(full_key)
            pipe.delete(f"{full_key}:meta")
            results = await pipe.execute()
            
            deleted_count = sum(results)
            
            if deleted_count > 0:
                self.stats["deletes"] += 1
                logger.debug(f"Cache DELETE: {full_key}")
                return True
            
            return False
            
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Cache DELETE failed for {key}: {e}")
            return False
    
    async def exists(self, key: str, namespace: str = "default") -> bool:
        """Check if key exists in cache"""
        
        if not self.is_connected:
            return False
        
        try:
            full_key = self._build_key(namespace, key)
            result = await self.async_redis_client.exists(full_key)
            return bool(result)
            
        except Exception as e:
            logger.error(f"Cache EXISTS failed for {key}: {e}")
            return False
    
    async def get_ttl(self, key: str, namespace: str = "default") -> Optional[int]:
        """Get TTL for cache key"""
        
        if not self.is_connected:
            return None
        
        try:
            full_key = self._build_key(namespace, key)
            ttl = await self.async_redis_client.ttl(full_key)
            return ttl if ttl > 0 else None
            
        except Exception as e:
            logger.error(f"Cache TTL failed for {key}: {e}")
            return None
    
    async def extend_ttl(self, key: str, ttl: int, namespace: str = "default") -> bool:
        """Extend TTL for existing cache entry"""
        
        if not self.is_connected:
            return False
        
        try:
            full_key = self._build_key(namespace, key)
            
            # Extend TTL for both data and metadata
            pipe = self.async_redis_client.pipeline()
            pipe.expire(full_key, ttl)
            pipe.expire(f"{full_key}:meta", ttl)
            results = await pipe.execute()
            
            return all(results)
            
        except Exception as e:
            logger.error(f"Cache TTL extension failed for {key}: {e}")
            return False
    
    async def get_or_set(
        self,
        key: str,
        factory_function: Callable,
        ttl: Optional[int] = None,
        namespace: str = "default",
        force_refresh: bool = False
    ) -> Any:
        """Get from cache or compute and set if not found"""
        
        if not force_refresh:
            cached_value = await self.get(key, namespace)
            if cached_value is not None:
                return cached_value
        
        # Compute new value
        try:
            if asyncio.iscoroutinefunction(factory_function):
                new_value = await factory_function()
            else:
                new_value = factory_function()
            
            # Cache the new value
            await self.set(key, new_value, ttl, namespace)
            return new_value
            
        except Exception as e:
            logger.error(f"Factory function failed for {key}: {e}")
            # Return cached value if factory fails
            if not force_refresh:
                return await self.get(key, namespace)
            raise
    
    async def set_many(
        self,
        items: Dict[str, Any],
        ttl: Optional[int] = None,
        namespace: str = "default"
    ) -> int:
        """Set multiple cache entries in batch"""
        
        if not self.is_connected or not items:
            return 0
        
        try:
            pipe = self.async_redis_client.pipeline()
            ttl = ttl or self.config.default_ttl
            
            for key, value in items.items():
                full_key = self._build_key(namespace, key)
                serialized_data, actual_format = self._serialize_value(value)
                
                metadata = {
                    "format": actual_format.value,
                    "created_at": datetime.utcnow().isoformat(),
                    "size": len(serialized_data)
                }
                
                pipe.setex(full_key, ttl, serialized_data)
                pipe.setex(f"{full_key}:meta", ttl, json.dumps(metadata))
            
            results = await pipe.execute()
            success_count = len([r for r in results if r is True])
            
            self.stats["sets"] += success_count // 2  # Each item has data + metadata
            
            logger.debug(f"Cache SET_MANY: {success_count // 2} items in {namespace}")
            return success_count // 2
            
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Cache SET_MANY failed: {e}")
            return 0
    
    async def get_many(self, keys: List[str], namespace: str = "default") -> Dict[str, Any]:
        """Get multiple cache entries in batch"""
        
        if not self.is_connected or not keys:
            return {}
        
        try:
            pipe = self.async_redis_client.pipeline()
            full_keys = [self._build_key(namespace, key) for key in keys]
            
            # Get all data and metadata
            for full_key in full_keys:
                pipe.get(full_key)
                pipe.get(f"{full_key}:meta")
            
            results = await pipe.execute()
            
            # Process results
            result_dict = {}
            for i, key in enumerate(keys):
                data_idx = i * 2
                meta_idx = i * 2 + 1
                
                data = results[data_idx]
                metadata_json = results[meta_idx]
                
                if data is not None:
                    try:
                        if metadata_json:
                            metadata = json.loads(metadata_json)
                            format_type = SerializationFormat(metadata["format"])
                        else:
                            format_type = self.config.default_serialization
                        
                        value = self._deserialize_value(data, format_type)
                        result_dict[key] = value
                        self.stats["hits"] += 1
                        
                    except Exception as e:
                        logger.error(f"Failed to deserialize {key}: {e}")
                        self.stats["errors"] += 1
                else:
                    self.stats["misses"] += 1
            
            logger.debug(f"Cache GET_MANY: {len(result_dict)}/{len(keys)} hits in {namespace}")
            return result_dict
            
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Cache GET_MANY failed: {e}")
            return {}
    
    async def delete_pattern(self, pattern: str, namespace: str = "default") -> int:
        """Delete all keys matching pattern"""
        
        if not self.is_connected:
            return 0
        
        try:
            full_pattern = self._build_key(namespace, pattern)
            
            # Get matching keys
            keys = await self.async_redis_client.keys(full_pattern)
            
            if not keys:
                return 0
            
            # Delete keys and their metadata
            pipe = self.async_redis_client.pipeline()
            for key in keys:
                pipe.delete(key)
                pipe.delete(f"{key}:meta")
            
            results = await pipe.execute()
            deleted_count = sum(results)
            
            self.stats["deletes"] += deleted_count
            
            logger.debug(f"Cache DELETE_PATTERN: {deleted_count} keys deleted for {full_pattern}")
            return deleted_count
            
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Cache DELETE_PATTERN failed for {pattern}: {e}")
            return 0
    
    async def clear_namespace(self, namespace: str) -> int:
        """Clear all entries in a namespace"""
        return await self.delete_pattern("*", namespace)
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        
        redis_info = {}
        if self.is_connected:
            try:
                info = await self.async_redis_client.info()
                redis_info = {
                    "redis_version": info.get("redis_version"),
                    "used_memory": info.get("used_memory"),
                    "used_memory_human": info.get("used_memory_human"),
                    "connected_clients": info.get("connected_clients"),
                    "total_commands_processed": info.get("total_commands_processed"),
                    "keyspace_hits": info.get("keyspace_hits"),
                    "keyspace_misses": info.get("keyspace_misses"),
                    "evicted_keys": info.get("evicted_keys"),
                    "expired_keys": info.get("expired_keys")
                }
            except Exception as e:
                logger.error(f"Failed to get Redis info: {e}")
        
        # Calculate hit rate
        total_reads = self.stats["hits"] + self.stats["misses"]
        hit_rate = (self.stats["hits"] / total_reads * 100) if total_reads > 0 else 0
        
        return {
            "connection_status": "connected" if self.is_connected else "disconnected",
            "hit_rate_percent": round(hit_rate, 2),
            "application_stats": self.stats,
            "redis_info": redis_info,
            "configuration": {
                "default_ttl": self.config.default_ttl,
                "eviction_policy": self.config.eviction_policy.value,
                "max_memory": self.config.max_memory,
                "cluster_enabled": self.config.cluster_enabled
            }
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform cache health check"""
        
        health_status = {
            "status": "healthy",
            "checks": {},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Connection check
        try:
            if self.is_connected:
                await self.async_redis_client.ping()
                health_status["checks"]["connection"] = "ok"
            else:
                health_status["checks"]["connection"] = "disconnected"
                health_status["status"] = "unhealthy"
        except Exception as e:
            health_status["checks"]["connection"] = f"error: {e}"
            health_status["status"] = "unhealthy"
        
        # Memory check
        try:
            info = await self.async_redis_client.info("memory")
            used_memory = info.get("used_memory", 0)
            max_memory = info.get("maxmemory", 0)
            
            if max_memory > 0:
                memory_usage_percent = (used_memory / max_memory) * 100
                if memory_usage_percent > 90:
                    health_status["checks"]["memory"] = f"high_usage: {memory_usage_percent:.1f}%"
                    health_status["status"] = "degraded"
                else:
                    health_status["checks"]["memory"] = f"ok: {memory_usage_percent:.1f}%"
            else:
                health_status["checks"]["memory"] = "ok: no_limit"
                
        except Exception as e:
            health_status["checks"]["memory"] = f"error: {e}"
        
        # Performance check
        try:
            start_time = datetime.utcnow()
            test_key = "health_check_perf_test"
            await self.set(test_key, "test_value", ttl=10)
            await self.get(test_key)
            await self.delete(test_key)
            
            response_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            if response_time > 100:  # > 100ms
                health_status["checks"]["performance"] = f"slow: {response_time:.1f}ms"
                health_status["status"] = "degraded"
            else:
                health_status["checks"]["performance"] = f"ok: {response_time:.1f}ms"
                
        except Exception as e:
            health_status["checks"]["performance"] = f"error: {e}"
            health_status["status"] = "unhealthy"
        
        return health_status
    
    async def close(self):
        """Close Redis connections"""
        try:
            if self.async_redis_client:
                await self.async_redis_client.close()
            
            if self.redis_client:
                self.redis_client.close()
            
            if self.cluster_client:
                self.cluster_client.close()
            
            self.is_connected = False
            logger.info("Redis cache connections closed")
            
        except Exception as e:
            logger.error(f"Error closing Redis connections: {e}")


# Global cache instance
_cache_instance: Optional[QESRedisCache] = None


async def get_cache() -> QESRedisCache:
    """Get global cache instance"""
    global _cache_instance
    
    if _cache_instance is None:
        # Load configuration from environment
        import os
        
        config = CacheConfig(
            host=os.getenv("REDIS_HOST", "localhost"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            password=os.getenv("REDIS_PASSWORD"),
            database=int(os.getenv("REDIS_DB", "0")),
            max_memory=os.getenv("REDIS_MAX_MEMORY", "256mb"),
            default_ttl=int(os.getenv("REDIS_DEFAULT_TTL", "3600")),
            eviction_policy=CacheStrategy(os.getenv("REDIS_EVICTION_POLICY", "allkeys-lru")),
            cluster_enabled=os.getenv("REDIS_CLUSTER_ENABLED", "false").lower() == "true",
            enable_ssl=os.getenv("REDIS_SSL_ENABLED", "false").lower() == "true"
        )
        
        _cache_instance = QESRedisCache(config)
        await _cache_instance.initialize()
    
    return _cache_instance


async def close_cache():
    """Close global cache instance"""
    global _cache_instance
    
    if _cache_instance:
        await _cache_instance.close()
        _cache_instance = None