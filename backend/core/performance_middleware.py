"""
Performance Monitoring Middleware

Advanced performance monitoring with detailed metrics collection,
response time tracking, and resource utilization monitoring.
"""

import logging
import time
import asyncio
from typing import Dict, Any, Optional, Callable
from datetime import datetime
from uuid import uuid4

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from core.metrics_collector import get_metrics_collector, MetricType
from core.audit_logger import AuditLogger, AuditEvent, AuditEventType

logger = logging.getLogger(__name__)


class PerformanceMonitoringMiddleware(BaseHTTPMiddleware):
    """
    Middleware for comprehensive performance monitoring.
    
    Features:
    - Request/response time tracking
    - Resource utilization monitoring
    - Error rate calculation
    - Slow query detection
    - Performance analytics
    """
    
    def __init__(
        self,
        app,
        slow_request_threshold: float = 2.0,
        enable_detailed_logging: bool = True
    ):
        super().__init__(app)
        self.slow_request_threshold = slow_request_threshold
        self.enable_detailed_logging = enable_detailed_logging
        self.metrics_collector = get_metrics_collector()
        self.audit_logger = AuditLogger({"postgres_enabled": True})
        
        # Performance tracking
        self.request_count = 0
        self.error_count = 0
        self.total_response_time = 0.0
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with performance monitoring"""
        
        start_time = time.time()
        request_id = str(uuid4())
        
        # Add request ID to headers for tracing
        request.state.request_id = request_id
        
        try:
            # Track request start
            await self._track_request_start(request, request_id)
            
            # Process request
            response = await call_next(request)
            
            # Calculate response time
            response_time = time.time() - start_time
            
            # Track request completion
            await self._track_request_completion(
                request, response, response_time, request_id
            )
            
            # Add performance headers
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Response-Time"] = f"{response_time:.3f}s"
            
            return response
            
        except Exception as e:
            # Track error
            response_time = time.time() - start_time
            await self._track_request_error(request, e, response_time, request_id)
            raise
    
    async def _track_request_start(self, request: Request, request_id: str):
        """Track request start metrics"""
        
        try:
            # Record request start metric
            await self.metrics_collector.record_metric(
                metric_type=MetricType.THROUGHPUT,
                name="request_started",
                value=1,
                labels={
                    "method": request.method,
                    "endpoint": self._normalize_endpoint(request.url.path),
                    "request_id": request_id
                },
                metadata={
                    "client_ip": request.client.host if request.client else "unknown",
                    "user_agent": request.headers.get("User-Agent", "unknown"),
                    "content_length": request.headers.get("Content-Length", "0")
                }
            )
            
            # Update request counter
            self.request_count += 1
            
        except Exception as e:
            logger.error(f"Failed to track request start: {e}")
    
    async def _track_request_completion(
        self,
        request: Request,
        response: Response,
        response_time: float,
        request_id: str
    ):
        """Track request completion metrics"""
        
        try:
            # Determine success/error status
            is_success = 200 <= response.status_code < 400
            is_client_error = 400 <= response.status_code < 500
            is_server_error = response.status_code >= 500
            
            # Record response time metric
            await self.metrics_collector.record_performance_metric(
                operation=self._normalize_endpoint(request.url.path),
                duration=response_time,
                success=is_success,
                metadata={
                    "method": request.method,
                    "status_code": response.status_code,
                    "request_id": request_id,
                    "response_size": len(response.body) if hasattr(response, 'body') else 0
                }
            )
            
            # Record throughput metric
            await self.metrics_collector.record_metric(
                metric_type=MetricType.THROUGHPUT,
                name="request_completed",
                value=1,
                labels={
                    "method": request.method,
                    "endpoint": self._normalize_endpoint(request.url.path),
                    "status": str(response.status_code),
                    "status_class": self._get_status_class(response.status_code)
                }
            )
            
            # Track error rate
            if not is_success:
                self.error_count += 1
                
                await self.metrics_collector.record_metric(
                    metric_type=MetricType.ERROR_RATE,
                    name="request_error",
                    value=1,
                    labels={
                        "method": request.method,
                        "endpoint": self._normalize_endpoint(request.url.path),
                        "status_code": str(response.status_code),
                        "error_type": "client_error" if is_client_error else "server_error"
                    }
                )
            
            # Track slow requests
            if response_time > self.slow_request_threshold:
                await self._track_slow_request(request, response, response_time, request_id)
            
            # Update running averages
            self.total_response_time += response_time
            
            # Calculate and record current error rate
            if self.request_count > 0:
                current_error_rate = (self.error_count / self.request_count) * 100
                await self.metrics_collector.record_metric(
                    metric_type=MetricType.ERROR_RATE,
                    name="overall_error_rate",
                    value=current_error_rate,
                    labels={"service": "qes_platform"}
                )
            
            # Detailed logging for significant events
            if self.enable_detailed_logging and (not is_success or response_time > self.slow_request_threshold):
                await self.audit_logger.log_event(AuditEvent(
                    event_type=AuditEventType.SYSTEM_ERROR if not is_success else AuditEventType.SYSTEM_ERROR,
                    details={
                        "request_id": request_id,
                        "method": request.method,
                        "endpoint": request.url.path,
                        "status_code": response.status_code,
                        "response_time": response_time,
                        "is_slow_request": response_time > self.slow_request_threshold,
                        "client_ip": request.client.host if request.client else "unknown"
                    }
                ))
            
        except Exception as e:
            logger.error(f"Failed to track request completion: {e}")
    
    async def _track_request_error(
        self,
        request: Request,
        error: Exception,
        response_time: float,
        request_id: str
    ):
        """Track request error metrics"""
        
        try:
            # Record error metric
            await self.metrics_collector.record_metric(
                metric_type=MetricType.ERROR_RATE,
                name="request_exception",
                value=1,
                labels={
                    "method": request.method,
                    "endpoint": self._normalize_endpoint(request.url.path),
                    "error_type": type(error).__name__,
                    "request_id": request_id
                },
                metadata={
                    "error_message": str(error),
                    "response_time": response_time
                }
            )
            
            # Update error counter
            self.error_count += 1
            
            # Log error for audit trail
            await self.audit_logger.log_event(AuditEvent(
                event_type=AuditEventType.SYSTEM_ERROR,
                details={
                    "request_id": request_id,
                    "method": request.method,
                    "endpoint": request.url.path,
                    "error_type": type(error).__name__,
                    "error_message": str(error),
                    "response_time": response_time
                }
            ))
            
        except Exception as e:
            logger.error(f"Failed to track request error: {e}")
    
    async def _track_slow_request(
        self,
        request: Request,
        response: Response,
        response_time: float,
        request_id: str
    ):
        """Track slow request for performance optimization"""
        
        try:
            # Record slow request metric
            await self.metrics_collector.record_metric(
                metric_type=MetricType.REQUEST_LATENCY,
                name="slow_request",
                value=response_time,
                labels={
                    "method": request.method,
                    "endpoint": self._normalize_endpoint(request.url.path),
                    "status": str(response.status_code),
                    "request_id": request_id
                },
                metadata={
                    "threshold": self.slow_request_threshold,
                    "slowness_factor": response_time / self.slow_request_threshold
                }
            )
            
            logger.warning(
                f"Slow request detected: {request.method} {request.url.path} "
                f"took {response_time:.3f}s (threshold: {self.slow_request_threshold}s)"
            )
            
        except Exception as e:
            logger.error(f"Failed to track slow request: {e}")
    
    def _normalize_endpoint(self, path: str) -> str:
        """Normalize endpoint path for consistent metrics"""
        
        # Replace UUIDs and other variable parts with placeholders
        import re
        
        # Replace UUID patterns
        path = re.sub(
            r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '/{uuid}',
            path
        )
        
        # Replace numeric IDs
        path = re.sub(r'/\d+(?=/|$)', '/{id}', path)
        
        # Remove query parameters
        path = path.split('?')[0]
        
        return path
    
    def _get_status_class(self, status_code: int) -> str:
        """Get status code class for metrics grouping"""
        
        if 200 <= status_code < 300:
            return "2xx"
        elif 300 <= status_code < 400:
            return "3xx"
        elif 400 <= status_code < 500:
            return "4xx"
        elif 500 <= status_code < 600:
            return "5xx"
        else:
            return "unknown"


class ResourceMonitoringMiddleware(BaseHTTPMiddleware):
    """
    Middleware for monitoring system resource utilization.
    """
    
    def __init__(self, app, monitoring_interval: int = 60):
        super().__init__(app)
        self.monitoring_interval = monitoring_interval
        self.metrics_collector = get_metrics_collector()
        self._last_monitoring = 0
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with resource monitoring"""
        
        # Check if it's time to collect resource metrics
        current_time = time.time()
        if current_time - self._last_monitoring > self.monitoring_interval:
            await self._collect_resource_metrics()
            self._last_monitoring = current_time
        
        return await call_next(request)
    
    async def _collect_resource_metrics(self):
        """Collect system resource metrics"""
        
        try:
            import psutil
            
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            await self.metrics_collector.record_metric(
                metric_type=MetricType.RESOURCE_UTILIZATION,
                name="cpu_usage_percent",
                value=cpu_percent,
                labels={"resource": "cpu", "host": "qes-backend"}
            )
            
            # Memory metrics
            memory = psutil.virtual_memory()
            await self.metrics_collector.record_metric(
                metric_type=MetricType.RESOURCE_UTILIZATION,
                name="memory_usage_percent",
                value=memory.percent,
                labels={"resource": "memory", "host": "qes-backend"}
            )
            
            await self.metrics_collector.record_metric(
                metric_type=MetricType.RESOURCE_UTILIZATION,
                name="memory_usage_bytes",
                value=memory.used,
                labels={"resource": "memory", "host": "qes-backend"}
            )
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            await self.metrics_collector.record_metric(
                metric_type=MetricType.RESOURCE_UTILIZATION,
                name="disk_usage_percent",
                value=disk_percent,
                labels={"resource": "disk", "host": "qes-backend", "mount": "/"}
            )
            
            # Network metrics (if available)
            try:
                network = psutil.net_io_counters()
                await self.metrics_collector.record_metric(
                    metric_type=MetricType.RESOURCE_UTILIZATION,
                    name="network_bytes_sent",
                    value=network.bytes_sent,
                    labels={"resource": "network", "host": "qes-backend", "direction": "sent"}
                )
                
                await self.metrics_collector.record_metric(
                    metric_type=MetricType.RESOURCE_UTILIZATION,
                    name="network_bytes_recv",
                    value=network.bytes_recv,
                    labels={"resource": "network", "host": "qes-backend", "direction": "received"}
                )
            except Exception:
                # Network metrics may not be available in all environments
                pass
            
        except Exception as e:
            logger.error(f"Failed to collect resource metrics: {e}")


def add_performance_monitoring(app):
    """Add performance monitoring middleware to FastAPI app"""
    
    # Add performance monitoring
    app.add_middleware(
        PerformanceMonitoringMiddleware,
        slow_request_threshold=2.0,
        enable_detailed_logging=True
    )
    
    # Add resource monitoring
    app.add_middleware(
        ResourceMonitoringMiddleware,
        monitoring_interval=60  # Monitor every minute
    )
    
    logger.info("Performance monitoring middleware added")