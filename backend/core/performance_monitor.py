"""
Performance Monitoring and Metrics Collection

Tracks database query performance and provides optimization insights.
"""

import time
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from functools import wraps
from contextlib import contextmanager
import asyncio
from dataclasses import dataclass, field

from sqlalchemy import event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


@dataclass
class QueryMetrics:
    """Metrics for a database query"""
    query: str
    execution_time: float
    timestamp: datetime
    row_count: Optional[int] = None
    parameters: Optional[Dict[str, Any]] = None
    stack_trace: Optional[str] = None


@dataclass
class PerformanceStats:
    """Aggregated performance statistics"""
    total_queries: int = 0
    avg_execution_time: float = 0.0
    max_execution_time: float = 0.0
    slow_queries_count: int = 0
    queries_by_table: Dict[str, int] = field(default_factory=dict)
    slowest_queries: List[QueryMetrics] = field(default_factory=list)


class PerformanceMonitor:
    """
    Database performance monitoring and optimization insights.
    
    Tracks query execution times, identifies slow queries,
    and provides optimization recommendations.
    """
    
    def __init__(self, slow_query_threshold: float = 1.0):
        self.slow_query_threshold = slow_query_threshold
        self.query_metrics: List[QueryMetrics] = []
        self.enabled = True
        self.max_metrics_history = 10000
    
    def enable_query_logging(self, engine: Engine):
        """Enable SQLAlchemy query logging with performance tracking"""
        
        @event.listens_for(engine, "before_cursor_execute")
        def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            context._query_start_time = time.time()
        
        @event.listens_for(engine, "after_cursor_execute")
        def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            if not self.enabled:
                return
            
            execution_time = time.time() - context._query_start_time
            
            # Clean up query for logging
            clean_query = self._clean_query(statement)
            
            # Record metrics
            metrics = QueryMetrics(
                query=clean_query,
                execution_time=execution_time,
                timestamp=datetime.utcnow(),
                row_count=cursor.rowcount if hasattr(cursor, 'rowcount') else None,
                parameters=self._sanitize_parameters(parameters)
            )
            
            self._record_query_metrics(metrics)
            
            # Log slow queries
            if execution_time > self.slow_query_threshold:
                logger.warning(f"Slow query detected ({execution_time:.3f}s): {clean_query[:200]}...")
    
    def _clean_query(self, query: str) -> str:
        """Clean and normalize query for analysis"""
        # Remove extra whitespace and normalize
        cleaned = ' '.join(query.split())
        
        # Truncate very long queries
        if len(cleaned) > 1000:
            cleaned = cleaned[:1000] + "..."
        
        return cleaned
    
    def _sanitize_parameters(self, parameters: Any) -> Dict[str, Any]:
        """Sanitize query parameters for logging"""
        if not parameters:
            return {}
        
        if isinstance(parameters, dict):
            # Remove sensitive data
            sanitized = {}
            for key, value in parameters.items():
                if any(sensitive in key.lower() for sensitive in ['password', 'token', 'secret', 'key']):
                    sanitized[key] = "[REDACTED]"
                elif isinstance(value, (str, int, float, bool)):
                    sanitized[key] = value
                else:
                    sanitized[key] = str(type(value))
            return sanitized
        
        return {"params": str(type(parameters))}
    
    def _record_query_metrics(self, metrics: QueryMetrics):
        """Record query metrics with memory management"""
        self.query_metrics.append(metrics)
        
        # Manage memory by keeping only recent metrics
        if len(self.query_metrics) > self.max_metrics_history:
            # Remove oldest 10%
            remove_count = self.max_metrics_history // 10
            self.query_metrics = self.query_metrics[remove_count:]
    
    def get_performance_stats(self, hours: int = 1) -> PerformanceStats:
        """Get aggregated performance statistics for the specified time period"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        recent_metrics = [m for m in self.query_metrics if m.timestamp >= cutoff_time]
        
        if not recent_metrics:
            return PerformanceStats()
        
        # Calculate statistics
        execution_times = [m.execution_time for m in recent_metrics]
        slow_queries = [m for m in recent_metrics if m.execution_time > self.slow_query_threshold]
        
        # Analyze queries by table
        queries_by_table = {}
        for metrics in recent_metrics:
            tables = self._extract_tables_from_query(metrics.query)
            for table in tables:
                queries_by_table[table] = queries_by_table.get(table, 0) + 1
        
        # Get slowest queries
        slowest_queries = sorted(recent_metrics, key=lambda x: x.execution_time, reverse=True)[:10]
        
        return PerformanceStats(
            total_queries=len(recent_metrics),
            avg_execution_time=sum(execution_times) / len(execution_times),
            max_execution_time=max(execution_times),
            slow_queries_count=len(slow_queries),
            queries_by_table=queries_by_table,
            slowest_queries=slowest_queries
        )
    
    def _extract_tables_from_query(self, query: str) -> List[str]:
        """Extract table names from SQL query"""
        import re
        
        # Simple regex to find table names after FROM and JOIN
        pattern = r'\b(?:FROM|JOIN)\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        matches = re.findall(pattern, query.upper())
        return list(set(matches))
    
    def get_optimization_recommendations(self) -> List[Dict[str, Any]]:
        """Generate optimization recommendations based on query analysis"""
        recommendations = []
        stats = self.get_performance_stats(hours=24)  # Analyze last 24 hours
        
        # Check for slow queries
        if stats.slow_queries_count > 0:
            slow_query_ratio = stats.slow_queries_count / max(1, stats.total_queries)
            if slow_query_ratio > 0.05:  # More than 5% slow queries
                recommendations.append({
                    "type": "slow_queries",
                    "severity": "high" if slow_query_ratio > 0.15 else "medium",
                    "message": f"{stats.slow_queries_count} slow queries detected ({slow_query_ratio:.1%} of total)",
                    "suggestion": "Review and optimize slow queries, consider adding indexes",
                    "details": {
                        "slow_queries_count": stats.slow_queries_count,
                        "total_queries": stats.total_queries,
                        "slowest_query_time": stats.max_execution_time
                    }
                })
        
        # Check for high query volume on specific tables
        for table, count in stats.queries_by_table.items():
            if count > 1000:  # More than 1000 queries per hour
                recommendations.append({
                    "type": "high_table_usage",
                    "severity": "medium",
                    "message": f"High query volume on table '{table}': {count} queries/hour",
                    "suggestion": "Consider adding indexes or caching for frequently accessed data",
                    "details": {
                        "table": table,
                        "query_count": count
                    }
                })
        
        # Check average execution time
        if stats.avg_execution_time > 0.5:  # Average > 500ms
            recommendations.append({
                "type": "high_avg_time",
                "severity": "medium",
                "message": f"High average query execution time: {stats.avg_execution_time:.3f}s",
                "suggestion": "Optimize frequent queries and consider database tuning",
                "details": {
                    "avg_execution_time": stats.avg_execution_time,
                    "total_queries": stats.total_queries
                }
            })
        
        return recommendations
    
    def analyze_query_patterns(self) -> Dict[str, Any]:
        """Analyze query patterns for optimization insights"""
        recent_metrics = self.query_metrics[-1000:]  # Last 1000 queries
        
        if not recent_metrics:
            return {}
        
        # Pattern analysis
        query_types = {}
        table_access_patterns = {}
        
        for metrics in recent_metrics:
            query = metrics.query.upper().strip()
            
            # Classify query type
            if query.startswith('SELECT'):
                query_types['SELECT'] = query_types.get('SELECT', 0) + 1
            elif query.startswith('INSERT'):
                query_types['INSERT'] = query_types.get('INSERT', 0) + 1
            elif query.startswith('UPDATE'):
                query_types['UPDATE'] = query_types.get('UPDATE', 0) + 1
            elif query.startswith('DELETE'):
                query_types['DELETE'] = query_types.get('DELETE', 0) + 1
            
            # Analyze table access patterns
            tables = self._extract_tables_from_query(query)
            for table in tables:
                if table not in table_access_patterns:
                    table_access_patterns[table] = {
                        'count': 0,
                        'avg_time': 0,
                        'max_time': 0
                    }
                
                pattern = table_access_patterns[table]
                pattern['count'] += 1
                pattern['avg_time'] = ((pattern['avg_time'] * (pattern['count'] - 1)) + 
                                     metrics.execution_time) / pattern['count']
                pattern['max_time'] = max(pattern['max_time'], metrics.execution_time)
        
        return {
            'query_types': query_types,
            'table_access_patterns': table_access_patterns,
            'total_analyzed': len(recent_metrics),
            'analysis_timestamp': datetime.utcnow().isoformat()
        }
    
    @contextmanager
    def query_timer(self, operation_name: str):
        """Context manager for timing specific operations"""
        start_time = time.time()
        try:
            yield
        finally:
            execution_time = time.time() - start_time
            logger.info(f"Operation '{operation_name}' completed in {execution_time:.3f}s")
            
            if execution_time > self.slow_query_threshold:
                logger.warning(f"Slow operation detected: '{operation_name}' took {execution_time:.3f}s")
    
    def enable(self):
        """Enable performance monitoring"""
        self.enabled = True
        logger.info("Performance monitoring enabled")
    
    def disable(self):
        """Disable performance monitoring"""
        self.enabled = False
        logger.info("Performance monitoring disabled")
    
    def clear_metrics(self):
        """Clear collected metrics"""
        self.query_metrics.clear()
        logger.info("Performance metrics cleared")
    
    def export_metrics(self, format: str = "json") -> str:
        """Export metrics in specified format"""
        stats = self.get_performance_stats(hours=24)
        recommendations = self.get_optimization_recommendations()
        patterns = self.analyze_query_patterns()
        
        export_data = {
            "performance_stats": {
                "total_queries": stats.total_queries,
                "avg_execution_time": stats.avg_execution_time,
                "max_execution_time": stats.max_execution_time,
                "slow_queries_count": stats.slow_queries_count,
                "queries_by_table": stats.queries_by_table
            },
            "recommendations": recommendations,
            "query_patterns": patterns,
            "export_timestamp": datetime.utcnow().isoformat()
        }
        
        if format.lower() == "json":
            import json
            return json.dumps(export_data, indent=2, default=str)
        else:
            return str(export_data)


# Global performance monitor instance
performance_monitor = PerformanceMonitor()


def query_performance_tracker(func):
    """Decorator to track function execution time"""
    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        with performance_monitor.query_timer(f"{func.__module__}.{func.__name__}"):
            return await func(*args, **kwargs)
    
    @wraps(func)
    def sync_wrapper(*args, **kwargs):
        with performance_monitor.query_timer(f"{func.__module__}.{func.__name__}"):
            return func(*args, **kwargs)
    
    return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper