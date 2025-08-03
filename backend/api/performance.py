"""
Performance Monitoring API Endpoints

FastAPI endpoints for database performance monitoring and optimization.
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
from core.performance_monitor import performance_monitor
from core.query_optimizer import create_query_optimizer

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/performance", tags=["performance"])


class PerformanceStatsResponse(BaseModel):
    """Response model for performance statistics"""
    total_queries: int
    avg_execution_time: float
    max_execution_time: float
    slow_queries_count: int
    queries_by_table: Dict[str, int]
    slowest_queries: List[Dict[str, Any]]
    analysis_period_hours: int


class OptimizationRecommendation(BaseModel):
    """Optimization recommendation"""
    type: str
    severity: str
    message: str
    suggestion: str
    details: Dict[str, Any]


class DatabaseStatsResponse(BaseModel):
    """Database statistics response"""
    tables: List[Dict[str, Any]]
    total_live_rows: int
    analysis_timestamp: datetime


class QueryPatternAnalysis(BaseModel):
    """Query pattern analysis response"""
    query_types: Dict[str, int]
    table_access_patterns: Dict[str, Dict[str, Any]]
    total_analyzed: int
    analysis_timestamp: str


@router.get("/stats", response_model=PerformanceStatsResponse)
async def get_performance_stats(
    hours: int = Query(default=1, ge=1, le=24, description="Hours to analyze"),
    current_user: User = Depends(get_current_user)
):
    """
    Get database performance statistics for the specified time period.
    
    Requires admin privileges to access performance data.
    """
    try:
        # Check if user has admin access
        if current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required for performance monitoring"
            )
        
        # Get performance statistics
        stats = performance_monitor.get_performance_stats(hours=hours)
        
        # Convert slowest queries to serializable format
        slowest_queries = []
        for query_metrics in stats.slowest_queries:
            slowest_queries.append({
                "query": query_metrics.query[:500] + "..." if len(query_metrics.query) > 500 else query_metrics.query,
                "execution_time": query_metrics.execution_time,
                "timestamp": query_metrics.timestamp.isoformat(),
                "row_count": query_metrics.row_count
            })
        
        return PerformanceStatsResponse(
            total_queries=stats.total_queries,
            avg_execution_time=stats.avg_execution_time,
            max_execution_time=stats.max_execution_time,
            slow_queries_count=stats.slow_queries_count,
            queries_by_table=stats.queries_by_table,
            slowest_queries=slowest_queries,
            analysis_period_hours=hours
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get performance stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve performance statistics"
        )


@router.get("/recommendations", response_model=List[OptimizationRecommendation])
async def get_optimization_recommendations(
    current_user: User = Depends(get_current_user)
):
    """
    Get database optimization recommendations based on query analysis.
    
    Analyzes recent query patterns and provides actionable optimization suggestions.
    """
    try:
        # Check admin access
        if current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required for optimization recommendations"
            )
        
        recommendations = performance_monitor.get_optimization_recommendations()
        
        return [
            OptimizationRecommendation(
                type=rec["type"],
                severity=rec["severity"],
                message=rec["message"],
                suggestion=rec["suggestion"],
                details=rec["details"]
            )
            for rec in recommendations
        ]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get optimization recommendations: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate optimization recommendations"
        )


@router.get("/database-stats", response_model=DatabaseStatsResponse)
async def get_database_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get comprehensive database statistics including table sizes and activity.
    
    Provides insights into database growth and usage patterns.
    """
    try:
        # Check admin access
        if current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required for database statistics"
            )
        
        optimizer = create_query_optimizer(db)
        stats = optimizer.get_database_stats()
        
        if 'error' in stats:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database stats error: {stats['error']}"
            )
        
        return DatabaseStatsResponse(
            tables=stats['tables'],
            total_live_rows=stats['total_live_rows'],
            analysis_timestamp=datetime.utcnow()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get database stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve database statistics"
        )


@router.get("/query-patterns", response_model=QueryPatternAnalysis)
async def get_query_patterns(
    current_user: User = Depends(get_current_user)
):
    """
    Analyze query patterns to identify optimization opportunities.
    
    Examines recent query types and table access patterns.
    """
    try:
        # Check admin access
        if current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required for query pattern analysis"
            )
        
        patterns = performance_monitor.analyze_query_patterns()
        
        return QueryPatternAnalysis(
            query_types=patterns.get('query_types', {}),
            table_access_patterns=patterns.get('table_access_patterns', {}),
            total_analyzed=patterns.get('total_analyzed', 0),
            analysis_timestamp=patterns.get('analysis_timestamp', datetime.utcnow().isoformat())
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to analyze query patterns: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to analyze query patterns"
        )


@router.post("/cleanup/expired-sessions")
async def cleanup_expired_sessions(
    batch_size: int = Query(default=1000, ge=100, le=10000, description="Batch size for cleanup"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Clean up expired signing sessions to optimize database performance.
    
    Removes expired sessions in batches to avoid locking issues.
    """
    try:
        # Check admin access
        if current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required for database cleanup"
            )
        
        optimizer = create_query_optimizer(db)
        deleted_count = optimizer.cleanup_expired_sessions(batch_size=batch_size)
        
        logger.info(f"Cleanup completed by user {current_user.id}: {deleted_count} expired sessions removed")
        
        return {
            "success": True,
            "deleted_sessions": deleted_count,
            "batch_size": batch_size,
            "cleanup_timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cleanup expired sessions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cleanup expired sessions"
        )


@router.post("/monitoring/enable")
async def enable_performance_monitoring(
    current_user: User = Depends(get_current_user)
):
    """Enable database performance monitoring"""
    try:
        if current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required for performance monitoring control"
            )
        
        performance_monitor.enable()
        
        return {
            "success": True,
            "message": "Performance monitoring enabled",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to enable performance monitoring: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to enable performance monitoring"
        )


@router.post("/monitoring/disable")
async def disable_performance_monitoring(
    current_user: User = Depends(get_current_user)
):
    """Disable database performance monitoring"""
    try:
        if current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required for performance monitoring control"
            )
        
        performance_monitor.disable()
        
        return {
            "success": True,
            "message": "Performance monitoring disabled",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to disable performance monitoring: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disable performance monitoring"
        )


@router.get("/export")
async def export_performance_metrics(
    format: str = Query(default="json", regex="^(json)$", description="Export format"),
    current_user: User = Depends(get_current_user)
):
    """
    Export performance metrics for external analysis.
    
    Generates comprehensive performance report in specified format.
    """
    try:
        if current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required for performance data export"
            )
        
        export_data = performance_monitor.export_metrics(format=format)
        
        from fastapi.responses import PlainTextResponse
        
        return PlainTextResponse(
            content=export_data,
            media_type="application/json" if format == "json" else "text/plain",
            headers={
                "Content-Disposition": f"attachment; filename=performance_metrics_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.{format}"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to export performance metrics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export performance metrics"
        )


@router.get("/health")
async def performance_monitoring_health():
    """Health check for performance monitoring service"""
    try:
        stats = performance_monitor.get_performance_stats(hours=1)
        
        return {
            "status": "healthy",
            "service": "performance-monitoring",
            "monitoring_enabled": performance_monitor.enabled,
            "metrics_collected": len(performance_monitor.query_metrics),
            "recent_queries": stats.total_queries,
            "avg_query_time": stats.avg_execution_time,
            "slow_queries": stats.slow_queries_count
        }
        
    except Exception as e:
        logger.error(f"Performance monitoring health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Performance monitoring unhealthy: {str(e)}"
        )