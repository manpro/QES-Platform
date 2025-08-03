"""
Database Query Optimization Utilities

Performance optimizations for common database operations.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy import text, func, and_, or_
from sqlalchemy.orm import Query, Session, joinedload, selectinload
from sqlalchemy.orm.strategy_options import Load
from datetime import datetime, timedelta

from models.document import Document, DocumentStatus
from models.signature import Signature, SignatureStatus
from models.user import User
from models.audit_log import AuditLog

logger = logging.getLogger(__name__)


class QueryOptimizer:
    """
    Centralized query optimization for common database operations.
    
    Provides optimized queries with proper indexing, eager loading,
    and query result caching strategies.
    """
    
    def __init__(self, db_session: Session):
        self.db = db_session
    
    def get_user_documents_optimized(
        self, 
        user_id: str, 
        status: Optional[DocumentStatus] = None,
        limit: int = 50,
        offset: int = 0,
        include_signatures: bool = True
    ) -> Tuple[List[Document], int]:
        """
        Optimized query for user documents with pagination.
        
        Uses composite index on (owner_id, status, created_at) for optimal performance.
        """
        # Base query with optimized ordering
        query = self.db.query(Document).filter(Document.owner_id == user_id)
        
        # Add status filter if specified
        if status:
            query = query.filter(Document.status == status)
        
        # Count total for pagination (before limit/offset)
        total_count = query.count()
        
        # Apply ordering using index
        query = query.order_by(Document.created_at.desc())
        
        # Eager load signatures if requested
        if include_signatures:
            query = query.options(
                selectinload(Document.signatures).options(
                    selectinload(Signature.signer)
                )
            )
        
        # Apply pagination
        documents = query.offset(offset).limit(limit).all()
        
        logger.debug(f"Retrieved {len(documents)} documents for user {user_id} (total: {total_count})")
        return documents, total_count
    
    def get_document_signatures_optimized(
        self, 
        document_id: str,
        include_verification: bool = True
    ) -> List[Signature]:
        """
        Optimized query for document signatures.
        
        Uses composite index on (document_id, status, created_at).
        """
        query = self.db.query(Signature).filter(Signature.document_id == document_id)
        
        # Eager load related data
        query = query.options(
            joinedload(Signature.signer),
            joinedload(Signature.document)
        )
        
        if include_verification:
            # Only load verification details for completed signatures
            query = query.filter(Signature.status == SignatureStatus.COMPLETED)
        
        # Order by creation time (newest first)
        signatures = query.order_by(Signature.created_at.desc()).all()
        
        logger.debug(f"Retrieved {len(signatures)} signatures for document {document_id}")
        return signatures
    
    def get_tenant_signature_stats(self, tenant_id: str, days: int = 30) -> Dict[str, Any]:
        """
        Optimized query for tenant signature statistics.
        
        Uses aggregate functions and date filtering for performance.
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Use raw SQL for complex aggregations
        stats_query = text("""
            SELECT 
                COUNT(*) as total_signatures,
                COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_signatures,
                COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_signatures,
                COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_signatures,
                COUNT(DISTINCT qes_provider) as providers_used,
                COUNT(DISTINCT signer_id) as unique_signers,
                AVG(EXTRACT(EPOCH FROM (updated_at - created_at))) as avg_completion_time_seconds
            FROM signatures 
            WHERE tenant_id = :tenant_id 
            AND created_at >= :cutoff_date
        """)
        
        result = self.db.execute(stats_query, {
            'tenant_id': tenant_id, 
            'cutoff_date': cutoff_date
        }).fetchone()
        
        stats = {
            'total_signatures': result.total_signatures or 0,
            'completed_signatures': result.completed_signatures or 0,
            'failed_signatures': result.failed_signatures or 0,
            'pending_signatures': result.pending_signatures or 0,
            'providers_used': result.providers_used or 0,
            'unique_signers': result.unique_signers or 0,
            'avg_completion_time_seconds': float(result.avg_completion_time_seconds or 0),
            'success_rate': round((result.completed_signatures or 0) / max(1, result.total_signatures or 1) * 100, 2),
            'period_days': days
        }
        
        logger.debug(f"Generated signature stats for tenant {tenant_id}: {stats}")
        return stats
    
    def get_provider_performance_metrics(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Optimized query for QES provider performance metrics.
        
        Uses provider index and date filtering for analytics.
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Raw SQL for complex provider analytics
        metrics_query = text("""
            SELECT 
                qes_provider,
                COUNT(*) as total_requests,
                COUNT(CASE WHEN status = 'completed' THEN 1 END) as successful_requests,
                COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_requests,
                AVG(EXTRACT(EPOCH FROM (updated_at - created_at))) as avg_response_time_seconds,
                MIN(created_at) as first_request,
                MAX(created_at) as last_request
            FROM signatures 
            WHERE created_at >= :cutoff_date
            GROUP BY qes_provider
            ORDER BY total_requests DESC
        """)
        
        results = self.db.execute(metrics_query, {'cutoff_date': cutoff_date}).fetchall()
        
        metrics = []
        for result in results:
            success_rate = (result.successful_requests / max(1, result.total_requests)) * 100
            
            metrics.append({
                'provider': result.qes_provider,
                'total_requests': result.total_requests,
                'successful_requests': result.successful_requests,
                'failed_requests': result.failed_requests,
                'success_rate': round(success_rate, 2),
                'avg_response_time_seconds': float(result.avg_response_time_seconds or 0),
                'first_request': result.first_request,
                'last_request': result.last_request
            })
        
        logger.debug(f"Generated provider metrics for {len(metrics)} providers")
        return metrics
    
    def search_documents_optimized(
        self, 
        tenant_id: str,
        search_term: str,
        document_type: Optional[str] = None,
        status: Optional[DocumentStatus] = None,
        limit: int = 50
    ) -> List[Document]:
        """
        Optimized full-text search for documents.
        
        Uses GIN index for full-text search performance.
        """
        # Use PostgreSQL full-text search
        search_query = text("""
            SELECT d.* FROM documents d
            WHERE d.tenant_id = :tenant_id
            AND to_tsvector('english', d.filename || ' ' || COALESCE(d.display_name, '')) 
                @@ plainto_tsquery('english', :search_term)
            AND (:document_type IS NULL OR d.document_type = :document_type)
            AND (:status IS NULL OR d.status = :status)
            ORDER BY ts_rank(
                to_tsvector('english', d.filename || ' ' || COALESCE(d.display_name, '')), 
                plainto_tsquery('english', :search_term)
            ) DESC, d.created_at DESC
            LIMIT :limit
        """)
        
        results = self.db.execute(search_query, {
            'tenant_id': tenant_id,
            'search_term': search_term,
            'document_type': document_type,
            'status': status.value if status else None,
            'limit': limit
        }).fetchall()
        
        # Convert results to Document objects
        document_ids = [result.id for result in results]
        if document_ids:
            documents = self.db.query(Document).filter(
                Document.id.in_(document_ids)
            ).options(
                selectinload(Document.signatures)
            ).all()
            
            # Maintain search ranking order
            ordered_documents = []
            for result in results:
                for doc in documents:
                    if doc.id == result.id:
                        ordered_documents.append(doc)
                        break
            
            logger.debug(f"Full-text search returned {len(ordered_documents)} documents")
            return ordered_documents
        
        return []
    
    def get_audit_events_optimized(
        self,
        tenant_id: Optional[str] = None,
        user_id: Optional[str] = None,
        event_types: Optional[List[str]] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0
    ) -> Tuple[List[AuditLog], int]:
        """
        Optimized audit log query with multiple filter options.
        
        Uses composite indexes for efficient filtering and pagination.
        """
        # Build query with filters
        query = self.db.query(AuditLog)
        
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        
        if event_types:
            query = query.filter(AuditLog.event_type.in_(event_types))
        
        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)
        
        # Count total results
        total_count = query.count()
        
        # Apply ordering and pagination
        events = query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()
        
        logger.debug(f"Retrieved {len(events)} audit events (total: {total_count})")
        return events, total_count
    
    def cleanup_expired_sessions(self, batch_size: int = 1000) -> int:
        """
        Optimized cleanup of expired signing sessions.
        
        Uses batch processing for large-scale cleanup operations.
        """
        try:
            # Delete expired sessions in batches
            deleted_count = 0
            
            while True:
                # Use raw SQL for efficient bulk deletion
                result = self.db.execute(text("""
                    DELETE FROM signing_sessions 
                    WHERE id IN (
                        SELECT id FROM signing_sessions 
                        WHERE expires_at < CURRENT_TIMESTAMP 
                        AND status != 'completed'
                        LIMIT :batch_size
                    )
                """), {'batch_size': batch_size})
                
                batch_deleted = result.rowcount
                deleted_count += batch_deleted
                
                if batch_deleted == 0:
                    break
                
                # Commit each batch
                self.db.commit()
                
                logger.debug(f"Deleted {batch_deleted} expired sessions (total: {deleted_count})")
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired sessions: {e}")
            self.db.rollback()
            return 0
    
    def get_database_stats(self) -> Dict[str, Any]:
        """
        Get database performance statistics and table sizes.
        """
        try:
            # Table sizes and row counts
            size_query = text("""
                SELECT 
                    schemaname,
                    tablename,
                    attname,
                    n_distinct,
                    correlation
                FROM pg_stats 
                WHERE schemaname = 'public'
                ORDER BY tablename, attname
            """)
            
            table_stats_query = text("""
                SELECT 
                    relname as table_name,
                    n_tup_ins as inserts,
                    n_tup_upd as updates,
                    n_tup_del as deletes,
                    n_live_tup as live_rows,
                    n_dead_tup as dead_rows,
                    last_vacuum,
                    last_autovacuum,
                    last_analyze,
                    last_autoanalyze
                FROM pg_stat_user_tables
                ORDER BY n_live_tup DESC
            """)
            
            stats_results = self.db.execute(table_stats_query).fetchall()
            
            stats = {
                'tables': [],
                'total_live_rows': 0
            }
            
            for result in stats_results:
                table_info = {
                    'table_name': result.table_name,
                    'live_rows': result.live_rows or 0,
                    'dead_rows': result.dead_rows or 0,
                    'inserts': result.inserts or 0,
                    'updates': result.updates or 0,
                    'deletes': result.deletes or 0,
                    'last_vacuum': result.last_vacuum,
                    'last_analyze': result.last_analyze
                }
                stats['tables'].append(table_info)
                stats['total_live_rows'] += table_info['live_rows']
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
            return {'error': str(e)}


def create_query_optimizer(db_session: Session) -> QueryOptimizer:
    """Create a QueryOptimizer instance for the given database session."""
    return QueryOptimizer(db_session)