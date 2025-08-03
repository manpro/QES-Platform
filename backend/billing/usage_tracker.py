"""
Usage tracking for QES Platform billing

Enhanced real-time usage tracking with advanced analytics,
quota enforcement, and billing integration.
"""

import logging
import asyncio
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Dict, List, Optional, Any
from uuid import UUID, uuid4

from ..database import get_db_connection
from .models import UsageRecord, UsageMetricType
from .exceptions import UsageTrackingException
from core.audit_logger import AuditLogger, AuditEvent, AuditEventType


logger = logging.getLogger(__name__)


class UsageTracker:
    """
    Enhanced usage tracker with real-time analytics and quota enforcement.
    
    Features:
    - Real-time usage recording
    - Bulk operations for performance
    - Advanced analytics and reporting
    - Integration with billing and audit systems
    - Predictive usage analysis
    """
    
    def __init__(self, audit_logger: AuditLogger = None):
        """Initialize usage tracker with audit logging"""
        self.audit_logger = audit_logger or AuditLogger({
            "postgres_enabled": True,
            "loki_enabled": True
        })
        self._batch_buffer = []
        self._batch_size = 100
        self._last_flush = datetime.utcnow()
    
    def record_usage(
        self,
        tenant_id: UUID,
        subscription_id: UUID,
        metric_type: UsageMetricType,
        quantity: int = 1,
        resource_id: str = None,
        user_id: UUID = None,
        metadata: Dict[str, any] = None
    ) -> UsageRecord:
        """
        Record a usage event
        
        Args:
            tenant_id: Tenant identifier
            subscription_id: Subscription identifier
            metric_type: Type of usage metric
            quantity: Usage quantity
            resource_id: Associated resource ID
            user_id: User who performed the action
            metadata: Additional metadata
            
        Returns:
            Created usage record
        """
        try:
            now = datetime.utcnow()
            
            # Calculate billing period (start of current month)
            billing_period_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            # Next month's start
            if billing_period_start.month == 12:
                billing_period_end = billing_period_start.replace(year=billing_period_start.year + 1, month=1)
            else:
                billing_period_end = billing_period_start.replace(month=billing_period_start.month + 1)
            
            usage_record = UsageRecord(
                id=uuid4(),
                tenant_id=tenant_id,
                subscription_id=subscription_id,
                metric_type=metric_type,
                quantity=quantity,
                timestamp=now,
                billing_period_start=billing_period_start,
                billing_period_end=billing_period_end,
                resource_id=resource_id,
                user_id=user_id,
                metadata=metadata or {}
            )
            
            self._save_usage_record(usage_record)
            
            logger.debug(
                f"Recorded usage: tenant={tenant_id}, metric={metric_type.value}, "
                f"quantity={quantity}, resource={resource_id}"
            )
            
            return usage_record
            
        except Exception as e:
            logger.error(f"Failed to record usage: {e}")
            raise UsageTrackingException(f"Failed to record usage: {e}", metric_type.value)
    
    def get_period_usage(
        self,
        tenant_id: UUID,
        period_start: datetime,
        period_end: datetime
    ) -> Dict[str, int]:
        """
        Get usage totals for a billing period
        
        Args:
            tenant_id: Tenant identifier
            period_start: Start of billing period
            period_end: End of billing period
            
        Returns:
            Dictionary of metric types to usage counts
        """
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT metric_type, SUM(quantity) as total
                    FROM usage_records
                    WHERE tenant_id = %s 
                      AND timestamp >= %s 
                      AND timestamp < %s
                    GROUP BY metric_type
                """, (str(tenant_id), period_start, period_end))
                
                usage = {}
                for row in cursor.fetchall():
                    metric_type = row[0]
                    total = int(row[1])
                    usage[metric_type] = total
                
                logger.debug(f"Retrieved period usage for tenant {tenant_id}: {usage}")
                return usage
                
        except Exception as e:
            logger.error(f"Failed to get period usage: {e}")
            raise UsageTrackingException(f"Failed to get period usage: {e}")
    
    def get_current_month_usage(self, tenant_id: UUID) -> Dict[str, int]:
        """
        Get usage totals for current month
        
        Args:
            tenant_id: Tenant identifier
            
        Returns:
            Dictionary of metric types to usage counts
        """
        now = datetime.utcnow()
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        if now.month == 12:
            month_end = month_start.replace(year=now.year + 1, month=1)
        else:
            month_end = month_start.replace(month=now.month + 1)
        
        return self.get_period_usage(tenant_id, month_start, month_end)
    
    def get_usage_history(
        self,
        tenant_id: UUID,
        metric_type: UsageMetricType = None,
        days: int = 30,
        limit: int = 100
    ) -> List[UsageRecord]:
        """
        Get usage history for a tenant
        
        Args:
            tenant_id: Tenant identifier
            metric_type: Filter by metric type
            days: Number of days to look back
            limit: Maximum number of records
            
        Returns:
            List of usage records
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                query = """
                    SELECT id, tenant_id, subscription_id, metric_type, quantity,
                           timestamp, billing_period_start, billing_period_end,
                           resource_id, user_id, billed, billed_at, invoice_id, metadata
                    FROM usage_records
                    WHERE tenant_id = %s AND timestamp >= %s
                """
                params = [str(tenant_id), cutoff_date]
                
                if metric_type:
                    query += " AND metric_type = %s"
                    params.append(metric_type.value)
                
                query += " ORDER BY timestamp DESC LIMIT %s"
                params.append(limit)
                
                cursor.execute(query, params)
                
                records = []
                for row in cursor.fetchall():
                    record = UsageRecord(
                        id=UUID(row[0]),
                        tenant_id=UUID(row[1]),
                        subscription_id=UUID(row[2]),
                        metric_type=UsageMetricType(row[3]),
                        quantity=row[4],
                        timestamp=row[5],
                        billing_period_start=row[6],
                        billing_period_end=row[7],
                        resource_id=row[8],
                        user_id=UUID(row[9]) if row[9] else None,
                        billed=row[10],
                        billed_at=row[11],
                        invoice_id=UUID(row[12]) if row[12] else None,
                        metadata=row[13] or {}
                    )
                    records.append(record)
                
                return records
                
        except Exception as e:
            logger.error(f"Failed to get usage history: {e}")
            raise UsageTrackingException(f"Failed to get usage history: {e}")
    
    def get_unbilled_usage(
        self,
        tenant_id: UUID,
        period_start: datetime,
        period_end: datetime
    ) -> List[UsageRecord]:
        """
        Get unbilled usage records for a period
        
        Args:
            tenant_id: Tenant identifier
            period_start: Start of billing period
            period_end: End of billing period
            
        Returns:
            List of unbilled usage records
        """
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, tenant_id, subscription_id, metric_type, quantity,
                           timestamp, billing_period_start, billing_period_end,
                           resource_id, user_id, billed, billed_at, invoice_id, metadata
                    FROM usage_records
                    WHERE tenant_id = %s 
                      AND timestamp >= %s 
                      AND timestamp < %s
                      AND billed = FALSE
                    ORDER BY timestamp ASC
                """, (str(tenant_id), period_start, period_end))
                
                records = []
                for row in cursor.fetchall():
                    record = UsageRecord(
                        id=UUID(row[0]),
                        tenant_id=UUID(row[1]),
                        subscription_id=UUID(row[2]),
                        metric_type=UsageMetricType(row[3]),
                        quantity=row[4],
                        timestamp=row[5],
                        billing_period_start=row[6],
                        billing_period_end=row[7],
                        resource_id=row[8],
                        user_id=UUID(row[9]) if row[9] else None,
                        billed=row[10],
                        billed_at=row[11],
                        invoice_id=UUID(row[12]) if row[12] else None,
                        metadata=row[13] or {}
                    )
                    records.append(record)
                
                return records
                
        except Exception as e:
            logger.error(f"Failed to get unbilled usage: {e}")
            raise UsageTrackingException(f"Failed to get unbilled usage: {e}")
    
    def mark_as_billed(
        self,
        usage_record_ids: List[UUID],
        invoice_id: UUID
    ) -> None:
        """
        Mark usage records as billed
        
        Args:
            usage_record_ids: List of usage record IDs to mark as billed
            invoice_id: Invoice ID that billed these records
        """
        try:
            now = datetime.utcnow()
            
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Convert UUIDs to strings for SQL
                record_ids_str = [str(record_id) for record_id in usage_record_ids]
                
                cursor.execute("""
                    UPDATE usage_records
                    SET billed = TRUE, billed_at = %s, invoice_id = %s
                    WHERE id = ANY(%s)
                """, (now, str(invoice_id), record_ids_str))
                
                conn.commit()
                
                logger.info(f"Marked {len(usage_record_ids)} usage records as billed for invoice {invoice_id}")
                
        except Exception as e:
            logger.error(f"Failed to mark usage as billed: {e}")
            raise UsageTrackingException(f"Failed to mark usage as billed: {e}")
    
    def calculate_overage_charges(
        self,
        tenant_id: UUID,
        usage_totals: Dict[str, int],
        plan_limits: Dict[str, int],
        overage_prices: Dict[str, Decimal]
    ) -> Dict[str, Decimal]:
        """
        Calculate overage charges for usage exceeding plan limits
        
        Args:
            tenant_id: Tenant identifier
            usage_totals: Usage totals by metric type
            plan_limits: Plan limits by metric type
            overage_prices: Overage prices by metric type
            
        Returns:
            Dictionary of metric types to overage charges
        """
        try:
            overage_charges = {}
            
            for metric_type, usage_count in usage_totals.items():
                limit = plan_limits.get(metric_type, 0)
                price = overage_prices.get(metric_type, Decimal("0"))
                
                if limit > 0 and usage_count > limit:
                    overage_quantity = usage_count - limit
                    overage_charge = overage_quantity * price
                    overage_charges[metric_type] = overage_charge
                    
                    logger.debug(
                        f"Calculated overage for {metric_type}: "
                        f"usage={usage_count}, limit={limit}, "
                        f"overage={overage_quantity}, charge={overage_charge}"
                    )
            
            return overage_charges
            
        except Exception as e:
            logger.error(f"Failed to calculate overage charges: {e}")
            raise UsageTrackingException(f"Failed to calculate overage charges: {e}")
    
    def _save_usage_record(self, usage_record: UsageRecord) -> None:
        """
        Save usage record to database
        
        Args:
            usage_record: Usage record to save
        """
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO usage_records (
                    id, tenant_id, subscription_id, metric_type, quantity,
                    timestamp, billing_period_start, billing_period_end,
                    resource_id, user_id, billed, billed_at, invoice_id, metadata
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                str(usage_record.id),
                str(usage_record.tenant_id),
                str(usage_record.subscription_id),
                usage_record.metric_type.value,
                usage_record.quantity,
                usage_record.timestamp,
                usage_record.billing_period_start,
                usage_record.billing_period_end,
                usage_record.resource_id,
                str(usage_record.user_id) if usage_record.user_id else None,
                usage_record.billed,
                usage_record.billed_at,
                str(usage_record.invoice_id) if usage_record.invoice_id else None,
                usage_record.metadata
            ))
            conn.commit()