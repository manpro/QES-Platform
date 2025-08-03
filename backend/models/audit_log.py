"""
Audit Log Database Model

SQLAlchemy model for storing audit events in PostgreSQL for compliance.
"""

from sqlalchemy import Column, String, DateTime, Text, Index, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID, JSONB
from datetime import datetime, timezone
import uuid

from .base import Base
from ..core.audit_logger import AuditEventType


class AuditLog(Base):
    """
    Audit log table for compliance and forensic analysis.
    
    This table stores all auditable events with proper indexing
    for efficient searches and compliance reporting.
    """
    __tablename__ = "audit_logs"
    
    # Primary key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Event identification
    event_id = Column(String(255), unique=True, nullable=False, index=True)
    event_type = Column(SQLEnum(AuditEventType), nullable=False, index=True)
    
    # Timestamp (critical for audit trails)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    
    # User and session context
    user_id = Column(String(255), nullable=True, index=True)
    session_id = Column(String(255), nullable=True, index=True)
    
    # Provider and resource context
    provider_name = Column(String(255), nullable=True, index=True)
    resource_id = Column(String(255), nullable=True, index=True)
    
    # Client information
    client_ip = Column(String(45), nullable=True)  # IPv6 support
    user_agent = Column(Text, nullable=True)
    
    # Tracing information
    trace_id = Column(String(255), nullable=True, index=True)
    span_id = Column(String(255), nullable=True)
    
    # Structured event details
    details = Column(JSONB, nullable=True)
    
    # Integrity and forensics
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Composite indexes for common queries
    __table_args__ = (
        Index('ix_audit_logs_user_time', 'user_id', 'timestamp'),
        Index('ix_audit_logs_event_time', 'event_type', 'timestamp'),
        Index('ix_audit_logs_provider_time', 'provider_name', 'timestamp'),
        Index('ix_audit_logs_trace', 'trace_id'),
        Index('ix_audit_logs_session_time', 'session_id', 'timestamp'),
        # GIN index for JSONB details column for efficient JSON queries
        Index('ix_audit_logs_details_gin', 'details', postgresql_using='gin'),
    )
    
    def __repr__(self):
        return f"<AuditLog(event_id='{self.event_id}', event_type='{self.event_type}', timestamp='{self.timestamp}')>"
    
    def to_dict(self) -> dict:
        """Convert audit log to dictionary"""
        return {
            'id': str(self.id),
            'event_id': self.event_id,
            'event_type': self.event_type.value if self.event_type else None,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'provider_name': self.provider_name,
            'resource_id': self.resource_id,
            'client_ip': self.client_ip,
            'user_agent': self.user_agent,
            'trace_id': self.trace_id,
            'span_id': self.span_id,
            'details': self.details,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }