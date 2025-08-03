"""Create audit logs table

Revision ID: 003
Revises: 002
Create Date: 2024-01-08 15:30:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create enum for audit event types
    audit_event_type = postgresql.ENUM(
        'USER_AUTHENTICATION',
        'CERTIFICATE_REQUEST', 
        'SIGNING_STARTED',
        'SIGNING_COMPLETED',
        'SIGNING_FAILED',
        'DOCUMENT_UPLOADED',
        'TIMESTAMP_REQUEST',
        'VALIDATION_CHECK',
        'PROVIDER_HEALTH_CHECK',
        'SYSTEM_ERROR',
        name='auditeventtype',
        create_type=False
    )
    audit_event_type.create(op.get_bind(), checkfirst=True)
    
    # Create audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('event_id', sa.String(255), nullable=False, unique=True),
        sa.Column('event_type', audit_event_type, nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('user_id', sa.String(255), nullable=True),
        sa.Column('session_id', sa.String(255), nullable=True),
        sa.Column('provider_name', sa.String(255), nullable=True),
        sa.Column('resource_id', sa.String(255), nullable=True),
        sa.Column('client_ip', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.Text, nullable=True),
        sa.Column('trace_id', sa.String(255), nullable=True),
        sa.Column('span_id', sa.String(255), nullable=True),
        sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    
    # Create indexes for efficient querying
    op.create_index('ix_audit_logs_event_id', 'audit_logs', ['event_id'])
    op.create_index('ix_audit_logs_event_type', 'audit_logs', ['event_type'])
    op.create_index('ix_audit_logs_timestamp', 'audit_logs', ['timestamp'])
    op.create_index('ix_audit_logs_user_id', 'audit_logs', ['user_id'])
    op.create_index('ix_audit_logs_session_id', 'audit_logs', ['session_id'])
    op.create_index('ix_audit_logs_provider_name', 'audit_logs', ['provider_name'])
    op.create_index('ix_audit_logs_trace_id', 'audit_logs', ['trace_id'])
    
    # Composite indexes for common queries
    op.create_index('ix_audit_logs_user_time', 'audit_logs', ['user_id', 'timestamp'])
    op.create_index('ix_audit_logs_event_time', 'audit_logs', ['event_type', 'timestamp'])
    op.create_index('ix_audit_logs_provider_time', 'audit_logs', ['provider_name', 'timestamp'])
    op.create_index('ix_audit_logs_session_time', 'audit_logs', ['session_id', 'timestamp'])
    
    # GIN index for JSONB details column
    op.create_index('ix_audit_logs_details_gin', 'audit_logs', ['details'], postgresql_using='gin')


def downgrade() -> None:
    # Drop all indexes
    op.drop_index('ix_audit_logs_details_gin', table_name='audit_logs')
    op.drop_index('ix_audit_logs_session_time', table_name='audit_logs')
    op.drop_index('ix_audit_logs_provider_time', table_name='audit_logs')
    op.drop_index('ix_audit_logs_event_time', table_name='audit_logs')
    op.drop_index('ix_audit_logs_user_time', table_name='audit_logs')
    op.drop_index('ix_audit_logs_trace_id', table_name='audit_logs')
    op.drop_index('ix_audit_logs_provider_name', table_name='audit_logs')
    op.drop_index('ix_audit_logs_session_id', table_name='audit_logs')
    op.drop_index('ix_audit_logs_user_id', table_name='audit_logs')
    op.drop_index('ix_audit_logs_timestamp', table_name='audit_logs')
    op.drop_index('ix_audit_logs_event_type', table_name='audit_logs')
    op.drop_index('ix_audit_logs_event_id', table_name='audit_logs')
    
    # Drop table
    op.drop_table('audit_logs')
    
    # Drop enum type
    audit_event_type = postgresql.ENUM(name='auditeventtype')
    audit_event_type.drop(op.get_bind(), checkfirst=True)