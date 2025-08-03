"""create usage tracking tables

Revision ID: 005
Revises: 004
Create Date: 2024-01-08 16:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '005'
down_revision = '004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create usage tracking tables"""
    
    # Create usage_records table
    op.create_table(
        'usage_records',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('subscription_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('metric_type', sa.String(50), nullable=False),
        sa.Column('quantity', sa.Integer, nullable=False, default=1),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('billing_period_start', sa.DateTime(timezone=True), nullable=False),
        sa.Column('billing_period_end', sa.DateTime(timezone=True), nullable=False),
        sa.Column('resource_id', sa.String(255), nullable=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('billed', sa.Boolean, nullable=False, default=False),
        sa.Column('billed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('invoice_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('metadata', postgresql.JSONB, nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now())
    )
    
    # Create indexes for performance
    op.create_index('idx_usage_records_tenant_timestamp', 'usage_records', ['tenant_id', 'timestamp'])
    op.create_index('idx_usage_records_billing_period', 'usage_records', ['tenant_id', 'billing_period_start', 'billing_period_end'])
    op.create_index('idx_usage_records_metric_type', 'usage_records', ['tenant_id', 'metric_type'])
    op.create_index('idx_usage_records_billed', 'usage_records', ['billed', 'billing_period_start'])
    op.create_index('idx_usage_records_subscription', 'usage_records', ['subscription_id', 'timestamp'])
    op.create_index('idx_usage_records_resource', 'usage_records', ['resource_id'])
    
    # Create quota_violations table for tracking quota enforcement
    op.create_table(
        'quota_violations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('subscription_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('metric_type', sa.String(50), nullable=False),
        sa.Column('violation_type', sa.String(50), nullable=False),  # soft_limit, hard_limit, overage, rate_limit
        sa.Column('usage_count', sa.Integer, nullable=False),
        sa.Column('limit_value', sa.Integer, nullable=False),
        sa.Column('overage_charge', sa.Numeric(10, 4), nullable=True),
        sa.Column('action_taken', sa.String(100), nullable=True),  # warning_sent, usage_blocked, overage_billed
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('resolved', sa.Boolean, nullable=False, default=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('metadata', postgresql.JSONB, nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now())
    )
    
    # Create indexes for quota violations
    op.create_index('idx_quota_violations_tenant_timestamp', 'quota_violations', ['tenant_id', 'timestamp'])
    op.create_index('idx_quota_violations_type', 'quota_violations', ['violation_type', 'timestamp'])
    op.create_index('idx_quota_violations_resolved', 'quota_violations', ['resolved', 'timestamp'])
    
    # Create usage_aggregates table for pre-computed usage summaries
    op.create_table(
        'usage_aggregates',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('subscription_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('metric_type', sa.String(50), nullable=False),
        sa.Column('period_type', sa.String(20), nullable=False),  # hourly, daily, monthly
        sa.Column('period_start', sa.DateTime(timezone=True), nullable=False),
        sa.Column('period_end', sa.DateTime(timezone=True), nullable=False),
        sa.Column('total_quantity', sa.Integer, nullable=False, default=0),
        sa.Column('request_count', sa.Integer, nullable=False, default=0),
        sa.Column('unique_users', sa.Integer, nullable=False, default=0),
        sa.Column('avg_quantity_per_request', sa.Numeric(10, 4), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now())
    )
    
    # Create unique constraint for aggregates to prevent duplicates
    op.create_index('idx_usage_aggregates_unique', 'usage_aggregates', 
                    ['tenant_id', 'metric_type', 'period_type', 'period_start'], unique=True)
    op.create_index('idx_usage_aggregates_period', 'usage_aggregates', ['period_start', 'period_end'])
    
    # Create rate_limit_violations table for tracking rate limiting
    op.create_table(
        'rate_limit_violations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('endpoint', sa.String(255), nullable=False),
        sa.Column('method', sa.String(10), nullable=False),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.Text, nullable=True),
        sa.Column('request_count', sa.Integer, nullable=False),
        sa.Column('limit_value', sa.Integer, nullable=False),
        sa.Column('window_start', sa.DateTime(timezone=True), nullable=False),
        sa.Column('window_end', sa.DateTime(timezone=True), nullable=False),
        sa.Column('blocked', sa.Boolean, nullable=False, default=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('metadata', postgresql.JSONB, nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now())
    )
    
    # Create indexes for rate limit violations
    op.create_index('idx_rate_limit_violations_tenant', 'rate_limit_violations', ['tenant_id', 'timestamp'])
    op.create_index('idx_rate_limit_violations_endpoint', 'rate_limit_violations', ['endpoint', 'timestamp'])
    op.create_index('idx_rate_limit_violations_ip', 'rate_limit_violations', ['ip_address', 'timestamp'])


def downgrade() -> None:
    """Drop usage tracking tables"""
    
    # Drop tables in reverse order
    op.drop_table('rate_limit_violations')
    op.drop_table('usage_aggregates') 
    op.drop_table('quota_violations')
    op.drop_table('usage_records')