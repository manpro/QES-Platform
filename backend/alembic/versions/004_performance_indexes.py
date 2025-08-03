"""Add performance indexes for common query patterns

Revision ID: 004
Revises: 003
Create Date: 2024-01-08 16:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '004'
down_revision = '003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add performance-optimized indexes for common query patterns"""
    
    # Documents table indexes
    # 1. User document listing (most common query)
    op.create_index(
        'ix_documents_owner_status_created', 
        'documents', 
        ['owner_id', 'status', 'created_at'],
        postgresql_ops={'created_at': 'DESC'}
    )
    
    # 2. Tenant document listing
    op.create_index(
        'ix_documents_tenant_status_created', 
        'documents', 
        ['tenant_id', 'status', 'created_at'],
        postgresql_ops={'created_at': 'DESC'}
    )
    
    # 3. Content hash for duplicate detection
    op.create_index('ix_documents_content_hash', 'documents', ['content_hash'])
    
    # 4. File type filtering
    op.create_index('ix_documents_document_type', 'documents', ['document_type'])
    
    # 5. Full-text search on filename and display_name
    op.execute("""
        CREATE INDEX ix_documents_filename_search 
        ON documents 
        USING gin(to_tsvector('english', filename || ' ' || COALESCE(display_name, '')))
    """)
    
    # 6. Storage path for cleanup operations
    op.create_index('ix_documents_storage_path', 'documents', ['storage_path'])
    
    # Signatures table indexes
    # 1. Document signatures (most common join)
    op.create_index(
        'ix_signatures_document_status_created', 
        'signatures', 
        ['document_id', 'status', 'created_at'],
        postgresql_ops={'created_at': 'DESC'}
    )
    
    # 2. User signatures listing
    op.create_index(
        'ix_signatures_signer_status_created', 
        'signatures', 
        ['signer_id', 'status', 'created_at'],
        postgresql_ops={'created_at': 'DESC'}
    )
    
    # 3. Tenant signatures
    op.create_index(
        'ix_signatures_tenant_status_created', 
        'signatures', 
        ['tenant_id', 'status', 'created_at'],
        postgresql_ops={'created_at': 'DESC'}
    )
    
    # 4. QES provider performance tracking
    op.create_index(
        'ix_signatures_provider_status_created', 
        'signatures', 
        ['qes_provider', 'status', 'created_at'],
        postgresql_ops={'created_at': 'DESC'}
    )
    
    # 5. Certificate-based queries
    op.create_index('ix_signatures_certificate_fingerprint', 'signatures', ['certificate_fingerprint'])
    op.create_index('ix_signatures_certificate_serial', 'signatures', ['certificate_serial'])
    
    # 6. Verification status queries
    op.create_index(
        'ix_signatures_verification_status', 
        'signatures', 
        ['is_valid', 'last_verified_at'],
        postgresql_ops={'last_verified_at': 'DESC'},
        postgresql_where=sa.text("is_valid IS NOT NULL")
    )
    
    # 7. Blockchain anchoring
    op.create_index(
        'ix_signatures_blockchain_anchor', 
        'signatures', 
        ['blockchain_anchor_id'],
        postgresql_where=sa.text("blockchain_anchor_id IS NOT NULL")
    )
    
    # 8. TSA timestamp queries
    op.create_index(
        'ix_signatures_tsa_timestamp', 
        'signatures', 
        ['tsa_timestamp'],
        postgresql_ops={'tsa_timestamp': 'DESC'},
        postgresql_where=sa.text("tsa_timestamp IS NOT NULL")
    )
    
    # Users table indexes
    # 1. Email lookup for authentication (should already exist, but ensure)
    op.create_index('ix_users_email_active', 'users', ['email', 'is_active'])
    
    # 2. Tenant user listing
    op.create_index(
        'ix_users_tenant_active_created', 
        'users', 
        ['tenant_id', 'is_active', 'created_at'],
        postgresql_ops={'created_at': 'DESC'}
    )
    
    # 3. Role-based queries
    op.create_index('ix_users_role_active', 'users', ['role', 'is_active'])
    
    # 4. Last login for analytics
    op.create_index(
        'ix_users_last_login', 
        'users', 
        ['last_login'],
        postgresql_ops={'last_login': 'DESC'},
        postgresql_where=sa.text("last_login IS NOT NULL")
    )
    
    # Audit logs table indexes (already has comprehensive indexes from previous migration)
    # Just add a few more for specific patterns
    
    # 1. Recent events for dashboard
    op.create_index(
        'ix_audit_logs_recent_events', 
        'audit_logs', 
        ['timestamp'],
        postgresql_ops={'timestamp': 'DESC'},
        postgresql_where=sa.text("timestamp > CURRENT_TIMESTAMP - INTERVAL '7 days'")
    )
    
    # 2. Error events for monitoring
    op.create_index(
        'ix_audit_logs_errors', 
        'audit_logs', 
        ['event_type', 'timestamp'],
        postgresql_ops={'timestamp': 'DESC'},
        postgresql_where=sa.text("event_type IN ('SIGNING_FAILED', 'SYSTEM_ERROR')")
    )
    
    # Signing sessions table indexes (if it exists)
    try:
        # Check if signing_sessions table exists
        op.create_index(
            'ix_signing_sessions_user_status_created', 
            'signing_sessions', 
            ['user_id', 'status', 'created_at'],
            postgresql_ops={'created_at': 'DESC'}
        )
        
        op.create_index(
            'ix_signing_sessions_provider_status', 
            'signing_sessions', 
            ['qes_provider', 'status', 'created_at'],
            postgresql_ops={'created_at': 'DESC'}
        )
        
        # Session cleanup index
        op.create_index(
            'ix_signing_sessions_expired', 
            'signing_sessions', 
            ['expires_at'],
            postgresql_where=sa.text("status = 'active'")
        )
    except Exception as e:
        # Table might not exist yet, skip
        pass


def downgrade() -> None:
    """Remove performance indexes"""
    
    # Documents indexes
    op.drop_index('ix_documents_owner_status_created', table_name='documents')
    op.drop_index('ix_documents_tenant_status_created', table_name='documents')
    op.drop_index('ix_documents_content_hash', table_name='documents')
    op.drop_index('ix_documents_document_type', table_name='documents')
    op.drop_index('ix_documents_filename_search', table_name='documents')
    op.drop_index('ix_documents_storage_path', table_name='documents')
    
    # Signatures indexes
    op.drop_index('ix_signatures_document_status_created', table_name='signatures')
    op.drop_index('ix_signatures_signer_status_created', table_name='signatures')
    op.drop_index('ix_signatures_tenant_status_created', table_name='signatures')
    op.drop_index('ix_signatures_provider_status_created', table_name='signatures')
    op.drop_index('ix_signatures_certificate_fingerprint', table_name='signatures')
    op.drop_index('ix_signatures_certificate_serial', table_name='signatures')
    op.drop_index('ix_signatures_verification_status', table_name='signatures')
    op.drop_index('ix_signatures_blockchain_anchor', table_name='signatures')
    op.drop_index('ix_signatures_tsa_timestamp', table_name='signatures')
    
    # Users indexes
    op.drop_index('ix_users_email_active', table_name='users')
    op.drop_index('ix_users_tenant_active_created', table_name='users')
    op.drop_index('ix_users_role_active', table_name='users')
    op.drop_index('ix_users_last_login', table_name='users')
    
    # Audit logs indexes
    op.drop_index('ix_audit_logs_recent_events', table_name='audit_logs')
    op.drop_index('ix_audit_logs_errors', table_name='audit_logs')
    
    # Signing sessions indexes
    try:
        op.drop_index('ix_signing_sessions_user_status_created', table_name='signing_sessions')
        op.drop_index('ix_signing_sessions_provider_status', table_name='signing_sessions')
        op.drop_index('ix_signing_sessions_expired', table_name='signing_sessions')
    except Exception:
        # Table might not exist, skip
        pass