-- Initialize multi-tenant database schemas for QES Platform

-- Create extension for UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create shared schema for platform-wide tables
CREATE SCHEMA IF NOT EXISTS platform;

-- Platform-wide tables
CREATE TABLE platform.tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    subdomain VARCHAR(63) NOT NULL UNIQUE,
    schema_name VARCHAR(63) NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true,
    settings JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE platform.adapter_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES platform.tenants(id) ON DELETE CASCADE,
    provider_name VARCHAR(100) NOT NULL,
    country_code CHAR(2) NOT NULL,
    config JSONB NOT NULL,
    is_enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, provider_name, country_code)
);

-- Create default tenant for development
INSERT INTO platform.tenants (name, subdomain, schema_name) 
VALUES ('Development Tenant', 'dev', 'tenant_dev')
ON CONFLICT (subdomain) DO NOTHING;

-- Function to create tenant schema
CREATE OR REPLACE FUNCTION create_tenant_schema(schema_name TEXT)
RETURNS VOID AS $$
BEGIN
    EXECUTE 'CREATE SCHEMA IF NOT EXISTS ' || quote_ident(schema_name);
    
    -- Users table for tenant
    EXECUTE 'CREATE TABLE IF NOT EXISTS ' || quote_ident(schema_name) || '.users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_identifier VARCHAR(255) NOT NULL UNIQUE,
        email VARCHAR(255),
        given_name VARCHAR(255),
        family_name VARCHAR(255),
        country_code CHAR(2),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_login TIMESTAMP WITH TIME ZONE,
        is_active BOOLEAN DEFAULT true,
        metadata JSONB DEFAULT \'{}\'::jsonb
    )';
    
    -- Signing sessions table
    EXECUTE 'CREATE TABLE IF NOT EXISTS ' || quote_ident(schema_name) || '.signing_sessions (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID REFERENCES ' || quote_ident(schema_name) || '.users(id),
        provider_name VARCHAR(100) NOT NULL,
        session_token VARCHAR(500),
        status VARCHAR(50) DEFAULT ''pending'',
        expires_at TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        metadata JSONB DEFAULT \'{}\'::jsonb
    )';
    
    -- Signatures table
    EXECUTE 'CREATE TABLE IF NOT EXISTS ' || quote_ident(schema_name) || '.signatures (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID REFERENCES ' || quote_ident(schema_name) || '.users(id),
        session_id UUID REFERENCES ' || quote_ident(schema_name) || '.signing_sessions(id),
        document_name VARCHAR(500) NOT NULL,
        document_hash VARCHAR(128) NOT NULL,
        signature_format VARCHAR(50) NOT NULL,
        signature_value TEXT,
        certificate_dn TEXT,
        timestamp_token TEXT,
        status VARCHAR(50) DEFAULT ''pending'',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        signed_at TIMESTAMP WITH TIME ZONE,
        metadata JSONB DEFAULT \'{}\'::jsonb
    )';
    
    -- Audit logs table
    EXECUTE 'CREATE TABLE IF NOT EXISTS ' || quote_ident(schema_name) || '.audit_logs (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID REFERENCES ' || quote_ident(schema_name) || '.users(id),
        action VARCHAR(100) NOT NULL,
        resource_type VARCHAR(100) NOT NULL,
        resource_id UUID,
        ip_address INET,
        user_agent TEXT,
        timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        details JSONB DEFAULT \'{}\'::jsonb
    )';
    
    -- Create indexes
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_' || schema_name || '_users_identifier ON ' || quote_ident(schema_name) || '.users(user_identifier)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_' || schema_name || '_sessions_user ON ' || quote_ident(schema_name) || '.signing_sessions(user_id)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_' || schema_name || '_signatures_user ON ' || quote_ident(schema_name) || '.signatures(user_id)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_' || schema_name || '_audit_user ON ' || quote_ident(schema_name) || '.audit_logs(user_id)';
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_' || schema_name || '_audit_timestamp ON ' || quote_ident(schema_name) || '.audit_logs(timestamp)';
END;
$$ LANGUAGE plpgsql;

-- Create default tenant schema
SELECT create_tenant_schema('tenant_dev');