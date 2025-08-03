"""
Tenant model for multi-tenancy support.
"""

from sqlalchemy import Column, String, Boolean, Text, JSON
from sqlalchemy.orm import relationship

from .base import BaseModel


class Tenant(BaseModel):
    """Tenant model for multi-tenant QES platform."""
    
    __tablename__ = "tenants"
    
    # Basic info
    name = Column(String(255), nullable=False, doc="Tenant name")
    slug = Column(String(100), unique=True, nullable=False, doc="URL-friendly identifier")
    domain = Column(String(255), unique=True, nullable=True, doc="Custom domain")
    
    # Contact info
    contact_email = Column(String(255), nullable=False, doc="Primary contact email")
    contact_name = Column(String(255), nullable=True, doc="Primary contact name")
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False, doc="Whether tenant is active")
    is_verified = Column(Boolean, default=False, nullable=False, doc="Whether tenant is verified")
    
    # Configuration
    settings = Column(JSON, default=dict, doc="Tenant-specific settings")
    allowed_qes_providers = Column(JSON, default=list, doc="Allowed QES providers")
    
    # Billing
    subscription_tier = Column(String(50), default="free", doc="Subscription tier")
    
    # Database schema
    database_schema = Column(String(100), nullable=False, doc="PostgreSQL schema name")
    
    # Relationships
    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    documents = relationship("Document", back_populates="tenant", cascade="all, delete-orphan")
    
    def __repr__(self) -> str:
        return f"<Tenant(name='{self.name}', slug='{self.slug}')>"