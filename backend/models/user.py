"""
User model for authentication and user management.
"""

from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import BaseModel


class User(BaseModel):
    """User model for QES platform users."""
    
    __tablename__ = "users"
    
    # Basic info
    email = Column(String(255), unique=True, nullable=False, doc="User email address")
    first_name = Column(String(100), nullable=True, doc="First name")
    last_name = Column(String(100), nullable=True, doc="Last name")
    
    # Authentication
    password_hash = Column(String(255), nullable=True, doc="Hashed password (if using password auth)")
    is_active = Column(Boolean, default=True, nullable=False, doc="Whether user account is active")
    is_verified = Column(Boolean, default=False, nullable=False, doc="Whether email is verified")
    
    # Timestamps
    last_login = Column(DateTime, nullable=True, doc="Last login timestamp")
    email_verified_at = Column(DateTime, nullable=True, doc="Email verification timestamp")
    
    # Multi-tenancy
    tenant_id = Column(
        UUID(as_uuid=True), 
        ForeignKey("tenants.id", ondelete="CASCADE"), 
        nullable=False,
        doc="Tenant this user belongs to"
    )
    
    # Role and permissions
    role = Column(String(50), default="user", doc="User role (user, admin, owner)")
    permissions = Column(JSON, default=list, doc="Additional permissions")
    
    # Preferences
    preferences = Column(JSON, default=dict, doc="User preferences and settings")
    locale = Column(String(10), default="en", doc="User locale/language")
    timezone = Column(String(50), default="UTC", doc="User timezone")
    
    # QES specific
    default_qes_provider = Column(String(50), nullable=True, doc="Default QES provider")
    qes_certificates = Column(JSON, default=list, doc="Associated QES certificates")
    
    # Relationships
    tenant = relationship("Tenant", back_populates="users")
    documents = relationship("Document", back_populates="owner", cascade="all, delete-orphan")
    signatures = relationship("Signature", back_populates="signer", cascade="all, delete-orphan")
    signing_sessions = relationship("SigningSession", back_populates="user", cascade="all, delete-orphan")
    
    @property
    def full_name(self) -> str:
        """Get user's full name."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        elif self.last_name:
            return self.last_name
        else:
            return self.email.split("@")[0]
    
    @property
    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return self.role in ("admin", "owner")
    
    def __repr__(self) -> str:
        return f"<User(email='{self.email}', role='{self.role}')>"