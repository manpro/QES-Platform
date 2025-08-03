"""
SigningSession model for tracking signature creation workflows.
"""

from enum import Enum
from datetime import datetime, timedelta
from sqlalchemy import Column, String, DateTime, Boolean, Text, ForeignKey, JSON, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import BaseModel


class SessionStatus(str, Enum):
    """Signing session status."""
    CREATED = "created"
    AUTHENTICATING = "authenticating"
    AUTHENTICATED = "authenticated"
    SIGNING = "signing"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class AuthenticationMethod(str, Enum):
    """Authentication method used."""
    OAUTH2 = "oauth2"
    MOBILE_APP = "mobile_app" 
    SMART_CARD = "smart_card"
    BIOMETRIC = "biometric"
    VIDEO_CALL = "video_call"
    SMS_OTP = "sms_otp"


class SigningSession(BaseModel):
    """SigningSession model for managing signature creation workflows."""
    
    __tablename__ = "signing_sessions"
    
    # Basic info
    session_id = Column(String(100), unique=True, nullable=False, doc="External session identifier")
    session_token = Column(String(255), nullable=True, doc="Secure session token")
    
    # User and tenant
    user_id = Column(
        UUID(as_uuid=True), 
        ForeignKey("users.id", ondelete="CASCADE"), 
        nullable=False,
        doc="User creating the signature"
    )
    tenant_id = Column(
        UUID(as_uuid=True), 
        ForeignKey("tenants.id", ondelete="CASCADE"), 
        nullable=False,
        doc="Tenant this session belongs to"
    )
    
    # Document being signed
    document_id = Column(
        UUID(as_uuid=True), 
        ForeignKey("documents.id", ondelete="CASCADE"), 
        nullable=False,
        doc="Document being signed"
    )
    
    # Associated signature (once created)
    signature_id = Column(
        UUID(as_uuid=True), 
        ForeignKey("signatures.id", ondelete="SET NULL"), 
        nullable=True,
        doc="Created signature (if any)"
    )
    
    # Session status
    status = Column(String(20), default=SessionStatus.CREATED, doc="Current session status")
    
    # QES Provider info
    qes_provider = Column(String(50), nullable=False, doc="QES provider being used")
    provider_session_id = Column(String(255), nullable=True, doc="Provider's session ID")
    provider_auth_url = Column(String(1000), nullable=True, doc="Provider authentication URL")
    
    # Authentication details
    auth_method = Column(String(20), nullable=True, doc="Authentication method used")
    auth_completed_at = Column(DateTime, nullable=True, doc="Authentication completion time")
    auth_details = Column(JSON, default=dict, doc="Authentication details")
    
    # Signature parameters
    signature_format = Column(String(20), nullable=False, doc="Requested signature format")
    signature_reason = Column(String(500), nullable=True, doc="Reason for signing")
    signature_location = Column(String(255), nullable=True, doc="Signing location")
    
    # Session timing
    expires_at = Column(DateTime, nullable=False, doc="Session expiration time")
    started_at = Column(DateTime, nullable=True, doc="When signing process started")
    completed_at = Column(DateTime, nullable=True, doc="When session completed")
    
    # Security
    ip_address = Column(String(45), nullable=True, doc="Client IP address")
    user_agent = Column(String(500), nullable=True, doc="Client user agent")
    
    # State management
    state_data = Column(JSON, default=dict, doc="Session state data")
    callback_url = Column(String(1000), nullable=True, doc="Callback URL after completion")
    
    # Error handling
    error_message = Column(Text, nullable=True, doc="Error message if session failed")
    retry_count = Column(Integer, default=0, doc="Number of retry attempts")
    
    # Progress tracking
    current_step = Column(String(50), nullable=True, doc="Current step in signing process")
    steps_completed = Column(JSON, default=list, doc="List of completed steps")
    
    # Notifications
    notifications_sent = Column(JSON, default=list, doc="Notifications sent during session")
    
    # Relationships
    user = relationship("User", back_populates="signing_sessions")
    document = relationship("Document")
    signature = relationship("Signature", back_populates="signing_session")
    
    def __init__(self, **kwargs):
        """Initialize signing session with default expiration."""
        super().__init__(**kwargs)
        if not self.expires_at:
            # Default session expires in 30 minutes
            self.expires_at = datetime.utcnow() + timedelta(minutes=30)
    
    @property
    def is_expired(self) -> bool:
        """Check if session has expired."""
        return datetime.utcnow() > self.expires_at
    
    @property
    def is_active(self) -> bool:
        """Check if session is active (not completed, failed, or expired)."""
        return self.status in (
            SessionStatus.CREATED,
            SessionStatus.AUTHENTICATING, 
            SessionStatus.AUTHENTICATED,
            SessionStatus.SIGNING
        ) and not self.is_expired
    
    @property
    def is_authenticated(self) -> bool:
        """Check if user has been authenticated."""
        return self.auth_completed_at is not None
    
    @property
    def duration_minutes(self) -> float:
        """Get session duration in minutes."""
        if self.completed_at:
            end_time = self.completed_at
        else:
            end_time = datetime.utcnow()
        
        duration = end_time - self.created_at
        return duration.total_seconds() / 60
    
    @property
    def time_remaining_minutes(self) -> float:
        """Get remaining time in minutes before expiration."""
        if self.is_expired:
            return 0
        
        remaining = self.expires_at - datetime.utcnow()
        return max(0, remaining.total_seconds() / 60)
    
    def extend_expiration(self, minutes: int = 30):
        """Extend session expiration by specified minutes."""
        self.expires_at = datetime.utcnow() + timedelta(minutes=minutes)
    
    def mark_step_completed(self, step_name: str):
        """Mark a step as completed."""
        if step_name not in self.steps_completed:
            self.steps_completed = self.steps_completed + [step_name]
            self.current_step = step_name
    
    def add_notification(self, notification_type: str, details: dict = None):
        """Add a notification record."""
        notification = {
            "type": notification_type,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details or {}
        }
        self.notifications_sent = self.notifications_sent + [notification]
    
    def __repr__(self) -> str:
        return f"<SigningSession(id='{self.session_id}', status='{self.status}')>"