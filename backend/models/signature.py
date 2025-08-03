"""
Signature model for tracking digital signatures.
"""

from enum import Enum
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Boolean, Text, ForeignKey, JSON, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import BaseModel


class SignatureStatus(str, Enum):
    """Signature processing status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    REVOKED = "revoked"
    EXPIRED = "expired"


class SignatureFormat(str, Enum):
    """Signature format types."""
    PADES_B = "PAdES-B"
    PADES_T = "PAdES-T"
    PADES_LT = "PAdES-LT"
    PADES_LTA = "PAdES-LTA"
    XADES_B = "XAdES-B"
    XADES_T = "XAdES-T"
    XADES_LT = "XAdES-LT"
    XADES_LTA = "XAdES-LTA"


class SignatureLevel(str, Enum):
    """eIDAS signature assurance levels."""
    QES = "qes"  # Qualified Electronic Signature
    ADES = "ades"  # Advanced Electronic Signature
    SES = "ses"  # Simple Electronic Signature


class Signature(BaseModel):
    """Signature model for digital signature tracking."""
    
    __tablename__ = "signatures"
    
    # Basic info
    signature_id = Column(String(100), unique=True, nullable=False, doc="External signature identifier")
    display_name = Column(String(255), nullable=True, doc="User-friendly signature name")
    
    # Document relationship
    document_id = Column(
        UUID(as_uuid=True), 
        ForeignKey("documents.id", ondelete="CASCADE"), 
        nullable=False,
        doc="Document being signed"
    )
    
    # Signer info
    signer_id = Column(
        UUID(as_uuid=True), 
        ForeignKey("users.id", ondelete="CASCADE"), 
        nullable=False,
        doc="User who created the signature"
    )
    tenant_id = Column(
        UUID(as_uuid=True), 
        ForeignKey("tenants.id", ondelete="CASCADE"), 
        nullable=False,
        doc="Tenant this signature belongs to"
    )
    
    # Signature details
    signature_format = Column(String(20), nullable=False, doc="Signature format (PAdES, XAdES)")
    signature_level = Column(String(10), default=SignatureLevel.QES, doc="eIDAS assurance level")
    status = Column(String(20), default=SignatureStatus.PENDING, doc="Signature status")
    
    # QES Provider info
    qes_provider = Column(String(50), nullable=False, doc="QES provider used")
    provider_session_id = Column(String(255), nullable=True, doc="Provider session identifier")
    provider_signature_id = Column(String(255), nullable=True, doc="Provider signature ID")
    
    # Certificate info
    certificate_fingerprint = Column(String(64), nullable=True, doc="Certificate fingerprint")
    certificate_serial = Column(String(100), nullable=True, doc="Certificate serial number")
    certificate_issuer = Column(String(500), nullable=True, doc="Certificate issuer DN")
    certificate_subject = Column(String(500), nullable=True, doc="Certificate subject DN")
    certificate_valid_from = Column(DateTime, nullable=True, doc="Certificate validity start")
    certificate_valid_to = Column(DateTime, nullable=True, doc="Certificate validity end")
    
    # Signature timestamps
    signature_timestamp = Column(DateTime, nullable=True, doc="When signature was created")
    tsa_timestamp = Column(DateTime, nullable=True, doc="TSA timestamp")
    
    # Hashes and verification
    document_hash = Column(String(64), nullable=True, doc="Hash of signed document")
    signature_hash = Column(String(64), nullable=True, doc="Hash of signature value")
    signature_value = Column(Text, nullable=True, doc="Base64 encoded signature value")
    
    # Storage
    signed_document_path = Column(String(500), nullable=True, doc="Path to signed document")
    signature_file_path = Column(String(500), nullable=True, doc="Path to signature file")
    
    # Verification status
    is_valid = Column(Boolean, nullable=True, doc="Last verification result")
    last_verified_at = Column(DateTime, nullable=True, doc="Last verification timestamp")
    verification_details = Column(JSON, default=dict, doc="Verification result details")
    
    # Long-term validation
    ltv_enabled = Column(Boolean, default=False, doc="Long-term validation enabled")
    ltv_updated_at = Column(DateTime, nullable=True, doc="LTV last update")
    
    # Blockchain anchoring
    blockchain_anchor_id = Column(String(100), nullable=True, doc="Blockchain anchor ID")
    blockchain_transaction = Column(String(100), nullable=True, doc="Blockchain transaction hash")
    
    # Audit and compliance
    signing_reason = Column(String(500), nullable=True, doc="Reason for signing")
    signing_location = Column(String(255), nullable=True, doc="Signing location")
    compliance_info = Column(JSON, default=dict, doc="Compliance and regulatory info")
    
    # Error handling
    error_message = Column(Text, nullable=True, doc="Error message if signature failed")
    retry_count = Column(Integer, default=0, doc="Number of retry attempts")
    
    # Relationships
    document = relationship("Document", back_populates="signatures")
    signer = relationship("User", back_populates="signatures")
    signing_session = relationship("SigningSession", back_populates="signature", uselist=False)
    
    @property
    def is_qes(self) -> bool:
        """Check if this is a qualified electronic signature."""
        return self.signature_level == SignatureLevel.QES
    
    @property
    def is_completed(self) -> bool:
        """Check if signature is completed."""
        return self.status == SignatureStatus.COMPLETED
    
    @property
    def is_failed(self) -> bool:
        """Check if signature failed."""
        return self.status == SignatureStatus.FAILED
    
    @property
    def certificate_info(self) -> dict:
        """Get certificate information as dict."""
        return {
            "fingerprint": self.certificate_fingerprint,
            "serial": self.certificate_serial,
            "issuer": self.certificate_issuer,
            "subject": self.certificate_subject,
            "valid_from": self.certificate_valid_from,
            "valid_to": self.certificate_valid_to
        }
    
    def __repr__(self) -> str:
        return f"<Signature(id='{self.signature_id}', status='{self.status}')>"