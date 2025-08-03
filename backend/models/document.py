"""
Document model for file management and tracking.
"""

from enum import Enum
from sqlalchemy import Column, String, Integer, Boolean, Text, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import BaseModel


class DocumentStatus(str, Enum):
    """Document processing status."""
    UPLOADED = "uploaded"
    PROCESSING = "processing"
    READY = "ready"
    SIGNED = "signed"
    ERROR = "error"
    DELETED = "deleted"


class DocumentType(str, Enum):
    """Document type classification."""
    PDF = "pdf"
    WORD = "word"
    IMAGE = "image"
    XML = "xml"
    OTHER = "other"


class Document(BaseModel):
    """Document model for managing uploaded files."""
    
    __tablename__ = "documents"
    
    # Basic info
    filename = Column(String(255), nullable=False, doc="Original filename")
    display_name = Column(String(255), nullable=True, doc="User-friendly display name")
    description = Column(Text, nullable=True, doc="Document description")
    
    # File info
    file_size = Column(Integer, nullable=False, doc="File size in bytes")
    mime_type = Column(String(100), nullable=False, doc="MIME type")
    document_type = Column(String(20), nullable=False, doc="Document type category")
    
    # Content hashes
    content_hash = Column(String(64), nullable=False, doc="SHA-256 hash of content")
    original_hash = Column(String(64), nullable=False, doc="Hash of original uploaded file")
    
    # Storage
    storage_path = Column(String(500), nullable=False, doc="Path in object storage")
    storage_bucket = Column(String(100), nullable=False, doc="Storage bucket name")
    
    # Status
    status = Column(String(20), default=DocumentStatus.UPLOADED, doc="Processing status")
    is_public = Column(Boolean, default=False, doc="Whether document is publicly accessible")
    
    # Ownership
    owner_id = Column(
        UUID(as_uuid=True), 
        ForeignKey("users.id", ondelete="CASCADE"), 
        nullable=False,
        doc="Document owner"
    )
    tenant_id = Column(
        UUID(as_uuid=True), 
        ForeignKey("tenants.id", ondelete="CASCADE"), 
        nullable=False,
        doc="Tenant this document belongs to"
    )
    
    # Metadata
    document_metadata = Column(JSON, default=dict, doc="Additional document metadata")
    tags = Column(JSON, default=list, doc="Document tags")
    
    # Processing info
    pages = Column(Integer, nullable=True, doc="Number of pages (for PDF/Word docs)")
    extracted_text = Column(Text, nullable=True, doc="Extracted text content")
    
    # Security
    encryption_key_id = Column(String(100), nullable=True, doc="Encryption key identifier")
    access_permissions = Column(JSON, default=dict, doc="Access control permissions")
    
    # Relationships
    owner = relationship("User", back_populates="documents")
    tenant = relationship("Tenant", back_populates="documents")
    signatures = relationship("Signature", back_populates="document", cascade="all, delete-orphan")
    
    @property
    def is_signed(self) -> bool:
        """Check if document has any signatures."""
        return len(self.signatures) > 0
    
    @property
    def signature_count(self) -> int:
        """Get number of signatures on this document."""
        return len(self.signatures)
    
    @property
    def file_size_mb(self) -> float:
        """Get file size in megabytes."""
        return round(self.file_size / (1024 * 1024), 2)
    
    def __repr__(self) -> str:
        return f"<Document(filename='{self.filename}', status='{self.status}')>"