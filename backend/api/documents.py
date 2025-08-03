"""
Document API Endpoints

FastAPI endpoints for document upload, management and retrieval.
"""

import logging
import hashlib
import os
from datetime import datetime
from typing import List, Optional, Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends, status, UploadFile, File, Form, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models.document import Document, DocumentStatus, DocumentType
from models.user import User
from models.tenant import Tenant
from storage.minio_client import MinIOClient, get_minio_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/documents", tags=["documents"])


# Pydantic models for API
class DocumentResponse(BaseModel):
    """Response model for document information."""
    id: UUID
    filename: str
    display_name: Optional[str]
    description: Optional[str]
    file_size: int
    file_size_mb: float
    mime_type: str
    document_type: str
    content_hash: str
    status: str
    is_signed: bool
    signature_count: int
    created_at: datetime
    updated_at: datetime
    tags: List[str]
    
    class Config:
        from_attributes = True


class DocumentListResponse(BaseModel):
    """Response model for document list."""
    documents: List[DocumentResponse]
    total: int
    page: int
    size: int
    has_next: bool


class DocumentUploadResponse(BaseModel):
    """Response model for document upload."""
    id: UUID
    filename: str
    file_size: int
    content_hash: str
    status: str
    message: str


# Import JWT authentication
from auth.jwt_auth import get_current_user


def get_tenant_from_user(user: User, db: Session = Depends(get_db)) -> Tenant:
    """Get tenant from user."""
    return db.query(Tenant).filter(Tenant.id == user.tenant_id).first()


@router.post("/upload", response_model=DocumentUploadResponse)
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    display_name: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    tags: Optional[str] = Form(None),  # Comma-separated tags
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    minio_client: MinIOClient = Depends(get_minio_client)
):
    """
    Upload a new document for signing.
    """
    try:
        # Read file content
        content = await file.read()
        
        # Validate file
        if len(content) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File is empty"
            )
        
        # Check file size (max 50MB)
        max_size = 50 * 1024 * 1024  # 50MB
        if len(content) > max_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File too large. Maximum size is {max_size // (1024*1024)}MB"
            )
        
        # Calculate hash
        content_hash = hashlib.sha256(content).hexdigest()
        
        # Determine document type
        mime_type = file.content_type or "application/octet-stream"
        doc_type = _determine_document_type(mime_type, file.filename)
        
        # Allow multiple versions of same document content
        # No duplicate check - users can upload same file multiple times
        # and sign it with different providers or create new versions
        
        # Generate unique storage path with timestamp to allow versions
        tenant = get_tenant_from_user(current_user, db)
        import uuid
        from datetime import datetime
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        unique_id = str(uuid.uuid4())[:8]
        storage_path = f"documents/{tenant.slug}/{current_user.id}/{content_hash[:8]}/{timestamp}_{unique_id}_{file.filename}"
        bucket_name = f"qes-{tenant.slug}"
        
        # Upload to MinIO
        await minio_client.upload_file(
            bucket_name=bucket_name,
            object_name=storage_path,
            data=content,
            content_type=mime_type
        )
        
        # Parse tags
        tag_list = []
        if tags:
            tag_list = [tag.strip() for tag in tags.split(",") if tag.strip()]
        
        # Create document record
        document = Document(
            filename=file.filename,
            display_name=display_name or file.filename,
            description=description,
            file_size=len(content),
            mime_type=mime_type,
            document_type=doc_type.value,
            content_hash=content_hash,
            original_hash=content_hash,
            storage_path=storage_path,
            storage_bucket=bucket_name,
            status=DocumentStatus.READY,
            owner_id=current_user.id,
            tenant_id=current_user.tenant_id,
            tags=tag_list,
            metadata={
                # Extract real client information
                "upload_ip": get_client_ip(request),
                "upload_user_agent": get_user_agent(request)
            }
        )
        
        # Import utility functions for request info at module level would be better
        # but importing here for clarity
        from utils.request_utils import get_client_ip, get_user_agent
        
        db.add(document)
        db.commit()
        db.refresh(document)
        
        logger.info(f"Document uploaded: {document.id} by user {current_user.id}")
        
        return DocumentUploadResponse(
            id=document.id,
            filename=document.filename,
            file_size=document.file_size,
            content_hash=document.content_hash,
            status=document.status,
            message="Document uploaded successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Document upload failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Upload failed: {str(e)}"
        )


@router.get("/", response_model=DocumentListResponse)
async def list_documents(
    page: int = 1,
    size: int = 20,
    status_filter: Optional[str] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List user's documents with pagination and filtering.
    """
    try:
        # Build query
        query = db.query(Document).filter(Document.owner_id == current_user.id)
        
        # Apply filters
        if status_filter:
            query = query.filter(Document.status == status_filter)
        
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                (Document.filename.ilike(search_term)) |
                (Document.display_name.ilike(search_term)) |
                (Document.description.ilike(search_term))
            )
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * size
        documents = query.order_by(Document.created_at.desc()).offset(offset).limit(size).all()
        
        # Convert to response models
        document_responses = [
            DocumentResponse(
                id=doc.id,
                filename=doc.filename,
                display_name=doc.display_name,
                description=doc.description,
                file_size=doc.file_size,
                file_size_mb=doc.file_size_mb,
                mime_type=doc.mime_type,
                document_type=doc.document_type,
                content_hash=doc.content_hash,
                status=doc.status,
                is_signed=doc.is_signed,
                signature_count=doc.signature_count,
                created_at=doc.created_at,
                updated_at=doc.updated_at,
                tags=doc.tags
            )
            for doc in documents
        ]
        
        has_next = offset + size < total
        
        return DocumentListResponse(
            documents=document_responses,
            total=total,
            page=page,
            size=size,
            has_next=has_next
        )
        
    except Exception as e:
        logger.error(f"Document list failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve documents: {str(e)}"
        )


@router.get("/{document_id}", response_model=DocumentResponse)
async def get_document(
    document_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get document details by ID.
    """
    document = db.query(Document).filter(
        Document.id == document_id,
        Document.owner_id == current_user.id
    ).first()
    
    if not document:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )
    
    return DocumentResponse(
        id=document.id,
        filename=document.filename,
        display_name=document.display_name,
        description=document.description,
        file_size=document.file_size,
        file_size_mb=document.file_size_mb,
        mime_type=document.mime_type,
        document_type=document.document_type,
        content_hash=document.content_hash,
        status=document.status,
        is_signed=document.is_signed,
        signature_count=document.signature_count,
        created_at=document.created_at,
        updated_at=document.updated_at,
        tags=document.tags
    )


@router.get("/{document_id}/download")
async def download_document(
    document_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    minio_client: MinIOClient = Depends(get_minio_client)
):
    """
    Download document file.
    """
    document = db.query(Document).filter(
        Document.id == document_id,
        Document.owner_id == current_user.id
    ).first()
    
    if not document:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )
    
    try:
        # Get file from MinIO
        file_data = await minio_client.download_file(
            bucket_name=document.storage_bucket,
            object_name=document.storage_path
        )
        
        # Return file as streaming response
        def generate():
            yield file_data
        
        return StreamingResponse(
            generate(),
            media_type=document.mime_type,
            headers={
                "Content-Disposition": f"attachment; filename=\"{document.filename}\""
            }
        )
        
    except Exception as e:
        logger.error(f"Document download failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Download failed"
        )


def _determine_document_type(mime_type: str, filename: str) -> DocumentType:
    """Determine document type from MIME type and filename."""
    mime_type = mime_type.lower()
    filename = filename.lower()
    
    if mime_type.startswith("application/pdf") or filename.endswith(".pdf"):
        return DocumentType.PDF
    elif (mime_type.startswith("application/msword") or 
          mime_type.startswith("application/vnd.openxmlformats") or
          filename.endswith((".doc", ".docx"))):
        return DocumentType.WORD
    elif mime_type.startswith("image/") or filename.endswith((".png", ".jpg", ".jpeg", ".gif")):
        return DocumentType.IMAGE
    elif mime_type.startswith("application/xml") or filename.endswith(".xml"):
        return DocumentType.XML
    else:
        return DocumentType.OTHER