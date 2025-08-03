"""
Signature API Endpoints

FastAPI endpoints for creating and managing digital signatures.
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends, status, Form
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models.document import Document
from models.signature import Signature, SignatureStatus, SignatureFormat, SignatureLevel
from models.signing_session import SigningSession, SessionStatus, AuthenticationMethod
from models.user import User
from auth.jwt_auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/signatures", tags=["signatures"])


# Pydantic models for API
class SignatureCreateRequest(BaseModel):
    """Request to create a new signature."""
    document_id: UUID = Field(..., description="Document to sign")
    qes_provider: str = Field(..., description="QES provider to use")
    signature_format: str = Field(default="PAdES-LTA", description="Signature format")
    signature_reason: Optional[str] = Field(None, description="Reason for signing")
    signature_location: Optional[str] = Field(None, description="Signing location")
    callback_url: Optional[str] = Field(None, description="Callback URL after completion")


class SignatureResponse(BaseModel):
    """Response model for signature information."""
    id: UUID
    signature_id: str
    document_id: UUID
    document_filename: str
    status: str
    signature_format: str
    signature_level: str
    qes_provider: str
    signer_name: str
    created_at: datetime
    signature_timestamp: Optional[datetime]
    is_valid: Optional[bool]
    certificate_info: Dict[str, Any]
    
    class Config:
        from_attributes = True


class SigningSessionResponse(BaseModel):
    """Response model for signing session."""
    session_id: str
    status: str
    document_id: UUID
    document_filename: str
    qes_provider: str
    signature_format: str
    auth_url: Optional[str]
    expires_at: datetime
    time_remaining_minutes: float
    current_step: Optional[str]
    
    class Config:
        from_attributes = True


class SignatureListResponse(BaseModel):
    """Response model for signature list."""
    signatures: List[SignatureResponse]
    total: int
    page: int
    size: int
    has_next: bool


@router.post("/", response_model=SigningSessionResponse)
async def create_signature(
    http_request: Request,
    request: SignatureCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a new signature for a document.
    This starts the signing process and returns a session for tracking.
    """
    try:
        # Validate document exists and belongs to user
        document = db.query(Document).filter(
            Document.id == request.document_id,
            Document.owner_id == current_user.id
        ).first()
        
        if not document:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found"
            )
        
        # Validate signature format
        try:
            sig_format = SignatureFormat(request.signature_format)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid signature format: {request.signature_format}"
            )
        
        # Validate QES provider
        valid_providers = ["freja-se", "dtrust-de", "fnmt-es", "itsme-be", "certinomis-fr", "camerfirma-es"]
        if request.qes_provider not in valid_providers:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid QES provider: {request.qes_provider}"
            )
        
        # Create signing session
        session_id = f"sess_{uuid.uuid4().hex[:12]}"
        signing_session = SigningSession(
            session_id=session_id,
            user_id=current_user.id,
            tenant_id=current_user.tenant_id,
            document_id=document.id,
            status=SessionStatus.CREATED,
            qes_provider=request.qes_provider,
            signature_format=request.signature_format,
            signature_reason=request.signature_reason,
            signature_location=request.signature_location,
            callback_url=request.callback_url,
            expires_at=datetime.utcnow() + timedelta(minutes=30),
            # Extract real client information  
            ip_address=get_client_ip(http_request),
            user_agent=get_user_agent(http_request),
            current_step="created"
        )
        
        # Import utility functions  
        from utils.request_utils import get_client_ip, get_user_agent
        
        db.add(signing_session)
        db.commit()
        db.refresh(signing_session)
        
        # TODO: 🔴 KRITISKT - Implementera riktig QES provider autentisering
        # Initialize QES provider authentication
        # For now, create a mock auth URL
        auth_url = f"/api/v1/signatures/sessions/{session_id}/authenticate"
        signing_session.provider_auth_url = auth_url
        signing_session.status = SessionStatus.AUTHENTICATING
        signing_session.current_step = "authenticating"
        
        db.commit()
        db.refresh(signing_session)
        
        logger.info(f"Created signing session {session_id} for document {document.id}")
        
        return SigningSessionResponse(
            session_id=signing_session.session_id,
            status=signing_session.status,
            document_id=document.id,
            document_filename=document.filename,
            qes_provider=signing_session.qes_provider,
            signature_format=signing_session.signature_format,
            auth_url=auth_url,
            expires_at=signing_session.expires_at,
            time_remaining_minutes=signing_session.time_remaining_minutes,
            current_step=signing_session.current_step
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Signature creation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Signature creation failed: {str(e)}"
        )


@router.get("/sessions/{session_id}", response_model=SigningSessionResponse)
async def get_signing_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get signing session status and details.
    """
    session = db.query(SigningSession).filter(
        SigningSession.session_id == session_id,
        SigningSession.user_id == current_user.id
    ).first()
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Signing session not found"
        )
    
    # Get document info
    document = db.query(Document).filter(Document.id == session.document_id).first()
    
    return SigningSessionResponse(
        session_id=session.session_id,
        status=session.status,
        document_id=session.document_id,
        document_filename=document.filename if document else "Unknown",
        qes_provider=session.qes_provider,
        signature_format=session.signature_format,
        auth_url=session.provider_auth_url,
        expires_at=session.expires_at,
        time_remaining_minutes=session.time_remaining_minutes,
        current_step=session.current_step
    )





@router.get("/", response_model=SignatureListResponse)
async def list_signatures(
    page: int = 1,
    size: int = 20,
    status_filter: Optional[str] = None,
    provider_filter: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List user's signatures with pagination and filtering.
    """
    try:
        # Build query
        query = db.query(Signature).filter(Signature.signer_id == current_user.id)
        
        # Apply filters
        if status_filter:
            query = query.filter(Signature.status == status_filter)
        
        if provider_filter:
            query = query.filter(Signature.qes_provider == provider_filter)
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        offset = (page - 1) * size
        signatures = query.order_by(Signature.created_at.desc()).offset(offset).limit(size).all()
        
        # Convert to response models
        signature_responses = []
        for sig in signatures:
            # Get document info
            document = db.query(Document).filter(Document.id == sig.document_id).first()
            
            signature_responses.append(SignatureResponse(
                id=sig.id,
                signature_id=sig.signature_id,
                document_id=sig.document_id,
                document_filename=document.filename if document else "Unknown",
                status=sig.status,
                signature_format=sig.signature_format,
                signature_level=sig.signature_level,
                qes_provider=sig.qes_provider,
                signer_name=current_user.full_name,
                created_at=sig.created_at,
                signature_timestamp=sig.signature_timestamp,
                is_valid=sig.is_valid,
                certificate_info=sig.certificate_info
            ))
        
        has_next = offset + size < total
        
        return SignatureListResponse(
            signatures=signature_responses,
            total=total,
            page=page,
            size=size,
            has_next=has_next
        )
        
    except Exception as e:
        logger.error(f"Signature list failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve signatures: {str(e)}"
        )


@router.get("/{signature_id}", response_model=SignatureResponse)
async def get_signature(
    signature_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get signature details by ID.
    """
    signature = db.query(Signature).filter(
        Signature.signature_id == signature_id,
        Signature.signer_id == current_user.id
    ).first()
    
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Signature not found"
        )
    
    # Get document info
    document = db.query(Document).filter(Document.id == signature.document_id).first()
    
    return SignatureResponse(
        id=signature.id,
        signature_id=signature.signature_id,
        document_id=signature.document_id,
        document_filename=document.filename if document else "Unknown",
        status=signature.status,
        signature_format=signature.signature_format,
        signature_level=signature.signature_level,
        qes_provider=signature.qes_provider,
        signer_name=current_user.full_name,
        created_at=signature.created_at,
        signature_timestamp=signature.signature_timestamp,
        is_valid=signature.is_valid,
        certificate_info=signature.certificate_info
    )