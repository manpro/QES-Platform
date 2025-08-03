"""
eIDAS AL2 API Endpoints

FastAPI endpoints for eIDAS Assurance Level 2 remote identity proofing.
"""

import logging
from datetime import datetime
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, HTTPException, Depends, status, UploadFile, File
from pydantic import BaseModel, Field

from ..core.eidas_al2 import (
    AL2IdentityProofingService, AL2Config, AL2VerificationSession,
    AL2IdentityMethod, AL2DocumentType, AL2VerificationStatus,
    AL2IdentityDocument, AL2BiometricData
)
from ..auth.dependencies import get_current_tenant
from ..models.tenant import Tenant

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/eidas-al2", tags=["eidas-al2"])


# Pydantic models for API
class StartVerificationRequest(BaseModel):
    """Request to start AL2 verification session"""
    applicant_id: str = Field(..., description="Unique applicant identifier")
    verification_method: str = Field(..., description="Verification method")
    given_name: str = Field(..., description="Given name")
    family_name: str = Field(..., description="Family name")
    date_of_birth: Optional[str] = Field(None, description="Date of birth (YYYY-MM-DD)")
    place_of_birth: Optional[str] = Field(None, description="Place of birth")
    nationality: str = Field(..., description="Nationality (ISO 3166-1 alpha-2)")
    email: str = Field(..., description="Email address")
    phone: Optional[str] = Field(None, description="Phone number")
    address: Optional[Dict[str, str]] = Field(default_factory=dict, description="Address information")


class VerificationSessionResponse(BaseModel):
    """Response containing verification session information"""
    session_id: str
    applicant_id: str
    verification_method: str
    status: str
    created_at: datetime
    expires_at: datetime
    given_name: str
    family_name: str
    nationality: str
    email: str
    
    @classmethod
    def from_session(cls, session: AL2VerificationSession) -> "VerificationSessionResponse":
        return cls(
            session_id=session.session_id,
            applicant_id=session.applicant_id,
            verification_method=session.verification_method.value,
            status=session.status.value,
            created_at=session.created_at,
            expires_at=session.expires_at,
            given_name=session.given_name,
            family_name=session.family_name,
            nationality=session.nationality,
            email=session.email
        )


class DocumentUploadResponse(BaseModel):
    """Response from document upload"""
    document_id: str
    document_type: str
    document_authentic: Optional[bool]
    quality_score: Optional[float]
    extracted_data: Dict[str, Any]


class BiometricCaptureResponse(BaseModel):
    """Response from biometric capture"""
    biometric_id: str
    quality_score: Optional[float]
    quality_level: str
    liveness_verified: bool


class VideoCallDetailsResponse(BaseModel):
    """Response containing video call details"""
    call_id: str
    join_url: str
    scheduled_time: str
    estimated_duration: int
    recording_enabled: bool


class VerificationCompletionRequest(BaseModel):
    """Request to complete verification"""
    verifier_id: str = Field(..., description="Human verifier ID")
    verification_notes: str = Field("", description="Verification notes")


class ComplianceReportResponse(BaseModel):
    """Response containing compliance report"""
    session_id: str
    verification_result: bool
    verification_timestamp: Optional[str]
    risk_score: Optional[float]
    eidas_al2_compliant: bool
    regulatory_compliance: Dict[str, Any]
    eidas_al2_attestation: Dict[str, Any]


# Global AL2 service instance (would be dependency injected in production)
al2_service: Optional[AL2IdentityProofingService] = None


def get_al2_service() -> AL2IdentityProofingService:
    """Get AL2 service instance"""
    if not al2_service:
        # Initialize with default config
        config = AL2Config()
        global al2_service
        al2_service = AL2IdentityProofingService(config)
    return al2_service


@router.post("/sessions", response_model=VerificationSessionResponse)
async def start_verification_session(
    request: StartVerificationRequest,
    tenant: Tenant = Depends(get_current_tenant),
    al2: AL2IdentityProofingService = Depends(get_al2_service)
):
    """
    Start new eIDAS AL2 identity verification session
    """
    try:
        # Parse verification method
        try:
            method = AL2IdentityMethod(request.verification_method)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid verification method: {request.verification_method}"
            )
        
        # Prepare personal info
        personal_info = {
            "given_name": request.given_name,
            "family_name": request.family_name,
            "date_of_birth": datetime.fromisoformat(request.date_of_birth) if request.date_of_birth else None,
            "place_of_birth": request.place_of_birth,
            "nationality": request.nationality,
            "email": request.email,
            "phone": request.phone,
            "address": request.address
        }
        
        session = await al2.start_verification_session(
            applicant_id=request.applicant_id,
            verification_method=method,
            personal_info=personal_info
        )
        
        logger.info(f"Started AL2 verification session for tenant {tenant.id}: {session.session_id}")
        
        return VerificationSessionResponse.from_session(session)
        
    except Exception as e:
        logger.error(f"Failed to start AL2 verification session for tenant {tenant.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start verification session: {str(e)}"
        )


@router.post("/sessions/{session_id}/documents", response_model=DocumentUploadResponse)
async def upload_identity_document(
    session_id: str,
    document_type: str,
    front_image: UploadFile = File(..., description="Front side of identity document"),
    back_image: Optional[UploadFile] = File(None, description="Back side of identity document"),
    tenant: Tenant = Depends(get_current_tenant),
    al2: AL2IdentityProofingService = Depends(get_al2_service)
):
    """
    Upload identity document for verification
    """
    try:
        # Parse document type
        try:
            doc_type = AL2DocumentType(document_type)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid document type: {document_type}"
            )
        
        # Read image files
        front_image_data = await front_image.read()
        back_image_data = await back_image.read() if back_image else None
        
        document = await al2.upload_identity_document(
            session_id=session_id,
            document_type=doc_type,
            front_image=front_image_data,
            back_image=back_image_data
        )
        
        logger.info(f"Document uploaded for session {session_id}: {document.document_id}")
        
        return DocumentUploadResponse(
            document_id=document.document_id,
            document_type=document.document_type.value,
            document_authentic=document.document_authentic,
            quality_score=document.quality_score,
            extracted_data=document.extracted_data
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Document upload failed for session {session_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Document upload failed: {str(e)}"
        )


@router.post("/sessions/{session_id}/biometrics", response_model=BiometricCaptureResponse)
async def capture_biometric_data(
    session_id: str,
    face_image: UploadFile = File(..., description="Face image for recognition"),
    liveness_video: Optional[UploadFile] = File(None, description="Video for liveness detection"),
    tenant: Tenant = Depends(get_current_tenant),
    al2: AL2IdentityProofingService = Depends(get_al2_service)
):
    """
    Capture biometric data for verification
    """
    try:
        # Read files
        face_image_data = await face_image.read()
        liveness_video_data = await liveness_video.read() if liveness_video else None
        
        biometric_data = await al2.capture_biometric_data(
            session_id=session_id,
            face_image=face_image_data,
            liveness_video=liveness_video_data
        )
        
        logger.info(f"Biometric data captured for session {session_id}: {biometric_data.biometric_id}")
        
        return BiometricCaptureResponse(
            biometric_id=biometric_data.biometric_id,
            quality_score=biometric_data.quality_score,
            quality_level=biometric_data.quality_level.value,
            liveness_verified=biometric_data.liveness_verified
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Biometric capture failed for session {session_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Biometric capture failed: {str(e)}"
        )


@router.post("/sessions/{session_id}/video-call", response_model=VideoCallDetailsResponse)
async def schedule_video_verification(
    session_id: str,
    preferred_time: Optional[str] = None,
    tenant: Tenant = Depends(get_current_tenant),
    al2: AL2IdentityProofingService = Depends(get_al2_service)
):
    """
    Schedule video call verification
    """
    try:
        preferred_datetime = None
        if preferred_time:
            try:
                preferred_datetime = datetime.fromisoformat(preferred_time)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid preferred_time format. Use ISO 8601 format."
                )
        
        call_details = await al2.schedule_video_verification(
            session_id=session_id,
            preferred_time=preferred_datetime
        )
        
        logger.info(f"Video verification scheduled for session {session_id}")
        
        return VideoCallDetailsResponse(**call_details)
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Video verification scheduling failed for session {session_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Video verification scheduling failed: {str(e)}"
        )


@router.post("/sessions/{session_id}/complete")
async def complete_video_verification(
    session_id: str,
    request: VerificationCompletionRequest,
    tenant: Tenant = Depends(get_current_tenant),
    al2: AL2IdentityProofingService = Depends(get_al2_service)
):
    """
    Complete video call verification
    """
    try:
        verification_passed = await al2.conduct_video_verification(
            session_id=session_id,
            verifier_id=request.verifier_id,
            verification_notes=request.verification_notes
        )
        
        logger.info(f"Video verification completed for session {session_id}: {verification_passed}")
        
        return {
            "success": True,
            "verification_passed": verification_passed,
            "message": "Verification completed successfully"
        }
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Video verification completion failed for session {session_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Video verification completion failed: {str(e)}"
        )


@router.get("/sessions/{session_id}/status", response_model=VerificationSessionResponse)
async def get_verification_status(
    session_id: str,
    tenant: Tenant = Depends(get_current_tenant),
    al2: AL2IdentityProofingService = Depends(get_al2_service)
):
    """
    Get verification session status
    """
    try:
        session = await al2.get_verification_status(session_id)
        
        return VerificationSessionResponse.from_session(session)
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to get verification status for session {session_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get verification status: {str(e)}"
        )


@router.get("/sessions/{session_id}/compliance-report", response_model=ComplianceReportResponse)
async def get_compliance_report(
    session_id: str,
    tenant: Tenant = Depends(get_current_tenant),
    al2: AL2IdentityProofingService = Depends(get_al2_service)
):
    """
    Generate compliance report for completed verification
    """
    try:
        report = await al2.generate_compliance_report(session_id)
        
        return ComplianceReportResponse(
            session_id=report["session_id"],
            verification_result=report["verification_result"],
            verification_timestamp=report["verification_timestamp"],
            risk_score=report["risk_score"],
            eidas_al2_compliant=report["regulatory_compliance"]["eidas_al2_compliant"],
            regulatory_compliance=report["regulatory_compliance"],
            eidas_al2_attestation=report["eidas_al2_attestation"]
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Compliance report generation failed for session {session_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Compliance report generation failed: {str(e)}"
        )


@router.get("/methods")
async def get_verification_methods(
    tenant: Tenant = Depends(get_current_tenant)
):
    """
    Get available verification methods
    """
    return {
        "methods": [method.value for method in AL2IdentityMethod],
        "document_types": [doc_type.value for doc_type in AL2DocumentType],
        "supported_features": {
            "document_verification": True,
            "biometric_matching": True,
            "liveness_detection": True,
            "video_call_verification": True,
            "risk_assessment": True,
            "compliance_reporting": True
        }
    }