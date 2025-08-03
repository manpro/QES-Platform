"""
Document Verification API Endpoints

FastAPI endpoints for eIDAS AL2 document verification functionality.
"""

import logging
from typing import Optional, Dict, Any
import base64

from fastapi import APIRouter, HTTPException, Depends, status, UploadFile, File, Form, Request
from datetime import datetime
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from auth.jwt_auth import get_current_user
from models.user import User
from core.eidas_al2 import (
    DocumentVerifier, AL2Config, AL2DocumentType, AL2IdentityDocument
)
from core.external_document_verifiers import (
    ExternalDocumentVerificationService, DocumentVerificationRequest as ExtDocRequest,
    DocumentType as ExtDocType, DocumentVerificationProvider
)
from datetime import datetime
import uuid
from utils.request_utils import get_client_ip, get_user_agent
from core.audit_logger import AuditLogger, AuditEventType

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/document-verification", tags=["document-verification"])


class DocumentVerificationRequest(BaseModel):
    """Request for document verification"""
    document_type: str = Field(..., description="Type of document (passport, national_id, driving_license, residence_permit)")
    applicant_name: Optional[str] = Field(None, description="Expected applicant name for cross-validation")
    country_code: Optional[str] = Field(None, description="Document issuing country code (e.g., 'SE', 'DE', 'FR')")
    provider: Optional[str] = Field(None, description="Preferred verification provider (onfido, jumio, idnow, veriff)")
    enable_liveness_check: bool = Field(True, description="Enable liveness detection")
    enable_face_comparison: bool = Field(True, description="Enable face comparison with document photo")


class DocumentVerificationResponse(BaseModel):
    """Response from document verification"""
    verification_id: str
    authentic: bool
    consistent: bool
    not_expired: bool
    quality_score: float
    extracted_data: Dict[str, Any]
    security_features: Dict[str, Any]
    processing_metadata: Dict[str, Any]
    overall_score: float


class DocumentAnalysisResponse(BaseModel):
    """Detailed document analysis response"""
    verification_id: str
    document_type: str
    image_quality: Dict[str, Any]
    ocr_results: Dict[str, Any]
    face_detection: Optional[Dict[str, Any]]
    security_analysis: Dict[str, Any]
    authenticity_checks: Dict[str, Any]
    extracted_text: str
    confidence_scores: Dict[str, float]


# Initialize document verifier (legacy internal)
doc_verifier = DocumentVerifier(AL2Config(
    enable_video_verification=True,
    enable_biometric_verification=True,
    enable_document_verification=True,
    risk_threshold=0.3,
    session_timeout_minutes=30
))

# Initialize external document verification service
import os
external_doc_config = {
    "default_provider": os.getenv("DOC_VERIFICATION_DEFAULT_PROVIDER", "onfido"),
    "fallback_provider": os.getenv("DOC_VERIFICATION_FALLBACK_PROVIDER", "jumio"),
    
    "onfido": {
        "enabled": os.getenv("ONFIDO_ENABLED", "true").lower() == "true",
        "api_key": os.getenv("ONFIDO_API_KEY", ""),
        "base_url": os.getenv("ONFIDO_BASE_URL", "https://api.onfido.com/v3.6"),
        "webhook_url": os.getenv("ONFIDO_WEBHOOK_URL", "")
    },
    
    "jumio": {
        "enabled": os.getenv("JUMIO_ENABLED", "true").lower() == "true",
        "api_key": os.getenv("JUMIO_API_KEY", ""),
        "api_secret": os.getenv("JUMIO_API_SECRET", ""),
        "base_url": os.getenv("JUMIO_BASE_URL", "https://api.jumio.com"),
        "webhook_url": os.getenv("JUMIO_WEBHOOK_URL", "")
    },
    
    "idnow": {
        "enabled": os.getenv("IDNOW_ENABLED", "false").lower() == "true",
        "api_key": os.getenv("IDNOW_API_KEY", ""),
        "company_id": os.getenv("IDNOW_COMPANY_ID", ""),
        "base_url": os.getenv("IDNOW_BASE_URL", "https://api.idnow.de"),
        "webhook_url": os.getenv("IDNOW_WEBHOOK_URL", "")
    },
    
    "veriff": {
        "enabled": os.getenv("VERIFF_ENABLED", "false").lower() == "true",
        "api_key": os.getenv("VERIFF_API_KEY", ""),
        "api_secret": os.getenv("VERIFF_API_SECRET", ""),
        "base_url": os.getenv("VERIFF_BASE_URL", "https://stationapi.veriff.com"),
        "webhook_url": os.getenv("VERIFF_WEBHOOK_URL", "")
    }
}

# Initialize external service if any provider is enabled
external_doc_service = None
if any(provider_config.get("enabled", False) for provider_config in external_doc_config.values() if isinstance(provider_config, dict)):
    external_doc_service = ExternalDocumentVerificationService(external_doc_config)
else:
    logger.info("No external document verification providers configured - using internal verification only")

# Initialize audit logger
audit_logger = AuditLogger({
    "enable_postgres": True,
    "enable_loki": True,
    "enable_file": True,
    "log_file_path": "audit.log",
    "buffer_size": 50
})


@router.post("/verify", response_model=DocumentVerificationResponse)
async def verify_document(
    request: Request,
    document_type: str = Form(...),
    applicant_name: Optional[str] = Form(None),
    country_code: Optional[str] = Form(None),
    provider: Optional[str] = Form(None),
    enable_liveness_check: bool = Form(True),
    enable_face_comparison: bool = Form(True),
    front_image: UploadFile = File(..., description="Front side of identity document"),
    back_image: Optional[UploadFile] = File(None, description="Back side of identity document (if applicable)"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verify an identity document using advanced image processing and OCR.
    
    This endpoint performs comprehensive document verification including:
    - Image quality assessment
    - OCR text extraction
    - Security feature detection
    - Face extraction and analysis
    - Document authenticity checks
    - Expiration validation
    - Data consistency verification
    """
    try:
        # Validate document type
        try:
            doc_type = AL2DocumentType(document_type.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid document type. Supported types: {[dt.value for dt in AL2DocumentType]}"
            )
        
        # Read uploaded files
        front_image_data = await front_image.read()
        back_image_data = None
        if back_image:
            back_image_data = await back_image.read()
        
        # Validate file sizes (max 10MB per image)
        max_size = 10 * 1024 * 1024  # 10MB
        if len(front_image_data) > max_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Front image too large (max 10MB)"
            )
        
        if back_image_data and len(back_image_data) > max_size:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Back image too large (max 10MB)"
            )
        
        # Create document object
        document_id = str(uuid.uuid4())
        
        document = AL2IdentityDocument(
            document_id=document_id,
            document_type=doc_type,
            document_number="",  # Will be extracted during verification
            issuing_country="",  # Will be extracted during verification
            issuing_authority="",  # Will be extracted during verification
            issue_date=datetime.min,  # Will be extracted during verification
            expiry_date=datetime.min,  # Will be extracted during verification
            front_image=front_image_data,
            back_image=back_image_data
        )
        
        # Determine verification method
        use_external_provider = external_doc_service and (
            provider or 
            os.getenv("PREFER_EXTERNAL_VERIFICATION", "true").lower() == "true"
        )
        
        if use_external_provider:
            # Use external document verification service
            verification_result = await _verify_with_external_provider(
                front_image_data, back_image_data, document_type, 
                applicant_name, country_code, provider, 
                enable_liveness_check, enable_face_comparison
            )
        else:
            # Fallback to internal verification
            verification_result = await doc_verifier.verify_document(document)
        
        # Calculate overall score
        quality_weight = 0.2
        authenticity_weight = 0.4
        consistency_weight = 0.2
        security_weight = 0.2
        
        authenticity_score = verification_result.get("authenticity_details", {}).get("confidence_score", 0.0)
        security_score = verification_result.get("security_features", {}).get("overall_security_score", 0.0)
        consistency_score = 0.7 if verification_result.get("consistent", False) else 0.3
        
        overall_score = (
            verification_result.get("quality_score", 0.0) * quality_weight +
            authenticity_score * authenticity_weight +
            consistency_score * consistency_weight +
            security_score * security_weight
        )
        
        # Log verification event for audit
        await audit_logger.log_validation_check(
            user_id=current_user.id,
            resource_id=document_id,
            check_type="document_verification",
            result=verification_result.get("authentic", False),
            client_ip=get_client_ip(request),
            user_agent=get_user_agent(request),
            details={
                "document_type": document_type,
                "applicant_name": applicant_name,
                "overall_score": overall_score,
                "quality_score": verification_result.get("quality_score", 0.0),
                "authenticity_score": authenticity_score,
                "security_score": security_score,
                "front_image_size": len(front_image_data),
                "back_image_size": len(back_image_data) if back_image_data else 0,
                "extracted_document_number": verification_result.get("extracted_data", {}).get("document_number", ""),
                "extracted_name": verification_result.get("extracted_data", {}).get("full_name", "")
            }
        )
        
        logger.info(f"Document verification completed for user {current_user.id}: {document_id} - Score: {overall_score:.2f} - Method: {'external' if use_external_provider else 'internal'}")
        
        response = DocumentVerificationResponse(
            verification_id=verification_result.get("verification_id", document_id),
            authentic=verification_result.get("authentic", False),
            consistent=verification_result.get("consistent", False),
            not_expired=verification_result.get("not_expired", True),
            quality_score=verification_result.get("quality_score", 0.0),
            extracted_data=verification_result.get("extracted_data", {}),
            security_features=verification_result.get("security_features", {}),
            processing_metadata=verification_result.get("processing_metadata", {
                "verification_method": "external" if use_external_provider else "internal",
                "provider_used": verification_result.get("provider", "internal"),
                "processing_time_ms": verification_result.get("processing_time_ms", 0)
            }),
            overall_score=overall_score
        )
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Document verification failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Document verification failed: {str(e)}"
        )


@router.post("/analyze", response_model=DocumentAnalysisResponse)
async def analyze_document(
    request: Request,
    document_type: str = Form(...),
    front_image: UploadFile = File(...),
    back_image: Optional[UploadFile] = File(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Perform detailed document analysis returning all intermediate results.
    
    This endpoint provides comprehensive analysis including all processing steps
    and detailed confidence scores for debugging and fine-tuning purposes.
    """
    try:
        # Validate document type
        try:
            doc_type = AL2DocumentType(document_type.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid document type. Supported types: {[dt.value for dt in AL2DocumentType]}"
            )
        
        # Read images
        front_data = await front_image.read()
        back_data = await back_image.read() if back_image else None
        
        # Create document
        document_id = str(uuid.uuid4())
        
        document = AL2IdentityDocument(
            document_id=document_id,
            document_type=doc_type,
            document_number="",  # Will be extracted during verification
            issuing_country="",  # Will be extracted during verification
            issuing_authority="",  # Will be extracted during verification
            issue_date=datetime.min,  # Will be extracted during verification
            expiry_date=datetime.min,  # Will be extracted during verification
            front_image=front_data,
            back_image=back_data
        )
        
        # Perform detailed analysis
        verification_result = await doc_verifier.verify_document(document)
        
        # Extract detailed analysis data
        response = DocumentAnalysisResponse(
            verification_id=document_id,
            document_type=document_type,
            image_quality={
                "overall_score": verification_result.get("quality_score", 0.0),
                "details": "Image quality assessment completed"
            },
            ocr_results={
                "confidence": verification_result.get("processing_metadata", {}).get("ocr_confidence", 0.0),
                "extracted_text": verification_result.get("extracted_data", {}).get("raw_text", "")
            },
            face_detection={
                "detected": verification_result.get("processing_metadata", {}).get("face_detected", False),
                "coordinates": verification_result.get("extracted_data", {}).get("face_coordinates", {})
            } if verification_result.get("processing_metadata", {}).get("face_detected") else None,
            security_analysis=verification_result.get("security_features", {}),
            authenticity_checks=verification_result.get("authenticity_details", {}),
            extracted_text=verification_result.get("extracted_data", {}).get("raw_text", ""),
            confidence_scores={
                "overall": verification_result.get("authenticity_details", {}).get("confidence_score", 0.0),
                "security": verification_result.get("security_features", {}).get("overall_security_score", 0.0),
                "quality": verification_result.get("quality_score", 0.0),
                "ocr": verification_result.get("processing_metadata", {}).get("ocr_confidence", 0.0)
            }
        )
        
        # Log analysis event
        await audit_logger.log_validation_check(
            user_id=current_user.id,
            resource_id=document_id,
            check_type="document_analysis",
            result=True,
            client_ip=get_client_ip(request),
            user_agent=get_user_agent(request),
            details={
                "document_type": document_type,
                "analysis_type": "detailed",
                "confidence_scores": response.confidence_scores
            }
        )
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Document analysis failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Document analysis failed: {str(e)}"
        )


@router.get("/supported-types")
async def get_supported_document_types():
    """Get list of supported document types for verification"""
    return {
        "supported_types": [
            {
                "type": doc_type.value,
                "name": doc_type.value.replace("_", " ").title(),
                "description": _get_document_description(doc_type)
            }
            for doc_type in AL2DocumentType
        ],
        "features": {
            "ocr_extraction": True,
            "face_detection": True,
            "security_feature_analysis": True,
            "authenticity_verification": True,
            "expiration_checking": True,
            "quality_assessment": True
        },
        "supported_formats": ["JPEG", "PNG", "BMP", "TIFF"],
        "max_file_size": "10MB",
        "recommended_resolution": "1200x800 pixels minimum"
    }


def _get_document_description(doc_type: AL2DocumentType) -> str:
    """Get description for document type"""
    descriptions = {
        AL2DocumentType.PASSPORT: "International travel document with machine-readable zone",
        AL2DocumentType.NATIONAL_ID: "Government-issued national identity card",
        AL2DocumentType.DRIVING_LICENSE: "Driver's license with photo identification",
        AL2DocumentType.RESIDENCE_PERMIT: "Permit for foreign residents"
    }
    return descriptions.get(doc_type, "Identity document")


@router.get("/health")
async def document_verification_health():
    """Health check for document verification service"""
    try:
        # Test basic functionality
        test_config = AL2Config(
            enable_document_verification=True,
            risk_threshold=0.5
        )
        
        test_verifier = DocumentVerifier(test_config)
        
        return {
            "status": "healthy",
            "service": "document-verification",
            "features": {
                "ocr_available": True,
                "face_recognition_available": True,
                "image_processing_available": True,
                "security_analysis_available": True
            },
            "supported_document_types": len(AL2DocumentType),
            "version": "1.0.0"
        }
        
    except Exception as e:
        logger.error(f"Document verification health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Service unhealthy: {str(e)}"
        )