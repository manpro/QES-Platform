"""
Biometric Verification API Endpoints

FastAPI endpoints for advanced biometric verification services including
face recognition, liveness detection, and anti-spoofing measures.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends, status, UploadFile, File, Form
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from auth.jwt_auth import get_current_user
from models.user import User
from core.eidas_al2 import AL2Config, BiometricVerifier
from core.audit_logger import AuditLogger, AuditEvent, AuditEventType
from utils.request_utils import get_client_ip, get_user_agent

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/biometric", tags=["biometric"])


class BiometricAnalysisResponse(BaseModel):
    """Response model for biometric analysis"""
    success: bool
    analysis_id: str
    quality_score: float
    quality_level: str
    face_detected: bool
    encoding_available: bool
    analysis_details: Dict[str, Any]
    processing_metadata: Dict[str, Any]
    error: Optional[str] = None


class LivenessDetectionResponse(BaseModel):
    """Response model for liveness detection"""
    success: bool
    session_id: str
    is_live: bool
    confidence: float
    liveness_score: float
    duration: float
    analysis_details: Dict[str, Any]
    processing_metadata: Dict[str, Any]
    error: Optional[str] = None


class FaceComparisonResponse(BaseModel):
    """Response model for face comparison"""
    success: bool
    comparison_id: str
    similarity_score: float
    confidence: float
    match: bool
    face1_analysis: Dict[str, Any]
    face2_analysis: Dict[str, Any]
    detailed_analysis: Dict[str, Any]
    processing_metadata: Dict[str, Any]
    error: Optional[str] = None


def get_biometric_verifier() -> BiometricVerifier:
    """Get configured biometric verifier instance"""
    config = AL2Config()
    return BiometricVerifier(config)


def get_audit_logger() -> AuditLogger:
    """Get audit logger instance"""
    return AuditLogger({
        "postgres_enabled": True,
        "loki_enabled": True
    })


@router.post("/analyze-face", response_model=BiometricAnalysisResponse)
async def analyze_face_image(
    image: UploadFile = File(..., description="Face image to analyze"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    verifier: BiometricVerifier = Depends(get_biometric_verifier),
    audit_logger: AuditLogger = Depends(get_audit_logger)
):
    """
    Analyze a face image for biometric recognition and quality assessment.
    
    Performs comprehensive face analysis including:
    - Face detection and quality assessment
    - Anti-spoofing analysis
    - Geometric analysis
    - Face encoding generation
    """
    try:
        # Validate file type
        if not image.content_type or not image.content_type.startswith('image/'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File must be an image"
            )
        
        # Read image data
        image_data = await image.read()
        
        if len(image_data) > 10 * 1024 * 1024:  # 10MB limit
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Image file too large (max 10MB)"
            )
        
        # Process face image
        analysis_result = await verifier.process_face_image(image_data)
        
        # Generate analysis ID
        import secrets
        analysis_id = secrets.token_urlsafe(16)
        
        # Log audit event
        await audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.BIOMETRIC_ANALYSIS,
            user_id=str(current_user.id),
            resource_id=analysis_id,
            details={
                "image_filename": image.filename,
                "image_size": len(image_data),
                "quality_score": analysis_result.get("quality_score", 0.0),
                "face_detected": analysis_result.get("face_count", 0) > 0,
                "encoding_generated": analysis_result.get("encoding") is not None
            }
        ))
        
        # Prepare response
        success = analysis_result.get("encoding") is not None
        
        return BiometricAnalysisResponse(
            success=success,
            analysis_id=analysis_id,
            quality_score=analysis_result.get("quality_score", 0.0),
            quality_level=analysis_result.get("quality_level", "LOW").value if hasattr(analysis_result.get("quality_level"), "value") else str(analysis_result.get("quality_level", "LOW")),
            face_detected=analysis_result.get("face_count", 0) > 0,
            encoding_available=analysis_result.get("encoding") is not None,
            analysis_details={
                "face_count": analysis_result.get("face_count", 0),
                "face_location": analysis_result.get("face_location", {}),
                "quality_details": analysis_result.get("quality_details", {}),
                "spoofing_analysis": analysis_result.get("spoofing_analysis", {}),
                "geometric_analysis": analysis_result.get("geometric_analysis", {})
            },
            processing_metadata=analysis_result.get("processing_metadata", {}),
            error=analysis_result.get("error")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Face analysis failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Face analysis failed"
        )


@router.post("/liveness-detection", response_model=LivenessDetectionResponse)
async def detect_liveness(
    video: UploadFile = File(..., description="Video file for liveness detection"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    verifier: BiometricVerifier = Depends(get_biometric_verifier),
    audit_logger: AuditLogger = Depends(get_audit_logger)
):
    """
    Perform liveness detection on a video file.
    
    Analyzes video for signs of life including:
    - Motion pattern analysis
    - Eye blink detection
    - 3D movement tracking
    - Temporal consistency checks
    """
    try:
        # Validate file type
        if not video.content_type or not video.content_type.startswith('video/'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File must be a video"
            )
        
        # Read video data
        video_data = await video.read()
        
        if len(video_data) > 50 * 1024 * 1024:  # 50MB limit
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Video file too large (max 50MB)"
            )
        
        # Process liveness detection
        liveness_result = await verifier.detect_liveness(video_data)
        
        # Generate session ID
        import secrets
        session_id = secrets.token_urlsafe(16)
        
        # Log audit event
        await audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.LIVENESS_DETECTION,
            user_id=str(current_user.id),
            session_id=session_id,
            details={
                "video_filename": video.filename,
                "video_size": len(video_data),
                "is_live": liveness_result.get("is_live", False),
                "confidence": liveness_result.get("confidence", 0.0),
                "liveness_score": liveness_result.get("liveness_score", 0.0),
                "duration": liveness_result.get("duration", 0.0)
            }
        ))
        
        # Prepare response
        success = "error" not in liveness_result
        
        return LivenessDetectionResponse(
            success=success,
            session_id=session_id,
            is_live=liveness_result.get("is_live", False),
            confidence=liveness_result.get("confidence", 0.0),
            liveness_score=liveness_result.get("liveness_score", 0.0),
            duration=liveness_result.get("duration", 0.0),
            analysis_details=liveness_result.get("analysis_details", {}),
            processing_metadata=liveness_result.get("processing_metadata", {}),
            error=liveness_result.get("error")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Liveness detection failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Liveness detection failed"
        )


@router.post("/compare-faces", response_model=FaceComparisonResponse)
async def compare_faces(
    image1: UploadFile = File(..., description="First face image"),
    image2: UploadFile = File(..., description="Second face image"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    verifier: BiometricVerifier = Depends(get_biometric_verifier),
    audit_logger: AuditLogger = Depends(get_audit_logger)
):
    """
    Compare two face images for identity verification.
    
    Performs detailed face comparison including:
    - Face encoding comparison
    - Quality assessment
    - Geometric similarity analysis
    - Confidence scoring
    """
    try:
        # Validate file types
        for img in [image1, image2]:
            if not img.content_type or not img.content_type.startswith('image/'):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Both files must be images"
                )
        
        # Read image data
        image1_data = await image1.read()
        image2_data = await image2.read()
        
        # Check file sizes
        for img_data, img_name in [(image1_data, "image1"), (image2_data, "image2")]:
            if len(img_data) > 10 * 1024 * 1024:  # 10MB limit
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"{img_name} file too large (max 10MB)"
                )
        
        # Compare faces
        comparison_result = await verifier.compare_faces(image1_data, image2_data)
        
        # Generate comparison ID
        import secrets
        comparison_id = secrets.token_urlsafe(16)
        
        # Log audit event
        await audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.FACE_COMPARISON,
            user_id=str(current_user.id),
            resource_id=comparison_id,
            details={
                "image1_filename": image1.filename,
                "image2_filename": image2.filename,
                "similarity_score": comparison_result.get("similarity_score", 0.0),
                "match": comparison_result.get("match", False),
                "confidence": comparison_result.get("confidence", 0.0)
            }
        ))
        
        # Prepare response
        success = "error" not in comparison_result
        
        return FaceComparisonResponse(
            success=success,
            comparison_id=comparison_id,
            similarity_score=comparison_result.get("similarity_score", 0.0),
            confidence=comparison_result.get("confidence", 0.0),
            match=comparison_result.get("match", False),
            face1_analysis=comparison_result.get("face1_analysis", {}),
            face2_analysis=comparison_result.get("face2_analysis", {}),
            detailed_analysis=comparison_result.get("detailed_analysis", {}),
            processing_metadata=comparison_result.get("processing_metadata", {}),
            error=comparison_result.get("error")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Face comparison failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Face comparison failed"
        )


@router.get("/capabilities")
async def get_biometric_capabilities(
    current_user: User = Depends(get_current_user)
):
    """
    Get information about available biometric verification capabilities.
    
    Returns details about supported features, quality thresholds,
    and configuration parameters.
    """
    try:
        config = AL2Config()
        
        return {
            "capabilities": {
                "face_recognition": True,
                "liveness_detection": True,
                "anti_spoofing": True,
                "quality_assessment": True,
                "geometric_analysis": True,
                "eye_blink_detection": True,
                "motion_analysis": True,
                "3d_movement_tracking": True
            },
            "thresholds": {
                "face_recognition_threshold": config.face_recognition_threshold,
                "liveness_detection_threshold": config.liveness_detection_threshold,
                "minimum_quality_score": 0.3,
                "maximum_image_size_mb": 10,
                "maximum_video_size_mb": 50
            },
            "supported_formats": {
                "images": ["image/jpeg", "image/png", "image/bmp", "image/webp"],
                "videos": ["video/mp4", "video/avi", "video/mov", "video/webm"]
            },
            "processing_features": {
                "algorithms": ["dlib_face_recognition", "opencv_detection", "mediapipe_analysis"],
                "anti_spoofing_methods": ["texture_analysis", "color_analysis", "frequency_domain", "reflection_analysis"],
                "liveness_indicators": ["motion_patterns", "eye_blinks", "3d_movement", "temporal_consistency"],
                "quality_metrics": ["sharpness", "brightness", "contrast", "symmetry", "pose", "resolution"]
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get biometric capabilities: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve capabilities"
        )


@router.get("/health")
async def biometric_service_health():
    """Health check for biometric verification service"""
    try:
        # Test biometric verifier initialization
        verifier = get_biometric_verifier()
        
        # Check if required models are available
        model_status = {
            "opencv_cascade": verifier._face_cascade is not None,
            "mediapipe_available": verifier._mediapipe_face_detection is not None
        }
        
        all_models_available = all(model_status.values())
        
        return {
            "status": "healthy" if all_models_available else "degraded",
            "service": "biometric-verification",
            "models": model_status,
            "features": {
                "face_recognition": True,
                "liveness_detection": True,
                "anti_spoofing": True,
                "quality_assessment": True
            },
            "dependencies": {
                "opencv": True,
                "face_recognition": True,
                "numpy": True,
                "scikit_image": True
            }
        }
        
    except Exception as e:
        logger.error(f"Biometric service health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Biometric service unhealthy: {str(e)}"
        )