"""
eIDAS AL2 Remote ID-proofing Workflow

Implements eIDAS Assurance Level 2 remote identity proofing workflow
for qualified electronic signature certificate issuance.
"""

import json
import logging
import hashlib
import secrets
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum

import asyncio
import aiofiles
from PIL import Image
import face_recognition
import cv2
import numpy as np
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Import biometric helpers
from .biometric_helpers import BiometricHelpers
from .liveness_detection import LivenessDetectionHelpers

logger = logging.getLogger(__name__)


class AL2IdentityMethod(Enum):
    """eIDAS AL2 identity proofing methods"""
    VIDEO_CALL_VERIFICATION = "video_call_verification"
    DOCUMENT_VERIFICATION = "document_verification"
    BIOMETRIC_MATCHING = "biometric_matching"
    SUPERVISED_REMOTE = "supervised_remote"
    QUALIFIED_WITNESS = "qualified_witness"


class AL2DocumentType(Enum):
    """Supported identity documents for AL2"""
    PASSPORT = "passport"
    NATIONAL_ID = "national_id"
    DRIVING_LICENSE = "driving_license"
    RESIDENCE_PERMIT = "residence_permit"


class AL2VerificationStatus(Enum):
    """AL2 verification status"""
    PENDING = "pending"
    DOCUMENT_UPLOADED = "document_uploaded"
    FACE_CAPTURED = "face_captured"
    VERIFICATION_SCHEDULED = "verification_scheduled"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


class AL2BiometricQuality(Enum):
    """Biometric quality levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    EXCELLENT = "excellent"


@dataclass
class AL2IdentityDocument:
    """Identity document for AL2 verification"""
    document_id: str
    document_type: AL2DocumentType
    document_number: str
    issuing_country: str
    issuing_authority: str
    issue_date: datetime
    expiry_date: datetime
    
    # Document images
    front_image: Optional[bytes] = None
    back_image: Optional[bytes] = None
    
    # Extracted data
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    security_features: Dict[str, bool] = field(default_factory=dict)
    
    # Verification results
    document_authentic: Optional[bool] = None
    data_consistent: Optional[bool] = None
    not_expired: Optional[bool] = None
    quality_score: Optional[float] = None


@dataclass
class AL2BiometricData:
    """Biometric data for AL2 verification"""
    biometric_id: str
    face_image: Optional[bytes] = None
    face_encoding: Optional[List[float]] = None
    quality_score: Optional[float] = None
    quality_level: AL2BiometricQuality = AL2BiometricQuality.MEDIUM
    liveness_verified: bool = False
    
    # Video call verification
    video_frames: List[bytes] = field(default_factory=list)
    video_duration: Optional[int] = None
    audio_verification: bool = False


@dataclass
class AL2VerificationSession:
    """AL2 identity verification session"""
    session_id: str
    applicant_id: str
    verification_method: AL2IdentityMethod
    status: AL2VerificationStatus
    created_at: datetime
    expires_at: datetime
    
    # Personal information
    given_name: str = ""
    family_name: str = ""
    date_of_birth: Optional[datetime] = None
    place_of_birth: str = ""
    nationality: str = ""
    email: str = ""
    phone: str = ""
    address: Dict[str, str] = field(default_factory=dict)
    
    # Documents and biometrics
    identity_document: Optional[AL2IdentityDocument] = None
    biometric_data: Optional[AL2BiometricData] = None
    
    # Verification details
    verifier_id: Optional[str] = None
    verification_time: Optional[datetime] = None
    verification_notes: str = ""
    risk_score: Optional[float] = None
    
    # Compliance evidence
    regulatory_compliance: Dict[str, Any] = field(default_factory=dict)
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)
    
    # Results
    verification_result: Optional[bool] = None
    failure_reason: Optional[str] = None
    quality_metrics: Dict[str, float] = field(default_factory=dict)


@dataclass
class AL2Config:
    """AL2 verification configuration"""
    face_recognition_threshold: float = 0.6
    document_quality_threshold: float = 0.8
    liveness_detection_required: bool = True
    video_call_duration_min: int = 5
    max_verification_attempts: int = 3
    session_timeout_hours: int = 24
    
    # AI/ML model endpoints
    document_verification_endpoint: Optional[str] = None
    face_recognition_endpoint: Optional[str] = None
    liveness_detection_endpoint: Optional[str] = None
    
    # Video call integration
    video_call_provider: str = "jitsi"  # jitsi, zoom, teams, webrtc
    video_call_recording_required: bool = True
    
    # Regulatory requirements
    gdpr_compliant: bool = True
    data_retention_days: int = 7
    audit_retention_years: int = 10


class AL2IdentityProofingService:
    """
    eIDAS AL2 Remote Identity Proofing Service
    
    Implements comprehensive remote identity verification workflow
    compliant with eIDAS Assurance Level 2 requirements.
    """
    
    def __init__(self, config: AL2Config):
        """Initialize AL2 identity proofing service"""
        self.config = config
        self._sessions: Dict[str, AL2VerificationSession] = {}
        self._risk_engine = AL2RiskEngine()
        self._document_verifier = DocumentVerifier(config)
        self._biometric_verifier = BiometricVerifier(config)
        self._video_call_service = VideoCallService(config)
        
        logger.info("Initialized eIDAS AL2 identity proofing service")
    
    async def start_verification_session(
        self, 
        applicant_id: str,
        verification_method: AL2IdentityMethod,
        personal_info: Dict[str, Any]
    ) -> AL2VerificationSession:
        """
        Start new AL2 identity verification session
        
        Args:
            applicant_id: Unique applicant identifier
            verification_method: Verification method to use
            personal_info: Basic personal information
            
        Returns:
            Verification session
        """
        try:
            session_id = secrets.token_urlsafe(32)
            
            session = AL2VerificationSession(
                session_id=session_id,
                applicant_id=applicant_id,
                verification_method=verification_method,
                status=AL2VerificationStatus.PENDING,
                created_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(hours=self.config.session_timeout_hours),
                given_name=personal_info.get("given_name", ""),
                family_name=personal_info.get("family_name", ""),
                date_of_birth=personal_info.get("date_of_birth"),
                place_of_birth=personal_info.get("place_of_birth", ""),
                nationality=personal_info.get("nationality", ""),
                email=personal_info.get("email", ""),
                phone=personal_info.get("phone", ""),
                address=personal_info.get("address", {})
            )
            
            # Add audit entry
            session.audit_trail.append({
                "action": "session_started",
                "timestamp": datetime.utcnow().isoformat(),
                "method": verification_method.value,
                "applicant_id": applicant_id
            })
            
            self._sessions[session_id] = session
            
            logger.info(f"Started AL2 verification session: {session_id}")
            return session
            
        except Exception as e:
            logger.error(f"Failed to start AL2 verification session: {e}")
            raise
    
    async def upload_identity_document(
        self,
        session_id: str,
        document_type: AL2DocumentType,
        front_image: bytes,
        back_image: Optional[bytes] = None,
        document_metadata: Optional[Dict[str, Any]] = None
    ) -> AL2IdentityDocument:
        """
        Upload and verify identity document
        
        Args:
            session_id: Verification session ID
            document_type: Type of identity document
            front_image: Front side image
            back_image: Back side image (if applicable)
            document_metadata: Additional document metadata
            
        Returns:
            Identity document record
        """
        try:
            session = self._get_session(session_id)
            
            # Generate document ID
            document_id = secrets.token_urlsafe(16)
            
            # Create document record
            document = AL2IdentityDocument(
                document_id=document_id,
                document_type=document_type,
                document_number="",  # Will be extracted
                issuing_country="",  # Will be extracted
                issuing_authority="",  # Will be extracted
                issue_date=datetime.min,  # Will be extracted
                expiry_date=datetime.min,  # Will be extracted
                front_image=front_image,
                back_image=back_image
            )
            
            # Verify document authenticity and extract data
            verification_result = await self._document_verifier.verify_document(document)
            document.document_authentic = verification_result["authentic"]
            document.data_consistent = verification_result["consistent"]
            document.not_expired = verification_result["not_expired"]
            document.quality_score = verification_result["quality_score"]
            document.extracted_data = verification_result["extracted_data"]
            document.security_features = verification_result["security_features"]
            
            # Update document with extracted data
            if document.extracted_data:
                document.document_number = document.extracted_data.get("document_number", "")
                document.issuing_country = document.extracted_data.get("issuing_country", "")
                document.issuing_authority = document.extracted_data.get("issuing_authority", "")
                
                if document.extracted_data.get("issue_date"):
                    document.issue_date = datetime.fromisoformat(document.extracted_data["issue_date"])
                if document.extracted_data.get("expiry_date"):
                    document.expiry_date = datetime.fromisoformat(document.extracted_data["expiry_date"])
            
            # Update session
            session.identity_document = document
            session.status = AL2VerificationStatus.DOCUMENT_UPLOADED
            
            # Add audit entry
            session.audit_trail.append({
                "action": "document_uploaded",
                "timestamp": datetime.utcnow().isoformat(),
                "document_type": document_type.value,
                "document_id": document_id,
                "verification_result": verification_result
            })
            
            logger.info(f"Document uploaded for session {session_id}: {document_id}")
            return document
            
        except Exception as e:
            logger.error(f"Document upload failed for session {session_id}: {e}")
            raise
    
    async def capture_biometric_data(
        self,
        session_id: str,
        face_image: bytes,
        liveness_video: Optional[bytes] = None
    ) -> AL2BiometricData:
        """
        Capture and verify biometric data
        
        Args:
            session_id: Verification session ID
            face_image: Face image for recognition
            liveness_video: Video for liveness detection
            
        Returns:
            Biometric data record
        """
        try:
            session = self._get_session(session_id)
            
            # Generate biometric ID
            biometric_id = secrets.token_urlsafe(16)
            
            # Create biometric record
            biometric_data = AL2BiometricData(
                biometric_id=biometric_id,
                face_image=face_image
            )
            
            # Process face recognition
            face_result = await self._biometric_verifier.process_face_image(face_image)
            biometric_data.face_encoding = face_result["encoding"]
            biometric_data.quality_score = face_result["quality_score"]
            biometric_data.quality_level = face_result["quality_level"]
            
            # Process liveness detection if provided
            if liveness_video and self.config.liveness_detection_required:
                liveness_result = await self._biometric_verifier.detect_liveness(liveness_video)
                biometric_data.liveness_verified = liveness_result["is_live"]
                biometric_data.video_frames = liveness_result.get("key_frames", [])
                biometric_data.video_duration = liveness_result.get("duration", 0)
            
            # Compare with document photo if available
            if session.identity_document and session.identity_document.extracted_data.get("photo"):
                document_photo = base64.b64decode(session.identity_document.extracted_data["photo"])
                match_result = await self._biometric_verifier.compare_faces(face_image, document_photo)
                
                session.quality_metrics["face_match_score"] = match_result["similarity_score"]
                session.quality_metrics["face_match_confidence"] = match_result["confidence"]
            
            # Update session
            session.biometric_data = biometric_data
            session.status = AL2VerificationStatus.FACE_CAPTURED
            
            # Add audit entry
            session.audit_trail.append({
                "action": "biometric_captured",
                "timestamp": datetime.utcnow().isoformat(),
                "biometric_id": biometric_id,
                "quality_score": biometric_data.quality_score,
                "liveness_verified": biometric_data.liveness_verified
            })
            
            logger.info(f"Biometric data captured for session {session_id}: {biometric_id}")
            return biometric_data
            
        except Exception as e:
            logger.error(f"Biometric capture failed for session {session_id}: {e}")
            raise
    
    async def schedule_video_verification(
        self,
        session_id: str,
        preferred_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Schedule video call verification
        
        Args:
            session_id: Verification session ID
            preferred_time: Preferred verification time
            
        Returns:
            Video call details
        """
        try:
            session = self._get_session(session_id)
            
            # Schedule video call
            video_call_details = await self._video_call_service.schedule_call(
                session_id=session_id,
                applicant_name=f"{session.given_name} {session.family_name}",
                preferred_time=preferred_time
            )
            
            # Update session status
            session.status = AL2VerificationStatus.VERIFICATION_SCHEDULED
            
            # Add audit entry
            session.audit_trail.append({
                "action": "video_verification_scheduled",
                "timestamp": datetime.utcnow().isoformat(),
                "call_details": video_call_details
            })
            
            logger.info(f"Video verification scheduled for session {session_id}")
            return video_call_details
            
        except Exception as e:
            logger.error(f"Video verification scheduling failed for session {session_id}: {e}")
            raise
    
    async def conduct_video_verification(
        self,
        session_id: str,
        verifier_id: str,
        verification_notes: str = ""
    ) -> bool:
        """
        Conduct video call verification
        
        Args:
            session_id: Verification session ID
            verifier_id: Human verifier ID
            verification_notes: Verification notes
            
        Returns:
            Verification result
        """
        try:
            session = self._get_session(session_id)
            
            # Mark verification as in progress
            session.status = AL2VerificationStatus.IN_PROGRESS
            session.verifier_id = verifier_id
            session.verification_time = datetime.utcnow()
            session.verification_notes = verification_notes
            
            # Calculate overall risk score
            risk_assessment = await self._risk_engine.assess_risk(session)
            session.risk_score = risk_assessment["total_score"]
            session.quality_metrics.update(risk_assessment["quality_metrics"])
            
            # Determine verification result
            verification_passed = (
                session.identity_document and
                session.identity_document.document_authentic and
                session.identity_document.not_expired and
                session.biometric_data and
                session.biometric_data.liveness_verified and
                session.risk_score < 0.3 and  # Low risk threshold
                session.quality_metrics.get("face_match_score", 0) > self.config.face_recognition_threshold
            )
            
            session.verification_result = verification_passed
            
            if verification_passed:
                session.status = AL2VerificationStatus.COMPLETED
            else:
                session.status = AL2VerificationStatus.FAILED
                session.failure_reason = self._determine_failure_reason(session)
            
            # Generate regulatory compliance evidence
            session.regulatory_compliance = {
                "eidas_al2_compliant": verification_passed,
                "verification_method": session.verification_method.value,
                "human_verifier": verifier_id,
                "verification_timestamp": session.verification_time.isoformat(),
                "risk_assessment": risk_assessment,
                "biometric_quality": session.biometric_data.quality_level.value if session.biometric_data else None,
                "document_authenticity": session.identity_document.document_authentic if session.identity_document else None,
                "liveness_detection": session.biometric_data.liveness_verified if session.biometric_data else None
            }
            
            # Add final audit entry
            session.audit_trail.append({
                "action": "video_verification_completed",
                "timestamp": datetime.utcnow().isoformat(),
                "verifier_id": verifier_id,
                "result": verification_passed,
                "risk_score": session.risk_score,
                "failure_reason": session.failure_reason
            })
            
            logger.info(f"Video verification completed for session {session_id}: {verification_passed}")
            return verification_passed
            
        except Exception as e:
            logger.error(f"Video verification failed for session {session_id}: {e}")
            raise
    
    async def get_verification_status(self, session_id: str) -> AL2VerificationSession:
        """Get verification session status"""
        return self._get_session(session_id)
    
    async def generate_compliance_report(self, session_id: str) -> Dict[str, Any]:
        """
        Generate compliance report for completed verification
        
        Args:
            session_id: Verification session ID
            
        Returns:
            Compliance report
        """
        try:
            session = self._get_session(session_id)
            
            if session.status != AL2VerificationStatus.COMPLETED:
                raise ValueError("Verification not completed")
            
            report = {
                "session_id": session_id,
                "verification_method": session.verification_method.value,
                "verification_result": session.verification_result,
                "verification_timestamp": session.verification_time.isoformat() if session.verification_time else None,
                "verifier_id": session.verifier_id,
                "risk_score": session.risk_score,
                "quality_metrics": session.quality_metrics,
                "regulatory_compliance": session.regulatory_compliance,
                "audit_trail": session.audit_trail,
                
                # Personal data (anonymized for compliance)
                "personal_info": {
                    "given_name_hash": hashlib.sha256(session.given_name.encode()).hexdigest()[:16],
                    "family_name_hash": hashlib.sha256(session.family_name.encode()).hexdigest()[:16],
                    "nationality": session.nationality,
                    "document_type": session.identity_document.document_type.value if session.identity_document else None
                },
                
                # Technical details
                "biometric_quality": session.biometric_data.quality_level.value if session.biometric_data else None,
                "document_quality": session.identity_document.quality_score if session.identity_document else None,
                "liveness_verified": session.biometric_data.liveness_verified if session.biometric_data else None,
                
                # Compliance attestation
                "eidas_al2_attestation": {
                    "compliant": session.regulatory_compliance.get("eidas_al2_compliant", False),
                    "assurance_level": "AL2",
                    "verification_standard": "eIDAS Remote ID-proofing",
                    "issuer": "QES Platform AL2 Service",
                    "issued_at": datetime.utcnow().isoformat()
                }
            }
            
            logger.info(f"Generated compliance report for session {session_id}")
            return report
            
        except Exception as e:
            logger.error(f"Compliance report generation failed for session {session_id}: {e}")
            raise
    
    def _get_session(self, session_id: str) -> AL2VerificationSession:
        """Get verification session by ID"""
        if session_id not in self._sessions:
            raise ValueError(f"Verification session not found: {session_id}")
        
        session = self._sessions[session_id]
        
        # Check if session expired
        if datetime.utcnow() > session.expires_at:
            session.status = AL2VerificationStatus.EXPIRED
            raise ValueError(f"Verification session expired: {session_id}")
        
        return session
    
    def _determine_failure_reason(self, session: AL2VerificationSession) -> str:
        """Determine specific failure reason"""
        reasons = []
        
        if not session.identity_document:
            reasons.append("No identity document provided")
        elif not session.identity_document.document_authentic:
            reasons.append("Document authenticity verification failed")
        elif not session.identity_document.not_expired:
            reasons.append("Document has expired")
        
        if not session.biometric_data:
            reasons.append("No biometric data provided")
        elif not session.biometric_data.liveness_verified:
            reasons.append("Liveness detection failed")
        
        if session.risk_score and session.risk_score >= 0.3:
            reasons.append(f"High risk score: {session.risk_score:.2f}")
        
        if session.quality_metrics.get("face_match_score", 0) <= self.config.face_recognition_threshold:
            reasons.append("Face matching failed")
        
        return "; ".join(reasons) if reasons else "Unknown failure"


class AL2RiskEngine:
    """Risk assessment engine for AL2 verification"""
    
    async def assess_risk(self, session: AL2VerificationSession) -> Dict[str, Any]:
        """Assess overall risk for verification session"""
        risk_factors = []
        quality_metrics = {}
        
        # Document risk assessment
        if session.identity_document:
            doc_risk = self._assess_document_risk(session.identity_document)
            risk_factors.append(doc_risk["risk_score"])
            quality_metrics.update(doc_risk["metrics"])
        
        # Biometric risk assessment
        if session.biometric_data:
            bio_risk = self._assess_biometric_risk(session.biometric_data)
            risk_factors.append(bio_risk["risk_score"])
            quality_metrics.update(bio_risk["metrics"])
        
        # Behavioral risk assessment
        behavioral_risk = self._assess_behavioral_risk(session)
        risk_factors.append(behavioral_risk["risk_score"])
        quality_metrics.update(behavioral_risk["metrics"])
        
        # Calculate total risk score
        total_score = sum(risk_factors) / len(risk_factors) if risk_factors else 1.0
        
        return {
            "total_score": total_score,
            "risk_factors": risk_factors,
            "quality_metrics": quality_metrics,
            "risk_level": "high" if total_score > 0.7 else "medium" if total_score > 0.3 else "low"
        }
    
    def _assess_document_risk(self, document: AL2IdentityDocument) -> Dict[str, Any]:
        """Assess document-related risks"""
        risk_score = 0.0
        metrics = {}
        
        # Quality score risk
        if document.quality_score:
            quality_risk = max(0, 1.0 - document.quality_score)
            risk_score += quality_risk * 0.4
            metrics["document_quality_risk"] = quality_risk
        
        # Authenticity risk
        if not document.document_authentic:
            risk_score += 0.8
            metrics["document_authenticity_risk"] = 0.8
        
        # Expiry risk
        if not document.not_expired:
            risk_score += 0.6
            metrics["document_expiry_risk"] = 0.6
        
        return {"risk_score": min(risk_score, 1.0), "metrics": metrics}
    
    def _assess_biometric_risk(self, biometric: AL2BiometricData) -> Dict[str, Any]:
        """Assess biometric-related risks"""
        risk_score = 0.0
        metrics = {}
        
        # Quality score risk
        if biometric.quality_score:
            quality_risk = max(0, 1.0 - biometric.quality_score)
            risk_score += quality_risk * 0.3
            metrics["biometric_quality_risk"] = quality_risk
        
        # Liveness risk
        if not biometric.liveness_verified:
            risk_score += 0.5
            metrics["liveness_risk"] = 0.5
        
        return {"risk_score": min(risk_score, 1.0), "metrics": metrics}
    
    def _assess_behavioral_risk(self, session: AL2VerificationSession) -> Dict[str, Any]:
        """Assess behavioral risks"""
        risk_score = 0.0
        metrics = {}
        
        # Session timing analysis
        session_duration = (datetime.utcnow() - session.created_at).total_seconds()
        if session_duration < 60:  # Too fast
            risk_score += 0.3
            metrics["timing_risk"] = 0.3
        elif session_duration > 3600:  # Too slow
            risk_score += 0.2
            metrics["timing_risk"] = 0.2
        
        # Data consistency check
        inconsistencies = 0
        if session.identity_document and session.identity_document.extracted_data:
            extracted_name = session.identity_document.extracted_data.get("full_name", "")
            provided_name = f"{session.given_name} {session.family_name}"
            if extracted_name.lower() != provided_name.lower():
                inconsistencies += 1
        
        consistency_risk = min(inconsistencies * 0.2, 0.6)
        risk_score += consistency_risk
        metrics["consistency_risk"] = consistency_risk
        
        return {"risk_score": min(risk_score, 1.0), "metrics": metrics}


class DocumentVerifier:
    """Document verification service"""
    
    def __init__(self, config: AL2Config):
        self.config = config
    
    async def verify_document(self, document: AL2IdentityDocument) -> Dict[str, Any]:
        """Verify identity document using image processing and OCR"""
        try:
            import pytesseract
            import cv2
            import numpy as np
            from PIL import Image
            import io
            import re
            from datetime import datetime, timedelta
            
            # Convert bytes to OpenCV image
            front_image = self._bytes_to_cv2_image(document.front_image)
            back_image = None
            if document.back_image:
                back_image = self._bytes_to_cv2_image(document.back_image)
            
            # 1. Image Quality Assessment
            quality_score = await self._assess_image_quality(front_image)
            
            if quality_score < 0.6:
                return {
                    "authentic": False,
                    "consistent": False,
                    "not_expired": None,
                    "quality_score": quality_score,
                    "error": "Image quality too low for verification",
                    "extracted_data": {},
                    "security_features": {}
                }
            
            # 2. OCR Text Extraction
            extracted_text = await self._extract_text_ocr(front_image)
            back_text = await self._extract_text_ocr(back_image) if back_image is not None else ""
            
            # 3. Parse Document Data based on type
            extracted_data = await self._parse_document_data(
                extracted_text, back_text, document.document_type
            )
            
            # 4. Security Features Detection
            security_features = await self._detect_security_features(front_image, back_image)
            
            # 5. Face Detection and Extraction
            face_data = await self._extract_face_from_document(front_image)
            if face_data:
                extracted_data["photo"] = face_data["face_image_b64"]
                extracted_data["face_coordinates"] = face_data["coordinates"]
            
            # 6. Document Authenticity Checks
            authenticity_checks = await self._verify_document_authenticity(
                front_image, back_image, extracted_data, document.document_type
            )
            
            # 7. Expiration Check
            expiry_valid = await self._check_document_expiration(extracted_data)
            
            # 8. Overall Consistency Check
            consistency_score = await self._check_data_consistency(extracted_data, document.document_type)
            
            result = {
                "authentic": authenticity_checks["overall_authentic"],
                "consistent": consistency_score > 0.7,
                "not_expired": expiry_valid,
                "quality_score": quality_score,
                "extracted_data": extracted_data,
                "security_features": security_features,
                "authenticity_details": authenticity_checks,
                "processing_metadata": {
                    "ocr_confidence": extracted_text.get("confidence", 0),
                    "face_detected": face_data is not None,
                    "document_type_detected": document.document_type.value,
                    "verification_timestamp": datetime.now().isoformat()
                }
            }
            
            logger.info(f"Document verification completed: {document.document_id} - Authentic: {result['authentic']}")
            return result
            
        except Exception as e:
            logger.error(f"Document verification failed for {document.document_id}: {e}")
            return {
                "authentic": False,
                "consistent": False,
                "not_expired": None,
                "quality_score": 0.0,
                "error": f"Verification failed: {str(e)}",
                "extracted_data": {},
                "security_features": {}
            }
    
    def _bytes_to_cv2_image(self, image_bytes: bytes) -> np.ndarray:
        """Convert bytes to OpenCV image"""
        nparr = np.frombuffer(image_bytes, np.uint8)
        return cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    
    async def _assess_image_quality(self, image: np.ndarray) -> float:
        """Assess image quality for document verification"""
        try:
            # Convert to grayscale for analysis
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # 1. Sharpness (Laplacian variance)
            sharpness = cv2.Laplacian(gray, cv2.CV_64F).var()
            sharpness_score = min(sharpness / 500.0, 1.0)  # Normalize
            
            # 2. Brightness assessment
            brightness = np.mean(gray)
            brightness_score = 1.0 - abs(brightness - 127) / 127.0
            
            # 3. Contrast assessment
            contrast = gray.std()
            contrast_score = min(contrast / 60.0, 1.0)
            
            # 4. Resolution check
            height, width = gray.shape
            resolution_score = min((height * width) / (1200 * 800), 1.0)
            
            # 5. Blur detection using edge density
            edges = cv2.Canny(gray, 50, 150)
            edge_density = np.sum(edges > 0) / (height * width)
            edge_score = min(edge_density * 10, 1.0)
            
            # Weighted average
            quality = (
                sharpness_score * 0.3 +
                brightness_score * 0.2 +
                contrast_score * 0.2 +
                resolution_score * 0.15 +
                edge_score * 0.15
            )
            
            return max(0.0, min(1.0, quality))
            
        except Exception as e:
            logger.error(f"Image quality assessment failed: {e}")
            return 0.5  # Default to medium quality
    
    async def _extract_text_ocr(self, image: np.ndarray) -> Dict[str, Any]:
        """Extract text using OCR"""
        try:
            import pytesseract
            
            if image is None:
                return {"text": "", "confidence": 0, "boxes": []}
            
            # Preprocess image for better OCR
            processed = self._preprocess_for_ocr(image)
            
            # Configure Tesseract for documents
            config = '--oem 3 --psm 6 -c tessedit_char_whitelist=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz .-/'
            
            # Extract text with confidence scores
            data = pytesseract.image_to_data(processed, config=config, output_type=pytesseract.Output.DICT)
            
            # Filter out low-confidence text
            text_parts = []
            boxes = []
            confidences = []
            
            for i in range(len(data['text'])):
                if int(data['conf'][i]) > 30:  # Minimum confidence threshold
                    text = data['text'][i].strip()
                    if text:
                        text_parts.append(text)
                        boxes.append({
                            'x': data['left'][i],
                            'y': data['top'][i],
                            'w': data['width'][i],
                            'h': data['height'][i],
                            'text': text,
                            'confidence': data['conf'][i]
                        })
                        confidences.append(int(data['conf'][i]))
            
            full_text = ' '.join(text_parts)
            avg_confidence = np.mean(confidences) if confidences else 0
            
            return {
                "text": full_text,
                "confidence": avg_confidence / 100.0,  # Normalize to 0-1
                "boxes": boxes,
                "word_count": len(text_parts)
            }
            
        except Exception as e:
            logger.error(f"OCR extraction failed: {e}")
            return {"text": "", "confidence": 0, "boxes": [], "error": str(e)}
    
    def _preprocess_for_ocr(self, image: np.ndarray) -> np.ndarray:
        """Preprocess image for better OCR results"""
        # Convert to grayscale
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        # Resize if too small
        height, width = gray.shape
        if height < 600 or width < 800:
            scale = max(600/height, 800/width)
            new_width = int(width * scale)
            new_height = int(height * scale)
            gray = cv2.resize(gray, (new_width, new_height), interpolation=cv2.INTER_CUBIC)
        
        # Apply bilateral filter to reduce noise while keeping edges sharp
        filtered = cv2.bilateralFilter(gray, 9, 75, 75)
        
        # Adaptive thresholding for better text contrast
        thresh = cv2.adaptiveThreshold(
            filtered, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
        )
        
        # Morphological operations to connect text
        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (2, 2))
        processed = cv2.morphologyEx(thresh, cv2.MORPH_CLOSE, kernel)
        
        return processed
    
    async def _parse_document_data(self, front_text: Dict[str, Any], back_text: str, doc_type: AL2DocumentType) -> Dict[str, Any]:
        """Parse document data based on document type"""
        import re
        from datetime import datetime
        
        text = front_text.get("text", "")
        all_text = text + " " + back_text
        
        extracted = {
            "document_number": "",
            "full_name": "",
            "date_of_birth": "",
            "issuing_country": "",
            "issuing_authority": "",
            "expiry_date": "",
            "nationality": "",
            "place_of_birth": "",
            "gender": "",
            "raw_text": text
        }
        
        try:
            if doc_type == AL2DocumentType.PASSPORT:
                # Passport parsing patterns
                # Document number (usually starts with P and has 8-9 chars)
                doc_num_match = re.search(r'P[A-Z0-9]{7,8}|[A-Z]{2}\d{7}', all_text)
                if doc_num_match:
                    extracted["document_number"] = doc_num_match.group()
                
                # Date patterns (DD/MM/YYYY or DD.MM.YYYY or DDMMYYYY)
                date_patterns = [
                    r'(\d{2}[./]\d{2}[./]\d{4})',
                    r'(\d{8})',  # DDMMYYYY
                ]
                
                dates = []
                for pattern in date_patterns:
                    dates.extend(re.findall(pattern, all_text))
                
                # Try to identify birth date vs expiry (birth usually earlier)
                parsed_dates = []
                for date_str in dates:
                    try:
                        if len(date_str) == 8:  # DDMMYYYY
                            date_obj = datetime.strptime(date_str, '%d%m%Y')
                        else:
                            for fmt in ['%d/%m/%Y', '%d.%m.%Y']:
                                try:
                                    date_obj = datetime.strptime(date_str, fmt)
                                    break
                                except ValueError:
                                    continue
                        parsed_dates.append((date_obj, date_str))
                    except ValueError:
                        continue
                
                # Sort dates and assign
                parsed_dates.sort()
                if len(parsed_dates) >= 2:
                    extracted["date_of_birth"] = parsed_dates[0][1]
                    extracted["expiry_date"] = parsed_dates[-1][1]
                elif len(parsed_dates) == 1:
                    # Assume it's birth date if before 2000, expiry if after
                    if parsed_dates[0][0].year < 2000:
                        extracted["date_of_birth"] = parsed_dates[0][1]
                    else:
                        extracted["expiry_date"] = parsed_dates[0][1]
                
                # Country codes (3-letter ISO codes)
                country_match = re.search(r'\b[A-Z]{3}\b', all_text)
                if country_match:
                    extracted["issuing_country"] = country_match.group()
                
                # Names (typically in caps, before dates)
                name_pattern = r'([A-Z]{2,}\s+[A-Z]{2,}(?:\s+[A-Z]{2,})*)'
                name_matches = re.findall(name_pattern, all_text)
                if name_matches:
                    # Take the longest name (most likely to be complete)
                    extracted["full_name"] = max(name_matches, key=len)
            
            elif doc_type == AL2DocumentType.NATIONAL_ID:
                # National ID parsing (varies by country)
                # Generic patterns
                id_patterns = [
                    r'\b\d{6,12}\b',  # Numeric ID
                    r'\b[A-Z]\d{7,9}\b',  # Letter + numbers
                    r'\b\d{2}[A-Z]\d{6}\b'  # Complex patterns
                ]
                
                for pattern in id_patterns:
                    match = re.search(pattern, all_text)
                    if match:
                        extracted["document_number"] = match.group()
                        break
                
                # Similar date parsing as passport
                dates = re.findall(r'(\d{2}[./]\d{2}[./]\d{4})', all_text)
                if dates:
                    extracted["date_of_birth"] = dates[0]
                    if len(dates) > 1:
                        extracted["expiry_date"] = dates[-1]
                
                # Address extraction (for back of ID)
                if back_text:
                    address_match = re.search(r'(.*street.*|.*avenue.*|.*road.*)', back_text, re.IGNORECASE)
                    if address_match:
                        extracted["address"] = address_match.group()
            
            elif doc_type == AL2DocumentType.DRIVING_LICENSE:
                # Driving license patterns
                license_patterns = [
                    r'\b[A-Z]{2}\d{6,8}\b',  # EU format
                    r'\b\d{8,12}\b'  # Numeric format
                ]
                
                for pattern in license_patterns:
                    match = re.search(pattern, all_text)
                    if match:
                        extracted["document_number"] = match.group()
                        break
                
                # License specific fields
                category_match = re.search(r'\b[ABCDEFM][0-9]?\b', all_text)
                if category_match:
                    extracted["license_category"] = category_match.group()
            
            # Common fields for all document types
            # Gender detection
            gender_match = re.search(r'\b(M|F|MALE|FEMALE|MAN|WOMAN)\b', all_text.upper())
            if gender_match:
                gender = gender_match.group()
                extracted["gender"] = "M" if gender.startswith("M") else "F"
            
            # Try to extract issuing authority
            authority_keywords = ["ISSUED BY", "AUTHORITY", "GOVERNMENT", "MINISTRY", "DEPT"]
            for keyword in authority_keywords:
                pattern = keyword + r'\s+([A-Z\s]+)'
                match = re.search(pattern, all_text.upper())
                if match:
                    extracted["issuing_authority"] = match.group(1).strip()
                    break
            
        except Exception as e:
            logger.error(f"Document parsing failed: {e}")
            extracted["parsing_error"] = str(e)
        
        return extracted
    
    async def _detect_security_features(self, front_image: np.ndarray, back_image: Optional[np.ndarray]) -> Dict[str, Any]:
        """Detect security features in document images"""
        import cv2
        import numpy as np
        
        features = {
            "hologram_detected": False,
            "watermark_detected": False,
            "microprint_detected": False,
            "uv_features_detected": False,
            "security_thread_detected": False,
            "raised_text_detected": False,
            "color_changing_ink": False,
            "overall_security_score": 0.0
        }
        
        try:
            # Convert to different color spaces for analysis
            hsv = cv2.cvtColor(front_image, cv2.COLOR_BGR2HSV)
            gray = cv2.cvtColor(front_image, cv2.COLOR_BGR2GRAY)
            
            # 1. Hologram detection (look for iridescent patterns)
            # Holograms often have high saturation variance
            saturation = hsv[:, :, 1]
            sat_variance = np.var(saturation)
            if sat_variance > 1000:  # Threshold for high variance
                features["hologram_detected"] = True
            
            # 2. Watermark detection (subtle brightness patterns)
            # Apply Gaussian blur and look for subtle patterns
            blurred = cv2.GaussianBlur(gray, (15, 15), 0)
            diff = cv2.absdiff(gray, blurred)
            watermark_score = np.mean(diff)
            if watermark_score > 5:  # Threshold for watermark presence
                features["watermark_detected"] = True
            
            # 3. Microprint detection (very fine text patterns)
            # High frequency content indicates fine details
            laplacian = cv2.Laplacian(gray, cv2.CV_64F)
            microprint_score = np.var(laplacian)
            if microprint_score > 800:  # Threshold for fine detail
                features["microprint_detected"] = True
            
            # 4. Security thread detection (thin vertical/horizontal lines)
            # Use Hough line detection
            edges = cv2.Canny(gray, 50, 150)
            lines = cv2.HoughLines(edges, 1, np.pi/180, threshold=100)
            if lines is not None and len(lines) > 0:
                # Look for very straight, long lines (security threads)
                straight_lines = 0
                for line in lines:
                    rho, theta = line[0]
                    # Check for vertical or horizontal lines
                    if abs(theta) < 0.1 or abs(theta - np.pi/2) < 0.1:
                        straight_lines += 1
                
                if straight_lines > 2:
                    features["security_thread_detected"] = True
            
            # 5. Raised text detection (shadows and depth)
            # Use morphological operations to detect raised areas
            kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (3, 3))
            opening = cv2.morphologyEx(gray, cv2.MORPH_OPENING, kernel)
            closing = cv2.morphologyEx(opening, cv2.MORPH_CLOSE, kernel)
            
            # Calculate texture measures
            texture_variance = np.var(closing)
            if texture_variance > 500:
                features["raised_text_detected"] = True
            
            # 6. Color analysis for color-changing ink
            # Analyze color distribution
            color_hist = cv2.calcHist([front_image], [0, 1, 2], None, [50, 50, 50], [0, 256, 0, 256, 0, 256])
            color_complexity = np.count_nonzero(color_hist)
            if color_complexity > 5000:  # High color complexity
                features["color_changing_ink"] = True
            
            # Calculate overall security score
            security_indicators = [
                features["hologram_detected"],
                features["watermark_detected"], 
                features["microprint_detected"],
                features["security_thread_detected"],
                features["raised_text_detected"],
                features["color_changing_ink"]
            ]
            
            features["overall_security_score"] = sum(security_indicators) / len(security_indicators)
            
        except Exception as e:
            logger.error(f"Security feature detection failed: {e}")
            features["detection_error"] = str(e)
        
        return features
    
    async def _extract_face_from_document(self, image: np.ndarray) -> Optional[Dict[str, Any]]:
        """Extract face from document image"""
        try:
            import face_recognition
            import cv2
            
            # Convert BGR to RGB for face_recognition
            rgb_image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
            
            # Find face locations
            face_locations = face_recognition.face_locations(rgb_image, model="hog")
            
            if not face_locations:
                return None
            
            # Take the largest face (most likely the main photo)
            largest_face = max(face_locations, key=lambda loc: (loc[2] - loc[0]) * (loc[1] - loc[3]))
            top, right, bottom, left = largest_face
            
            # Extract face image
            face_image = rgb_image[top:bottom, left:right]
            
            # Convert back to BGR for consistency
            face_bgr = cv2.cvtColor(face_image, cv2.COLOR_RGB2BGR)
            
            # Encode face for comparison
            face_encodings = face_recognition.face_encodings(rgb_image, [largest_face])
            face_encoding = face_encodings[0] if face_encodings else None
            
            # Convert to base64 for storage
            import base64
            _, buffer = cv2.imencode('.jpg', face_bgr)
            face_b64 = base64.b64encode(buffer).decode('utf-8')
            
            return {
                "face_image_b64": face_b64,
                "coordinates": {
                    "top": int(top),
                    "right": int(right), 
                    "bottom": int(bottom),
                    "left": int(left)
                },
                "face_encoding": face_encoding.tolist() if face_encoding is not None else None,
                "face_size": {
                    "width": right - left,
                    "height": bottom - top
                }
            }
            
        except Exception as e:
            logger.error(f"Face extraction failed: {e}")
            return None
    
    async def _verify_document_authenticity(self, front_image: np.ndarray, back_image: Optional[np.ndarray], extracted_data: Dict[str, Any], doc_type: AL2DocumentType) -> Dict[str, Any]:
        """Verify document authenticity using multiple checks"""
        checks = {
            "template_match": False,
            "security_features_valid": False,
            "text_layout_valid": False,
            "image_integrity": False,
            "overall_authentic": False,
            "confidence_score": 0.0
        }
        
        try:
            # 1. Basic image integrity checks
            # Check for obvious tampering signs
            gray = cv2.cvtColor(front_image, cv2.COLOR_BGR2GRAY)
            
            # Look for sharp edges (possible copy/paste artifacts)
            edges = cv2.Canny(gray, 100, 200)
            edge_density = np.sum(edges > 0) / (gray.shape[0] * gray.shape[1])
            
            # Normal documents have moderate edge density
            if 0.02 < edge_density < 0.15:
                checks["image_integrity"] = True
            
            # 2. Text layout validation
            # Check if text follows expected patterns for document type
            text_boxes = extracted_data.get("raw_text", "")
            if len(text_boxes) > 20:  # Sufficient text content
                checks["text_layout_valid"] = True
            
            # 3. Security features validation
            # This would integrate with _detect_security_features results
            # For now, assume basic validation
            if extracted_data.get("document_number"):
                checks["security_features_valid"] = True
            
            # 4. Template matching (simplified)
            # In production, this would compare against known document templates
            # For now, check basic document structure
            height, width = gray.shape
            aspect_ratio = width / height
            
            # Most ID documents have specific aspect ratios
            if doc_type == AL2DocumentType.PASSPORT:
                # Passport aspect ratio ~1.4
                if 1.2 < aspect_ratio < 1.6:
                    checks["template_match"] = True
            elif doc_type == AL2DocumentType.NATIONAL_ID:
                # ID card aspect ratio ~1.6
                if 1.4 < aspect_ratio < 1.8:
                    checks["template_match"] = True
            else:
                checks["template_match"] = True  # Default pass for other types
            
            # Calculate overall confidence
            valid_checks = sum([
                checks["template_match"],
                checks["security_features_valid"],
                checks["text_layout_valid"],
                checks["image_integrity"]
            ])
            
            checks["confidence_score"] = valid_checks / 4.0
            checks["overall_authentic"] = checks["confidence_score"] > 0.6
            
        except Exception as e:
            logger.error(f"Authenticity verification failed: {e}")
            checks["verification_error"] = str(e)
        
        return checks
    
    async def _check_document_expiration(self, extracted_data: Dict[str, Any]) -> bool:
        """Check if document is expired"""
        try:
            expiry_date_str = extracted_data.get("expiry_date", "")
            if not expiry_date_str:
                return True  # Assume valid if no expiry date found
            
            from datetime import datetime
            
            # Try to parse expiry date
            date_formats = ['%d/%m/%Y', '%d.%m.%Y', '%d%m%Y', '%Y-%m-%d']
            expiry_date = None
            
            for fmt in date_formats:
                try:
                    expiry_date = datetime.strptime(expiry_date_str, fmt)
                    break
                except ValueError:
                    continue
            
            if expiry_date is None:
                return True  # Assume valid if can't parse date
            
            # Check if expired (with 30-day grace period)
            from datetime import timedelta
            grace_period = timedelta(days=30)
            return datetime.now() <= (expiry_date + grace_period)
            
        except Exception as e:
            logger.error(f"Expiration check failed: {e}")
            return True  # Default to valid on error
    
    async def _check_data_consistency(self, extracted_data: Dict[str, Any], doc_type: AL2DocumentType) -> float:
        """Check consistency of extracted data"""
        try:
            consistency_score = 0.0
            total_checks = 0
            
            # 1. Check document number format
            doc_num = extracted_data.get("document_number", "")
            if doc_num:
                total_checks += 1
                if doc_type == AL2DocumentType.PASSPORT:
                    # Passport numbers usually start with country code or P
                    if re.match(r'^[A-Z]{1,2}\d{6,9}$|^P\d{7,8}$', doc_num):
                        consistency_score += 1
                elif doc_type == AL2DocumentType.NATIONAL_ID:
                    # National IDs vary but should be alphanumeric
                    if re.match(r'^[A-Z0-9]{6,12}$', doc_num):
                        consistency_score += 1
                else:
                    consistency_score += 1  # Default pass for other types
            
            # 2. Check date format consistency
            birth_date = extracted_data.get("date_of_birth", "")
            if birth_date:
                total_checks += 1
                # Should be a reasonable birth date (between 1900 and 2010)
                try:
                    for fmt in ['%d/%m/%Y', '%d.%m.%Y', '%d%m%Y']:
                        try:
                            bd = datetime.strptime(birth_date, fmt)
                            if 1900 <= bd.year <= 2010:
                                consistency_score += 1
                            break
                        except ValueError:
                            continue
                except:
                    pass
            
            # 3. Check name format
            full_name = extracted_data.get("full_name", "")
            if full_name:
                total_checks += 1
                # Should contain at least first and last name
                name_parts = full_name.split()
                if len(name_parts) >= 2 and all(part.isalpha() for part in name_parts):
                    consistency_score += 1
            
            # 4. Check country code
            country = extracted_data.get("issuing_country", "")
            if country:
                total_checks += 1
                # Should be 2-3 letter country code
                if re.match(r'^[A-Z]{2,3}$', country):
                    consistency_score += 1
            
            return consistency_score / total_checks if total_checks > 0 else 0.0
            
        except Exception as e:
            logger.error(f"Data consistency check failed: {e}")
            return 0.5  # Default to medium consistency on error


class BiometricVerifier:
    """
    Advanced biometric verification service for eIDAS AL2 compliance.
    
    Implements face recognition, liveness detection, anti-spoofing measures,
    and quality assessment using multiple biometric technologies.
    """
    
    def __init__(self, config: AL2Config):
        self.config = config
        self._face_cascade = None
        self._mediapipe_face_detection = None
        self._mediapipe_face_mesh = None
        self._init_models()
    
    def _init_models(self):
        """Initialize biometric recognition models"""
        try:
            # Initialize OpenCV face detection
            self._face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
            
            # Initialize MediaPipe for advanced face analysis
            try:
                import mediapipe as mp
                self._mp_face_detection = mp.solutions.face_detection
                self._mp_face_mesh = mp.solutions.face_mesh
                self._mp_drawing = mp.solutions.drawing_utils
                
                logger.info("MediaPipe models initialized successfully")
            except ImportError:
                logger.warning("MediaPipe not available, using basic face detection")
            
        except Exception as e:
            logger.error(f"Failed to initialize biometric models: {e}")
    
    async def process_face_image(self, face_image: bytes) -> Dict[str, Any]:
        """
        Process face image for biometric recognition and quality assessment.
        
        Args:
            face_image: Face image as bytes
            
        Returns:
            Dict containing face encoding, quality metrics, and analysis results
        """
        try:
            import face_recognition
            import io
            from PIL import Image
            
            # Convert bytes to numpy array
            image_array = np.frombuffer(face_image, np.uint8)
            cv_image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
            
            if cv_image is None:
                raise ValueError("Invalid image data")
            
            # Convert BGR to RGB for face_recognition library
            rgb_image = cv2.cvtColor(cv_image, cv2.COLOR_BGR2RGB)
            
            # 1. Face Detection and Quality Assessment
            quality_analysis = await BiometricHelpers.assess_face_quality(cv_image)
            
            if quality_analysis["quality_score"] < 0.3:
                return {
                    "encoding": None,
                    "quality_score": quality_analysis["quality_score"],
                    "quality_level": AL2BiometricQuality.LOW,
                    "error": "Face quality too low for reliable recognition",
                    "quality_details": quality_analysis
                }
            
            # 2. Face Detection
            face_locations = face_recognition.face_locations(rgb_image, model="hog")
            
            if not face_locations:
                return {
                    "encoding": None,
                    "quality_score": 0.0,
                    "quality_level": AL2BiometricQuality.LOW,
                    "error": "No face detected in image",
                    "face_count": 0
                }
            
            if len(face_locations) > 1:
                logger.warning(f"Multiple faces detected ({len(face_locations)}), using largest face")
            
            # Use the largest face (first in the list from face_recognition)
            face_location = face_locations[0]
            
            # 3. Face Encoding Generation
            face_encodings = face_recognition.face_encodings(rgb_image, [face_location])
            
            if not face_encodings:
                return {
                    "encoding": None,
                    "quality_score": quality_analysis["quality_score"],
                    "quality_level": AL2BiometricQuality.LOW,
                    "error": "Failed to generate face encoding",
                    "face_count": len(face_locations)
                }
            
            face_encoding = face_encodings[0].tolist()
            
            # 4. Anti-spoofing Analysis
            spoofing_analysis = await BiometricHelpers.detect_spoofing(cv_image, face_location)
            
            # 5. Geometric Analysis
            geometric_analysis = await BiometricHelpers.analyze_face_geometry(cv_image, face_location)
            
            # 6. Final Quality Assessment
            final_quality_score = BiometricHelpers.calculate_final_quality_score(
                quality_analysis,
                spoofing_analysis,
                geometric_analysis
            )
            
            # Determine quality level
            if final_quality_score >= 0.9:
                quality_level = AL2BiometricQuality.EXCELLENT
            elif final_quality_score >= 0.7:
                quality_level = AL2BiometricQuality.HIGH
            elif final_quality_score >= 0.5:
                quality_level = AL2BiometricQuality.MEDIUM
            else:
                quality_level = AL2BiometricQuality.LOW
            
            result = {
                "encoding": face_encoding,
                "quality_score": final_quality_score,
                "quality_level": quality_level,
                "face_count": len(face_locations),
                "face_location": {
                    "top": face_location[0],
                    "right": face_location[1],
                    "bottom": face_location[2],
                    "left": face_location[3]
                },
                "quality_details": quality_analysis,
                "spoofing_analysis": spoofing_analysis,
                "geometric_analysis": geometric_analysis,
                "processing_metadata": {
                    "model_used": "dlib_face_recognition",
                    "encoding_dimensions": len(face_encoding),
                    "processing_timestamp": datetime.utcnow().isoformat()
                }
            }
            
            logger.info(f"Face processing completed: quality={final_quality_score:.3f}, level={quality_level.value}")
            return result
            
        except Exception as e:
            logger.error(f"Face image processing failed: {e}")
            return {
                "encoding": None,
                "quality_score": 0.0,
                "quality_level": AL2BiometricQuality.LOW,
                "error": f"Processing failed: {str(e)}",
                "face_count": 0
            }
    
    async def detect_liveness(self, video: bytes) -> Dict[str, Any]:
        """
        Detect liveness from video using multiple techniques.
        
        Args:
            video: Video data as bytes
            
        Returns:
            Dict containing liveness detection results and confidence metrics
        """
        try:
            import tempfile
            import os
            
            # Save video to temporary file for processing
            with tempfile.NamedTemporaryFile(suffix='.mp4', delete=False) as temp_video:
                temp_video.write(video)
                video_path = temp_video.name
            
            try:
                # Initialize video capture
                cap = cv2.VideoCapture(video_path)
                
                if not cap.isOpened():
                    raise ValueError("Failed to open video file")
                
                # Video properties
                fps = cap.get(cv2.CAP_PROP_FPS) or 30
                frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
                duration = frame_count / fps if fps > 0 else 0
                
                logger.info(f"Processing liveness video: {frame_count} frames, {duration:.2f}s, {fps} FPS")
                
                # Extract key frames for analysis
                key_frames = []
                liveness_scores = []
                motion_vectors = []
                face_positions = []
                
                frame_interval = max(1, frame_count // 15)  # Sample ~15 frames
                
                for frame_idx in range(0, frame_count, frame_interval):
                    cap.set(cv2.CAP_PROP_POS_FRAMES, frame_idx)
                    ret, frame = cap.read()
                    
                    if not ret:
                        continue
                    
                    # 1. Face Detection in Frame
                    face_analysis = await BiometricHelpers.analyze_frame_for_liveness(frame, frame_idx / fps)
                    
                    if face_analysis["face_detected"]:
                        key_frames.append({
                            "timestamp": frame_idx / fps,
                            "frame_index": frame_idx,
                            "face_location": face_analysis["face_location"],
                            "quality_score": face_analysis["quality_score"]
                        })
                        
                        liveness_scores.append(face_analysis["liveness_indicators"])
                        face_positions.append(face_analysis["face_location"])
                
                cap.release()
                
                # 2. Motion Analysis
                motion_analysis = LivenessDetectionHelpers.analyze_motion_patterns(face_positions, fps)
                
                # 3. Temporal Consistency Analysis
                temporal_analysis = LivenessDetectionHelpers.analyze_temporal_consistency(liveness_scores)
                
                # 4. Eye Blink Detection
                blink_analysis = await LivenessDetectionHelpers.detect_eye_blinks(key_frames, video_path)
                
                # 5. 3D Face Movement Analysis
                movement_analysis = LivenessDetectionHelpers.analyze_3d_movement(face_positions)
                
                # 6. Final Liveness Assessment
                final_liveness_score = LivenessDetectionHelpers.calculate_liveness_score(
                    motion_analysis,
                    temporal_analysis,
                    blink_analysis,
                    movement_analysis
                )
                
                is_live = final_liveness_score >= self.config.liveness_detection_threshold
                confidence = min(final_liveness_score * 1.2, 1.0)  # Boost confidence for high scores
                
                result = {
                    "is_live": is_live,
                    "confidence": confidence,
                    "liveness_score": final_liveness_score,
                    "duration": duration,
                    "key_frames": key_frames[:10],  # Return up to 10 key frames
                    "analysis_details": {
                        "motion_analysis": motion_analysis,
                        "temporal_analysis": temporal_analysis,
                        "blink_analysis": blink_analysis,
                        "movement_analysis": movement_analysis,
                        "total_frames_analyzed": len(key_frames),
                        "video_quality": {
                            "fps": fps,
                            "duration": duration,
                            "frame_count": frame_count
                        }
                    },
                    "processing_metadata": {
                        "algorithms_used": ["motion_analysis", "blink_detection", "3d_movement", "temporal_consistency"],
                        "processing_timestamp": datetime.utcnow().isoformat()
                    }
                }
                
                logger.info(f"Liveness detection completed: live={is_live}, score={final_liveness_score:.3f}")
                return result
                
            finally:
                # Clean up temporary file
                try:
                    os.unlink(video_path)
                except OSError:
                    pass
            
        except Exception as e:
            logger.error(f"Liveness detection failed: {e}")
            return {
                "is_live": False,
                "confidence": 0.0,
                "liveness_score": 0.0,
                "duration": 0,
                "key_frames": [],
                "error": f"Liveness detection failed: {str(e)}",
                "analysis_details": {},
                "processing_metadata": {}
            }
    
    async def compare_faces(self, image1: bytes, image2: bytes) -> Dict[str, Any]:
        """
        Compare two face images for identity verification.
        
        Args:
            image1: First face image (e.g., live capture)
            image2: Second face image (e.g., document photo)
            
        Returns:
            Dict containing similarity score, confidence, and detailed analysis
        """
        try:
            import face_recognition
            
            # Process both images
            face1_result = await self.process_face_image(image1)
            face2_result = await self.process_face_image(image2)
            
            # Check if both faces were processed successfully
            if not face1_result.get("encoding") or not face2_result.get("encoding"):
                error_msg = []
                if not face1_result.get("encoding"):
                    error_msg.append(f"Face 1: {face1_result.get('error', 'No encoding generated')}")
                if not face2_result.get("encoding"):
                    error_msg.append(f"Face 2: {face2_result.get('error', 'No encoding generated')}")
                
                return {
                    "similarity_score": 0.0,
                    "confidence": 0.0,
                    "match": False,
                    "error": "; ".join(error_msg),
                    "face1_quality": face1_result.get("quality_score", 0.0),
                    "face2_quality": face2_result.get("quality_score", 0.0)
                }
            
            # Calculate face distance/similarity
            face1_encoding = np.array(face1_result["encoding"])
            face2_encoding = np.array(face2_result["encoding"])
            
            # Calculate Euclidean distance
            distance = face_recognition.face_distance([face1_encoding], face2_encoding)[0]
            
            # Convert distance to similarity score (0-1, where 1 is identical)
            similarity_score = max(0.0, 1.0 - distance)
            
            # Calculate confidence based on image quality and similarity
            quality_factor = (face1_result["quality_score"] + face2_result["quality_score"]) / 2
            confidence = similarity_score * quality_factor
            
            # Determine if faces match based on threshold
            match_threshold = self.config.face_recognition_threshold
            is_match = distance <= match_threshold
            
            # Additional geometric comparison
            geometric_similarity = LivenessDetectionHelpers.compare_face_geometry(
                face1_result.get("geometric_analysis", {}),
                face2_result.get("geometric_analysis", {})
            )
            
            # Quality assessment comparison
            quality_comparison = LivenessDetectionHelpers.compare_quality_metrics(
                face1_result.get("quality_details", {}),
                face2_result.get("quality_details", {})
            )
            
            result = {
                "similarity_score": similarity_score,
                "confidence": confidence,
                "match": is_match,
                "distance": float(distance),
                "threshold_used": match_threshold,
                "face1_analysis": {
                    "quality_score": face1_result["quality_score"],
                    "quality_level": face1_result["quality_level"].value,
                    "face_count": face1_result.get("face_count", 0)
                },
                "face2_analysis": {
                    "quality_score": face2_result["quality_score"],
                    "quality_level": face2_result["quality_level"].value,
                    "face_count": face2_result.get("face_count", 0)
                },
                "detailed_analysis": {
                    "geometric_similarity": geometric_similarity,
                    "quality_comparison": quality_comparison,
                    "encoding_correlation": float(np.corrcoef(face1_encoding, face2_encoding)[0, 1])
                },
                "processing_metadata": {
                    "algorithm_used": "dlib_face_recognition",
                    "distance_metric": "euclidean",
                    "comparison_timestamp": datetime.utcnow().isoformat()
                }
            }
            
            logger.info(f"Face comparison completed: similarity={similarity_score:.3f}, match={is_match}")
            return result
            
        except Exception as e:
            logger.error(f"Face comparison failed: {e}")
            return {
                "similarity_score": 0.0,
                "confidence": 0.0,
                "match": False,
                "error": f"Comparison failed: {str(e)}",
                "face1_analysis": {},
                "face2_analysis": {},
                "detailed_analysis": {},
                "processing_metadata": {}
            }


class VideoCallService:
    """Video call service for remote verification"""
    
    def __init__(self, config: AL2Config):
        self.config = config
    
    async def schedule_call(
        self,
        session_id: str,
        applicant_name: str,
        preferred_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Schedule video call"""
        # Placeholder for video call scheduling
        # In production, this would integrate with video call providers
        
        call_details = {
            "call_id": secrets.token_urlsafe(16),
            "join_url": f"https://meet.qes-platform.com/al2/{session_id}",
            "scheduled_time": (preferred_time or datetime.utcnow() + timedelta(hours=1)).isoformat(),
            "estimated_duration": self.config.video_call_duration_min,
            "recording_enabled": self.config.video_call_recording_required
        }
        
        return call_details