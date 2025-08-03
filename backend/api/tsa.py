"""
Timestamp Authority (TSA) API Endpoints

FastAPI endpoints for RFC 3161 timestamp services.
"""

import logging
from typing import Optional, Dict, Any
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends, status, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from auth.jwt_auth import get_current_user
from models.user import User
from core.tsa_client import TSAClient, TSAError
from utils.request_utils import get_client_ip, get_user_agent
from core.audit_logger import AuditLogger, AuditEventType

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/tsa", tags=["timestamp"])


class TimestampRequest(BaseModel):
    """Request for timestamp service"""
    data: str = Field(..., description="Base64 encoded data to timestamp")
    hash_algorithm: str = Field(default="SHA-256", description="Hash algorithm to use")
    tsa_url: Optional[str] = Field(None, description="TSA URL override")
    policy_id: Optional[str] = Field(None, description="TSA policy ID")


class TimestampResponse(BaseModel):
    """Response from timestamp service"""
    token: str = Field(..., description="Base64 encoded timestamp token")
    timestamp: datetime = Field(..., description="Timestamp from TSA")
    serial_number: str = Field(..., description="TSA serial number")
    hash_algorithm: str = Field(..., description="Hash algorithm used")
    tsa_url: str = Field(..., description="TSA URL used")
    token_size: int = Field(..., description="Token size in bytes")


class TimestampVerificationRequest(BaseModel):
    """Request for timestamp verification"""
    token: str = Field(..., description="Base64 encoded timestamp token")
    original_data: str = Field(..., description="Base64 encoded original data")
    hash_algorithm: str = Field(default="SHA-256", description="Hash algorithm used")


class TimestampVerificationResponse(BaseModel):
    """Response from timestamp verification"""
    valid: bool = Field(..., description="Whether the timestamp is valid")
    timestamp: Optional[datetime] = Field(None, description="Timestamp from token")
    serial_number: Optional[str] = Field(None, description="TSA serial number")
    message_imprint_valid: bool = Field(..., description="Message imprint validity")
    signature_valid: bool = Field(..., description="Signature validity")
    certificate_valid: bool = Field(..., description="Certificate validity")
    errors: list = Field(default_factory=list, description="Validation errors")


# Initialize audit logger
audit_logger = AuditLogger({
    "enable_postgres": True,
    "enable_loki": True,
    "enable_file": True,
    "log_file_path": "audit.log",
    "buffer_size": 50
})


@router.post("/request", response_model=TimestampResponse)
async def request_timestamp(
    request: Request,
    timestamp_request: TimestampRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Request a timestamp from a TSA server.
    
    This endpoint accepts data and returns an RFC 3161 timestamp token
    that can be used to prove the data existed at a specific time.
    """
    try:
        import base64
        
        # Decode the data
        try:
            data = base64.b64decode(timestamp_request.data)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid base64 data: {str(e)}"
            )
        
        # Use default TSA URL if not provided
        tsa_url = timestamp_request.tsa_url or "http://timestamp.digicert.com"
        
        # Initialize TSA client
        tsa_client = TSAClient(
            tsa_url=tsa_url,
            config={
                "timeout": 30,
                "verify_ssl": True,
                "policy_id": timestamp_request.policy_id
            }
        )
        
        # Get timestamp
        tsa_response = await tsa_client.get_timestamp(
            data, 
            hash_algorithm=timestamp_request.hash_algorithm
        )
        
        # Encode token for response
        token_b64 = base64.b64encode(tsa_response.token_data).decode('utf-8')
        
        # Log the timestamp request for audit
        await audit_logger.log_timestamp_request(
            user_id=current_user.id,
            tsa_url=tsa_url,
            hash_algorithm=timestamp_request.hash_algorithm,
            data_size=len(data),
            success=True,
            client_ip=get_client_ip(request),
            user_agent=get_user_agent(request),
            details={
                "serial_number": tsa_response.serial_number,
                "token_size": len(tsa_response.token_data),
                "policy_id": timestamp_request.policy_id
            }
        )
        
        logger.info(f"Timestamp request successful for user {current_user.id}: {tsa_response.serial_number}")
        
        return TimestampResponse(
            token=token_b64,
            timestamp=tsa_response.timestamp,
            serial_number=tsa_response.serial_number,
            hash_algorithm=tsa_response.hash_algorithm,
            tsa_url=tsa_url,
            token_size=len(tsa_response.token_data)
        )
        
    except TSAError as e:
        logger.error(f"TSA error for user {current_user.id}: {e}")
        
        # Log failed timestamp request
        await audit_logger.log_timestamp_request(
            user_id=current_user.id,
            tsa_url=tsa_url,
            hash_algorithm=timestamp_request.hash_algorithm,
            data_size=len(data) if 'data' in locals() else 0,
            success=False,
            client_ip=get_client_ip(request),
            user_agent=get_user_agent(request),
            details={
                "error": str(e),
                "status_code": getattr(e, 'status_code', None)
            }
        )
        
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"TSA request failed: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Timestamp request failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Timestamp request failed: {str(e)}"
        )


@router.post("/verify", response_model=TimestampVerificationResponse)
async def verify_timestamp(
    request: Request,
    verification_request: TimestampVerificationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verify a timestamp token against original data.
    
    This endpoint verifies that a timestamp token is valid and was created
    for the provided original data.
    """
    try:
        import base64
        
        # Decode token and original data
        try:
            token_data = base64.b64decode(verification_request.token)
            original_data = base64.b64decode(verification_request.original_data)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid base64 data: {str(e)}"
            )
        
        # Create TSA client for verification (URL not needed for verification)
        tsa_client = TSAClient("", config={"verify_ssl": True})
        
        # Verify timestamp token
        verification_result = await tsa_client.verify_timestamp_token(
            token_data, 
            original_data,
            hash_algorithm=verification_request.hash_algorithm
        )
        
        # Log verification attempt
        await audit_logger.log_validation_check(
            user_id=current_user.id,
            resource_id="timestamp_token",
            check_type="timestamp_verification",
            result=verification_result["valid"],
            client_ip=get_client_ip(request),
            user_agent=get_user_agent(request),
            details={
                "hash_algorithm": verification_request.hash_algorithm,
                "token_size": len(token_data),
                "data_size": len(original_data),
                "verification_details": verification_result
            }
        )
        
        logger.info(f"Timestamp verification for user {current_user.id}: valid={verification_result['valid']}")
        
        return TimestampVerificationResponse(
            valid=verification_result["valid"],
            timestamp=verification_result.get("timestamp"),
            serial_number=verification_result.get("serial_number"),
            message_imprint_valid=verification_result.get("message_imprint_valid", False),
            signature_valid=verification_result.get("signature_valid", False),
            certificate_valid=verification_result.get("certificate_valid", False),
            errors=verification_result.get("errors", [])
        )
        
    except Exception as e:
        logger.error(f"Timestamp verification failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Timestamp verification failed: {str(e)}"
        )


@router.get("/info/{token}")
async def get_timestamp_info(
    token: str,
    current_user: User = Depends(get_current_user)
):
    """
    Extract information from a timestamp token without verification.
    
    This endpoint parses a timestamp token and returns its metadata
    without performing cryptographic verification.
    """
    try:
        import base64
        
        # Decode token
        try:
            token_data = base64.b64decode(token)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid base64 token: {str(e)}"
            )
        
        # Create TSA client for info extraction
        tsa_client = TSAClient("", config={})
        
        # Extract timestamp info
        info = tsa_client.get_timestamp_info(token_data)
        
        logger.info(f"Timestamp info extracted for user {current_user.id}")
        
        return {
            "token_info": info,
            "extracted_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Timestamp info extraction failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to extract timestamp info: {str(e)}"
        )


@router.get("/providers")
async def get_tsa_providers():
    """Get list of available TSA providers and their endpoints"""
    return {
        "providers": [
            {
                "name": "DigiCert",
                "url": "http://timestamp.digicert.com",
                "description": "Free TSA service by DigiCert",
                "cost": "Free",
                "supported_algorithms": ["SHA-1", "SHA-256", "SHA-512"]
            },
            {
                "name": "Comodo",
                "url": "http://timestamp.comodoca.com/rfc3161",
                "description": "Free TSA service by Comodo/Sectigo",
                "cost": "Free",
                "supported_algorithms": ["SHA-1", "SHA-256"]
            },
            {
                "name": "GlobalSign",
                "url": "http://timestamp.globalsign.com/scripts/timstamp.dll",
                "description": "TSA service by GlobalSign",
                "cost": "Varies",
                "supported_algorithms": ["SHA-1", "SHA-256"]
            },
            {
                "name": "Apple",
                "url": "http://timestamp.apple.com/ts01",
                "description": "Apple's TSA service",
                "cost": "Free",
                "supported_algorithms": ["SHA-1", "SHA-256"]
            }
        ],
        "recommended": "DigiCert",
        "usage_notes": [
            "Free TSA services have rate limits",
            "For production use, consider paid TSA services",
            "Always verify TSA certificate chains",
            "Keep TSA responses for long-term validation"
        ]
    }


@router.get("/health")
async def tsa_health():
    """Health check for TSA service"""
    try:
        # Test basic TSA functionality
        test_data = b"health_check_test_data"
        
        tsa_client = TSAClient(
            "http://timestamp.digicert.com",
            config={"timeout": 10, "verify_ssl": True}
        )
        
        # Try to get a timestamp
        tsa_response = await tsa_client.get_timestamp(test_data)
        
        return {
            "status": "healthy",
            "service": "timestamp-authority",
            "test_timestamp": tsa_response.timestamp.isoformat(),
            "test_serial": tsa_response.serial_number,
            "asn1_available": True,
            "rfc3161_compliant": True
        }
        
    except Exception as e:
        logger.error(f"TSA health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"TSA service unhealthy: {str(e)}"
        )