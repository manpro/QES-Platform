"""
Base QES Provider Interface

This module defines the abstract interface that all QES provider adapters
must implement to ensure consistent behavior across different countries
and providers.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass
from enum import Enum
import asyncio


class SignatureFormat(Enum):
    """Supported signature formats"""
    XADES_B = "XAdES-B"
    XADES_T = "XAdES-T"
    XADES_LT = "XAdES-LT"
    XADES_LTA = "XAdES-LTA"
    PADES_B = "PAdES-B"
    PADES_T = "PAdES-T"
    PADES_LT = "PAdES-LT"
    PADES_LTA = "PAdES-LTA"
    CADES_B = "CAdES-B"
    CADES_T = "CAdES-T"
    CADES_LT = "CAdES-LT"
    CADES_LTA = "CAdES-LTA"


class AuthenticationStatus(Enum):
    """Authentication status states"""
    PENDING = "pending"
    AUTHENTICATED = "authenticated"
    FAILED = "failed"
    EXPIRED = "expired"


@dataclass
class Certificate:
    """Represents a digital certificate"""
    certificate_data: bytes
    certificate_chain: List[bytes]
    subject_dn: str
    issuer_dn: str
    serial_number: str
    valid_from: str
    valid_to: str
    key_usage: List[str]
    certificate_policies: List[str]


@dataclass
class AuthenticationResult:
    """Result of authentication process"""
    status: AuthenticationStatus
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    error_message: Optional[str] = None
    expires_at: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class SigningRequest:
    """Signing request parameters"""
    document: bytes
    document_name: str
    document_mime_type: str
    signature_format: SignatureFormat
    user_id: str
    session_id: str
    signature_policy: Optional[str] = None
    timestamp_server_url: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class SigningResult:
    """Result of signing operation"""
    signed_document: bytes
    signature_id: str
    timestamp: str
    certificate_used: Certificate
    signature_format: SignatureFormat
    validation_info: Optional[Dict[str, Any]] = None
    audit_trail: Optional[Dict[str, Any]] = None


@dataclass
class VerificationResult:
    """Result of signature verification"""
    is_valid: bool
    certificate: Certificate
    signing_time: str
    signature_format: SignatureFormat
    validation_errors: List[str]
    trust_status: str
    revocation_status: str
    timestamp_valid: bool


class QESProviderError(Exception):
    """Base exception for QES provider errors"""
    def __init__(self, message: str, error_code: str = None, 
                 details: Dict[str, Any] = None):
        super().__init__(message)
        self.error_code = error_code
        self.details = details or {}


class AuthenticationError(QESProviderError):
    """Authentication-related errors"""
    pass


class SigningError(QESProviderError):
    """Signing-related errors"""
    pass


class CertificateError(QESProviderError):
    """Certificate-related errors"""
    pass


class QESProvider(ABC):
    """
    Abstract base class for all QES providers.
    
    Each country-specific adapter must implement this interface
    to provide a consistent API across different QES providers.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the QES provider with configuration.
        
        Args:
            config: Provider-specific configuration dictionary
        """
        self.config = config
        self.provider_name = config.get("provider_name", "unknown")
        self.country_code = config.get("country_code", "unknown")
    
    @abstractmethod
    async def authenticate(self, user_identifier: str, 
                          auth_params: Dict[str, Any]) -> AuthenticationResult:
        """
        Authenticate a user with the QES provider.
        
        Args:
            user_identifier: User identifier (email, personal number, etc.)
            auth_params: Provider-specific authentication parameters
            
        Returns:
            AuthenticationResult with session info
            
        Raises:
            AuthenticationError: If authentication fails
        """
        pass
    
    @abstractmethod
    async def get_certificate(self, session_id: str, 
                             user_id: str) -> Certificate:
        """
        Retrieve the user's certificate for signing.
        
        Args:
            session_id: Authentication session ID
            user_id: User identifier
            
        Returns:
            Certificate object with cert data and metadata
            
        Raises:
            CertificateError: If certificate retrieval fails
        """
        pass
    
    @abstractmethod
    async def sign(self, signing_request: SigningRequest) -> SigningResult:
        """
        Sign a document using the QES provider.
        
        Args:
            signing_request: Complete signing request with document and params
            
        Returns:
            SigningResult with signed document and metadata
            
        Raises:
            SigningError: If signing operation fails
        """
        pass
    
    @abstractmethod
    async def verify(self, signed_document: bytes, 
                    original_document: Optional[bytes] = None) -> VerificationResult:
        """
        Verify a signed document.
        
        Args:
            signed_document: The signed document to verify
            original_document: Original document (for detached signatures)
            
        Returns:
            VerificationResult with validation status and details
            
        Raises:
            QESProviderError: If verification fails
        """
        pass
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Check the health status of the QES provider.
        
        Returns:
            Dictionary with health status information
        """
        return {
            "provider": self.provider_name,
            "country": self.country_code,
            "status": "unknown",
            "message": "Health check not implemented"
        }
    
    def get_supported_formats(self) -> List[SignatureFormat]:
        """
        Get list of supported signature formats.
        
        Returns:
            List of supported SignatureFormat enum values
        """
        return [
            SignatureFormat.XADES_B,
            SignatureFormat.XADES_T,
            SignatureFormat.PADES_B,
            SignatureFormat.PADES_T
        ]
    
    def validate_config(self) -> bool:
        """
        Validate the provider configuration.
        
        Returns:
            True if configuration is valid
            
        Raises:
            QESProviderError: If configuration is invalid
        """
        required_fields = ["provider_name", "country_code"]
        
        for field in required_fields:
            if field not in self.config:
                raise QESProviderError(
                    f"Missing required configuration field: {field}"
                )
        
        return True