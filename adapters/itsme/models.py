"""
Data models for itsme QES integration
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum


class ItsmeEnvironment(str, Enum):
    """itsme environment types"""
    SANDBOX = "sandbox"
    PRODUCTION = "production"


class ItsmeLoA(str, Enum):
    """itsme Level of Assurance"""
    LOW = "1"
    SUBSTANTIAL = "2"  # eIDAS LoA Substantial
    HIGH = "3"         # eIDAS LoA High


class ItsmeServiceType(str, Enum):
    """itsme service types"""
    IDENTIFICATION = "identification"
    AUTHENTICATION = "authentication"
    SIGNING = "signing"
    SEALING = "sealing"


@dataclass
class ItsmeConfig:
    """Configuration for itsme QES provider"""
    
    # Basic configuration
    client_id: str
    client_secret: str
    environment: ItsmeEnvironment = ItsmeEnvironment.SANDBOX
    
    # Endpoints (auto-configured based on environment)
    authorization_url: Optional[str] = None
    token_url: Optional[str] = None
    userinfo_url: Optional[str] = None
    signing_url: Optional[str] = None
    
    # Certificate configuration
    signing_certificate_url: Optional[str] = None
    certificate_chain_url: Optional[str] = None
    
    # Service configuration
    service_code: str = "QES_SIGNING"  # itsme service code
    loa: ItsmeLoA = ItsmeLoA.SUBSTANTIAL
    
    # Callback URLs
    redirect_uri: str = "https://your-platform.com/callback/itsme"
    
    # Optional configuration
    timeout: int = 30
    max_retries: int = 3
    
    def __post_init__(self):
        """Auto-configure URLs based on environment"""
        if self.environment == ItsmeEnvironment.SANDBOX:
            self.authorization_url = "https://sandbox.itsme.services/oidc/authorization"
            self.token_url = "https://sandbox.itsme.services/oidc/token"
            self.userinfo_url = "https://sandbox.itsme.services/oidc/userinfo"
            self.signing_url = "https://sandbox.itsme.services/signing/v1"
            self.signing_certificate_url = "https://sandbox.itsme.services/certificates/v1"
        else:
            self.authorization_url = "https://itsme.services/oidc/authorization"
            self.token_url = "https://itsme.services/oidc/token"
            self.userinfo_url = "https://itsme.services/oidc/userinfo"
            self.signing_url = "https://itsme.services/signing/v1"
            self.signing_certificate_url = "https://itsme.services/certificates/v1"


@dataclass
class ItsmeAuthRequest:
    """itsme authentication request"""
    
    # Required parameters
    scope: str = "openid profile ial2"  # Include eIDAS LoA Substantial
    response_type: str = "code"
    state: str = ""
    nonce: str = ""
    
    # Optional parameters
    prompt: Optional[str] = None
    max_age: Optional[int] = None
    ui_locales: str = "en nl fr de"  # Support multiple languages
    
    # itsme specific
    acr_values: str = "ial2"  # Identity Assurance Level 2
    claims: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        """Set default claims for eIDAS compliance"""
        if self.claims is None:
            self.claims = {
                "userinfo": {
                    "given_name": {"essential": True},
                    "family_name": {"essential": True},
                    "birthdate": {"essential": True},
                    "ial": {"essential": True, "value": "2"},
                    "sub": {"essential": True}
                }
            }


@dataclass
class ItsmeAuthResponse:
    """itsme authentication response"""
    
    # OAuth2/OIDC standard fields
    access_token: str
    token_type: str
    expires_in: int
    id_token: str
    scope: str
    
    # User information
    sub: str  # Subject identifier
    given_name: str
    family_name: str
    birthdate: str
    ial: str  # Identity Assurance Level
    
    # itsme specific
    phone_number: Optional[str] = None
    email: Optional[str] = None
    address: Optional[Dict[str, str]] = None
    
    # Metadata
    auth_time: datetime
    issued_at: datetime
    expires_at: datetime


@dataclass
class ItsmeSigningRequest:
    """itsme signing request"""
    
    # Document information
    document_hash: str
    hash_algorithm: str = "SHA256"
    document_name: str
    document_description: Optional[str] = None
    
    # Signing parameters
    signature_format: str = "XAdES"  # XAdES, PAdES, CAdES
    signature_level: str = "LTA"     # B, T, LTA
    
    # User context
    user_sub: str  # From authentication
    
    # Display information
    signing_text: str = "Please confirm signing of the document"
    language: str = "en"
    
    # Technical parameters
    callback_url: Optional[str] = None
    reference_id: Optional[str] = None
    
    # Metadata
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ItsmeSigningResponse:
    """itsme signing response"""
    
    # Signing result
    signature_id: str
    status: str  # "pending", "completed", "failed", "cancelled"
    
    # Signature data (when completed)
    signature_value: Optional[str] = None
    signature_algorithm: str = "RSA_SHA256"
    certificate: Optional[str] = None
    certificate_chain: Optional[List[str]] = None
    
    # Timestamp information
    timestamp_token: Optional[str] = None
    timestamp_authority: Optional[str] = None
    
    # Metadata
    signed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    
    # Error information
    error_code: Optional[str] = None
    error_message: Optional[str] = None


@dataclass
class ItsmeUserInfo:
    """itsme user information"""
    
    # Standard OIDC claims
    sub: str
    given_name: str
    family_name: str
    birthdate: str
    
    # itsme specific claims
    ial: str  # Identity Assurance Level
    phone_number: Optional[str] = None
    email: Optional[str] = None
    
    # Address information
    address: Optional[Dict[str, str]] = None
    
    # National identifier (if available)
    national_identifier: Optional[str] = None
    
    # Verification status
    phone_number_verified: bool = False
    email_verified: bool = False
    
    # Metadata
    updated_at: Optional[datetime] = None


@dataclass
class ItsmeErrorResponse:
    """itsme API error response"""
    
    error: str
    error_description: Optional[str] = None
    error_uri: Optional[str] = None
    state: Optional[str] = None
    
    # Additional itsme error details
    error_code: Optional[str] = None
    correlation_id: Optional[str] = None
    timestamp: Optional[datetime] = None