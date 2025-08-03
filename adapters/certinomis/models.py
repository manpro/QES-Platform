"""
Data models for Certinomis QES integration
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum


class CertinomisEnvironment(str, Enum):
    """Certinomis environment types"""
    TESTING = "testing"
    PREPRODUCTION = "preproduction"
    PRODUCTION = "production"


class CertinomisAuthMethod(str, Enum):
    """Certinomis authentication methods"""
    FRANCE_CONNECT = "france_connect"
    CERTIFICATE = "certificate"
    SMS_OTP = "sms_otp"
    MOBILE_APP = "mobile_app"


class CertinomisLoA(str, Enum):
    """Certinomis Level of Assurance"""
    SUBSTANTIAL = "substantial"  # eIDAS LoA Substantial
    HIGH = "high"               # eIDAS LoA High


class CertinomisSignatureType(str, Enum):
    """Certinomis signature types"""
    SIMPLE = "simple"
    ADVANCED = "advanced"
    QUALIFIED = "qualified"


@dataclass
class CertinomisConfig:
    """Configuration for Certinomis QES provider"""
    
    # Basic configuration
    client_id: str
    client_secret: str
    environment: CertinomisEnvironment = CertinomisEnvironment.TESTING
    
    # API endpoints (auto-configured based on environment)
    api_base_url: Optional[str] = None
    auth_url: Optional[str] = None
    token_url: Optional[str] = None
    signing_url: Optional[str] = None
    certificates_url: Optional[str] = None
    
    # Authentication configuration
    auth_method: CertinomisAuthMethod = CertinomisAuthMethod.FRANCE_CONNECT
    loa: CertinomisLoA = CertinomisLoA.HIGH
    
    # Callback configuration
    redirect_uri: str = "https://your-platform.com/callback/certinomis"
    
    # Certificate configuration
    certificate_profile: str = "QUALIFIED_ESIGN"
    key_size: int = 2048
    
    # Optional configuration
    timeout: int = 30
    max_retries: int = 3
    
    # FranceConnect specific
    france_connect_client_id: Optional[str] = None
    france_connect_client_secret: Optional[str] = None
    
    def __post_init__(self):
        """Auto-configure URLs based on environment"""
        if self.environment == CertinomisEnvironment.TESTING:
            self.api_base_url = "https://test-api.certinomis.fr"
            self.auth_url = "https://test-auth.certinomis.fr/oauth2/authorize"
            self.token_url = "https://test-auth.certinomis.fr/oauth2/token"
            self.signing_url = "https://test-api.certinomis.fr/signature/v2"
            self.certificates_url = "https://test-api.certinomis.fr/certificates/v2"
        elif self.environment == CertinomisEnvironment.PREPRODUCTION:
            self.api_base_url = "https://preprod-api.certinomis.fr"
            self.auth_url = "https://preprod-auth.certinomis.fr/oauth2/authorize"
            self.token_url = "https://preprod-auth.certinomis.fr/oauth2/token"
            self.signing_url = "https://preprod-api.certinomis.fr/signature/v2"
            self.certificates_url = "https://preprod-api.certinomis.fr/certificates/v2"
        else:  # PRODUCTION
            self.api_base_url = "https://api.certinomis.fr"
            self.auth_url = "https://auth.certinomis.fr/oauth2/authorize"
            self.token_url = "https://auth.certinomis.fr/oauth2/token"
            self.signing_url = "https://api.certinomis.fr/signature/v2"
            self.certificates_url = "https://api.certinomis.fr/certificates/v2"


@dataclass
class CertinomisAuthRequest:
    """Certinomis authentication request"""
    
    # OAuth2 parameters
    response_type: str = "code"
    scope: str = "openid profile signature"
    state: str = ""
    nonce: str = ""
    
    # eIDAS parameters
    acr_values: str = "eidas3"  # eIDAS LoA High
    
    # Certinomis specific
    signature_type: CertinomisSignatureType = CertinomisSignatureType.QUALIFIED
    certificate_profile: str = "QUALIFIED_ESIGN"
    
    # FranceConnect integration
    france_connect: bool = False
    
    # Localization
    locale: str = "fr-FR"
    
    # Optional parameters
    max_age: Optional[int] = None
    prompt: Optional[str] = None


@dataclass
class CertinomisAuthResponse:
    """Certinomis authentication response"""
    
    # OAuth2 tokens
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    scope: str
    
    # User information
    user_id: str
    given_name: str
    family_name: str
    email: str
    
    # French specific identifiers
    siret: Optional[str] = None  # Company identifier
    siren: Optional[str] = None  # Company identifier
    
    # Certificate information
    certificate_dn: Optional[str] = None
    certificate_serial: Optional[str] = None
    
    # eIDAS information
    loa_level: str = "high"
    eidas_compliant: bool = True
    
    # Metadata
    auth_time: datetime
    issued_at: datetime
    expires_at: datetime


@dataclass
class CertinomisSigningRequest:
    """Certinomis signing request"""
    
    # Document information
    document_id: str
    document_hash: str
    hash_algorithm: str = "SHA256"
    document_name: str
    document_mime_type: str = "application/pdf"
    
    # Signing parameters
    signature_format: str = "PAdES-LTA"
    signature_level: str = "LTA"
    signature_type: CertinomisSignatureType = CertinomisSignatureType.QUALIFIED
    
    # Certificate selection
    certificate_id: Optional[str] = None
    
    # Visual signature (for PDF)
    visual_signature: Optional[Dict[str, Any]] = None
    
    # Timestamping
    timestamp_required: bool = True
    timestamp_authority: Optional[str] = None
    
    # Signature policy
    signature_policy_id: Optional[str] = None
    
    # Metadata
    reason: Optional[str] = None
    location: Optional[str] = None
    contact_info: Optional[str] = None


@dataclass
class CertinomisSigningResponse:
    """Certinomis signing response"""
    
    # Signing result
    signature_id: str
    status: str  # "pending", "completed", "failed", "cancelled"
    
    # Signature data
    signature_value: Optional[str] = None
    signature_format: str = "PAdES-LTA"
    
    # Certificate information
    signing_certificate: Optional[str] = None
    certificate_chain: Optional[List[str]] = None
    
    # Timestamp information
    timestamp_token: Optional[str] = None
    timestamp_info: Optional[Dict[str, Any]] = None
    
    # Signed document
    signed_document: Optional[bytes] = None
    signed_document_url: Optional[str] = None
    
    # Verification information
    signature_validation: Optional[Dict[str, Any]] = None
    
    # Metadata
    signing_time: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    
    # Error information
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None


@dataclass
class CertinomisCertificate:
    """Certinomis certificate information"""
    
    # Certificate identification
    certificate_id: str
    certificate_pem: str
    subject_dn: str
    issuer_dn: str
    serial_number: str
    
    # Validity
    valid_from: datetime
    valid_to: datetime
    
    # Certificate properties
    certificate_type: str = "qualified"
    key_usage: List[str] = None
    extended_key_usage: List[str] = None
    
    # Certificate chain
    certificate_chain: List[str] = None
    
    # French specific
    qualified_status: bool = True
    qscd_status: bool = True  # Qualified Signature Creation Device
    
    # Metadata
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.key_usage is None:
            self.key_usage = ["digital_signature", "non_repudiation"]
        if self.certificate_chain is None:
            self.certificate_chain = []


@dataclass
class CertinomisUserInfo:
    """Certinomis user information"""
    
    # Basic user information
    user_id: str
    given_name: str
    family_name: str
    email: str
    phone: Optional[str] = None
    
    # Address information
    address: Optional[Dict[str, str]] = None
    
    # French specific identifiers
    social_security_number: Optional[str] = None  # Numéro de sécurité sociale
    siret: Optional[str] = None
    siren: Optional[str] = None
    
    # Professional information
    company_name: Optional[str] = None
    job_title: Optional[str] = None
    
    # Verification status
    identity_verified: bool = False
    professional_verified: bool = False
    
    # eIDAS information
    loa_level: str = "high"
    
    # Metadata
    last_login: Optional[datetime] = None
    account_created: Optional[datetime] = None


@dataclass
class CertinomisVisualSignature:
    """Visual signature configuration for PDF documents"""
    
    # Position
    page: int = 1
    x: float = 100
    y: float = 100
    width: float = 200
    height: float = 80
    
    # Content
    text: Optional[str] = None
    image_url: Optional[str] = None
    image_data: Optional[bytes] = None
    
    # Appearance
    font_size: int = 12
    font_color: str = "#000000"
    background_color: Optional[str] = None
    border: bool = True
    
    # Information to display
    show_signature_time: bool = True
    show_signer_name: bool = True
    show_reason: bool = False
    show_location: bool = False
    
    # Custom fields
    custom_fields: Optional[Dict[str, str]] = None


@dataclass
class CertinomisErrorResponse:
    """Certinomis API error response"""
    
    error: str
    error_description: Optional[str] = None
    error_code: Optional[str] = None
    error_uri: Optional[str] = None
    
    # Request information
    request_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    
    # Additional details
    details: Optional[Dict[str, Any]] = None