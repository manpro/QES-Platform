"""
Data models for Camerfirma QES integration
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum


class CamerfirmaEnvironment(str, Enum):
    """Camerfirma environment types"""
    SANDBOX = "sandbox"
    PREPRODUCTION = "preproduction"
    PRODUCTION = "production"


class CamerfirmaAuthMethod(str, Enum):
    """Camerfirma authentication methods"""
    DNI_ELECTRONIC = "dni_electronic"  # DNI electrónico
    CERTIFICATE = "certificate"        # Certificate-based
    SMS_OTP = "sms_otp"               # SMS OTP
    MOBILE_SIGNATURE = "mobile_signature"  # Mobile signature
    VIDEO_ID = "video_id"             # Video identification


class CamerfirmaLoA(str, Enum):
    """Camerfirma Level of Assurance"""
    SUBSTANTIAL = "substantial"  # eIDAS LoA Substantial
    HIGH = "high"               # eIDAS LoA High


class CamerfirmaSignatureType(str, Enum):
    """Camerfirma signature types"""
    SIMPLE = "simple"
    ADVANCED = "advanced"
    QUALIFIED = "qualified"


class CamerfirmaDocumentType(str, Enum):
    """Camerfirma document types"""
    PDF = "pdf"
    XML = "xml"
    OFFICE = "office"
    TEXT = "text"
    BINARY = "binary"


@dataclass
class CamerfirmaConfig:
    """Configuration for Camerfirma QES provider"""
    
    # Basic configuration
    client_id: str
    client_secret: str
    environment: CamerfirmaEnvironment = CamerfirmaEnvironment.SANDBOX
    
    # API endpoints (auto-configured based on environment)
    api_base_url: Optional[str] = None
    auth_url: Optional[str] = None
    token_url: Optional[str] = None
    signing_url: Optional[str] = None
    certificates_url: Optional[str] = None
    verification_url: Optional[str] = None
    
    # Authentication configuration
    auth_method: CamerfirmaAuthMethod = CamerfirmaAuthMethod.CERTIFICATE
    loa: CamerfirmaLoA = CamerfirmaLoA.HIGH
    
    # Callback configuration
    redirect_uri: str = "https://your-platform.com/callback/camerfirma"
    
    # Certificate configuration
    certificate_profile: str = "QUALIFIED_SIGNATURE"
    key_algorithm: str = "RSA"
    key_size: int = 2048
    
    # Spanish specific
    spanish_government_integration: bool = False
    dni_verification_required: bool = True
    
    # Optional configuration
    timeout: int = 30
    max_retries: int = 3
    
    # Mobile signature configuration
    mobile_operator: Optional[str] = None
    mobile_country_code: str = "ES"
    
    def __post_init__(self):
        """Auto-configure URLs based on environment"""
        if self.environment == CamerfirmaEnvironment.SANDBOX:
            self.api_base_url = "https://sandbox-api.camerfirma.com"
            self.auth_url = "https://sandbox-auth.camerfirma.com/oauth2/authorize"
            self.token_url = "https://sandbox-auth.camerfirma.com/oauth2/token"
            self.signing_url = "https://sandbox-api.camerfirma.com/signature/v3"
            self.certificates_url = "https://sandbox-api.camerfirma.com/certificates/v3"
            self.verification_url = "https://sandbox-api.camerfirma.com/verification/v3"
        elif self.environment == CamerfirmaEnvironment.PREPRODUCTION:
            self.api_base_url = "https://preprod-api.camerfirma.com"
            self.auth_url = "https://preprod-auth.camerfirma.com/oauth2/authorize"
            self.token_url = "https://preprod-auth.camerfirma.com/oauth2/token"
            self.signing_url = "https://preprod-api.camerfirma.com/signature/v3"
            self.certificates_url = "https://preprod-api.camerfirma.com/certificates/v3"
            self.verification_url = "https://preprod-api.camerfirma.com/verification/v3"
        else:  # PRODUCTION
            self.api_base_url = "https://api.camerfirma.com"
            self.auth_url = "https://auth.camerfirma.com/oauth2/authorize"
            self.token_url = "https://auth.camerfirma.com/oauth2/token"
            self.signing_url = "https://api.camerfirma.com/signature/v3"
            self.certificates_url = "https://api.camerfirma.com/certificates/v3"
            self.verification_url = "https://api.camerfirma.com/verification/v3"


@dataclass
class CamerfirmaAuthRequest:
    """Camerfirma authentication request"""
    
    # OAuth2 parameters
    response_type: str = "code"
    scope: str = "openid profile signature"
    state: str = ""
    nonce: str = ""
    
    # eIDAS parameters
    acr_values: str = "eidas3"  # eIDAS LoA High
    
    # Camerfirma specific
    auth_method: CamerfirmaAuthMethod = CamerfirmaAuthMethod.CERTIFICATE
    signature_type: CamerfirmaSignatureType = CamerfirmaSignatureType.QUALIFIED
    
    # Spanish identity verification
    dni_required: bool = True
    nie_accepted: bool = True  # Número de Identidad de Extranjero
    
    # Localization
    locale: str = "es-ES"
    
    # Mobile signature specific
    mobile_number: Optional[str] = None
    mobile_operator: Optional[str] = None
    
    # Optional parameters
    max_age: Optional[int] = None
    prompt: Optional[str] = None


@dataclass
class CamerfirmaAuthResponse:
    """Camerfirma authentication response"""
    
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
    
    # Spanish identity information
    dni: Optional[str] = None  # Documento Nacional de Identidad
    nie: Optional[str] = None  # Número de Identidad de Extranjero
    nif: Optional[str] = None  # Número de Identificación Fiscal
    
    # Certificate information
    certificate_dn: Optional[str] = None
    certificate_serial: Optional[str] = None
    certificate_issuer: Optional[str] = None
    
    # eIDAS information
    loa_level: str = "high"
    eidas_compliant: bool = True
    
    # Metadata
    auth_time: datetime
    issued_at: datetime
    expires_at: datetime


@dataclass
class CamerfirmaSigningRequest:
    """Camerfirma signing request"""
    
    # Document information
    document_id: str
    document_hash: str
    hash_algorithm: str = "SHA256"
    document_name: str
    document_type: CamerfirmaDocumentType = CamerfirmaDocumentType.PDF
    
    # Signing parameters
    signature_format: str = "PAdES-LTA"
    signature_level: str = "LTA"
    signature_type: CamerfirmaSignatureType = CamerfirmaSignatureType.QUALIFIED
    
    # Certificate selection
    certificate_id: Optional[str] = None
    
    # Visual signature (for PDF)
    visual_signature: Optional[Dict[str, Any]] = None
    
    # Timestamping
    timestamp_required: bool = True
    timestamp_authority: Optional[str] = None
    
    # Signature policy
    signature_policy_oid: Optional[str] = None
    signature_policy_url: Optional[str] = None
    
    # Spanish regulatory compliance
    regulation_compliance: List[str] = None
    
    # Metadata
    reason: Optional[str] = None
    location: Optional[str] = None
    contact_info: Optional[str] = None
    
    def __post_init__(self):
        if self.regulation_compliance is None:
            self.regulation_compliance = ["eIDAS", "ENI"]  # Esquema Nacional de Interoperabilidad


@dataclass
class CamerfirmaSigningResponse:
    """Camerfirma signing response"""
    
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
    
    # Spanish regulatory information
    eni_compliant: bool = True  # Esquema Nacional de Interoperabilidad
    regulatory_evidence: Optional[Dict[str, Any]] = None
    
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
class CamerfirmaCertificate:
    """Camerfirma certificate information"""
    
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
    
    # Spanish specific
    qualified_status: bool = True
    qscd_status: bool = True
    dni_embedded: bool = False
    
    # Regulatory compliance
    eni_compliant: bool = True
    spanish_government_approved: bool = True
    
    # Metadata
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.key_usage is None:
            self.key_usage = ["digital_signature", "non_repudiation"]
        if self.certificate_chain is None:
            self.certificate_chain = []


@dataclass
class CamerfirmaUserInfo:
    """Camerfirma user information"""
    
    # Basic user information
    user_id: str
    given_name: str
    family_name: str
    email: str
    phone: Optional[str] = None
    
    # Spanish identity information
    dni: Optional[str] = None
    nie: Optional[str] = None
    nif: Optional[str] = None
    
    # Address information
    address: Optional[Dict[str, str]] = None
    
    # Professional information
    company_name: Optional[str] = None
    company_nif: Optional[str] = None
    job_title: Optional[str] = None
    
    # Verification status
    identity_verified: bool = False
    professional_verified: bool = False
    dni_verified: bool = False
    
    # eIDAS information
    loa_level: str = "high"
    
    # Metadata
    last_login: Optional[datetime] = None
    account_created: Optional[datetime] = None


@dataclass
class CamerfirmaMobileSignature:
    """Camerfirma mobile signature configuration"""
    
    # Mobile information
    mobile_number: str
    mobile_operator: Optional[str] = None
    country_code: str = "ES"
    
    # Signature parameters
    signature_text: str = "Confirmar firma electrónica"
    language: str = "es"
    
    # Security parameters
    otp_required: bool = True
    biometric_required: bool = False
    
    # Timeout configuration
    timeout_seconds: int = 300  # 5 minutes
    
    # Notification preferences
    sms_notification: bool = True
    email_notification: bool = False


@dataclass
class CamerfirmaVisualSignature:
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
    font_family: str = "Arial"
    font_color: str = "#000000"
    background_color: Optional[str] = None
    border: bool = True
    
    # Information to display
    show_signature_time: bool = True
    show_signer_name: bool = True
    show_signer_dni: bool = False
    show_reason: bool = False
    show_location: bool = False
    
    # Spanish specific
    show_regulatory_info: bool = True
    regulatory_text: str = "Firmado conforme a la normativa eIDAS"


@dataclass
class CamerfirmaErrorResponse:
    """Camerfirma API error response"""
    
    error: str
    error_description: Optional[str] = None
    error_code: Optional[str] = None
    error_uri: Optional[str] = None
    
    # Request information
    request_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    
    # Spanish specific error details
    regulatory_error: Optional[str] = None
    dni_validation_error: Optional[str] = None
    
    # Additional details
    details: Optional[Dict[str, Any]] = None