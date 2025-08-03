"""
FNMT QES Data Models

Data models for FNMT (Fábrica Nacional de Moneda y Timbre) integration.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional


class FNMTEnvironment(Enum):
    """FNMT environment types"""
    SANDBOX = "sandbox"
    PRODUCTION = "production"


class FNMTAuthMethod(Enum):
    """FNMT authentication methods"""
    CERTIFICATE = "certificate"
    DNI_ELECTRONICO = "dni_electronico"
    CLAVE_PIN = "clave_pin"
    MOBILE_ID = "mobile_id"


class FNMTLoA(Enum):
    """FNMT Level of Assurance"""
    SUBSTANTIAL = "substantial"
    HIGH = "high"


class FNMTSignatureType(Enum):
    """FNMT signature types"""
    QUALIFIED = "qualified"
    ADVANCED = "advanced"
    SIMPLE = "simple"


@dataclass
class FNMTConfig:
    """FNMT configuration"""
    client_id: str
    client_secret: str
    environment: FNMTEnvironment
    redirect_uri: str
    auth_method: FNMTAuthMethod = FNMTAuthMethod.DNI_ELECTRONICO
    timeout: int = 30
    max_retries: int = 3
    dni_verification_required: bool = True
    certificate_validation_strict: bool = True
    
    def __post_init__(self):
        """Configure URLs based on environment"""
        if self.environment == FNMTEnvironment.SANDBOX:
            self.api_base_url = "https://test.fnmt.es/api/v1"
            self.auth_url = "https://test.fnmt.es/oauth2/authorize"
            self.token_url = "https://test.fnmt.es/oauth2/token"
            self.certificates_url = "https://test.fnmt.es/api/v1/certificates"
            self.signing_url = "https://test.fnmt.es/api/v1/signing"
            self.verification_url = "https://test.fnmt.es/api/v1/verification"
        else:
            self.api_base_url = "https://sede.fnmt.gob.es/api/v1"
            self.auth_url = "https://sede.fnmt.gob.es/oauth2/authorize"
            self.token_url = "https://sede.fnmt.gob.es/oauth2/token"
            self.certificates_url = "https://sede.fnmt.gob.es/api/v1/certificates"
            self.signing_url = "https://sede.fnmt.gob.es/api/v1/signing"
            self.verification_url = "https://sede.fnmt.gob.es/api/v1/verification"


@dataclass
class FNMTAuthRequest:
    """FNMT authentication request"""
    state: str
    nonce: str
    response_type: str = "code"
    scope: str = "openid profile email dni_info certificate_info"
    auth_method: FNMTAuthMethod = FNMTAuthMethod.DNI_ELECTRONICO
    acr_values: str = "http://loa.fnmt.es/loa/high"
    locale: str = "es-ES"
    max_age: Optional[int] = 3600
    prompt: Optional[str] = None
    
    # eIDAS specific parameters
    eidas_loa: str = "http://eidas.europa.eu/LoA/high"
    eidas_natural_person: bool = True
    eidas_attributes: List[str] = field(default_factory=lambda: [
        "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName",
        "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName",
        "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier",
        "http://eidas.europa.eu/attributes/naturalperson/DateOfBirth"
    ])
    
    # Spanish specific parameters
    dni_required: bool = True
    certificate_required: bool = True
    qualified_certificate_only: bool = True


@dataclass 
class FNMTAuthResponse:
    """FNMT authentication response"""
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: Optional[str]
    id_token: Optional[str]
    scope: str
    
    # User information
    user_id: str
    given_name: str = ""
    family_name: str = ""
    email: str = ""
    dni: Optional[str] = None
    nif: Optional[str] = None
    date_of_birth: Optional[str] = None
    
    # Certificate information
    certificate_dn: Optional[str] = None
    certificate_serial: Optional[str] = None
    certificate_issuer: Optional[str] = None
    
    # eIDAS compliance
    loa_level: str = "high"
    eidas_compliant: bool = True
    
    # Timestamps
    auth_time: datetime = field(default_factory=datetime.utcnow)
    issued_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class FNMTSigningRequest:
    """FNMT signing request"""
    document_id: str
    document_hash: str
    hash_algorithm: str = "SHA256"
    document_name: str = "document"
    signature_format: str = "PAdES-B"
    signature_level: str = "B"
    signature_type: FNMTSignatureType = FNMTSignatureType.QUALIFIED
    certificate_id: Optional[str] = None
    timestamp_required: bool = True
    
    # Spanish regulatory compliance
    eni_compliant: bool = True  # Esquema Nacional de Interoperabilidad
    spanish_gov_approval: bool = True
    
    # Signing parameters
    reason: Optional[str] = None
    location: Optional[str] = None
    contact_info: Optional[str] = None


@dataclass
class FNMTSigningResponse:
    """FNMT signing response"""
    signature_id: str
    status: str
    signature_value: Optional[str] = None
    signature_algorithm: Optional[str] = None
    signing_certificate: Optional[str] = None
    certificate_chain: List[str] = field(default_factory=list)
    timestamp_token: Optional[str] = None
    signing_time: Optional[datetime] = None
    
    # Regulatory compliance evidence
    eni_evidence: Optional[Dict] = None
    spanish_gov_evidence: Optional[Dict] = None


@dataclass
class FNMTCertificate:
    """FNMT certificate information"""
    certificate_id: str
    certificate_pem: str
    subject_dn: str
    issuer_dn: str
    serial_number: str
    valid_from: datetime
    valid_to: datetime
    certificate_type: str = "qualified"
    
    # Spanish specific flags
    dni_embedded: bool = False
    spanish_government_issued: bool = True
    eni_compliant: bool = True
    
    # eIDAS compliance
    qscd_status: bool = True
    eidas_qualified: bool = True
    
    # Key usage
    key_usage: List[str] = field(default_factory=list)
    extended_key_usage: List[str] = field(default_factory=list)


@dataclass
class FNMTUserInfo:
    """FNMT user information"""
    user_id: str
    given_name: str
    family_name: str
    email: str
    dni: Optional[str] = None
    nif: Optional[str] = None
    date_of_birth: Optional[str] = None
    nationality: str = "ES"
    
    # Certificate information
    certificates: List[FNMTCertificate] = field(default_factory=list)
    
    # Authentication details
    auth_method: FNMTAuthMethod = FNMTAuthMethod.DNI_ELECTRONICO
    loa_achieved: str = "high"
    auth_time: datetime = field(default_factory=datetime.utcnow)


@dataclass
class FNMTErrorResponse:
    """FNMT error response"""
    error: str
    error_description: str
    error_code: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)