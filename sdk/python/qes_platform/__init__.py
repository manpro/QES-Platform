"""
QES Platform Python SDK

A comprehensive SDK for integrating with the QES Platform API,
providing qualified electronic signature services compliant with
eIDAS regulation and ETSI standards.

Example:
    >>> from qes_platform import QESClient
    >>> client = QESClient(api_url="https://api.qes-platform.com/v1", 
    ...                    api_key="your-api-key",
    ...                    tenant_id="your-tenant-id")
    >>> 
    >>> # Authenticate user
    >>> auth_result = client.auth.login(
    ...     provider="freja-se",
    ...     user_identifier="user@example.com"
    ... )
    >>> 
    >>> # Sign document
    >>> with open("document.pdf", "rb") as f:
    ...     result = client.signatures.sign(
    ...         document=f.read(),
    ...         document_name="document.pdf",
    ...         signature_format="PAdES-LTA"
    ...     )
"""

from ._version import __version__
from .client import QESClient
from .models import (
    # Authentication models
    LoginRequest,
    LoginResponse,
    AuthenticationResult,
    UserInfo,
    
    # Certificate models
    Certificate,
    CertificateInfo,
    
    # Signature models
    SigningRequest,
    SigningResponse,
    SignatureInfo,
    VerificationRequest,
    VerificationResult,
    
    # Provider models
    ProviderInfo,
    ProviderStatus,
    
    # Error models
    QESError,
    AuthenticationError,
    SigningError,
    VerificationError,
    RateLimitError,
    ValidationError,
)
from .exceptions import (
    QESException,
    QESAuthenticationException,
    QESSigningException,
    QESVerificationException,
    QESRateLimitException,
    QESValidationException,
    QESConnectionException,
    QESTimeoutException,
)

__all__ = [
    "__version__",
    # Client
    "QESClient",
    # Models
    "LoginRequest",
    "LoginResponse", 
    "AuthenticationResult",
    "UserInfo",
    "Certificate",
    "CertificateInfo",
    "SigningRequest",
    "SigningResponse",
    "SignatureInfo",
    "VerificationRequest",
    "VerificationResult",
    "ProviderInfo",
    "ProviderStatus",
    "QESError",
    "AuthenticationError",
    "SigningError",
    "VerificationError",
    "RateLimitError",
    "ValidationError",
    # Exceptions
    "QESException",
    "QESAuthenticationException",
    "QESSigningException", 
    "QESVerificationException",
    "QESRateLimitException",
    "QESValidationException",
    "QESConnectionException",
    "QESTimeoutException",
]