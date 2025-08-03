"""
Camerfirma QES Provider for Spain

Camerfirma is one of Spain's leading trust service providers,
offering qualified electronic signature services compliant with eIDAS.

Features:
- Spanish national identity verification (DNI/NIE)
- Qualified certificates
- Remote signing services
- Mobile signatures
- eIDAS Level of Assurance High
- Integration with Spanish government services
"""

from .provider import CamerfirmaQESProvider
from .models import CamerfirmaConfig, CamerfirmaAuthRequest, CamerfirmaAuthResponse
from .exceptions import CamerfirmaException, CamerfirmaAuthenticationException

__all__ = [
    "CamerfirmaQESProvider",
    "CamerfirmaConfig",
    "CamerfirmaAuthRequest",
    "CamerfirmaAuthResponse", 
    "CamerfirmaException",
    "CamerfirmaAuthenticationException"
]