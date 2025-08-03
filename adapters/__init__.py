"""
QES Provider Adapters

This package contains adapters for various QES (Qualified Electronic Signature) providers.
"""

from .freja_eid import FrejaEIDQESProvider
from .d_trust import DTrustQESProvider
from .itsme import ItsmeQESProvider
from .certinomis import CertinomisQESProvider
from .camerfirma import CamerfirmaQESProvider
from .fnmt import FNMTQESProvider

# QES Provider registry
QES_PROVIDERS = {
    "freja_eid": FrejaEIDQESProvider,
    "d_trust": DTrustQESProvider,
    "itsme": ItsmeQESProvider,
    "certinomis": CertinomisQESProvider,
    "camerfirma": CamerfirmaQESProvider,
    "fnmt": FNMTQESProvider,
}

__all__ = [
    "QES_PROVIDERS",
    "FrejaEIDQESProvider", 
    "DTrustQESProvider",
    "ItsmeQESProvider",
    "CertinomisQESProvider", 
    "CamerfirmaQESProvider",
    "FNMTQESProvider",
]