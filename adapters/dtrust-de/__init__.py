"""
D-Trust QES Provider for Germany

Implements QES provider interface for D-Trust (Bundesdruckerei) 
services with eIDAS node integration and remote signing.
"""

from .dtrust_provider import DTrustQESProvider

__all__ = ["DTrustQESProvider"]