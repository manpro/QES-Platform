"""
Freja eID QES Provider for Sweden

Implements QES provider interface for Freja eID QES services
with OAuth2 authentication and remote signing capabilities.
"""

from .freja_provider import FrejaQESProvider

__all__ = ["FrejaQESProvider"]