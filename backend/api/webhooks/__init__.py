"""
Webhook handlers for external service integrations.

This module contains webhook endpoints for receiving asynchronous
notifications from external services like document verification
providers, payment processors, and other third-party APIs.
"""

# Re-export main webhook routers for easy importing
from .document_verification import router as document_verification_router

__all__ = [
    "document_verification_router"
]