"""
Unit tests for QES Provider base interface
"""

import pytest
import asyncio
from typing import Dict, Any
from datetime import datetime, timezone

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../'))

from adapters.base.qes_provider import (
    QESProvider, SigningRequest, SigningResult, AuthenticationResult,
    Certificate, VerificationResult, SignatureFormat, AuthenticationStatus,
    QESProviderError, AuthenticationError, SigningError, CertificateError
)


class MockQESProvider(QESProvider):
    """Mock implementation for testing"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.mock_responses = {}
    
    async def authenticate(self, user_identifier: str, 
                          auth_params: Dict[str, Any]) -> AuthenticationResult:
        if user_identifier == "test_user":
            return AuthenticationResult(
                status=AuthenticationStatus.AUTHENTICATED,
                session_id="test_session_123",
                user_id=user_identifier,
                expires_at=(datetime.now(timezone.utc)).isoformat(),
                metadata={"test": True}
            )
        else:
            return AuthenticationResult(
                status=AuthenticationStatus.FAILED,
                error_message="User not found"
            )
    
    async def get_certificate(self, session_id: str, user_id: str) -> Certificate:
        if session_id == "test_session_123":
            return Certificate(
                certificate_data=b"mock_cert_data",
                certificate_chain=[b"mock_ca_cert"],
                subject_dn="CN=Test User,O=Test Org",
                issuer_dn="CN=Test CA,O=Test CA Org",
                serial_number="123456789",
                valid_from="2024-01-01T00:00:00Z",
                valid_to="2025-01-01T00:00:00Z",
                key_usage=["digitalSignature", "nonRepudiation"],
                certificate_policies=["1.2.3.4.5"]
            )
        else:
            raise CertificateError("Invalid session")
    
    async def sign(self, signing_request: SigningRequest) -> SigningResult:
        if signing_request.user_id == "test_user":
            return SigningResult(
                signed_document=signing_request.document + b"_signed",
                signature_id="sig_123",
                timestamp=datetime.now(timezone.utc).isoformat(),
                certificate_used=await self.get_certificate(
                    signing_request.session_id, signing_request.user_id
                ),
                signature_format=signing_request.signature_format,
                validation_info={"test": True},
                audit_trail={"test": True}
            )
        else:
            raise SigningError("Signing failed")
    
    async def verify(self, signed_document: bytes, 
                    original_document: bytes = None) -> VerificationResult:
        return VerificationResult(
            is_valid=True,
            certificate=await self.get_certificate("test_session_123", "test_user"),
            signing_time=datetime.now(timezone.utc).isoformat(),
            signature_format=SignatureFormat.XADES_B,
            validation_errors=[],
            trust_status="valid",
            revocation_status="good",
            timestamp_valid=True
        )


@pytest.fixture
def mock_provider():
    config = {
        "provider_name": "mock_provider",
        "country_code": "SE"
    }
    return MockQESProvider(config)


@pytest.mark.asyncio
async def test_authentication_success(mock_provider):
    """Test successful authentication"""
    result = await mock_provider.authenticate("test_user", {"method": "bankid"})
    
    assert result.status == AuthenticationStatus.AUTHENTICATED
    assert result.session_id == "test_session_123"
    assert result.user_id == "test_user"
    assert result.error_message is None


@pytest.mark.asyncio
async def test_authentication_failure(mock_provider):
    """Test failed authentication"""
    result = await mock_provider.authenticate("invalid_user", {"method": "bankid"})
    
    assert result.status == AuthenticationStatus.FAILED
    assert result.session_id is None
    assert result.error_message == "User not found"


@pytest.mark.asyncio
async def test_get_certificate_success(mock_provider):
    """Test successful certificate retrieval"""
    cert = await mock_provider.get_certificate("test_session_123", "test_user")
    
    assert cert.certificate_data == b"mock_cert_data"
    assert cert.subject_dn == "CN=Test User,O=Test Org"
    assert cert.issuer_dn == "CN=Test CA,O=Test CA Org"
    assert cert.serial_number == "123456789"
    assert "digitalSignature" in cert.key_usage


@pytest.mark.asyncio
async def test_get_certificate_invalid_session(mock_provider):
    """Test certificate retrieval with invalid session"""
    with pytest.raises(CertificateError, match="Invalid session"):
        await mock_provider.get_certificate("invalid_session", "test_user")


@pytest.mark.asyncio
async def test_signing_success(mock_provider):
    """Test successful document signing"""
    signing_request = SigningRequest(
        document=b"test_document",
        document_name="test.pdf",
        document_mime_type="application/pdf",
        signature_format=SignatureFormat.PADES_B,
        user_id="test_user",
        session_id="test_session_123"
    )
    
    result = await mock_provider.sign(signing_request)
    
    assert result.signed_document == b"test_document_signed"
    assert result.signature_id == "sig_123"
    assert result.signature_format == SignatureFormat.PADES_B
    assert result.certificate_used.subject_dn == "CN=Test User,O=Test Org"


@pytest.mark.asyncio
async def test_signing_failure(mock_provider):
    """Test failed document signing"""
    signing_request = SigningRequest(
        document=b"test_document",
        document_name="test.pdf",
        document_mime_type="application/pdf",
        signature_format=SignatureFormat.PADES_B,
        user_id="invalid_user",
        session_id="test_session_123"
    )
    
    with pytest.raises(SigningError, match="Signing failed"):
        await mock_provider.sign(signing_request)


@pytest.mark.asyncio
async def test_verification_success(mock_provider):
    """Test successful signature verification"""
    result = await mock_provider.verify(b"signed_document")
    
    assert result.is_valid is True
    assert result.signature_format == SignatureFormat.XADES_B
    assert result.trust_status == "valid"
    assert result.revocation_status == "good"
    assert result.timestamp_valid is True
    assert len(result.validation_errors) == 0


def test_health_check(mock_provider):
    """Test health check functionality"""
    health = asyncio.run(mock_provider.health_check())
    
    assert health["provider"] == "mock_provider"
    assert health["country"] == "SE"
    assert "status" in health


def test_supported_formats(mock_provider):
    """Test supported signature formats"""
    formats = mock_provider.get_supported_formats()
    
    assert SignatureFormat.XADES_B in formats
    assert SignatureFormat.PADES_B in formats
    assert len(formats) >= 4


def test_config_validation_success(mock_provider):
    """Test successful configuration validation"""
    is_valid = mock_provider.validate_config()
    assert is_valid is True


def test_config_validation_failure():
    """Test failed configuration validation"""
    provider = MockQESProvider({"invalid": "config"})
    
    with pytest.raises(QESProviderError, match="Missing required configuration field"):
        provider.validate_config()


def test_signature_formats():
    """Test signature format enum values"""
    assert SignatureFormat.XADES_B.value == "XAdES-B"
    assert SignatureFormat.XADES_T.value == "XAdES-T"
    assert SignatureFormat.PADES_LTA.value == "PAdES-LTA"


def test_authentication_status():
    """Test authentication status enum values"""
    assert AuthenticationStatus.PENDING.value == "pending"
    assert AuthenticationStatus.AUTHENTICATED.value == "authenticated"
    assert AuthenticationStatus.FAILED.value == "failed"
    assert AuthenticationStatus.EXPIRED.value == "expired"


def test_qes_provider_error():
    """Test QES provider error handling"""
    error = QESProviderError(
        "Test error",
        error_code="TEST_ERROR",
        details={"key": "value"}
    )
    
    assert str(error) == "Test error"
    assert error.error_code == "TEST_ERROR"
    assert error.details == {"key": "value"}


def test_authentication_error():
    """Test authentication error inheritance"""
    error = AuthenticationError("Auth failed")
    assert isinstance(error, QESProviderError)
    assert str(error) == "Auth failed"


def test_signing_error():
    """Test signing error inheritance"""
    error = SigningError("Signing failed")
    assert isinstance(error, QESProviderError)
    assert str(error) == "Signing failed"


def test_certificate_error():
    """Test certificate error inheritance"""
    error = CertificateError("Cert error")
    assert isinstance(error, QESProviderError)
    assert str(error) == "Cert error"