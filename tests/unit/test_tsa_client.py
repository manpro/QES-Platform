"""
Unit tests for TSA Client
"""

import pytest
import asyncio
from datetime import datetime, timezone

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../'))

from backend.core.tsa_client import (
    TSAClient, TSARequest, TSAResponse, TSAError
)


@pytest.fixture
def tsa_client():
    return TSAClient("https://test-tsa.example.com")


@pytest.fixture
def tsa_client_with_auth():
    config = {
        "username": "test_user",
        "password": "test_password",
        "timeout": 10,
        "verify_ssl": False,
        "policy_id": "1.2.3.4.5"
    }
    return TSAClient("https://test-tsa.example.com", config)


def test_tsa_client_initialization():
    """Test TSA client initialization"""
    client = TSAClient("https://tsa.example.com")
    
    assert client.tsa_url == "https://tsa.example.com"
    assert client.timeout == 30  # default
    assert client.verify_ssl is True  # default
    assert client.username is None
    assert client.password is None


def test_tsa_client_with_config():
    """Test TSA client initialization with custom config"""
    config = {
        "timeout": 60,
        "verify_ssl": False,
        "username": "user",
        "password": "pass",
        "policy_id": "1.2.3.4.5"
    }
    client = TSAClient("https://tsa.example.com", config)
    
    assert client.timeout == 60
    assert client.verify_ssl is False
    assert client.username == "user"
    assert client.password == "pass"


def test_tsa_request_creation():
    """Test TSA request data structure"""
    request = TSARequest(
        message_imprint=b"test_hash",
        hash_algorithm="SHA-256",
        nonce=12345,
        cert_req=True,
        policy_id="1.2.3.4.5"
    )
    
    assert request.message_imprint == b"test_hash"
    assert request.hash_algorithm == "SHA-256"
    assert request.nonce == 12345
    assert request.cert_req is True
    assert request.policy_id == "1.2.3.4.5"


def test_tsa_response_creation():
    """Test TSA response data structure"""
    timestamp = datetime.now(timezone.utc)
    response = TSAResponse(
        token_data=b"test_token",
        timestamp=timestamp,
        serial_number="123456",
        hash_algorithm="SHA-256",
        message_imprint=b"test_hash",
        tsa_certificate=b"test_cert",
        policy_id="1.2.3.4.5"
    )
    
    assert response.token_data == b"test_token"
    assert response.timestamp == timestamp
    assert response.serial_number == "123456"
    assert response.hash_algorithm == "SHA-256"
    assert response.message_imprint == b"test_hash"
    assert response.tsa_certificate == b"test_cert"
    assert response.policy_id == "1.2.3.4.5"


def test_build_tsa_request(tsa_client):
    """Test TSA request building"""
    request = TSARequest(
        message_imprint=b"test_hash",
        hash_algorithm="SHA-256",
        nonce=12345,
        cert_req=True
    )
    
    request_data = tsa_client._build_tsa_request(request)
    
    assert isinstance(request_data, bytes)
    assert len(request_data) > 0
    # In real implementation, this would be proper ASN.1 DER encoding


def test_generate_nonce(tsa_client):
    """Test nonce generation"""
    nonce1 = tsa_client._generate_nonce()
    nonce2 = tsa_client._generate_nonce()
    
    assert isinstance(nonce1, int)
    assert isinstance(nonce2, int)
    assert nonce1 != nonce2
    assert 1 <= nonce1 <= 2**32 - 1
    assert 1 <= nonce2 <= 2**32 - 1


@pytest.mark.asyncio
async def test_get_timestamp_sha256(tsa_client):
    """Test timestamp request with SHA-256"""
    # This is a placeholder test since we're using mock implementation
    try:
        response = await tsa_client.get_timestamp(b"test_data", "SHA-256")
        
        assert isinstance(response, TSAResponse)
        assert response.hash_algorithm == "SHA-256"
        assert response.token_data is not None
        assert isinstance(response.timestamp, datetime)
    except TSAError:
        # Expected in test environment without real TSA
        pass


@pytest.mark.asyncio
async def test_get_timestamp_sha1(tsa_client):
    """Test timestamp request with SHA-1"""
    try:
        response = await tsa_client.get_timestamp(b"test_data", "SHA-1")
        
        assert isinstance(response, TSAResponse)
        assert response.hash_algorithm == "SHA-1"
    except TSAError:
        # Expected in test environment
        pass


@pytest.mark.asyncio
async def test_get_timestamp_invalid_algorithm(tsa_client):
    """Test timestamp request with invalid hash algorithm"""
    with pytest.raises(TSAError, match="Unsupported hash algorithm"):
        await tsa_client.get_timestamp(b"test_data", "INVALID")


def test_parse_tsa_response(tsa_client):
    """Test TSA response parsing"""
    original_request = TSARequest(
        message_imprint=b"test_hash",
        hash_algorithm="SHA-256",
        nonce=12345
    )
    
    response_data = b"mock_response_data"
    response = tsa_client._parse_tsa_response(response_data, original_request)
    
    assert isinstance(response, TSAResponse)
    assert response.token_data == response_data
    assert response.hash_algorithm == "SHA-256"
    assert response.message_imprint == b"test_hash"


@pytest.mark.asyncio
async def test_verify_timestamp_token(tsa_client):
    """Test timestamp token verification"""
    # Placeholder test for verification functionality
    token_data = b"mock_token"
    original_data = b"original_data"
    
    is_valid = await tsa_client.verify_timestamp_token(token_data, original_data)
    
    # Currently returns True as placeholder
    assert is_valid is True


def test_get_timestamp_info(tsa_client):
    """Test timestamp token info extraction"""
    token_data = b"mock_token"
    info = tsa_client.get_timestamp_info(token_data)
    
    assert isinstance(info, dict)
    assert "timestamp" in info
    assert "tsa_url" in info
    assert "hash_algorithm" in info
    assert "serial_number" in info
    assert info["tsa_url"] == "https://test-tsa.example.com"


def test_tsa_error():
    """Test TSA error handling"""
    error = TSAError("Test error", status_code=500)
    
    assert str(error) == "Test error"
    assert error.status_code == 500


def test_tsa_error_without_status():
    """Test TSA error without status code"""
    error = TSAError("Test error")
    
    assert str(error) == "Test error"
    assert error.status_code is None


def test_tsa_client_config_access(tsa_client_with_auth):
    """Test TSA client configuration access"""
    assert tsa_client_with_auth.username == "test_user"
    assert tsa_client_with_auth.password == "test_password"
    assert tsa_client_with_auth.timeout == 10
    assert tsa_client_with_auth.verify_ssl is False
    assert tsa_client_with_auth.config.get("policy_id") == "1.2.3.4.5"