"""
Unit tests for Core Signing Engine
"""

import pytest
import asyncio
from typing import Dict, Any
from datetime import datetime, timezone

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../'))

from backend.core.signing_engine import (
    SigningEngine, SigningJob, SigningStep, TimestampToken
)
from adapters.base.qes_provider import (
    SignatureFormat, SigningRequest, SigningResult, 
    Certificate, AuthenticationResult, AuthenticationStatus
)
from tests.unit.test_qes_provider import MockQESProvider


@pytest.fixture
def signing_engine():
    config = {
        "tsa_url": "https://test-tsa.example.com",
        "signature_policy": "test_policy"
    }
    return SigningEngine(config)


@pytest.fixture
def mock_provider():
    config = {
        "provider_name": "test_provider",
        "country_code": "SE"
    }
    return MockQESProvider(config)


@pytest.mark.asyncio
async def test_create_signing_job(signing_engine, mock_provider):
    """Test creating a new signing job"""
    job = await signing_engine.create_signing_job(
        document=b"test_document",
        document_name="test.pdf",
        document_mime_type="application/pdf",
        target_format=SignatureFormat.XADES_LTA,
        user_id="test_user",
        session_id="test_session",
        provider=mock_provider,
        metadata={"test": "value"}
    )
    
    assert job.document == b"test_document"
    assert job.document_name == "test.pdf"
    assert job.target_format == SignatureFormat.XADES_LTA
    assert job.current_step == SigningStep.BASELINE
    assert job.user_id == "test_user"
    assert job.session_id == "test_session"
    assert job.metadata["test"] == "value"
    assert job.job_id.startswith("job_")


@pytest.mark.asyncio
async def test_execute_baseline_workflow(signing_engine, mock_provider):
    """Test executing baseline signature workflow (XAdES-B)"""
    job = await signing_engine.create_signing_job(
        document=b"test_document",
        document_name="test.pdf",
        document_mime_type="application/pdf",
        target_format=SignatureFormat.XADES_B,
        user_id="test_user",
        session_id="test_session_123",
        provider=mock_provider
    )
    
    result = await signing_engine.execute_signing_workflow(job)
    
    assert result.signed_document == b"test_document_signed"
    assert result.signature_format == SignatureFormat.XADES_B
    assert result.validation_info["workflow_completed"] is True
    assert SigningStep.BASELINE.value in result.validation_info["steps_executed"]
    assert result.audit_trail["job_id"] == job.job_id


@pytest.mark.asyncio
async def test_execute_timestamped_workflow(signing_engine, mock_provider):
    """Test executing timestamped signature workflow (XAdES-T)"""
    job = await signing_engine.create_signing_job(
        document=b"test_document",
        document_name="test.pdf",
        document_mime_type="application/pdf",
        target_format=SignatureFormat.XADES_T,
        user_id="test_user",
        session_id="test_session_123",
        provider=mock_provider
    )
    
    result = await signing_engine.execute_signing_workflow(job)
    
    assert result.signature_format == SignatureFormat.XADES_T
    assert SigningStep.BASELINE.value in result.validation_info["steps_executed"]
    assert SigningStep.TIMESTAMP.value in result.validation_info["steps_executed"]
    assert result.validation_info["tsa_used"] == "https://test-tsa.example.com"


@pytest.mark.asyncio
async def test_execute_lta_workflow(signing_engine, mock_provider):
    """Test executing full LTA signature workflow (XAdES-LTA)"""
    job = await signing_engine.create_signing_job(
        document=b"test_document",
        document_name="test.pdf",
        document_mime_type="application/pdf",
        target_format=SignatureFormat.XADES_LTA,
        user_id="test_user",
        session_id="test_session_123",
        provider=mock_provider
    )
    
    result = await signing_engine.execute_signing_workflow(job)
    
    assert result.signature_format == SignatureFormat.XADES_LTA
    expected_steps = [
        SigningStep.BASELINE.value,
        SigningStep.TIMESTAMP.value,
        SigningStep.LONG_TERM.value,
        SigningStep.ARCHIVAL.value
    ]
    for step in expected_steps:
        assert step in result.validation_info["steps_executed"]


@pytest.mark.asyncio
async def test_execute_pades_workflow(signing_engine, mock_provider):
    """Test executing PAdES signature workflow"""
    job = await signing_engine.create_signing_job(
        document=b"test_pdf_document",
        document_name="test.pdf",
        document_mime_type="application/pdf",
        target_format=SignatureFormat.PADES_LTA,
        user_id="test_user",
        session_id="test_session_123",
        provider=mock_provider
    )
    
    result = await signing_engine.execute_signing_workflow(job)
    
    assert result.signature_format == SignatureFormat.PADES_LTA
    assert b"<timestamp_placeholder>" in result.signed_document
    assert b"<validation_info_placeholder>" in result.signed_document
    assert b"<archival_timestamp_placeholder>" in result.signed_document


def test_requires_timestamp(signing_engine):
    """Test timestamp requirement detection"""
    assert signing_engine._requires_timestamp(SignatureFormat.XADES_B) is False
    assert signing_engine._requires_timestamp(SignatureFormat.XADES_T) is True
    assert signing_engine._requires_timestamp(SignatureFormat.PADES_LTA) is True


def test_requires_long_term_validation(signing_engine):
    """Test long-term validation requirement detection"""
    assert signing_engine._requires_long_term_validation(SignatureFormat.XADES_B) is False
    assert signing_engine._requires_long_term_validation(SignatureFormat.XADES_T) is False
    assert signing_engine._requires_long_term_validation(SignatureFormat.XADES_LT) is True
    assert signing_engine._requires_long_term_validation(SignatureFormat.PADES_LTA) is True


def test_requires_archival_timestamp(signing_engine):
    """Test archival timestamp requirement detection"""
    assert signing_engine._requires_archival_timestamp(SignatureFormat.XADES_B) is False
    assert signing_engine._requires_archival_timestamp(SignatureFormat.XADES_LT) is False
    assert signing_engine._requires_archival_timestamp(SignatureFormat.XADES_LTA) is True
    assert signing_engine._requires_archival_timestamp(SignatureFormat.PADES_LTA) is True


def test_get_baseline_format(signing_engine):
    """Test baseline format detection"""
    assert signing_engine._get_baseline_format(SignatureFormat.XADES_LTA) == SignatureFormat.XADES_B
    assert signing_engine._get_baseline_format(SignatureFormat.PADES_T) == SignatureFormat.PADES_B
    assert signing_engine._get_baseline_format(SignatureFormat.CADES_LT) == SignatureFormat.CADES_B


def test_get_executed_steps(signing_engine):
    """Test executed steps calculation"""
    steps_b = signing_engine._get_executed_steps(SignatureFormat.XADES_B)
    assert steps_b == [SigningStep.BASELINE]
    
    steps_t = signing_engine._get_executed_steps(SignatureFormat.PADES_T)
    assert steps_t == [SigningStep.BASELINE, SigningStep.TIMESTAMP]
    
    steps_lta = signing_engine._get_executed_steps(SignatureFormat.XADES_LTA)
    assert steps_lta == [
        SigningStep.BASELINE,
        SigningStep.TIMESTAMP,
        SigningStep.LONG_TERM,
        SigningStep.ARCHIVAL
    ]


def test_generate_job_id(signing_engine):
    """Test job ID generation"""
    job_id1 = signing_engine._generate_job_id()
    job_id2 = signing_engine._generate_job_id()
    
    assert job_id1.startswith("job_")
    assert job_id2.startswith("job_")
    assert job_id1 != job_id2
    assert len(job_id1) == 16  # "job_" + 12 char hex


@pytest.mark.asyncio
async def test_get_job_status(signing_engine, mock_provider):
    """Test job status retrieval"""
    job = await signing_engine.create_signing_job(
        document=b"test_document",
        document_name="test.pdf",
        document_mime_type="application/pdf",
        target_format=SignatureFormat.XADES_B,
        user_id="test_user",
        session_id="test_session",
        provider=mock_provider
    )
    
    status = signing_engine.get_job_status(job.job_id)
    
    assert status is not None
    assert status["job_id"] == job.job_id
    assert status["current_step"] == SigningStep.BASELINE.value
    assert status["target_format"] == SignatureFormat.XADES_B.value
    
    # Test non-existent job
    assert signing_engine.get_job_status("non_existent") is None


def test_signing_step_enum():
    """Test SigningStep enum values"""
    assert SigningStep.BASELINE.value == "baseline"
    assert SigningStep.TIMESTAMP.value == "timestamp"
    assert SigningStep.LONG_TERM.value == "long_term"
    assert SigningStep.ARCHIVAL.value == "archival"


def test_timestamp_token():
    """Test TimestampToken dataclass"""
    token = TimestampToken(
        token_data=b"test_token",
        timestamp=datetime.now(timezone.utc),
        tsa_url="https://tsa.example.com",
        hash_algorithm="SHA-256",
        issuer="Test TSA"
    )
    
    assert token.token_data == b"test_token"
    assert token.tsa_url == "https://tsa.example.com"
    assert token.hash_algorithm == "SHA-256"
    assert token.issuer == "Test TSA"


@pytest.mark.asyncio
async def test_workflow_cleanup(signing_engine, mock_provider):
    """Test that completed jobs are cleaned up"""
    job = await signing_engine.create_signing_job(
        document=b"test_document",
        document_name="test.pdf",
        document_mime_type="application/pdf",
        target_format=SignatureFormat.XADES_B,
        user_id="test_user",
        session_id="test_session_123",
        provider=mock_provider
    )
    
    job_id = job.job_id
    
    # Job should exist before execution
    assert signing_engine.get_job_status(job_id) is not None
    
    # Execute workflow
    await signing_engine.execute_signing_workflow(job)
    
    # Job should be cleaned up after completion
    assert signing_engine.get_job_status(job_id) is None


def test_engine_configuration():
    """Test signing engine configuration"""
    config = {
        "tsa_url": "https://custom-tsa.example.com",
        "signature_policy": "custom_policy"
    }
    engine = SigningEngine(config)
    
    assert engine.tsa_url == "https://custom-tsa.example.com"
    assert engine.default_signature_policy == "custom_policy"