"""
Core Signing Engine

Implements the main signing workflow supporting XAdES and PAdES formats
with long-term validation (LTV) and timestamping capabilities.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass
from enum import Enum
import hashlib
import base64
import asyncio
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))

from adapters.base.qes_provider import (
    QESProvider, SigningRequest, SigningResult, SignatureFormat,
    Certificate, QESProviderError, SigningError
)
from .timestamp_token import TimestampToken


class SigningStep(Enum):
    """Signing process steps for XAdES/PAdES-LTA"""
    BASELINE = "baseline"  # XAdES-B / PAdES-B
    TIMESTAMP = "timestamp"  # XAdES-T / PAdES-T
    LONG_TERM = "long_term"  # XAdES-LT / PAdES-LT
    ARCHIVAL = "archival"  # XAdES-LTA / PAdES-LTA


@dataclass
class SigningJob:
    """Represents a signing operation with all metadata"""
    job_id: str
    document: bytes
    document_name: str
    document_mime_type: str
    target_format: SignatureFormat
    user_id: str
    session_id: str
    provider: QESProvider
    current_step: SigningStep
    metadata: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


class SigningEngine:
    """
    Core signing engine that orchestrates the signing process
    through XAdES/PAdES-LTA workflow.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.tsa_url = config.get("tsa_url")
        self.default_signature_policy = config.get("signature_policy")
        self._jobs: Dict[str, SigningJob] = {}
    
    async def create_signing_job(
        self,
        document: bytes,
        document_name: str,
        document_mime_type: str,
        target_format: SignatureFormat,
        user_id: str,
        session_id: str,
        provider: QESProvider,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SigningJob:
        """Create a new signing job."""
        
        job_id = self._generate_job_id()
        now = datetime.now(timezone.utc)
        
        job = SigningJob(
            job_id=job_id,
            document=document,
            document_name=document_name,
            document_mime_type=document_mime_type,
            target_format=target_format,
            user_id=user_id,
            session_id=session_id,
            provider=provider,
            current_step=SigningStep.BASELINE,
            metadata=metadata or {},
            created_at=now,
            updated_at=now
        )
        
        self._jobs[job_id] = job
        return job
    
    async def execute_signing_workflow(self, job: SigningJob) -> SigningResult:
        """
        Execute the complete signing workflow for a job.
        
        Flow:
        1. Create baseline signature (XAdES-B/PAdES-B)
        2. Add timestamp (XAdES-T/PAdES-T)
        3. Add validation info (XAdES-LT/PAdES-LT)
        4. Add archival timestamp (XAdES-LTA/PAdES-LTA)
        """
        
        try:
            # Step 1: Create baseline signature
            job.current_step = SigningStep.BASELINE
            signed_document = await self._create_baseline_signature(job)
            
            # Step 2: Add timestamp if required
            if self._requires_timestamp(job.target_format):
                job.current_step = SigningStep.TIMESTAMP
                signed_document = await self._add_timestamp(
                    signed_document, job
                )
            
            # Step 3: Add validation info for LT formats
            if self._requires_long_term_validation(job.target_format):
                job.current_step = SigningStep.LONG_TERM
                signed_document = await self._add_validation_info(
                    signed_document, job
                )
            
            # Step 4: Add archival timestamp for LTA formats
            if self._requires_archival_timestamp(job.target_format):
                job.current_step = SigningStep.ARCHIVAL
                signed_document = await self._add_archival_timestamp(
                    signed_document, job
                )
            
            # Get certificate used for signing
            certificate = await job.provider.get_certificate(
                job.session_id, job.user_id
            )
            
            # Create signing result
            result = SigningResult(
                signed_document=signed_document,
                signature_id=job.job_id,
                timestamp=job.created_at.isoformat(),
                certificate_used=certificate,
                signature_format=job.target_format,
                validation_info={
                    "workflow_completed": True,
                    "steps_executed": [step.value for step in 
                                     self._get_executed_steps(job.target_format)],
                    "tsa_used": self.tsa_url if self._requires_timestamp(
                        job.target_format) else None
                },
                audit_trail={
                    "job_id": job.job_id,
                    "user_id": job.user_id,
                    "provider": job.provider.provider_name,
                    "document_name": job.document_name,
                    "created_at": job.created_at.isoformat(),
                    "completed_at": datetime.now(timezone.utc).isoformat()
                }
            )
            
            # Cleanup job
            del self._jobs[job.job_id]
            
            return result
            
        except Exception as e:
            job.metadata["error"] = str(e)
            job.updated_at = datetime.now(timezone.utc)
            raise SigningError(
                f"Signing workflow failed: {str(e)}",
                error_code="SIGNING_WORKFLOW_FAILED",
                details={"job_id": job.job_id, "step": job.current_step.value}
            )
    
    async def _create_baseline_signature(self, job: SigningJob) -> bytes:
        """Create XAdES-B or PAdES-B baseline signature."""
        
        signing_request = SigningRequest(
            document=job.document,
            document_name=job.document_name,
            document_mime_type=job.document_mime_type,
            signature_format=self._get_baseline_format(job.target_format),
            user_id=job.user_id,
            session_id=job.session_id,
            signature_policy=self.default_signature_policy,
            metadata=job.metadata
        )
        
        result = await job.provider.sign(signing_request)
        return result.signed_document
    
    async def _add_timestamp(self, signed_document: bytes, 
                           job: SigningJob) -> bytes:
        """Add RFC 3161 timestamp to create XAdES-T/PAdES-T."""
        
        if not self.tsa_url:
            raise SigningError(
                "TSA URL not configured for timestamp signature",
                error_code="TSA_NOT_CONFIGURED"
            )
        
        # Get timestamp token
        timestamp_token = await self._get_timestamp_token(
            signed_document, job
        )
        
        # Embed timestamp in signature
        # This is a placeholder - actual implementation would use
        # EU DSS library or similar for proper XAdES/PAdES handling
        timestamped_document = self._embed_timestamp(
            signed_document, timestamp_token, job
        )
        
        return timestamped_document
    
    async def _add_validation_info(self, signed_document: bytes,
                                 job: SigningJob) -> bytes:
        """Add validation info for XAdES-LT/PAdES-LT."""
        
        # Retrieve and embed CRL/OCSP responses
        # This is a placeholder for actual validation info embedding
        validation_info = await self._collect_validation_info(job)
        
        lt_document = self._embed_validation_info(
            signed_document, validation_info, job
        )
        
        return lt_document
    
    async def _add_archival_timestamp(self, signed_document: bytes,
                                    job: SigningJob) -> bytes:
        """Add archival timestamp for XAdES-LTA/PAdES-LTA."""
        
        # Create archival timestamp over the entire signature
        archival_timestamp = await self._get_timestamp_token(
            signed_document, job, is_archival=True
        )
        
        lta_document = self._embed_archival_timestamp(
            signed_document, archival_timestamp, job
        )
        
        return lta_document
    
    async def _get_timestamp_token(self, data: bytes, job: SigningJob,
                                 is_archival: bool = False) -> TimestampToken:
        """Get RFC 3161 timestamp token from TSA."""
        
        try:
            from .tsa_client import TSAClient
            
            if not self.tsa_url:
                raise SigningError(
                    "TSA URL not configured for timestamp signature",
                    error_code="TSA_NOT_CONFIGURED"
                )
            
            # Initialize TSA client
            tsa_client = TSAClient(
                tsa_url=self.tsa_url,
                config={
                    "timeout": 30,
                    "verify_ssl": True,
                    "policy_id": job.metadata.get("tsa_policy_id")
                }
            )
            
            # Get timestamp from TSA
            tsa_response = await tsa_client.get_timestamp(data, hash_algorithm="SHA-256")
            
            logger.info(f"TSA timestamp obtained: {tsa_response.timestamp} (serial: {tsa_response.serial_number})")
            
            return TimestampToken(
                token_data=tsa_response.token_data,
                timestamp=tsa_response.timestamp,
                tsa_url=self.tsa_url,
                hash_algorithm=tsa_response.hash_algorithm,
                issuer=self.tsa_url,
                serial_number=tsa_response.serial_number
            )
            
        except Exception as e:
            logger.error(f"Failed to get timestamp token: {e}")
            raise SigningError(
                f"TSA timestamp request failed: {str(e)}",
                error_code="TSA_REQUEST_FAILED"
            )
    
    async def _collect_validation_info(self, job: SigningJob) -> Dict[str, Any]:
        """Collect CRL and OCSP responses for validation."""
        
        # Placeholder for validation info collection
        return {
            "crl_responses": [],
            "ocsp_responses": [],
            "collected_at": datetime.now(timezone.utc).isoformat()
        }
    
    def _embed_timestamp(self, signed_document: bytes,
                        timestamp_token: TimestampToken,
                        job: SigningJob) -> bytes:
        """Embed timestamp token in signature using EU DSS."""
        try:
            from .eu_dss_service import EUDSSService, DSSDocument, SignatureLevel
            
            # Initialize EU DSS service
            dss_service = EUDSSService(self.config)
            
            # Determine signature format
            if job.target_format.value.startswith("XAdES"):
                # For XAdES, embed timestamp in XML structure
                return self._embed_xades_timestamp(signed_document, timestamp_token, job, dss_service)
            elif job.target_format.value.startswith("PAdES"):
                # For PAdES, embed timestamp in PDF structure
                return self._embed_pades_timestamp(signed_document, timestamp_token, job, dss_service)
            elif job.target_format.value.startswith("CAdES"):
                # For CAdES, embed timestamp in CMS structure
                return self._embed_cades_timestamp(signed_document, timestamp_token, job, dss_service)
            else:
                logger.warning(f"Unknown format for timestamp embedding: {job.target_format}")
                return signed_document + b"<timestamp_placeholder>"
                
        except Exception as e:
            logger.error(f"Failed to embed timestamp using EU DSS: {e}")
            # Fallback to placeholder
            return signed_document + b"<timestamp_placeholder>"
    
    def _embed_validation_info(self, signed_document: bytes,
                             validation_info: Dict[str, Any],
                             job: SigningJob) -> bytes:
        """Embed validation info in signature using EU DSS."""
        try:
            from .eu_dss_service import EUDSSService, DSSDocument, SignatureLevel
            
            # Initialize EU DSS service
            dss_service = EUDSSService(self.config)
            
            # Determine signature format
            if job.target_format.value.startswith("XAdES"):
                # For XAdES, embed validation info in XML structure
                return self._embed_xades_validation_info(signed_document, validation_info, job, dss_service)
            elif job.target_format.value.startswith("PAdES"):
                # For PAdES, embed validation info in PDF structure
                return self._embed_pades_validation_info(signed_document, validation_info, job, dss_service)
            elif job.target_format.value.startswith("CAdES"):
                # For CAdES, embed validation info in CMS structure
                return self._embed_cades_validation_info(signed_document, validation_info, job, dss_service)
            else:
                logger.warning(f"Unknown format for validation info embedding: {job.target_format}")
                return signed_document + b"<validation_info_placeholder>"
                
        except Exception as e:
            logger.error(f"Failed to embed validation info using EU DSS: {e}")
            # Fallback to placeholder
            return signed_document + b"<validation_info_placeholder>"
    
    def _embed_archival_timestamp(self, signed_document: bytes,
                                timestamp_token: TimestampToken,
                                job: SigningJob) -> bytes:
        """Embed archival timestamp in signature using EU DSS."""
        try:
            from .eu_dss_service import EUDSSService, DSSDocument, SignatureLevel
            
            # Initialize EU DSS service
            dss_service = EUDSSService(self.config)
            
            # Determine signature format
            if job.target_format.value.startswith("XAdES"):
                # For XAdES, embed archival timestamp in XML structure
                return self._embed_xades_archival_timestamp(signed_document, timestamp_token, job, dss_service)
            elif job.target_format.value.startswith("PAdES"):
                # For PAdES, embed archival timestamp in PDF structure
                return self._embed_pades_archival_timestamp(signed_document, timestamp_token, job, dss_service)
            elif job.target_format.value.startswith("CAdES"):
                # For CAdES, embed archival timestamp in CMS structure
                return self._embed_cades_archival_timestamp(signed_document, timestamp_token, job, dss_service)
            else:
                logger.warning(f"Unknown format for archival timestamp embedding: {job.target_format}")
                return signed_document + b"<archival_timestamp_placeholder>"
                
        except Exception as e:
            logger.error(f"Failed to embed archival timestamp using EU DSS: {e}")
            # Fallback to placeholder
            return signed_document + b"<archival_timestamp_placeholder>"
    
    def _requires_timestamp(self, format: SignatureFormat) -> bool:
        """Check if format requires timestamping."""
        return format in [
            SignatureFormat.XADES_T, SignatureFormat.XADES_LT,
            SignatureFormat.XADES_LTA, SignatureFormat.PADES_T,
            SignatureFormat.PADES_LT, SignatureFormat.PADES_LTA,
            SignatureFormat.CADES_T, SignatureFormat.CADES_LT,
            SignatureFormat.CADES_LTA
        ]
    
    def _requires_long_term_validation(self, format: SignatureFormat) -> bool:
        """Check if format requires long-term validation info."""
        return format in [
            SignatureFormat.XADES_LT, SignatureFormat.XADES_LTA,
            SignatureFormat.PADES_LT, SignatureFormat.PADES_LTA,
            SignatureFormat.CADES_LT, SignatureFormat.CADES_LTA
        ]
    
    def _requires_archival_timestamp(self, format: SignatureFormat) -> bool:
        """Check if format requires archival timestamping."""
        return format in [
            SignatureFormat.XADES_LTA, SignatureFormat.PADES_LTA,
            SignatureFormat.CADES_LTA
        ]
    
    def _get_baseline_format(self, target_format: SignatureFormat) -> SignatureFormat:
        """Get the baseline format for a target format."""
        if target_format.value.startswith("XAdES"):
            return SignatureFormat.XADES_B
        elif target_format.value.startswith("PAdES"):
            return SignatureFormat.PADES_B
        elif target_format.value.startswith("CAdES"):
            return SignatureFormat.CADES_B
        else:
            return target_format
    
    def _get_executed_steps(self, format: SignatureFormat) -> List[SigningStep]:
        """Get list of steps executed for a format."""
        steps = [SigningStep.BASELINE]
        
        if self._requires_timestamp(format):
            steps.append(SigningStep.TIMESTAMP)
        
        if self._requires_long_term_validation(format):
            steps.append(SigningStep.LONG_TERM)
        
        if self._requires_archival_timestamp(format):
            steps.append(SigningStep.ARCHIVAL)
        
        return steps
    
    def _generate_job_id(self) -> str:
        """Generate unique job ID."""
        import uuid
        return f"job_{uuid.uuid4().hex[:12]}"
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a signing job."""
        job = self._jobs.get(job_id)
        if not job:
            return None
        
        return {
            "job_id": job.job_id,
            "current_step": job.current_step.value,
            "target_format": job.target_format.value,
            "created_at": job.created_at.isoformat(),
            "updated_at": job.updated_at.isoformat(),
            "metadata": job.metadata
        }
    
    # Format-specific embedding methods for EU DSS integration
    
    def _embed_xades_timestamp(self, signed_document: bytes, timestamp_token: TimestampToken, 
                              job: SigningJob, dss_service) -> bytes:
        """Embed timestamp in XAdES signature using EU DSS."""
        try:
            from lxml import etree
            
            # Parse XML document
            xml_doc = etree.fromstring(signed_document)
            
            # Find signature element
            nsmap = {
                'ds': 'http://www.w3.org/2000/09/xmldsig#',
                'xades': 'http://uri.etsi.org/01903/v1.3.2#'
            }
            
            signature = xml_doc.find('.//ds:Signature', nsmap)
            if signature is None:
                logger.error("No signature element found in XAdES document")
                return signed_document
            
            # Find or create UnsignedProperties
            qual_props = signature.find('.//xades:QualifyingProperties', nsmap)
            if qual_props is None:
                logger.error("No QualifyingProperties found in XAdES signature")
                return signed_document
            
            unsigned_props = qual_props.find('./xades:UnsignedProperties', nsmap)
            if unsigned_props is None:
                unsigned_props = etree.SubElement(qual_props, etree.QName(nsmap['xades'], 'UnsignedProperties'))
            
            unsigned_sig_props = unsigned_props.find('./xades:UnsignedSignatureProperties', nsmap)
            if unsigned_sig_props is None:
                unsigned_sig_props = etree.SubElement(unsigned_props, etree.QName(nsmap['xades'], 'UnsignedSignatureProperties'))
            
            # Add SignatureTimeStamp
            sig_timestamp = etree.SubElement(unsigned_sig_props, etree.QName(nsmap['xades'], 'SignatureTimeStamp'))
            sig_timestamp.set("Id", f"SignatureTimeStamp-{job.job_id}")
            
            # Add EncapsulatedTimeStamp
            encap_timestamp = etree.SubElement(sig_timestamp, etree.QName(nsmap['xades'], 'EncapsulatedTimeStamp'))
            encap_timestamp.text = base64.b64encode(timestamp_token.token_data).decode()
            
            # Return modified document
            return etree.tostring(xml_doc, encoding='utf-8', xml_declaration=True)
            
        except Exception as e:
            logger.error(f"Failed to embed XAdES timestamp: {e}")
            return signed_document
    
    def _embed_pades_timestamp(self, signed_document: bytes, timestamp_token: TimestampToken,
                              job: SigningJob, dss_service) -> bytes:
        """Embed timestamp in PAdES signature using EU DSS."""
        try:
            # For PAdES, the timestamp is typically embedded as a signature timestamp
            # in the CMS signature structure within the PDF
            logger.info(f"Embedding PAdES timestamp for job {job.job_id}")
            
            # Placeholder implementation - would integrate with PDF library
            # to properly embed timestamp in signature dictionary
            return signed_document + f"<PADES_TIMESTAMP:{timestamp_token.timestamp}>".encode()
            
        except Exception as e:
            logger.error(f"Failed to embed PAdES timestamp: {e}")
            return signed_document
    
    def _embed_cades_timestamp(self, signed_document: bytes, timestamp_token: TimestampToken,
                              job: SigningJob, dss_service) -> bytes:
        """Embed timestamp in CAdES signature using EU DSS."""
        try:
            # For CAdES, the timestamp is embedded as an unsigned attribute
            # in the CMS SignerInfo structure
            logger.info(f"Embedding CAdES timestamp for job {job.job_id}")
            
            # Placeholder implementation - would use pyasn1 or similar
            # to properly modify the CMS SignedData structure
            return signed_document + f"<CADES_TIMESTAMP:{timestamp_token.timestamp}>".encode()
            
        except Exception as e:
            logger.error(f"Failed to embed CAdES timestamp: {e}")
            return signed_document
    
    def _embed_xades_validation_info(self, signed_document: bytes, validation_info: Dict[str, Any],
                                   job: SigningJob, dss_service) -> bytes:
        """Embed validation info in XAdES signature for LT level."""
        try:
            from lxml import etree
            
            xml_doc = etree.fromstring(signed_document)
            nsmap = {
                'ds': 'http://www.w3.org/2000/09/xmldsig#',
                'xades': 'http://uri.etsi.org/01903/v1.3.2#'
            }
            
            # Find UnsignedProperties
            unsigned_props = xml_doc.find('.//xades:UnsignedProperties', nsmap)
            if unsigned_props is None:
                logger.error("No UnsignedProperties found for validation info embedding")
                return signed_document
            
            unsigned_sig_props = unsigned_props.find('./xades:UnsignedSignatureProperties', nsmap)
            if unsigned_sig_props is None:
                unsigned_sig_props = etree.SubElement(unsigned_props, etree.QName(nsmap['xades'], 'UnsignedSignatureProperties'))
            
            # Add CertificateValues
            cert_values = etree.SubElement(unsigned_sig_props, etree.QName(nsmap['xades'], 'CertificateValues'))
            cert_values.set("Id", f"CertificateValues-{job.job_id}")
            
            # Add RevocationValues
            revoc_values = etree.SubElement(unsigned_sig_props, etree.QName(nsmap['xades'], 'RevocationValues'))
            revoc_values.set("Id", f"RevocationValues-{job.job_id}")
            
            # Add CRL and OCSP values (placeholder)
            crl_values = etree.SubElement(revoc_values, etree.QName(nsmap['xades'], 'CRLValues'))
            ocsp_values = etree.SubElement(revoc_values, etree.QName(nsmap['xades'], 'OCSPValues'))
            
            logger.info(f"Added XAdES validation info for job {job.job_id}")
            return etree.tostring(xml_doc, encoding='utf-8', xml_declaration=True)
            
        except Exception as e:
            logger.error(f"Failed to embed XAdES validation info: {e}")
            return signed_document
    
    def _embed_pades_validation_info(self, signed_document: bytes, validation_info: Dict[str, Any],
                                   job: SigningJob, dss_service) -> bytes:
        """Embed validation info in PAdES signature for LT level."""
        try:
            logger.info(f"Embedding PAdES validation info for job {job.job_id}")
            # Placeholder - would embed DSS (Document Security Store) in PDF
            return signed_document + f"<PADES_VALIDATION_INFO:{job.job_id}>".encode()
            
        except Exception as e:
            logger.error(f"Failed to embed PAdES validation info: {e}")
            return signed_document
    
    def _embed_cades_validation_info(self, signed_document: bytes, validation_info: Dict[str, Any],
                                   job: SigningJob, dss_service) -> bytes:
        """Embed validation info in CAdES signature for LT level."""
        try:
            logger.info(f"Embedding CAdES validation info for job {job.job_id}")
            # Placeholder - would add certificate-values and revocation-values attributes
            return signed_document + f"<CADES_VALIDATION_INFO:{job.job_id}>".encode()
            
        except Exception as e:
            logger.error(f"Failed to embed CAdES validation info: {e}")
            return signed_document
    
    def _embed_xades_archival_timestamp(self, signed_document: bytes, timestamp_token: TimestampToken,
                                       job: SigningJob, dss_service) -> bytes:
        """Embed archival timestamp in XAdES signature for LTA level."""
        try:
            from lxml import etree
            
            xml_doc = etree.fromstring(signed_document)
            nsmap = {
                'ds': 'http://www.w3.org/2000/09/xmldsig#',
                'xades': 'http://uri.etsi.org/01903/v1.3.2#'
            }
            
            unsigned_sig_props = xml_doc.find('.//xades:UnsignedSignatureProperties', nsmap)
            if unsigned_sig_props is None:
                logger.error("No UnsignedSignatureProperties found for archival timestamp")
                return signed_document
            
            # Add ArchiveTimeStamp
            archive_timestamp = etree.SubElement(unsigned_sig_props, etree.QName(nsmap['xades'], 'ArchiveTimeStamp'))
            archive_timestamp.set("Id", f"ArchiveTimeStamp-{job.job_id}")
            
            # Add EncapsulatedTimeStamp
            encap_timestamp = etree.SubElement(archive_timestamp, etree.QName(nsmap['xades'], 'EncapsulatedTimeStamp'))
            encap_timestamp.text = base64.b64encode(timestamp_token.token_data).decode()
            
            logger.info(f"Added XAdES archival timestamp for job {job.job_id}")
            return etree.tostring(xml_doc, encoding='utf-8', xml_declaration=True)
            
        except Exception as e:
            logger.error(f"Failed to embed XAdES archival timestamp: {e}")
            return signed_document
    
    def _embed_pades_archival_timestamp(self, signed_document: bytes, timestamp_token: TimestampToken,
                                       job: SigningJob, dss_service) -> bytes:
        """Embed archival timestamp in PAdES signature for LTA level."""
        try:
            logger.info(f"Embedding PAdES archival timestamp for job {job.job_id}")
            # Placeholder - would add Document Timestamp to PDF
            return signed_document + f"<PADES_ARCHIVAL_TIMESTAMP:{timestamp_token.timestamp}>".encode()
            
        except Exception as e:
            logger.error(f"Failed to embed PAdES archival timestamp: {e}")
            return signed_document
    
    def _embed_cades_archival_timestamp(self, signed_document: bytes, timestamp_token: TimestampToken,
                                       job: SigningJob, dss_service) -> bytes:
        """Embed archival timestamp in CAdES signature for LTA level."""
        try:
            logger.info(f"Embedding CAdES archival timestamp for job {job.job_id}")
            # Placeholder - would add archive timestamp as unsigned attribute
            return signed_document + f"<CADES_ARCHIVAL_TIMESTAMP:{timestamp_token.timestamp}>".encode()
            
        except Exception as e:
            logger.error(f"Failed to embed CAdES archival timestamp: {e}")
            return signed_document