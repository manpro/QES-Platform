"""
FNMT QES Provider Implementation

Provides integration with FNMT (Fábrica Nacional de Moneda y Timbre)
for Spanish qualified electronic signatures.
"""

import json
import logging
import hashlib
import secrets
import base64
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, parse_qs

import requests
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from ..base.qes_provider import QESProvider, AuthenticationResult, Certificate, SigningRequest, SigningResult, VerificationResult
from .models import (
    FNMTConfig, FNMTAuthRequest, FNMTAuthResponse,
    FNMTSigningRequest, FNMTSigningResponse, FNMTCertificate,
    FNMTSignatureType
)
from .exceptions import (
    FNMTException, FNMTAuthenticationException, FNMTSigningException,
    FNMTAPIException, FNMTTokenException, FNMTCertificateException,
    FNMTDNIException
)


logger = logging.getLogger(__name__)


class FNMTQESProvider(QESProvider):
    """
    FNMT QES Provider for Spain
    
    Supports:
    - eIDAS Level of Assurance High
    - Spanish DNI/NIF identity verification 
    - Qualified electronic signatures
    - Remote signing capabilities
    - ENI compliance (Esquema Nacional de Interoperabilidad)
    - Spanish government certificate validation
    """
    
    def __init__(self, config: FNMTConfig):
        """
        Initialize FNMT QES provider
        
        Args:
            config: FNMT configuration
        """
        self.config = config
        self.session = requests.Session()
        self.session.timeout = config.timeout
        
        # Setup retry strategy
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=config.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Setup default headers
        self.session.headers.update({
            "User-Agent": "QES-Platform-FNMT/1.0",
            "Accept": "application/json",
            "Content-Type": "application/json"
        })
        
        logger.info(f"Initialized FNMT QES provider for {config.environment.value}")
    
    async def authenticate(self, user_identifier: str, **kwargs) -> AuthenticationResult:
        """
        Authenticate user with FNMT
        
        Args:
            user_identifier: DNI, NIF, or email
            **kwargs: Additional parameters
            
        Returns:
            Authentication result with authorization URL
        """
        try:
            # Validate DNI/NIF if provided
            if self._is_spanish_id(user_identifier):
                if not self._validate_spanish_id(user_identifier):
                    raise FNMTDNIException(f"Invalid DNI/NIF format: {user_identifier}")
            
            # Generate state and nonce for security
            state = secrets.token_urlsafe(32)
            nonce = secrets.token_urlsafe(32)
            
            # Create authentication request
            auth_request = FNMTAuthRequest(
                state=state,
                nonce=nonce,
                auth_method=kwargs.get("auth_method", self.config.auth_method),
                locale=kwargs.get("locale", "es-ES"),
                max_age=kwargs.get("max_age", 3600)
            )
            
            # Build authorization URL
            auth_params = {
                "response_type": auth_request.response_type,
                "client_id": self.config.client_id,
                "redirect_uri": self.config.redirect_uri,
                "scope": auth_request.scope,
                "state": auth_request.state,
                "nonce": auth_request.nonce,
                "acr_values": auth_request.acr_values,
                "locale": auth_request.locale,
                "auth_method": auth_request.auth_method.value,
                "eidas_loa": auth_request.eidas_loa,
                "eidas_natural_person": str(auth_request.eidas_natural_person).lower()
            }
            
            if auth_request.max_age:
                auth_params["max_age"] = str(auth_request.max_age)
            if auth_request.prompt:
                auth_params["prompt"] = auth_request.prompt
            if self.config.dni_verification_required:
                auth_params["dni_required"] = "true"
            if self.config.certificate_validation_strict:
                auth_params["strict_validation"] = "true"
            
            authorization_url = f"{self.config.auth_url}?{urlencode(auth_params)}"
            
            # Store session data for callback verification
            session_data = {
                "state": state,
                "nonce": nonce,
                "timestamp": datetime.utcnow().isoformat(),
                "user_identifier": user_identifier,
                "auth_method": auth_request.auth_method.value
            }
            
            logger.info(f"Created FNMT authentication request for user: {user_identifier}")
            
            return AuthenticationResult(
                provider="fnmt",
                session_id=state,
                authorization_url=authorization_url,
                expires_at=datetime.utcnow() + timedelta(minutes=15),
                metadata={
                    "state": state,
                    "nonce": nonce,
                    "loa": auth_request.acr_values,
                    "auth_method": auth_request.auth_method.value,
                    "dni_verification": self.config.dni_verification_required,
                    "environment": self.config.environment.value,
                    "eidas_compliant": True
                }
            )
            
        except FNMTException:
            raise
        except Exception as e:
            logger.error(f"FNMT authentication failed: {e}")
            raise FNMTAuthenticationException(f"Authentication request failed: {e}")
    
    async def handle_callback(self, callback_data: Dict[str, str]) -> FNMTAuthResponse:
        """
        Handle FNMT OAuth callback
        
        Args:
            callback_data: Callback parameters from FNMT
            
        Returns:
            Authentication response with tokens
        """
        try:
            # Extract callback parameters
            code = callback_data.get("code")
            state = callback_data.get("state")
            error = callback_data.get("error")
            
            if error:
                error_description = callback_data.get("error_description", "Unknown error")
                raise FNMTAuthenticationException(
                    f"Authentication error: {error} - {error_description}",
                    error=error
                )
            
            if not code or not state:
                raise FNMTAuthenticationException("Missing authorization code or state parameter")
            
            # Exchange authorization code for tokens
            token_data = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.config.redirect_uri,
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret
            }
            
            response = self.session.post(self.config.token_url, data=token_data)
            
            if not response.ok:
                logger.error(f"Token exchange failed: {response.status_code} - {response.text}")
                raise FNMTTokenException(f"Token exchange failed: {response.status_code}")
            
            token_response = response.json()
            
            # Get user information
            user_info = await self._get_user_info(token_response["access_token"])
            
            now = datetime.utcnow()
            expires_at = now + timedelta(seconds=token_response.get("expires_in", 3600))
            
            return FNMTAuthResponse(
                access_token=token_response["access_token"],
                token_type=token_response.get("token_type", "Bearer"),
                expires_in=token_response.get("expires_in", 3600),
                refresh_token=token_response.get("refresh_token"),
                id_token=token_response.get("id_token"),
                scope=token_response.get("scope", ""),
                user_id=user_info["user_id"],
                given_name=user_info.get("given_name", ""),
                family_name=user_info.get("family_name", ""),
                email=user_info.get("email", ""),
                dni=user_info.get("dni"),
                nif=user_info.get("nif"),
                date_of_birth=user_info.get("date_of_birth"),
                certificate_dn=user_info.get("certificate_dn"),
                certificate_serial=user_info.get("certificate_serial"),
                certificate_issuer=user_info.get("certificate_issuer"),
                loa_level=user_info.get("loa_level", "high"),
                eidas_compliant=user_info.get("eidas_compliant", True),
                auth_time=datetime.fromtimestamp(user_info.get("auth_time", now.timestamp())),
                issued_at=now,
                expires_at=expires_at
            )
            
        except FNMTException:
            raise
        except Exception as e:
            logger.error(f"FNMT callback handling failed: {e}")
            raise FNMTAuthenticationException(f"Callback handling failed: {e}")
    
    async def get_certificate(self, user_context: Dict[str, str]) -> Certificate:
        """
        Get user's qualified certificate from FNMT
        
        Args:
            user_context: User context from authentication
            
        Returns:
            User's certificate
        """
        try:
            access_token = user_context.get("access_token")
            if not access_token:
                raise FNMTException("Access token required for certificate retrieval")
            
            # Get user's certificates
            headers = {"Authorization": f"Bearer {access_token}"}
            cert_response = self.session.get(
                f"{self.config.certificates_url}/user/certificates",
                headers=headers
            )
            
            if not cert_response.ok:
                logger.error(f"Certificate retrieval failed: {cert_response.status_code}")
                raise FNMTAPIException(f"Certificate retrieval failed: {cert_response.status_code}")
            
            cert_data = cert_response.json()
            certificates = cert_data.get("certificates", [])
            
            if not certificates:
                raise FNMTCertificateException("No certificates found for user")
            
            # Select the first qualified certificate
            qualified_cert = None
            for cert in certificates:
                if (cert.get("certificate_type") == "qualified" and 
                    cert.get("status") == "active" and
                    cert.get("spanish_government_issued", True)):
                    qualified_cert = cert
                    break
            
            if not qualified_cert:
                raise FNMTCertificateException("No active qualified certificate found")
            
            # Parse certificate
            cert_pem = qualified_cert["certificate_pem"]
            cert_obj = x509.load_pem_x509_certificate(cert_pem.encode())
            
            # Extract certificate information
            subject = cert_obj.subject
            issuer = cert_obj.issuer
            
            return Certificate(
                certificate_pem=cert_pem,
                subject_dn=subject.rfc4514_string(),
                issuer_dn=issuer.rfc4514_string(),
                serial_number=str(cert_obj.serial_number),
                valid_from=cert_obj.not_valid_before,
                valid_to=cert_obj.not_valid_after,
                key_usage=self._extract_key_usage(cert_obj),
                certificate_chain=qualified_cert.get("certificate_chain", []),
                provider="fnmt",
                metadata={
                    "certificate_id": qualified_cert.get("certificate_id"),
                    "certificate_type": "qualified",
                    "qscd_status": qualified_cert.get("qscd_status", True),
                    "dni_embedded": qualified_cert.get("dni_embedded", False),
                    "eni_compliant": qualified_cert.get("eni_compliant", True),
                    "spanish_government_issued": True,
                    "loa": user_context.get("loa_level", "high"),
                    "eidas_compliant": True
                }
            )
            
        except FNMTException:
            raise
        except Exception as e:
            logger.error(f"Certificate retrieval failed: {e}")
            raise FNMTException(f"Certificate retrieval failed: {e}")
    
    async def sign(self, signing_request: SigningRequest, user_context: Dict[str, str]) -> SigningResult:
        """
        Sign document with FNMT remote signing
        
        Args:
            signing_request: Document signing request
            user_context: User context from authentication
            
        Returns:
            Signing result
        """
        try:
            access_token = user_context.get("access_token")
            if not access_token:
                raise FNMTSigningException("Access token required for signing")
            
            # Upload document first
            document_id = await self._upload_document(
                signing_request.document,
                signing_request.document_name or "document",
                access_token
            )
            
            # Calculate document hash
            document_hash = hashlib.sha256(signing_request.document).hexdigest()
            
            # Create FNMT signing request
            fnmt_request = FNMTSigningRequest(
                document_id=document_id,
                document_hash=document_hash,
                hash_algorithm="SHA256",
                document_name=signing_request.document_name or "document",
                signature_format=signing_request.signature_format,
                signature_level=self._extract_signature_level(signing_request.signature_format),
                signature_type=FNMTSignatureType.QUALIFIED,
                certificate_id=signing_request.metadata.get("certificate_id"),
                timestamp_required=True,
                reason=signing_request.metadata.get("reason"),
                location=signing_request.metadata.get("location"),
                contact_info=signing_request.metadata.get("contact_info")
            )
            
            # Submit signing request
            signing_data = {
                "document_id": fnmt_request.document_id,
                "document_hash": fnmt_request.document_hash,
                "hash_algorithm": fnmt_request.hash_algorithm,
                "signature_format": fnmt_request.signature_format,
                "signature_level": fnmt_request.signature_level,
                "signature_type": fnmt_request.signature_type.value,
                "timestamp_required": fnmt_request.timestamp_required,
                "eni_compliant": fnmt_request.eni_compliant,
                "spanish_gov_approval": fnmt_request.spanish_gov_approval
            }
            
            if fnmt_request.certificate_id:
                signing_data["certificate_id"] = fnmt_request.certificate_id
            if fnmt_request.reason:
                signing_data["reason"] = fnmt_request.reason
            if fnmt_request.location:
                signing_data["location"] = fnmt_request.location
            
            headers = {"Authorization": f"Bearer {access_token}"}
            response = self.session.post(
                f"{self.config.signing_url}/sign",
                json=signing_data,
                headers=headers
            )
            
            if not response.ok:
                logger.error(f"Signing request failed: {response.status_code} - {response.text}")
                raise FNMTSigningException(f"Signing request failed: {response.status_code}")
            
            signing_response = response.json()
            signature_id = signing_response["signature_id"]
            status = signing_response.get("status", "pending")
            
            if status == "completed":
                return self._create_completed_signing_result(signing_response, document_id)
            else:
                return SigningResult(
                    signature_id=signature_id,
                    status="pending",
                    provider="fnmt",
                    metadata={
                        "fnmt_signature_id": signature_id,
                        "document_id": document_id,
                        "confirmation_required": True,
                        "polling_url": f"{self.config.signing_url}/sign/{signature_id}",
                        "estimated_completion": "30 seconds to 2 minutes"
                    }
                )
                
        except FNMTException:
            raise
        except Exception as e:
            logger.error(f"FNMT signing failed: {e}")
            raise FNMTSigningException(f"Signing failed: {e}")
    
    async def get_signing_status(self, signature_id: str, user_context: Dict[str, str]) -> SigningResult:
        """
        Get status of FNMT signing operation
        
        Args:
            signature_id: FNMT signature ID
            user_context: User context
            
        Returns:
            Current signing status
        """
        try:
            access_token = user_context.get("access_token")
            if not access_token:
                raise FNMTException("Access token required")
            
            headers = {"Authorization": f"Bearer {access_token}"}
            response = self.session.get(
                f"{self.config.signing_url}/sign/{signature_id}",
                headers=headers
            )
            
            if not response.ok:
                raise FNMTAPIException(f"Status check failed: {response.status_code}")
            
            status_data = response.json()
            status = status_data.get("status", "unknown")
            
            if status == "completed":
                document_id = status_data.get("document_id")
                return self._create_completed_signing_result(status_data, document_id)
            elif status in ["pending", "user_action_required"]:
                return SigningResult(
                    signature_id=signature_id,
                    status="pending",
                    provider="fnmt",
                    metadata={
                        "fnmt_signature_id": signature_id,
                        "current_status": status,
                        "updated_at": datetime.utcnow().isoformat()
                    }
                )
            elif status in ["failed", "cancelled", "expired"]:
                return SigningResult(
                    signature_id=signature_id,
                    status="failed",
                    provider="fnmt",
                    error_code=status_data.get("error_code"),
                    error_message=status_data.get("error_message", f"Signing {status}"),
                    metadata={"fnmt_status": status}
                )
            else:
                raise FNMTSigningException(f"Unknown status: {status}")
                
        except FNMTException:
            raise
        except Exception as e:
            logger.error(f"Status check failed: {e}")
            raise FNMTAPIException(f"Status check failed: {e}")
    
    async def verify(self, document: bytes, signature: bytes, **kwargs) -> VerificationResult:
        """
        Verify FNMT signature
        
        Args:
            document: Original document
            signature: Signature to verify
            **kwargs: Additional parameters
            
        Returns:
            Verification result
        """
        try:
            # Upload signature for verification
            verification_data = {
                "signature_data": base64.b64encode(signature).decode(),
                "document_data": base64.b64encode(document).decode(),
                "verification_level": "full",
                "check_eni_compliance": True,
                "check_spanish_regulations": True
            }
            
            response = self.session.post(
                f"{self.config.verification_url}/verify",
                json=verification_data
            )
            
            if not response.ok:
                logger.error(f"Verification failed: {response.status_code}")
                return VerificationResult(
                    is_valid=False,
                    provider="fnmt",
                    error_message=f"Verification API failed: {response.status_code}",
                    verification_time=datetime.utcnow()
                )
            
            verification_result = response.json()
            
            return VerificationResult(
                is_valid=verification_result.get("is_valid", False),
                provider="fnmt",
                signature_format=verification_result.get("signature_format"),
                signer_certificate=verification_result.get("signer_certificate"),
                signing_time=datetime.fromisoformat(verification_result.get("signing_time")) if verification_result.get("signing_time") else None,
                verification_time=datetime.utcnow(),
                trust_anchor=verification_result.get("trust_anchor", "FNMT Qualified CA"),
                revocation_status=verification_result.get("revocation_status", "unknown"),
                loa_level="high",
                metadata={
                    "verification_method": "fnmt_qualified",
                    "eidas_compliant": True,
                    "eni_compliant": verification_result.get("eni_compliant", True),
                    "spanish_government_approved": verification_result.get("spanish_government_approved", True),
                    "qscd_status": verification_result.get("qscd_status", True),
                    "verification_details": verification_result.get("details", {}),
                    "regulatory_evidence": verification_result.get("regulatory_evidence", {})
                }
            )
            
        except Exception as e:
            logger.error(f"FNMT signature verification failed: {e}")
            return VerificationResult(
                is_valid=False,
                provider="fnmt",
                error_message=f"Verification failed: {e}",
                verification_time=datetime.utcnow()
            )
    
    async def _get_user_info(self, access_token: str) -> Dict[str, any]:
        """Get user information from FNMT"""
        headers = {"Authorization": f"Bearer {access_token}"}
        response = self.session.get(f"{self.config.api_base_url}/user/info", headers=headers)
        
        if not response.ok:
            raise FNMTAPIException(f"User info retrieval failed: {response.status_code}")
        
        return response.json()
    
    async def _upload_document(self, document: bytes, document_name: str, access_token: str) -> str:
        """Upload document to FNMT for signing"""
        headers = {"Authorization": f"Bearer {access_token}"}
        
        files = {
            "document": (document_name, document, "application/octet-stream")
        }
        
        response = self.session.post(
            f"{self.config.api_base_url}/documents/upload",
            files=files,
            headers=headers
        )
        
        if not response.ok:
            raise FNMTAPIException(f"Document upload failed: {response.status_code}")
        
        upload_result = response.json()
        return upload_result["document_id"]
    
    def _extract_signature_level(self, format_str: str) -> str:
        """Extract signature level from format"""
        if format_str.endswith("-LTA"):
            return "LTA"
        elif format_str.endswith("-T"):
            return "T"
        else:
            return "B"
    
    def _is_spanish_id(self, identifier: str) -> bool:
        """Check if identifier is a Spanish DNI or NIF"""
        # DNI: 8 digits + 1 letter
        # NIF: Various formats for legal entities
        dni_pattern = r'^\d{8}[A-Z]$'
        nif_pattern = r'^[A-Z]\d{7}[0-9A-Z]$'
        
        identifier = identifier.upper().replace('-', '').replace(' ', '')
        return bool(re.match(dni_pattern, identifier) or re.match(nif_pattern, identifier))
    
    def _validate_spanish_id(self, identifier: str) -> bool:
        """Validate Spanish DNI/NIF using check digit algorithm"""
        identifier = identifier.upper().replace('-', '').replace(' ', '')
        
        if len(identifier) != 9:
            return False
        
        # DNI validation
        if identifier[0].isdigit():
            digits = identifier[:8]
            check_letter = identifier[8]
            letters = "TRWAGMYFPDXBNJZSQVHLCKE"
            expected_letter = letters[int(digits) % 23]
            return check_letter == expected_letter
        
        # Basic NIF validation (simplified)
        elif identifier[0].isalpha():
            # More complex validation would be needed for full NIF support
            return True
        
        return False
    
    def _extract_key_usage(self, cert: x509.Certificate) -> List[str]:
        """Extract key usage from certificate"""
        try:
            key_usage_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
            key_usage = key_usage_ext.value
            
            usages = []
            if key_usage.digital_signature:
                usages.append("digital_signature")
            if key_usage.non_repudiation:
                usages.append("non_repudiation")
            if key_usage.key_encipherment:
                usages.append("key_encipherment")
            
            return usages
        except x509.ExtensionNotFound:
            return ["digital_signature", "non_repudiation"]
    
    def _create_completed_signing_result(self, response_data: Dict[str, any], document_id: str) -> SigningResult:
        """Create completed signing result from FNMT response"""
        return SigningResult(
            signature_id=response_data["signature_id"],
            status="completed",
            signature_value=response_data.get("signature_value"),
            signature_algorithm=response_data.get("signature_algorithm", "RSA_SHA256"),
            certificate=response_data.get("signing_certificate"),
            certificate_chain=response_data.get("certificate_chain", []),
            timestamp_token=response_data.get("timestamp_token"),
            provider="fnmt",
            signed_at=datetime.fromisoformat(response_data.get("signing_time", datetime.utcnow().isoformat())),
            metadata={
                "fnmt_signature_id": response_data["signature_id"],
                "document_id": document_id,
                "signature_format": response_data.get("signature_format"),
                "signature_level": response_data.get("signature_level"),
                "loa": "high",
                "eidas_compliant": True,
                "eni_compliant": response_data.get("eni_compliant", True),
                "spanish_government_approved": True,
                "qscd_status": True,
                "signed_document_url": response_data.get("signed_document_url"),
                "regulatory_evidence": response_data.get("regulatory_evidence", {})
            }
        )