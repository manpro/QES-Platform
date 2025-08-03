"""
Certinomis QES Provider Implementation

Provides integration with Certinomis trust service provider
for French qualified electronic signatures.
"""

import json
import logging
import hashlib
import secrets
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, parse_qs

import requests
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from ..base.qes_provider import QESProvider, AuthenticationResult, Certificate, SigningRequest, SigningResult, VerificationResult
from .models import (
    CertinomisConfig, CertinomisAuthRequest, CertinomisAuthResponse, 
    CertinomisSigningRequest, CertinomisSigningResponse, CertinomisCertificate,
    CertinomisSignatureType, CertinomisVisualSignature
)
from .exceptions import (
    CertinomisException, CertinomisAuthenticationException, CertinomisSigningException,
    CertinomisAPIException, CertinomisTokenException, CertinomisCertificateException
)


logger = logging.getLogger(__name__)


class CertinomisQESProvider(QESProvider):
    """
    Certinomis QES Provider for France
    
    Supports:
    - eIDAS Level of Assurance High
    - French national identity verification
    - Qualified electronic signatures
    - FranceConnect integration
    - Remote signing capabilities
    """
    
    def __init__(self, config: CertinomisConfig):
        """
        Initialize Certinomis QES provider
        
        Args:
            config: Certinomis configuration
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
            "User-Agent": "QES-Platform-Certinomis/1.0",
            "Accept": "application/json",
            "Content-Type": "application/json"
        })
        
        logger.info(f"Initialized Certinomis QES provider for {config.environment.value}")
    
    async def authenticate(self, user_identifier: str, **kwargs) -> AuthenticationResult:
        """
        Authenticate user with Certinomis
        
        Args:
            user_identifier: Email or phone number
            **kwargs: Additional parameters
            
        Returns:
            Authentication result with authorization URL
        """
        try:
            # Generate state and nonce for security
            state = secrets.token_urlsafe(32)
            nonce = secrets.token_urlsafe(32)
            
            # Create authentication request
            auth_request = CertinomisAuthRequest(
                state=state,
                nonce=nonce,
                locale=kwargs.get("locale", "fr-FR"),
                max_age=kwargs.get("max_age", 3600),
                france_connect=kwargs.get("france_connect", False)
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
                "signature_type": auth_request.signature_type.value,
                "certificate_profile": auth_request.certificate_profile
            }
            
            if auth_request.max_age:
                auth_params["max_age"] = str(auth_request.max_age)
            if auth_request.prompt:
                auth_params["prompt"] = auth_request.prompt
            if auth_request.france_connect:
                auth_params["france_connect"] = "true"
                if self.config.france_connect_client_id:
                    auth_params["fc_client_id"] = self.config.france_connect_client_id
            
            authorization_url = f"{self.config.auth_url}?{urlencode(auth_params)}"
            
            # Store session data for callback verification
            session_data = {
                "state": state,
                "nonce": nonce,
                "timestamp": datetime.utcnow().isoformat(),
                "user_identifier": user_identifier,
                "auth_method": self.config.auth_method.value
            }
            
            logger.info(f"Created Certinomis authentication request for user: {user_identifier}")
            
            return AuthenticationResult(
                provider="certinomis",
                session_id=state,
                authorization_url=authorization_url,
                expires_at=datetime.utcnow() + timedelta(minutes=15),
                metadata={
                    "state": state,
                    "nonce": nonce,
                    "loa": auth_request.acr_values,
                    "signature_type": auth_request.signature_type.value,
                    "france_connect": auth_request.france_connect,
                    "environment": self.config.environment.value
                }
            )
            
        except Exception as e:
            logger.error(f"Certinomis authentication failed: {e}")
            raise CertinomisAuthenticationException(f"Authentication request failed: {e}")
    
    async def handle_callback(self, callback_data: Dict[str, str]) -> CertinomisAuthResponse:
        """
        Handle Certinomis OAuth callback
        
        Args:
            callback_data: Callback parameters from Certinomis
            
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
                raise CertinomisAuthenticationException(
                    f"Authentication error: {error} - {error_description}", 
                    error=error
                )
            
            if not code or not state:
                raise CertinomisAuthenticationException("Missing authorization code or state parameter")
            
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
                raise CertinomisTokenException(f"Token exchange failed: {response.status_code}")
            
            token_response = response.json()
            
            # Get user information
            user_info = await self._get_user_info(token_response["access_token"])
            
            now = datetime.utcnow()
            expires_at = now + timedelta(seconds=token_response.get("expires_in", 3600))
            
            return CertinomisAuthResponse(
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
                siret=user_info.get("siret"),
                siren=user_info.get("siren"),
                certificate_dn=user_info.get("certificate_dn"),
                certificate_serial=user_info.get("certificate_serial"),
                loa_level=user_info.get("loa_level", "high"),
                eidas_compliant=user_info.get("eidas_compliant", True),
                auth_time=datetime.fromtimestamp(user_info.get("auth_time", now.timestamp())),
                issued_at=now,
                expires_at=expires_at
            )
            
        except CertinomisException:
            raise
        except Exception as e:
            logger.error(f"Certinomis callback handling failed: {e}")
            raise CertinomisAuthenticationException(f"Callback handling failed: {e}")
    
    async def get_certificate(self, user_context: Dict[str, str]) -> Certificate:
        """
        Get user's qualified certificate from Certinomis
        
        Args:
            user_context: User context from authentication
            
        Returns:
            User's certificate
        """
        try:
            access_token = user_context.get("access_token")
            if not access_token:
                raise CertinomisException("Access token required for certificate retrieval")
            
            # Get user's certificates
            headers = {"Authorization": f"Bearer {access_token}"}
            cert_response = self.session.get(
                f"{self.config.certificates_url}/user/certificates",
                headers=headers
            )
            
            if not cert_response.ok:
                logger.error(f"Certificate retrieval failed: {cert_response.status_code}")
                raise CertinomisAPIException(f"Certificate retrieval failed: {cert_response.status_code}")
            
            cert_data = cert_response.json()
            certificates = cert_data.get("certificates", [])
            
            if not certificates:
                raise CertinomisCertificateException("No certificates found for user")
            
            # Select the first qualified certificate
            qualified_cert = None
            for cert in certificates:
                if cert.get("certificate_type") == "qualified" and cert.get("status") == "active":
                    qualified_cert = cert
                    break
            
            if not qualified_cert:
                raise CertinomisCertificateException("No active qualified certificate found")
            
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
                provider="certinomis",
                metadata={
                    "certificate_id": qualified_cert.get("certificate_id"),
                    "certificate_type": "qualified",
                    "qscd_status": qualified_cert.get("qscd_status", True),
                    "loa": user_context.get("loa_level", "high"),
                    "eidas_compliant": True
                }
            )
            
        except CertinomisException:
            raise
        except Exception as e:
            logger.error(f"Certificate retrieval failed: {e}")
            raise CertinomisException(f"Certificate retrieval failed: {e}")
    
    async def sign(self, signing_request: SigningRequest, user_context: Dict[str, str]) -> SigningResult:
        """
        Sign document with Certinomis remote signing
        
        Args:
            signing_request: Document signing request
            user_context: User context from authentication
            
        Returns:
            Signing result
        """
        try:
            access_token = user_context.get("access_token")
            if not access_token:
                raise CertinomisSigningException("Access token required for signing")
            
            # Upload document first
            document_id = await self._upload_document(
                signing_request.document,
                signing_request.document_name or "document",
                access_token
            )
            
            # Calculate document hash
            document_hash = hashlib.sha256(signing_request.document).hexdigest()
            
            # Prepare visual signature if needed (for PDF)
            visual_signature = None
            if signing_request.signature_format.startswith("PAdES") and signing_request.metadata.get("visual_signature"):
                visual_signature = self._prepare_visual_signature(signing_request.metadata["visual_signature"])
            
            # Create Certinomis signing request
            certinomis_request = CertinomisSigningRequest(
                document_id=document_id,
                document_hash=document_hash,
                hash_algorithm="SHA256",
                document_name=signing_request.document_name or "document",
                document_mime_type=signing_request.metadata.get("mime_type", "application/pdf"),
                signature_format=signing_request.signature_format,
                signature_level=self._extract_signature_level(signing_request.signature_format),
                signature_type=CertinomisSignatureType.QUALIFIED,
                certificate_id=signing_request.metadata.get("certificate_id"),
                visual_signature=visual_signature,
                timestamp_required=True,
                reason=signing_request.metadata.get("reason"),
                location=signing_request.metadata.get("location"),
                contact_info=signing_request.metadata.get("contact_info")
            )
            
            # Submit signing request
            signing_data = {
                "document_id": certinomis_request.document_id,
                "document_hash": certinomis_request.document_hash,
                "hash_algorithm": certinomis_request.hash_algorithm,
                "signature_format": certinomis_request.signature_format,
                "signature_level": certinomis_request.signature_level,
                "signature_type": certinomis_request.signature_type.value,
                "timestamp_required": certinomis_request.timestamp_required
            }
            
            if certinomis_request.certificate_id:
                signing_data["certificate_id"] = certinomis_request.certificate_id
            if certinomis_request.visual_signature:
                signing_data["visual_signature"] = certinomis_request.visual_signature
            if certinomis_request.reason:
                signing_data["reason"] = certinomis_request.reason
            if certinomis_request.location:
                signing_data["location"] = certinomis_request.location
            
            headers = {"Authorization": f"Bearer {access_token}"}
            response = self.session.post(
                f"{self.config.signing_url}/sign",
                json=signing_data,
                headers=headers
            )
            
            if not response.ok:
                logger.error(f"Signing request failed: {response.status_code} - {response.text}")
                raise CertinomisSigningException(f"Signing request failed: {response.status_code}")
            
            signing_response = response.json()
            signature_id = signing_response["signature_id"]
            status = signing_response.get("status", "pending")
            
            if status == "completed":
                # Signature completed immediately
                return self._create_completed_signing_result(signing_response, document_id)
            else:
                # Signature pending (requires user confirmation)
                return SigningResult(
                    signature_id=signature_id,
                    status="pending",
                    provider="certinomis",
                    metadata={
                        "certinomis_signature_id": signature_id,
                        "document_id": document_id,
                        "confirmation_required": True,
                        "polling_url": f"{self.config.signing_url}/sign/{signature_id}",
                        "estimated_completion": "1-3 minutes"
                    }
                )
                
        except CertinomisException:
            raise
        except Exception as e:
            logger.error(f"Certinomis signing failed: {e}")
            raise CertinomisSigningException(f"Signing failed: {e}")
    
    async def get_signing_status(self, signature_id: str, user_context: Dict[str, str]) -> SigningResult:
        """
        Get status of Certinomis signing operation
        
        Args:
            signature_id: Certinomis signature ID
            user_context: User context
            
        Returns:
            Current signing status
        """
        try:
            access_token = user_context.get("access_token")
            if not access_token:
                raise CertinomisException("Access token required")
            
            headers = {"Authorization": f"Bearer {access_token}"}
            response = self.session.get(
                f"{self.config.signing_url}/sign/{signature_id}",
                headers=headers
            )
            
            if not response.ok:
                raise CertinomisAPIException(f"Status check failed: {response.status_code}")
            
            status_data = response.json()
            status = status_data.get("status", "unknown")
            
            if status == "completed":
                document_id = status_data.get("document_id")
                return self._create_completed_signing_result(status_data, document_id)
            elif status in ["pending", "user_action_required"]:
                return SigningResult(
                    signature_id=signature_id,
                    status="pending",
                    provider="certinomis",
                    metadata={
                        "certinomis_signature_id": signature_id,
                        "current_status": status,
                        "updated_at": datetime.utcnow().isoformat()
                    }
                )
            elif status in ["failed", "cancelled", "expired"]:
                return SigningResult(
                    signature_id=signature_id,
                    status="failed",
                    provider="certinomis",
                    error_code=status_data.get("error_code"),
                    error_message=status_data.get("error_message", f"Signing {status}"),
                    metadata={"certinomis_status": status}
                )
            else:
                raise CertinomisSigningException(f"Unknown status: {status}")
                
        except CertinomisException:
            raise
        except Exception as e:
            logger.error(f"Status check failed: {e}")
            raise CertinomisAPIException(f"Status check failed: {e}")
    
    async def verify(self, document: bytes, signature: bytes, **kwargs) -> VerificationResult:
        """
        Verify Certinomis signature
        
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
                "verification_level": "full"
            }
            
            response = self.session.post(
                f"{self.config.api_base_url}/verification/verify",
                json=verification_data
            )
            
            if not response.ok:
                logger.error(f"Verification failed: {response.status_code}")
                return VerificationResult(
                    is_valid=False,
                    provider="certinomis",
                    error_message=f"Verification API failed: {response.status_code}",
                    verification_time=datetime.utcnow()
                )
            
            verification_result = response.json()
            
            return VerificationResult(
                is_valid=verification_result.get("is_valid", False),
                provider="certinomis",
                signature_format=verification_result.get("signature_format"),
                signer_certificate=verification_result.get("signer_certificate"),
                signing_time=datetime.fromisoformat(verification_result.get("signing_time")) if verification_result.get("signing_time") else None,
                verification_time=datetime.utcnow(),
                trust_anchor=verification_result.get("trust_anchor", "Certinomis Qualified CA"),
                revocation_status=verification_result.get("revocation_status", "unknown"),
                loa_level="high",
                metadata={
                    "verification_method": "certinomis_qualified",
                    "eidas_compliant": True,
                    "qscd_status": verification_result.get("qscd_status", True),
                    "verification_details": verification_result.get("details", {})
                }
            )
            
        except Exception as e:
            logger.error(f"Certinomis signature verification failed: {e}")
            return VerificationResult(
                is_valid=False,
                provider="certinomis",
                error_message=f"Verification failed: {e}",
                verification_time=datetime.utcnow()
            )
    
    async def _get_user_info(self, access_token: str) -> Dict[str, any]:
        """Get user information from Certinomis"""
        headers = {"Authorization": f"Bearer {access_token}"}
        response = self.session.get(f"{self.config.api_base_url}/user/info", headers=headers)
        
        if not response.ok:
            raise CertinomisAPIException(f"User info retrieval failed: {response.status_code}")
        
        return response.json()
    
    async def _upload_document(self, document: bytes, document_name: str, access_token: str) -> str:
        """Upload document to Certinomis for signing"""
        headers = {"Authorization": f"Bearer {access_token}"}
        
        files = {
            "document": (document_name, document, "application/octet-stream")
        }
        
        # Remove Content-Type header for multipart upload
        upload_headers = headers.copy()
        
        response = self.session.post(
            f"{self.config.api_base_url}/documents/upload",
            files=files,
            headers=upload_headers
        )
        
        if not response.ok:
            raise CertinomisAPIException(f"Document upload failed: {response.status_code}")
        
        upload_result = response.json()
        return upload_result["document_id"]
    
    def _prepare_visual_signature(self, visual_config: Dict[str, any]) -> Dict[str, any]:
        """Prepare visual signature configuration"""
        visual_sig = CertinomisVisualSignature(**visual_config)
        
        return {
            "page": visual_sig.page,
            "x": visual_sig.x,
            "y": visual_sig.y,
            "width": visual_sig.width,
            "height": visual_sig.height,
            "text": visual_sig.text,
            "font_size": visual_sig.font_size,
            "font_color": visual_sig.font_color,
            "show_signature_time": visual_sig.show_signature_time,
            "show_signer_name": visual_sig.show_signer_name,
            "show_reason": visual_sig.show_reason,
            "show_location": visual_sig.show_location
        }
    
    def _extract_signature_level(self, format_str: str) -> str:
        """Extract signature level from format"""
        if format_str.endswith("-LTA"):
            return "LTA"
        elif format_str.endswith("-T"):
            return "T"
        else:
            return "B"
    
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
        """Create completed signing result from Certinomis response"""
        return SigningResult(
            signature_id=response_data["signature_id"],
            status="completed",
            signature_value=response_data.get("signature_value"),
            signature_algorithm=response_data.get("signature_algorithm", "RSA_SHA256"),
            certificate=response_data.get("signing_certificate"),
            certificate_chain=response_data.get("certificate_chain", []),
            timestamp_token=response_data.get("timestamp_token"),
            provider="certinomis",
            signed_at=datetime.fromisoformat(response_data.get("signing_time", datetime.utcnow().isoformat())),
            metadata={
                "certinomis_signature_id": response_data["signature_id"],
                "document_id": document_id,
                "signature_format": response_data.get("signature_format"),
                "signature_level": response_data.get("signature_level"),
                "loa": "high",
                "eidas_compliant": True,
                "qscd_status": True,
                "signed_document_url": response_data.get("signed_document_url")
            }
        )