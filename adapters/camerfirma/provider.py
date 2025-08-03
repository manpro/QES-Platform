"""
Camerfirma QES Provider Implementation

Provides integration with Camerfirma trust service provider
for Spanish qualified electronic signatures with DNI/NIE support.
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
    CamerfirmaConfig, CamerfirmaAuthRequest, CamerfirmaAuthResponse,
    CamerfirmaSigningRequest, CamerfirmaSigningResponse, CamerfirmaCertificate,
    CamerfirmaSignatureType, CamerfirmaVisualSignature, CamerfirmaMobileSignature
)
from .exceptions import (
    CamerfirmaException, CamerfirmaAuthenticationException, CamerfirmaSigningException,
    CamerfirmaAPIException, CamerfirmaTokenException, CamerfirmaCertificateException,
    CamerfirmaDNIException, CamerfirmaMobileSignatureException
)


logger = logging.getLogger(__name__)


class CamerfirmaQESProvider(QESProvider):
    """
    Camerfirma QES Provider for Spain
    
    Supports:
    - eIDAS Level of Assurance High
    - Spanish DNI/NIE identity verification
    - Qualified electronic signatures
    - Mobile signatures
    - Remote signing capabilities
    - ENI compliance (Esquema Nacional de Interoperabilidad)
    """
    
    def __init__(self, config: CamerfirmaConfig):
        """
        Initialize Camerfirma QES provider
        
        Args:
            config: Camerfirma configuration
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
            "User-Agent": "QES-Platform-Camerfirma/1.0",
            "Accept": "application/json",
            "Content-Type": "application/json"
        })
        
        logger.info(f"Initialized Camerfirma QES provider for {config.environment.value}")
    
    async def authenticate(self, user_identifier: str, **kwargs) -> AuthenticationResult:
        """
        Authenticate user with Camerfirma
        
        Args:
            user_identifier: DNI, NIE, email or mobile number
            **kwargs: Additional parameters
            
        Returns:
            Authentication result with authorization URL
        """
        try:
            # Validate DNI/NIE if provided
            if self._is_dni_or_nie(user_identifier):
                if not self._validate_spanish_id(user_identifier):
                    raise CamerfirmaDNIException(f"Invalid DNI/NIE format: {user_identifier}")
            
            # Generate state and nonce for security
            state = secrets.token_urlsafe(32)
            nonce = secrets.token_urlsafe(32)
            
            # Determine authentication method
            auth_method = kwargs.get("auth_method", self.config.auth_method)
            if self._is_mobile_number(user_identifier):
                auth_method = CamerfirmaAuthMethod.MOBILE_SIGNATURE
            
            # Create authentication request
            auth_request = CamerfirmaAuthRequest(
                state=state,
                nonce=nonce,
                auth_method=auth_method,
                locale=kwargs.get("locale", "es-ES"),
                max_age=kwargs.get("max_age", 3600),
                mobile_number=user_identifier if self._is_mobile_number(user_identifier) else None,
                mobile_operator=kwargs.get("mobile_operator", self.config.mobile_operator)
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
                "signature_type": auth_request.signature_type.value
            }
            
            if auth_request.max_age:
                auth_params["max_age"] = str(auth_request.max_age)
            if auth_request.prompt:
                auth_params["prompt"] = auth_request.prompt
            if auth_request.mobile_number:
                auth_params["mobile_number"] = auth_request.mobile_number
            if auth_request.mobile_operator:
                auth_params["mobile_operator"] = auth_request.mobile_operator
            if self.config.dni_verification_required:
                auth_params["dni_required"] = "true"
            
            authorization_url = f"{self.config.auth_url}?{urlencode(auth_params)}"
            
            # Store session data for callback verification
            session_data = {
                "state": state,
                "nonce": nonce,
                "timestamp": datetime.utcnow().isoformat(),
                "user_identifier": user_identifier,
                "auth_method": auth_method.value
            }
            
            logger.info(f"Created Camerfirma authentication request for user: {user_identifier}")
            
            return AuthenticationResult(
                provider="camerfirma",
                session_id=state,
                authorization_url=authorization_url,
                expires_at=datetime.utcnow() + timedelta(minutes=15),
                metadata={
                    "state": state,
                    "nonce": nonce,
                    "loa": auth_request.acr_values,
                    "auth_method": auth_method.value,
                    "mobile_signature": auth_method == CamerfirmaAuthMethod.MOBILE_SIGNATURE,
                    "dni_verification": self.config.dni_verification_required,
                    "environment": self.config.environment.value
                }
            )
            
        except CamerfirmaException:
            raise
        except Exception as e:
            logger.error(f"Camerfirma authentication failed: {e}")
            raise CamerfirmaAuthenticationException(f"Authentication request failed: {e}")
    
    async def handle_callback(self, callback_data: Dict[str, str]) -> CamerfirmaAuthResponse:
        """
        Handle Camerfirma OAuth callback
        
        Args:
            callback_data: Callback parameters from Camerfirma
            
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
                raise CamerfirmaAuthenticationException(
                    f"Authentication error: {error} - {error_description}",
                    error=error
                )
            
            if not code or not state:
                raise CamerfirmaAuthenticationException("Missing authorization code or state parameter")
            
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
                raise CamerfirmaTokenException(f"Token exchange failed: {response.status_code}")
            
            token_response = response.json()
            
            # Get user information
            user_info = await self._get_user_info(token_response["access_token"])
            
            now = datetime.utcnow()
            expires_at = now + timedelta(seconds=token_response.get("expires_in", 3600))
            
            return CamerfirmaAuthResponse(
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
                nie=user_info.get("nie"),
                nif=user_info.get("nif"),
                certificate_dn=user_info.get("certificate_dn"),
                certificate_serial=user_info.get("certificate_serial"),
                certificate_issuer=user_info.get("certificate_issuer"),
                loa_level=user_info.get("loa_level", "high"),
                eidas_compliant=user_info.get("eidas_compliant", True),
                auth_time=datetime.fromtimestamp(user_info.get("auth_time", now.timestamp())),
                issued_at=now,
                expires_at=expires_at
            )
            
        except CamerfirmaException:
            raise
        except Exception as e:
            logger.error(f"Camerfirma callback handling failed: {e}")
            raise CamerfirmaAuthenticationException(f"Callback handling failed: {e}")
    
    async def get_certificate(self, user_context: Dict[str, str]) -> Certificate:
        """
        Get user's qualified certificate from Camerfirma
        
        Args:
            user_context: User context from authentication
            
        Returns:
            User's certificate
        """
        try:
            access_token = user_context.get("access_token")
            if not access_token:
                raise CamerfirmaException("Access token required for certificate retrieval")
            
            # Get user's certificates
            headers = {"Authorization": f"Bearer {access_token}"}
            cert_response = self.session.get(
                f"{self.config.certificates_url}/user/certificates",
                headers=headers
            )
            
            if not cert_response.ok:
                logger.error(f"Certificate retrieval failed: {cert_response.status_code}")
                raise CamerfirmaAPIException(f"Certificate retrieval failed: {cert_response.status_code}")
            
            cert_data = cert_response.json()
            certificates = cert_data.get("certificates", [])
            
            if not certificates:
                raise CamerfirmaCertificateException("No certificates found for user")
            
            # Select the first qualified certificate
            qualified_cert = None
            for cert in certificates:
                if (cert.get("certificate_type") == "qualified" and 
                    cert.get("status") == "active" and
                    cert.get("spanish_government_approved", False)):
                    qualified_cert = cert
                    break
            
            if not qualified_cert:
                raise CamerfirmaCertificateException("No active qualified certificate found")
            
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
                provider="camerfirma",
                metadata={
                    "certificate_id": qualified_cert.get("certificate_id"),
                    "certificate_type": "qualified",
                    "qscd_status": qualified_cert.get("qscd_status", True),
                    "dni_embedded": qualified_cert.get("dni_embedded", False),
                    "eni_compliant": qualified_cert.get("eni_compliant", True),
                    "spanish_government_approved": True,
                    "loa": user_context.get("loa_level", "high"),
                    "eidas_compliant": True
                }
            )
            
        except CamerfirmaException:
            raise
        except Exception as e:
            logger.error(f"Certificate retrieval failed: {e}")
            raise CamerfirmaException(f"Certificate retrieval failed: {e}")
    
    async def sign(self, signing_request: SigningRequest, user_context: Dict[str, str]) -> SigningResult:
        """
        Sign document with Camerfirma remote signing
        
        Args:
            signing_request: Document signing request
            user_context: User context from authentication
            
        Returns:
            Signing result
        """
        try:
            access_token = user_context.get("access_token")
            if not access_token:
                raise CamerfirmaSigningException("Access token required for signing")
            
            # Check if mobile signature is requested
            is_mobile_signature = signing_request.metadata.get("mobile_signature", False)
            
            if is_mobile_signature:
                return await self._sign_with_mobile(signing_request, user_context)
            else:
                return await self._sign_with_certificate(signing_request, user_context)
                
        except CamerfirmaException:
            raise
        except Exception as e:
            logger.error(f"Camerfirma signing failed: {e}")
            raise CamerfirmaSigningException(f"Signing failed: {e}")
    
    async def _sign_with_certificate(self, signing_request: SigningRequest, user_context: Dict[str, str]) -> SigningResult:
        """Sign document with certificate-based signing"""
        access_token = user_context.get("access_token")
        
        # Upload document first
        document_id = await self._upload_document(
            signing_request.document,
            signing_request.document_name or "document",
            access_token
        )
        
        # Calculate document hash
        document_hash = hashlib.sha256(signing_request.document).hexdigest()
        
        # Prepare visual signature if needed
        visual_signature = None
        if signing_request.signature_format.startswith("PAdES") and signing_request.metadata.get("visual_signature"):
            visual_signature = self._prepare_visual_signature(signing_request.metadata["visual_signature"])
        
        # Create Camerfirma signing request
        camerfirma_request = CamerfirmaSigningRequest(
            document_id=document_id,
            document_hash=document_hash,
            hash_algorithm="SHA256",
            document_name=signing_request.document_name or "document",
            document_type=self._detect_document_type(signing_request.document),
            signature_format=signing_request.signature_format,
            signature_level=self._extract_signature_level(signing_request.signature_format),
            signature_type=CamerfirmaSignatureType.QUALIFIED,
            certificate_id=signing_request.metadata.get("certificate_id"),
            visual_signature=visual_signature,
            timestamp_required=True,
            reason=signing_request.metadata.get("reason"),
            location=signing_request.metadata.get("location"),
            contact_info=signing_request.metadata.get("contact_info")
        )
        
        # Submit signing request
        signing_data = {
            "document_id": camerfirma_request.document_id,
            "document_hash": camerfirma_request.document_hash,
            "hash_algorithm": camerfirma_request.hash_algorithm,
            "document_type": camerfirma_request.document_type.value,
            "signature_format": camerfirma_request.signature_format,
            "signature_level": camerfirma_request.signature_level,
            "signature_type": camerfirma_request.signature_type.value,
            "timestamp_required": camerfirma_request.timestamp_required,
            "regulation_compliance": camerfirma_request.regulation_compliance
        }
        
        if camerfirma_request.certificate_id:
            signing_data["certificate_id"] = camerfirma_request.certificate_id
        if camerfirma_request.visual_signature:
            signing_data["visual_signature"] = camerfirma_request.visual_signature
        if camerfirma_request.reason:
            signing_data["reason"] = camerfirma_request.reason
        if camerfirma_request.location:
            signing_data["location"] = camerfirma_request.location
        
        headers = {"Authorization": f"Bearer {access_token}"}
        response = self.session.post(
            f"{self.config.signing_url}/sign",
            json=signing_data,
            headers=headers
        )
        
        if not response.ok:
            logger.error(f"Signing request failed: {response.status_code} - {response.text}")
            raise CamerfirmaSigningException(f"Signing request failed: {response.status_code}")
        
        signing_response = response.json()
        signature_id = signing_response["signature_id"]
        status = signing_response.get("status", "pending")
        
        if status == "completed":
            return self._create_completed_signing_result(signing_response, document_id)
        else:
            return SigningResult(
                signature_id=signature_id,
                status="pending",
                provider="camerfirma",
                metadata={
                    "camerfirma_signature_id": signature_id,
                    "document_id": document_id,
                    "confirmation_required": True,
                    "polling_url": f"{self.config.signing_url}/sign/{signature_id}",
                    "estimated_completion": "1-3 minutes"
                }
            )
    
    async def _sign_with_mobile(self, signing_request: SigningRequest, user_context: Dict[str, str]) -> SigningResult:
        """Sign document with mobile signature"""
        access_token = user_context.get("access_token")
        mobile_number = user_context.get("mobile_number") or signing_request.metadata.get("mobile_number")
        
        if not mobile_number:
            raise CamerfirmaMobileSignatureException("Mobile number required for mobile signature")
        
        # Configure mobile signature
        mobile_config = CamerfirmaMobileSignature(
            mobile_number=mobile_number,
            mobile_operator=signing_request.metadata.get("mobile_operator"),
            signature_text=signing_request.metadata.get("signature_text", "Confirmar firma electrónica"),
            language=signing_request.metadata.get("language", "es"),
            timeout_seconds=signing_request.metadata.get("timeout_seconds", 300)
        )
        
        # Upload document
        document_id = await self._upload_document(
            signing_request.document,
            signing_request.document_name or "document",
            access_token
        )
        
        # Submit mobile signing request
        mobile_signing_data = {
            "document_id": document_id,
            "mobile_number": mobile_config.mobile_number,
            "signature_text": mobile_config.signature_text,
            "language": mobile_config.language,
            "timeout_seconds": mobile_config.timeout_seconds,
            "signature_format": signing_request.signature_format
        }
        
        headers = {"Authorization": f"Bearer {access_token}"}
        response = self.session.post(
            f"{self.config.signing_url}/mobile-sign",
            json=mobile_signing_data,
            headers=headers
        )
        
        if not response.ok:
            raise CamerfirmaMobileSignatureException(f"Mobile signing failed: {response.status_code}")
        
        signing_response = response.json()
        
        return SigningResult(
            signature_id=signing_response["signature_id"],
            status="pending",
            provider="camerfirma",
            metadata={
                "camerfirma_signature_id": signing_response["signature_id"],
                "document_id": document_id,
                "mobile_signature": True,
                "mobile_number": mobile_config.mobile_number,
                "confirmation_method": "sms",
                "estimated_completion": "2-5 minutes"
            }
        )
    
    async def get_signing_status(self, signature_id: str, user_context: Dict[str, str]) -> SigningResult:
        """
        Get status of Camerfirma signing operation
        
        Args:
            signature_id: Camerfirma signature ID
            user_context: User context
            
        Returns:
            Current signing status
        """
        try:
            access_token = user_context.get("access_token")
            if not access_token:
                raise CamerfirmaException("Access token required")
            
            headers = {"Authorization": f"Bearer {access_token}"}
            response = self.session.get(
                f"{self.config.signing_url}/sign/{signature_id}",
                headers=headers
            )
            
            if not response.ok:
                raise CamerfirmaAPIException(f"Status check failed: {response.status_code}")
            
            status_data = response.json()
            status = status_data.get("status", "unknown")
            
            if status == "completed":
                document_id = status_data.get("document_id")
                return self._create_completed_signing_result(status_data, document_id)
            elif status in ["pending", "user_action_required", "sms_sent"]:
                return SigningResult(
                    signature_id=signature_id,
                    status="pending",
                    provider="camerfirma",
                    metadata={
                        "camerfirma_signature_id": signature_id,
                        "current_status": status,
                        "updated_at": datetime.utcnow().isoformat()
                    }
                )
            elif status in ["failed", "cancelled", "expired", "rejected"]:
                return SigningResult(
                    signature_id=signature_id,
                    status="failed",
                    provider="camerfirma",
                    error_code=status_data.get("error_code"),
                    error_message=status_data.get("error_message", f"Signing {status}"),
                    metadata={"camerfirma_status": status}
                )
            else:
                raise CamerfirmaSigningException(f"Unknown status: {status}")
                
        except CamerfirmaException:
            raise
        except Exception as e:
            logger.error(f"Status check failed: {e}")
            raise CamerfirmaAPIException(f"Status check failed: {e}")
    
    async def verify(self, document: bytes, signature: bytes, **kwargs) -> VerificationResult:
        """
        Verify Camerfirma signature
        
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
                    provider="camerfirma",
                    error_message=f"Verification API failed: {response.status_code}",
                    verification_time=datetime.utcnow()
                )
            
            verification_result = response.json()
            
            return VerificationResult(
                is_valid=verification_result.get("is_valid", False),
                provider="camerfirma",
                signature_format=verification_result.get("signature_format"),
                signer_certificate=verification_result.get("signer_certificate"),
                signing_time=datetime.fromisoformat(verification_result.get("signing_time")) if verification_result.get("signing_time") else None,
                verification_time=datetime.utcnow(),
                trust_anchor=verification_result.get("trust_anchor", "Camerfirma Qualified CA"),
                revocation_status=verification_result.get("revocation_status", "unknown"),
                loa_level="high",
                metadata={
                    "verification_method": "camerfirma_qualified",
                    "eidas_compliant": True,
                    "eni_compliant": verification_result.get("eni_compliant", True),
                    "spanish_government_approved": verification_result.get("spanish_government_approved", True),
                    "qscd_status": verification_result.get("qscd_status", True),
                    "verification_details": verification_result.get("details", {}),
                    "regulatory_evidence": verification_result.get("regulatory_evidence", {})
                }
            )
            
        except Exception as e:
            logger.error(f"Camerfirma signature verification failed: {e}")
            return VerificationResult(
                is_valid=False,
                provider="camerfirma",
                error_message=f"Verification failed: {e}",
                verification_time=datetime.utcnow()
            )
    
    async def _get_user_info(self, access_token: str) -> Dict[str, any]:
        """Get user information from Camerfirma"""
        headers = {"Authorization": f"Bearer {access_token}"}
        response = self.session.get(f"{self.config.api_base_url}/user/info", headers=headers)
        
        if not response.ok:
            raise CamerfirmaAPIException(f"User info retrieval failed: {response.status_code}")
        
        return response.json()
    
    async def _upload_document(self, document: bytes, document_name: str, access_token: str) -> str:
        """Upload document to Camerfirma for signing"""
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
            raise CamerfirmaAPIException(f"Document upload failed: {response.status_code}")
        
        upload_result = response.json()
        return upload_result["document_id"]
    
    def _prepare_visual_signature(self, visual_config: Dict[str, any]) -> Dict[str, any]:
        """Prepare visual signature configuration"""
        visual_sig = CamerfirmaVisualSignature(**visual_config)
        
        return {
            "page": visual_sig.page,
            "x": visual_sig.x,
            "y": visual_sig.y,
            "width": visual_sig.width,
            "height": visual_sig.height,
            "text": visual_sig.text,
            "font_size": visual_sig.font_size,
            "font_family": visual_sig.font_family,
            "font_color": visual_sig.font_color,
            "show_signature_time": visual_sig.show_signature_time,
            "show_signer_name": visual_sig.show_signer_name,
            "show_signer_dni": visual_sig.show_signer_dni,
            "show_reason": visual_sig.show_reason,
            "show_location": visual_sig.show_location,
            "show_regulatory_info": visual_sig.show_regulatory_info,
            "regulatory_text": visual_sig.regulatory_text
        }
    
    def _detect_document_type(self, document: bytes) -> str:
        """Detect document type from content"""
        if document.startswith(b'%PDF'):
            return "pdf"
        elif document.startswith(b'<?xml') or document.startswith(b'<'):
            return "xml"
        elif (document.startswith(b'PK\x03\x04') or  # ZIP-based formats
              document.startswith(b'\xd0\xcf\x11\xe0')):  # OLE formats
            return "office"
        else:
            return "binary"
    
    def _extract_signature_level(self, format_str: str) -> str:
        """Extract signature level from format"""
        if format_str.endswith("-LTA"):
            return "LTA"
        elif format_str.endswith("-T"):
            return "T"
        else:
            return "B"
    
    def _is_dni_or_nie(self, identifier: str) -> bool:
        """Check if identifier is a DNI or NIE"""
        # DNI: 8 digits + 1 letter
        # NIE: X/Y/Z + 7 digits + 1 letter
        dni_pattern = r'^\d{8}[A-Z]$'
        nie_pattern = r'^[XYZ]\d{7}[A-Z]$'
        
        identifier = identifier.upper().replace('-', '').replace(' ', '')
        return bool(re.match(dni_pattern, identifier) or re.match(nie_pattern, identifier))
    
    def _is_mobile_number(self, identifier: str) -> bool:
        """Check if identifier is a mobile number"""
        # Spanish mobile numbers: +34 6XX XXX XXX or 6XX XXX XXX
        mobile_pattern = r'^(\+34)?[67]\d{8}$'
        clean_number = re.sub(r'[\s-]', '', identifier)
        return bool(re.match(mobile_pattern, clean_number))
    
    def _validate_spanish_id(self, identifier: str) -> bool:
        """Validate Spanish DNI/NIE using check digit algorithm"""
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
        
        # NIE validation
        elif identifier[0] in 'XYZ':
            nie_conversion = {'X': '0', 'Y': '1', 'Z': '2'}
            digits = nie_conversion[identifier[0]] + identifier[1:8]
            check_letter = identifier[8]
            letters = "TRWAGMYFPDXBNJZSQVHLCKE"
            expected_letter = letters[int(digits) % 23]
            return check_letter == expected_letter
        
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
        """Create completed signing result from Camerfirma response"""
        return SigningResult(
            signature_id=response_data["signature_id"],
            status="completed",
            signature_value=response_data.get("signature_value"),
            signature_algorithm=response_data.get("signature_algorithm", "RSA_SHA256"),
            certificate=response_data.get("signing_certificate"),
            certificate_chain=response_data.get("certificate_chain", []),
            timestamp_token=response_data.get("timestamp_token"),
            provider="camerfirma",
            signed_at=datetime.fromisoformat(response_data.get("signing_time", datetime.utcnow().isoformat())),
            metadata={
                "camerfirma_signature_id": response_data["signature_id"],
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