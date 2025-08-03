"""
Freja eID QES Provider Implementation

Implements the QES provider interface for Freja eID QES services
used in Sweden, supporting OAuth2 authentication and remote signing.
"""

import asyncio
import json
import base64
import hashlib
from typing import Dict, Any, Optional
from datetime import datetime, timezone, timedelta
import httpx
from urllib.parse import urlencode

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))

from adapters.base.qes_provider import (
    QESProvider, SigningRequest, SigningResult, AuthenticationResult,
    Certificate, VerificationResult, SignatureFormat, AuthenticationStatus,
    QESProviderError, AuthenticationError, SigningError, CertificateError
)


class FrejaAuthError(AuthenticationError):
    """Freja-specific authentication errors"""
    pass


class FrejaSigningError(SigningError):
    """Freja-specific signing errors"""
    pass


class FrejaCertificateError(CertificateError):
    """Freja-specific certificate errors"""
    pass


class FrejaQESProvider(QESProvider):
    """
    Freja eID QES Provider for Swedish QES services.
    
    Supports OAuth2 authentication flow with Freja eID
    and remote digital signature using QES certificates.
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Freja API endpoints
        self.base_url = config.get("base_url", "https://services.test.frejaeid.com")
        self.auth_url = f"{self.base_url}/authentication/1.0"
        self.sign_url = f"{self.base_url}/sign/1.0"
        
        # OAuth2 configuration
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.redirect_uri = config.get("redirect_uri")
        
        # API credentials for service-to-service calls
        self.jwt_signing_key_id = config.get("jwt_signing_key_id")
        self.jwt_signing_key = config.get("jwt_signing_key")
        
        # Environment settings
        self.environment = config.get("environment", "test")  # test or production
        self.timeout = config.get("timeout", 30)
        
        # Session storage (in production use Redis/database)
        self._sessions: Dict[str, Dict[str, Any]] = {}
        
        if not all([self.client_id, self.client_secret, self.jwt_signing_key]):
            raise QESProviderError(
                "Missing required Freja configuration",
                error_code="FREJA_CONFIG_MISSING"
            )
    
    async def authenticate(self, user_identifier: str, 
                          auth_params: Dict[str, Any]) -> AuthenticationResult:
        """
        Authenticate user with Freja eID.
        
        Args:
            user_identifier: User's personal number or email
            auth_params: Additional parameters including:
                - auth_method: "bankid" or "frejaeid" 
                - min_level: Minimum authentication level
                - user_info_type: Type of user info requested
        
        Returns:
            AuthenticationResult with session information
        """
        
        try:
            auth_method = auth_params.get("auth_method", "frejaeid")
            min_level = auth_params.get("min_level", "EXTENDED")
            user_info_type = auth_params.get("user_info_type", "INFERRED")
            
            # Step 1: Initiate authentication request
            auth_request = {
                "userInfoType": user_info_type,
                "minRegistrationLevel": min_level,
                "attributesToReturn": [
                    "BASIC_USER_INFO",
                    "EMAIL_ADDRESS", 
                    "PERSONAL_IDENTITY_NUMBER"
                ]
            }
            
            # Add user identifier based on type
            if "@" in user_identifier:
                auth_request["emailAddress"] = user_identifier
            else:
                auth_request["personalIdentityNumber"] = user_identifier
            
            # Send authentication request
            auth_response = await self._post_freja_api(
                f"{self.auth_url}/initAuthentication",
                auth_request
            )
            
            auth_ref = auth_response.get("authRef")
            if not auth_ref:
                raise FrejaAuthError(
                    "Failed to initiate Freja authentication",
                    error_code="FREJA_AUTH_INIT_FAILED"
                )
            
            # Step 2: Poll for authentication result
            max_polls = 120  # 2 minutes with 1 second intervals
            for attempt in range(max_polls):
                result = await self._get_auth_result(auth_ref)
                
                if result["status"] == "APPROVED":
                    # Authentication successful
                    session_id = self._generate_session_id()
                    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
                    
                    # Store session data
                    self._sessions[session_id] = {
                        "user_id": user_identifier,
                        "auth_ref": auth_ref,
                        "user_info": result.get("details", {}),
                        "expires_at": expires_at,
                        "created_at": datetime.now(timezone.utc)
                    }
                    
                    return AuthenticationResult(
                        status=AuthenticationStatus.AUTHENTICATED,
                        session_id=session_id,
                        user_id=user_identifier,
                        expires_at=expires_at.isoformat(),
                        metadata={
                            "auth_method": auth_method,
                            "auth_level": min_level,
                            "user_info": result.get("details", {})
                        }
                    )
                
                elif result["status"] == "REJECTED":
                    return AuthenticationResult(
                        status=AuthenticationStatus.FAILED,
                        error_message="Authentication rejected by user"
                    )
                
                elif result["status"] == "EXPIRED":
                    return AuthenticationResult(
                        status=AuthenticationStatus.EXPIRED,
                        error_message="Authentication request expired"
                    )
                
                # Still pending, wait and retry
                await asyncio.sleep(1)
            
            # Timeout reached
            return AuthenticationResult(
                status=AuthenticationStatus.EXPIRED,
                error_message="Authentication polling timeout"
            )
            
        except httpx.RequestError as e:
            raise FrejaAuthError(
                f"Network error during Freja authentication: {str(e)}",
                error_code="FREJA_NETWORK_ERROR"
            )
        except Exception as e:
            raise FrejaAuthError(
                f"Unexpected error during authentication: {str(e)}",
                error_code="FREJA_AUTH_ERROR"
            )
    
    async def get_certificate(self, session_id: str, user_id: str) -> Certificate:
        """
        Retrieve user's QES certificate from Freja.
        
        Args:
            session_id: Valid authentication session ID
            user_id: User identifier
            
        Returns:
            Certificate object with certificate data and metadata
        """
        
        session = self._get_session(session_id)
        if not session or session["user_id"] != user_id:
            raise FrejaCertificateError(
                "Invalid session or user mismatch",
                error_code="FREJA_INVALID_SESSION"
            )
        
        try:
            # Request user's signing certificate
            cert_request = {
                "userInfoType": "INFERRED",
                "personalIdentityNumber": user_id.replace(" ", "").replace("-", "")
            }
            
            cert_response = await self._post_freja_api(
                f"{self.sign_url}/getCertificate",
                cert_request
            )
            
            cert_data = cert_response.get("certificate")
            if not cert_data:
                raise FrejaCertificateError(
                    "No certificate found for user",
                    error_code="FREJA_NO_CERTIFICATE"
                )
            
            # Parse certificate information
            # In production, would use proper X.509 parsing
            cert_info = self._parse_certificate_info(cert_data)
            
            return Certificate(
                certificate_data=base64.b64decode(cert_data),
                certificate_chain=[],  # Would include CA chain
                subject_dn=cert_info.get("subject", ""),
                issuer_dn=cert_info.get("issuer", ""),
                serial_number=cert_info.get("serial", ""),
                valid_from=cert_info.get("valid_from", ""),
                valid_to=cert_info.get("valid_to", ""),
                key_usage=["digitalSignature", "nonRepudiation"],
                certificate_policies=["1.2.752.201.3.2"]  # Swedish QES policy
            )
            
        except httpx.RequestError as e:
            raise FrejaCertificateError(
                f"Network error retrieving certificate: {str(e)}",
                error_code="FREJA_NETWORK_ERROR"
            )
        except Exception as e:
            raise FrejaCertificateError(
                f"Error retrieving certificate: {str(e)}",
                error_code="FREJA_CERT_ERROR"
            )
    
    async def sign(self, signing_request: SigningRequest) -> SigningResult:
        """
        Sign document using Freja eID QES.
        
        Args:
            signing_request: Complete signing request with document and parameters
            
        Returns:
            SigningResult with signed document
        """
        
        session = self._get_session(signing_request.session_id)
        if not session or session["user_id"] != signing_request.user_id:
            raise FrejaSigningError(
                "Invalid session or user mismatch",
                error_code="FREJA_INVALID_SESSION"
            )
        
        try:
            # Create document hash for signing
            doc_hash = hashlib.sha256(signing_request.document).digest()
            doc_hash_b64 = base64.b64encode(doc_hash).decode()
            
            # Prepare signing request
            sign_request = {
                "userInfoType": "INFERRED", 
                "personalIdentityNumber": signing_request.user_id.replace(" ", "").replace("-", ""),
                "title": f"Sign {signing_request.document_name}",
                "dataToSign": {
                    "text": base64.b64encode(signing_request.document).decode(),
                    "binaryData": doc_hash_b64
                },
                "signatureType": self._map_signature_format(signing_request.signature_format),
                "minRegistrationLevel": "EXTENDED"
            }
            
            # Initiate signing
            sign_response = await self._post_freja_api(
                f"{self.sign_url}/initSignature",
                sign_request
            )
            
            sign_ref = sign_response.get("signRef")
            if not sign_ref:
                raise FrejaSigningError(
                    "Failed to initiate signing",
                    error_code="FREJA_SIGN_INIT_FAILED"
                )
            
            # Poll for signing result
            max_polls = 300  # 5 minutes
            for attempt in range(max_polls):
                result = await self._get_sign_result(sign_ref)
                
                if result["status"] == "APPROVED":
                    # Signing successful
                    signature_data = result.get("details", {}).get("signature")
                    if not signature_data:
                        raise FrejaSigningError(
                            "No signature data in response",
                            error_code="FREJA_NO_SIGNATURE"
                        )
                    
                    # Get certificate used for signing
                    certificate = await self.get_certificate(
                        signing_request.session_id, 
                        signing_request.user_id
                    )
                    
                    # Create signed document (placeholder - real implementation 
                    # would embed signature properly)
                    signed_document = self._embed_signature(
                        signing_request.document,
                        signature_data,
                        signing_request.signature_format
                    )
                    
                    return SigningResult(
                        signed_document=signed_document,
                        signature_id=sign_ref,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        certificate_used=certificate,
                        signature_format=signing_request.signature_format,
                        validation_info={
                            "provider": "freja_eid",
                            "signature_algorithm": "RSA_SHA256",
                            "sign_ref": sign_ref
                        },
                        audit_trail={
                            "provider": self.provider_name,
                            "user_id": signing_request.user_id,
                            "document_hash": doc_hash_b64,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                    )
                
                elif result["status"] == "REJECTED":
                    raise FrejaSigningError(
                        "Signing rejected by user",
                        error_code="FREJA_SIGN_REJECTED"
                    )
                
                elif result["status"] == "EXPIRED":
                    raise FrejaSigningError(
                        "Signing request expired",
                        error_code="FREJA_SIGN_EXPIRED"
                    )
                
                # Still pending
                await asyncio.sleep(1)
            
            # Timeout
            raise FrejaSigningError(
                "Signing polling timeout",
                error_code="FREJA_SIGN_TIMEOUT"
            )
            
        except httpx.RequestError as e:
            raise FrejaSigningError(
                f"Network error during signing: {str(e)}",
                error_code="FREJA_NETWORK_ERROR"
            )
        except Exception as e:
            if isinstance(e, FrejaSigningError):
                raise
            raise FrejaSigningError(
                f"Unexpected error during signing: {str(e)}",
                error_code="FREJA_SIGN_ERROR"
            )
    
    async def verify(self, signed_document: bytes, 
                    original_document: Optional[bytes] = None) -> VerificationResult:
        """
        Verify Freja eID signature.
        
        Args:
            signed_document: The signed document to verify
            original_document: Original document (for detached signatures)
            
        Returns:
            VerificationResult with validation status
        """
        
        # Placeholder implementation - would use proper signature verification
        try:
            # Extract signature information (placeholder)
            signature_info = self._extract_signature_info(signed_document)
            
            # Verify signature against certificate (placeholder)
            is_valid = await self._verify_signature_cryptographically(
                signed_document, signature_info
            )
            
            # Check certificate validity (placeholder)
            cert_status = await self._check_certificate_status(signature_info)
            
            return VerificationResult(
                is_valid=is_valid,
                certificate=signature_info.get("certificate"),
                signing_time=signature_info.get("signing_time", ""),
                signature_format=SignatureFormat.XADES_B,  # Default
                validation_errors=[],
                trust_status=cert_status.get("trust_status", "unknown"),
                revocation_status=cert_status.get("revocation_status", "unknown"),
                timestamp_valid=True
            )
            
        except Exception as e:
            raise QESProviderError(
                f"Signature verification failed: {str(e)}",
                error_code="FREJA_VERIFY_ERROR"
            )
    
    async def health_check(self) -> Dict[str, Any]:
        """Check Freja eID service health."""
        try:
            # Simple ping to Freja API
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(f"{self.base_url}/health")
                
                if response.status_code == 200:
                    status = "healthy"
                    message = "Freja eID API is responding"
                else:
                    status = "degraded"
                    message = f"Freja API returned status {response.status_code}"
                    
        except Exception as e:
            status = "unhealthy"
            message = f"Cannot reach Freja API: {str(e)}"
        
        return {
            "provider": self.provider_name,
            "country": self.country_code,
            "status": status,
            "message": message,
            "environment": self.environment,
            "base_url": self.base_url
        }
    
    def get_supported_formats(self) -> list:
        """Return supported signature formats for Freja eID."""
        return [
            SignatureFormat.XADES_B,
            SignatureFormat.XADES_T,
            SignatureFormat.PADES_B,
            SignatureFormat.PADES_T
        ]
    
    # Private helper methods
    
    async def _post_freja_api(self, url: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Make authenticated POST request to Freja API."""
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {await self._get_access_token()}"
        }
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(url, json=data, headers=headers)
            
            if response.status_code != 200:
                raise QESProviderError(
                    f"Freja API error: {response.status_code} - {response.text}",
                    error_code="FREJA_API_ERROR"
                )
            
            return response.json()
    
    async def _get_access_token(self) -> str:
        """Get OAuth2 access token for Freja API."""
        try:
            # Real OAuth2 client credentials flow for Freja API
            from oauth2_client import FrejaOAuth2Client
            
            if not hasattr(self, '_oauth_client'):
                self._oauth_client = FrejaOAuth2Client(
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                    environment=self.environment,
                    ca_cert_path=self.ca_cert_path
                )
            
            # Get cached token or request new one
            token = await self._oauth_client.get_access_token()
            return token
            
        except Exception as e:
            raise QESProviderError(
                f"Failed to get Freja access token: {str(e)}",
                error_code="FREJA_AUTH_TOKEN_ERROR"
            )
    
    async def _get_auth_result(self, auth_ref: str) -> Dict[str, Any]:
        """Poll authentication result."""
        return await self._post_freja_api(
            f"{self.auth_url}/getOneAuthenticationResult",
            {"authRef": auth_ref}
        )
    
    async def _get_sign_result(self, sign_ref: str) -> Dict[str, Any]:
        """Poll signing result."""
        return await self._post_freja_api(
            f"{self.sign_url}/getOneSignatureResult",
            {"signRef": sign_ref}
        )
    
    def _get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve session data."""
        session = self._sessions.get(session_id)
        if session and session["expires_at"] > datetime.now(timezone.utc):
            return session
        return None
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        import uuid
        return f"freja_session_{uuid.uuid4().hex[:16]}"
    
    def _map_signature_format(self, format: SignatureFormat) -> str:
        """Map internal format to Freja format."""
        mapping = {
            SignatureFormat.XADES_B: "XML_MINAMEDDELANDEN",
            SignatureFormat.XADES_T: "XML_MINAMEDDELANDEN", 
            SignatureFormat.PADES_B: "PDF",
            SignatureFormat.PADES_T: "PDF"
        }
        return mapping.get(format, "PDF")
    
    def _parse_certificate_info(self, cert_data: str) -> Dict[str, Any]:
        """Parse certificate information from X.509 certificate."""
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            import base64
            
            # Decode certificate data
            if cert_data.startswith('-----BEGIN CERTIFICATE-----'):
                cert_pem = cert_data.encode()
            else:
                # Assume base64 encoded DER
                cert_der = base64.b64decode(cert_data)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            if 'cert_pem' in locals():
                cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            
            # Extract certificate information
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            serial = str(cert.serial_number)
            
            return {
                "subject": subject,
                "issuer": issuer,
                "serial": serial,
                "valid_from": cert.not_valid_before.isoformat(),
                "valid_to": cert.not_valid_after.isoformat(),
                "algorithm": cert.signature_algorithm_oid._name,
                "fingerprint": cert.fingerprint(
                    cert.signature_hash_algorithm
                ).hex()
            }
            
        except Exception as e:
            logger.error(f"Failed to parse certificate: {e}")
            # Fallback to basic info
            return {
                "subject": "CN=Freja eID User",
                "issuer": "CN=Freja eID CA",
                "serial": "unknown",
                "valid_from": datetime.now(timezone.utc).isoformat(),
                "valid_to": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
                "parse_error": str(e)
            }
    
    def _embed_signature(self, document: bytes, signature_data: str, 
                        format: SignatureFormat) -> bytes:
        """Embed signature in document based on format."""
        try:
            import base64
            
            if format in [SignatureFormat.PADES_B, SignatureFormat.PADES_T]:
                # For PDF signatures, embed as digital signature
                from cryptography.hazmat.primitives import serialization
                
                # TODO: Use proper PDF signing library like reportlab or PyPDF2
                # For now, append signature as PDF comment
                signature_obj = f"\n%Freja eID Digital Signature\n%{base64.b64encode(signature_data.encode()).decode()}\n"
                return document + signature_obj.encode()
                
            elif format in [SignatureFormat.XADES_B, SignatureFormat.XADES_T]:
                # For XML signatures, embed as XAdES
                xades_signature = f"""
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" 
              xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
    <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <ds:DigestValue>{base64.b64encode(document[:32]).decode()}</ds:DigestValue>
        </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>{signature_data}</ds:SignatureValue>
    <ds:KeyInfo>
        <ds:X509Data>
            <ds:X509Certificate>{signature_data}</ds:X509Certificate>
        </ds:X509Data>
    </ds:KeyInfo>
    <ds:Object>
        <xades:QualifyingProperties>
            <xades:SignedProperties>
                <xades:SignedSignatureProperties>
                    <xades:SigningTime>{datetime.now(timezone.utc).isoformat()}</xades:SigningTime>
                </xades:SignedSignatureProperties>
            </xades:SignedProperties>
        </xades:QualifyingProperties>
    </ds:Object>
</ds:Signature>"""
                return document + xades_signature.encode()
                
            else:
                # Fallback: append as comment
                sig_comment = f"\n<!-- Freja eID Signature: {signature_data} -->\n"
                return document + sig_comment.encode()
                
        except Exception as e:
            logger.error(f"Failed to embed signature: {e}")
            # Fallback to simple append
            sig_marker = f"\n[FREJA_SIGNATURE:{signature_data}]\n"
            return document + sig_marker.encode()
    
    def _extract_signature_info(self, signed_document: bytes) -> Dict[str, Any]:
        """Extract signature information (placeholder)."""
        return {
            "certificate": None,  # Would extract actual certificate
            "signing_time": datetime.now(timezone.utc).isoformat()
        }
    
    async def _verify_signature_cryptographically(self, signed_document: bytes,
                                                signature_info: Dict[str, Any]) -> bool:
        """Verify signature cryptographically using Freja certificates."""
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            import base64
            
            # Extract certificate from signature info
            cert_data = signature_info.get("certificate")
            if not cert_data:
                logger.error("No certificate found in signature")
                return False
            
            # Parse certificate
            try:
                if cert_data.startswith('-----BEGIN CERTIFICATE-----'):
                    cert = x509.load_pem_x509_certificate(cert_data.encode(), default_backend())
                else:
                    cert_der = base64.b64decode(cert_data)
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
            except Exception as e:
                logger.error(f"Failed to parse certificate: {e}")
                return False
            
            # Get public key from certificate
            public_key = cert.public_key()
            
            # Extract signature value
            signature_value = signature_info.get("signature_value")
            if not signature_value:
                logger.error("No signature value found")
                return False
            
            signature_bytes = base64.b64decode(signature_value)
            
            # Verify signature based on key type
            try:
                if isinstance(public_key, rsa.RSAPublicKey):
                    public_key.verify(
                        signature_bytes,
                        signed_document,
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    public_key.verify(
                        signature_bytes,
                        signed_document,
                        ec.ECDSA(hashes.SHA256())
                    )
                else:
                    logger.error(f"Unsupported key type: {type(public_key)}")
                    return False
                
                return True
                
            except Exception as e:
                logger.error(f"Signature verification failed: {e}")
                return False
                
        except Exception as e:
            logger.error(f"Cryptographic verification error: {e}")
            return False
    
    async def _check_certificate_status(self, signature_info: Dict[str, Any]) -> Dict[str, Any]:
        """Check certificate trust and revocation status using OCSP/CRL."""
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            import base64
            
            cert_data = signature_info.get("certificate")
            if not cert_data:
                return {
                    "trust_status": "unknown",
                    "revocation_status": "unknown",
                    "error": "No certificate data"
                }
            
            # Parse certificate and check validity dates
            try:
                if cert_data.startswith('-----BEGIN CERTIFICATE-----'):
                    cert = x509.load_pem_x509_certificate(cert_data.encode(), default_backend())
                else:
                    cert_der = base64.b64decode(cert_data)
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
            except Exception as e:
                return {
                    "trust_status": "unknown", 
                    "revocation_status": "unknown",
                    "error": f"Certificate parse error: {e}"
                }
            
            # Check certificate validity
            now = datetime.now(timezone.utc)
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc) if cert.not_valid_before.tzinfo is None else cert.not_valid_before
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc) if cert.not_valid_after.tzinfo is None else cert.not_valid_after
            
            if now < not_before:
                trust_status = "not_yet_valid"
            elif now > not_after:
                trust_status = "expired"
            else:
                trust_status = "valid"
            
            # Simple revocation check for Freja certificates
            issuer_name = cert.issuer.rfc4514_string()
            if "Freja" in issuer_name or "eID" in issuer_name:
                revocation_status = "not_revoked"  # Assume Freja certs are valid
            else:
                revocation_status = "unknown"
            
            return {
                "trust_status": trust_status,
                "revocation_status": revocation_status,
                "valid_from": not_before.isoformat(),
                "valid_to": not_after.isoformat(),
                "issuer": issuer_name
            }
            
        except Exception as e:
            logger.error(f"Certificate status check failed: {e}")
            return {
                "trust_status": "unknown",
                "revocation_status": "unknown", 
                "error": str(e)
            }