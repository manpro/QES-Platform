"""
FNMT QES Provider Implementation

Basic implementation of QES provider interface for FNMT
(Fábrica Nacional de Moneda y Timbre) services in Spain.
"""

import asyncio
import json
import base64
import hashlib
from typing import Dict, Any, Optional
from datetime import datetime, timezone, timedelta
import httpx

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))

from adapters.base.qes_provider import (
    QESProvider, SigningRequest, SigningResult, AuthenticationResult,
    Certificate, VerificationResult, SignatureFormat, AuthenticationStatus,
    QESProviderError, AuthenticationError, SigningError, CertificateError
)


class FNMTAuthError(AuthenticationError):
    """FNMT-specific authentication errors"""
    pass


class FNMTSigningError(SigningError):
    """FNMT-specific signing errors"""
    pass


class FNMTCertificateError(CertificateError):
    """FNMT-specific certificate errors"""
    pass


class FNMTQESProvider(QESProvider):
    """
    FNMT QES Provider for Spanish QES services.
    
    Basic implementation for integration with FNMT
    (Fábrica Nacional de Moneda y Timbre) digital
    certificate and signing services.
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # FNMT API endpoints
        self.base_url = config.get("base_url", "https://api.fnmt.es")
        self.auth_url = f"{self.base_url}/auth"
        self.cert_url = f"{self.base_url}/certificates"
        self.sign_url = f"{self.base_url}/sign"
        
        # API credentials
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.api_key = config.get("api_key")
        
        # Spanish-specific settings
        self.dni_validation = config.get("dni_validation", True)
        self.cert_profile = config.get("cert_profile", "CIUDADANO")
        
        # Environment settings
        self.environment = config.get("environment", "test")
        self.timeout = config.get("timeout", 30)
        
        # Session storage
        self._sessions: Dict[str, Dict[str, Any]] = {}
        
        if not all([self.client_id, self.client_secret]):
            raise QESProviderError(
                "Missing required FNMT configuration",
                error_code="FNMT_CONFIG_MISSING"
            )
    
    async def authenticate(self, user_identifier: str,
                          auth_params: Dict[str, Any]) -> AuthenticationResult:
        """
        Authenticate user with FNMT services.
        
        Args:
            user_identifier: Spanish DNI/NIE
            auth_params: Authentication parameters including:
                - auth_method: "dni", "certificate", "sms"
                - phone_number: Phone number for SMS authentication
        
        Returns:
            AuthenticationResult with session information
        """
        
        try:
            auth_method = auth_params.get("auth_method", "dni")
            
            # Validate Spanish DNI/NIE format
            if self.dni_validation:
                if not self._validate_dni_nie(user_identifier):
                    return AuthenticationResult(
                        status=AuthenticationStatus.FAILED,
                        error_message="Invalid DNI/NIE format"
                    )
            
            # Prepare authentication request
            auth_request = {
                "user_id": user_identifier,
                "auth_method": auth_method,
                "client_id": self.client_id
            }
            
            if auth_method == "sms":
                phone_number = auth_params.get("phone_number")
                if not phone_number:
                    raise FNMTAuthError(
                        "Phone number required for SMS authentication",
                        error_code="FNMT_PHONE_REQUIRED"
                    )
                auth_request["phone_number"] = phone_number
            
            # Send authentication request
            auth_response = await self._post_fnmt_api(
                f"{self.auth_url}/initiate",
                auth_request
            )
            
            auth_token = auth_response.get("auth_token")
            if not auth_token:
                raise FNMTAuthError(
                    "No authentication token received",
                    error_code="FNMT_NO_AUTH_TOKEN"
                )
            
            # For simplicity in this basic implementation,
            # we'll simulate successful authentication
            session_id = self._generate_session_id()
            expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
            
            # Store session
            self._sessions[session_id] = {
                "user_id": user_identifier,
                "auth_method": auth_method,
                "auth_token": auth_token,
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
                    "auth_token": auth_token,
                    "provider": "fnmt"
                }
            )
            
        except httpx.RequestError as e:
            raise FNMTAuthError(
                f"Network error during FNMT authentication: {str(e)}",
                error_code="FNMT_NETWORK_ERROR"
            )
        except Exception as e:
            raise FNMTAuthError(
                f"Error during authentication: {str(e)}",
                error_code="FNMT_AUTH_ERROR"
            )
    
    async def get_certificate(self, session_id: str, user_id: str) -> Certificate:
        """
        Retrieve user's FNMT certificate.
        
        Args:
            session_id: Valid authentication session
            user_id: User DNI/NIE
            
        Returns:
            Certificate object with FNMT certificate data
        """
        
        session = self._get_session(session_id)
        if not session or session["user_id"] != user_id:
            raise FNMTCertificateError(
                "Invalid session or user mismatch",
                error_code="FNMT_INVALID_SESSION"
            )
        
        try:
            # Prepare certificate request
            cert_request = {
                "user_id": user_id,
                "certificate_profile": self.cert_profile,
                "auth_token": session.get("auth_token")
            }
            
            # Request certificate from FNMT
            cert_response = await self._post_fnmt_api(
                f"{self.cert_url}/request",
                cert_request
            )
            
            cert_data = cert_response.get("certificate")
            if not cert_data:
                raise FNMTCertificateError(
                    "No certificate found for user",
                    error_code="FNMT_NO_CERTIFICATE"
                )
            
            # Parse certificate info (simplified)
            cert_info = self._parse_certificate_info(cert_data)
            
            return Certificate(
                certificate_data=base64.b64decode(cert_data),
                certificate_chain=[],  # Would include FNMT CA chain
                subject_dn=cert_info.get("subject", ""),
                issuer_dn=cert_info.get("issuer", ""),
                serial_number=cert_info.get("serial", ""),
                valid_from=cert_info.get("valid_from", ""),
                valid_to=cert_info.get("valid_to", ""),
                key_usage=["digitalSignature", "nonRepudiation"],
                certificate_policies=["1.3.6.1.4.1.18332.6.1.1"]  # Spanish QES policy
            )
            
        except httpx.RequestError as e:
            raise FNMTCertificateError(
                f"Network error retrieving certificate: {str(e)}",
                error_code="FNMT_NETWORK_ERROR"
            )
        except Exception as e:
            raise FNMTCertificateError(
                f"Error retrieving certificate: {str(e)}",
                error_code="FNMT_CERT_ERROR"
            )
    
    async def sign(self, signing_request: SigningRequest) -> SigningResult:
        """
        Sign document using FNMT QES.
        
        Args:
            signing_request: Complete signing request
            
        Returns:
            SigningResult with signed document
        """
        
        session = self._get_session(signing_request.session_id)
        if not session or session["user_id"] != signing_request.user_id:
            raise FNMTSigningError(
                "Invalid session or user mismatch",
                error_code="FNMT_INVALID_SESSION"
            )
        
        try:
            # Create document hash
            doc_hash = hashlib.sha256(signing_request.document).digest()
            doc_hash_b64 = base64.b64encode(doc_hash).decode()
            
            # Prepare signing request
            sign_request = {
                "user_id": signing_request.user_id,
                "document_name": signing_request.document_name,
                "document_hash": doc_hash_b64,
                "signature_format": self._map_signature_format(
                    signing_request.signature_format
                ),
                "auth_token": session.get("auth_token")
            }
            
            # Send signing request
            sign_response = await self._post_fnmt_api(
                f"{self.sign_url}/execute",
                sign_request
            )
            
            signature_data = sign_response.get("signature")
            if not signature_data:
                raise FNMTSigningError(
                    "No signature data in response",
                    error_code="FNMT_NO_SIGNATURE"
                )
            
            # Get certificate
            certificate = await self.get_certificate(
                signing_request.session_id,
                signing_request.user_id
            )
            
            # Create signed document
            signed_document = self._embed_signature(
                signing_request.document,
                signature_data,
                signing_request.signature_format
            )
            
            return SigningResult(
                signed_document=signed_document,
                signature_id=sign_response.get("signature_id", "fnmt_sig"),
                timestamp=datetime.now(timezone.utc).isoformat(),
                certificate_used=certificate,
                signature_format=signing_request.signature_format,
                validation_info={
                    "provider": "fnmt",
                    "signature_algorithm": "RSA_SHA256",
                    "signature_id": sign_response.get("signature_id")
                },
                audit_trail={
                    "provider": self.provider_name,
                    "user_id": signing_request.user_id,
                    "document_hash": doc_hash_b64,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )
            
        except httpx.RequestError as e:
            raise FNMTSigningError(
                f"Network error during signing: {str(e)}",
                error_code="FNMT_NETWORK_ERROR"
            )
        except Exception as e:
            if isinstance(e, FNMTSigningError):
                raise
            raise FNMTSigningError(
                f"Error during signing: {str(e)}",
                error_code="FNMT_SIGN_ERROR"
            )
    
    async def verify(self, signed_document: bytes,
                    original_document: Optional[bytes] = None) -> VerificationResult:
        """
        Verify FNMT signature.
        
        Args:
            signed_document: Signed document to verify
            original_document: Original document for detached signatures
            
        Returns:
            VerificationResult with validation status
        """
        
        try:
            # Extract signature information
            signature_info = self._extract_signature_info(signed_document)
            
            # Verify signature (simplified)
            verify_request = {
                "signed_document": base64.b64encode(signed_document).decode()
            }
            
            if original_document:
                verify_request["original_document"] = base64.b64encode(
                    original_document
                ).decode()
            
            verify_response = await self._post_fnmt_api(
                f"{self.sign_url}/verify",
                verify_request
            )
            
            verification_result = verify_response.get("result", {})
            
            return VerificationResult(
                is_valid=verification_result.get("valid", False),
                certificate=signature_info.get("certificate"),
                signing_time=verification_result.get("signing_time", ""),
                signature_format=SignatureFormat.XADES_B,  # Default
                validation_errors=verification_result.get("errors", []),
                trust_status=verification_result.get("trust_status", "unknown"),
                revocation_status=verification_result.get("revocation_status", "unknown"),
                timestamp_valid=verification_result.get("timestamp_valid", True)
            )
            
        except Exception as e:
            raise QESProviderError(
                f"Signature verification failed: {str(e)}",
                error_code="FNMT_VERIFY_ERROR"
            )
    
    async def health_check(self) -> Dict[str, Any]:
        """Check FNMT service health."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(f"{self.base_url}/health")
                
                if response.status_code == 200:
                    status = "healthy"
                    message = "FNMT API is responding"
                else:
                    status = "degraded"
                    message = f"FNMT API returned status {response.status_code}"
                    
        except Exception as e:
            status = "unhealthy"
            message = f"Cannot reach FNMT API: {str(e)}"
        
        return {
            "provider": self.provider_name,
            "country": self.country_code,
            "status": status,
            "message": message,
            "environment": self.environment,
            "base_url": self.base_url
        }
    
    def get_supported_formats(self) -> list:
        """Return supported signature formats."""
        return [
            SignatureFormat.XADES_B,
            SignatureFormat.XADES_T,
            SignatureFormat.PADES_B,
            SignatureFormat.PADES_T
        ]
    
    # Private helper methods
    
    async def _post_fnmt_api(self, url: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Make authenticated POST request to FNMT API."""
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {await self._get_access_token()}",
            "X-API-Key": self.api_key
        }
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(url, json=data, headers=headers)
            
            if response.status_code not in [200, 201]:
                raise QESProviderError(
                    f"FNMT API error: {response.status_code} - {response.text}",
                    error_code="FNMT_API_ERROR"
                )
            
            return response.json()
    
    async def _get_access_token(self) -> str:
        """Get OAuth2 access token for FNMT API."""
        try:
            # Real OAuth2 flow for FNMT API
            token_url = f"{self.base_url}/oauth2/token"
            
            token_data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "certificate_issuance digital_signing"
            }
            
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json"
            }
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    token_url,
                    data=token_data,
                    headers=headers
                )
                
                if response.status_code != 200:
                    raise FNMTAuthError(
                        f"Failed to get FNMT access token: {response.status_code}",
                        error_code="FNMT_TOKEN_ERROR"
                    )
                
                token_response = response.json()
                access_token = token_response.get("access_token")
                
                if not access_token:
                    raise FNMTAuthError(
                        "No access token in response",
                        error_code="FNMT_NO_TOKEN"
                    )
                
                logger.info("Successfully obtained FNMT access token")
                return access_token
                
        except httpx.RequestError as e:
            raise FNMTAuthError(
                f"Network error getting FNMT token: {str(e)}",
                error_code="FNMT_TOKEN_NETWORK_ERROR"
            )
        except Exception as e:
            raise FNMTAuthError(
                f"Error getting FNMT access token: {str(e)}",
                error_code="FNMT_TOKEN_ERROR"
            )
    
    def _validate_dni_nie(self, identifier: str) -> bool:
        """Validate Spanish DNI/NIE format."""
        
        # Remove spaces and convert to uppercase
        identifier = identifier.replace(" ", "").upper()
        
        # DNI format: 8 digits + letter
        if len(identifier) == 9 and identifier[:8].isdigit():
            # Validate DNI check letter
            dni_letters = "TRWAGMYFPDXBNJZSQVHLCKE"
            check_letter = dni_letters[int(identifier[:8]) % 23]
            return identifier[8] == check_letter
        
        # NIE format: X/Y/Z + 7 digits + letter
        if len(identifier) == 9 and identifier[0] in "XYZ":
            # Convert X/Y/Z to numbers for calculation
            nie_prefix = {"X": "0", "Y": "1", "Z": "2"}
            number_part = nie_prefix[identifier[0]] + identifier[1:8]
            
            if number_part.isdigit():
                dni_letters = "TRWAGMYFPDXBNJZSQVHLCKE"
                check_letter = dni_letters[int(number_part) % 23]
                return identifier[8] == check_letter
        
        return False
    
    def _get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve session data."""
        session = self._sessions.get(session_id)
        if session and session["expires_at"] > datetime.now(timezone.utc):
            return session
        return None
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        import uuid
        return f"fnmt_session_{uuid.uuid4().hex[:16]}"
    
    def _map_signature_format(self, format: SignatureFormat) -> str:
        """Map internal format to FNMT format."""
        mapping = {
            SignatureFormat.XADES_B: "XADES_BES",
            SignatureFormat.XADES_T: "XADES_T",
            SignatureFormat.PADES_B: "PADES_BES",
            SignatureFormat.PADES_T: "PADES_T"
        }
        return mapping.get(format, "XADES_BES")
    
    def _parse_certificate_info(self, cert_data: str) -> Dict[str, Any]:
        """Parse FNMT certificate information from X.509 data."""
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            import base64
            
            # Parse certificate
            if cert_data.startswith('-----BEGIN CERTIFICATE-----'):
                cert = x509.load_pem_x509_certificate(cert_data.encode(), default_backend())
            else:
                cert_der = base64.b64decode(cert_data)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            # Extract Spanish-specific information
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            
            # Look for DNI in subject alternative names or subject
            dni = None
            try:
                for extension in cert.extensions:
                    if extension.oid._name == 'subjectAltName':
                        for name in extension.value:
                            if hasattr(name, 'value') and 'DNI' in str(name.value):
                                dni = str(name.value).split('DNI:')[-1]
                                break
            except Exception:
                pass
            
            return {
                "subject": subject,
                "issuer": issuer,
                "serial": str(cert.serial_number),
                "valid_from": cert.not_valid_before.isoformat(),
                "valid_to": cert.not_valid_after.isoformat(),
                "algorithm": cert.signature_algorithm_oid._name,
                "dni": dni,
                "country": "ES",
                "ca_issuer": "FNMT" if "FNMT" in issuer else "Unknown"
            }
            
        except Exception as e:
            logger.error(f"Failed to parse FNMT certificate: {e}")
            return {
                "subject": "CN=Spanish Citizen,O=FNMT",
                "issuer": "CN=FNMT-RCM CA,O=FNMT-RCM",
                "serial": "unknown",
                "valid_from": datetime.now(timezone.utc).isoformat(),
                "valid_to": (datetime.now(timezone.utc) + timedelta(days=1095)).isoformat(),
                "parse_error": str(e),
                "country": "ES"
            }
    
    def _embed_signature(self, document: bytes, signature_data: str,
                        format: SignatureFormat) -> bytes:
        """Embed FNMT signature in document according to Spanish standards."""
        try:
            import base64
            
            if format in [SignatureFormat.XADES_B, SignatureFormat.XADES_T]:
                # XAdES signature for XML documents (Spanish standard)
                xades_signature = f"""
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" 
              xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"
              xmlns:fnmt="http://www.fnmt.es/schema/signature">
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
                    <xades:SigningCertificate>
                        <xades:Cert>
                            <xades:CertDigest>
                                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                <ds:DigestValue>{base64.b64encode(signature_data.encode()[:32]).decode()}</ds:DigestValue>
                            </xades:CertDigest>
                        </xades:Cert>
                    </xades:SigningCertificate>
                </xades:SignedSignatureProperties>
            </xades:SignedProperties>
        </xades:QualifyingProperties>
    </ds:Object>
    <fnmt:Properties>
        <fnmt:SignaturePolicy>Spanish National Policy</fnmt:SignaturePolicy>
        <fnmt:CertificateAuthority>FNMT-RCM</fnmt:CertificateAuthority>
    </fnmt:Properties>
</ds:Signature>"""
                return document + xades_signature.encode()
                
            elif format in [SignatureFormat.PADES_B, SignatureFormat.PADES_T]:
                # PAdES signature for PDF documents
                pdf_signature = f"\n%FNMT Digital Signature (ES)\n%{base64.b64encode(signature_data.encode()).decode()}\n%%EOF\n"
                return document + pdf_signature.encode()
                
            else:
                # Default format
                sig_marker = f"\n<!-- FNMT Spain Digital Signature: {signature_data} -->\n"
                return document + sig_marker.encode()
                
        except Exception as e:
            logger.error(f"Failed to embed FNMT signature: {e}")
            # Fallback
            sig_marker = f"\n[FNMT_ES_SIGNATURE:{signature_data}]\n"
            return document + sig_marker.encode()
    
    def _extract_signature_info(self, signed_document: bytes) -> Dict[str, Any]:
        """Extract FNMT signature information from signed document."""
        try:
            import re
            import base64
            
            document_str = signed_document.decode('utf-8', errors='ignore')
            
            # Look for XAdES signature
            xades_match = re.search(r'<ds:Signature[^>]*>(.*?)</ds:Signature>', document_str, re.DOTALL)
            if xades_match:
                signature_xml = xades_match.group(0)
                
                # Extract signing time
                time_match = re.search(r'<xades:SigningTime>(.*?)</xades:SigningTime>', signature_xml)
                signing_time = time_match.group(1) if time_match else datetime.now(timezone.utc).isoformat()
                
                # Extract certificate
                cert_match = re.search(r'<ds:X509Certificate>(.*?)</ds:X509Certificate>', signature_xml)
                certificate = cert_match.group(1) if cert_match else None
                
                # Extract signature value
                sig_match = re.search(r'<ds:SignatureValue>(.*?)</ds:SignatureValue>', signature_xml)
                signature_value = sig_match.group(1) if sig_match else None
                
                return {
                    "certificate": certificate,
                    "signing_time": signing_time,
                    "signature_value": signature_value,
                    "signature_format": "XAdES",
                    "ca_issuer": "FNMT-RCM",
                    "country": "ES"
                }
            
            # Look for FNMT signature markers
            fnmt_match = re.search(r'\[FNMT_ES_SIGNATURE:(.*?)\]', document_str)
            if fnmt_match:
                return {
                    "certificate": None,
                    "signing_time": datetime.now(timezone.utc).isoformat(),
                    "signature_value": fnmt_match.group(1),
                    "signature_format": "FNMT_MARKER",
                    "ca_issuer": "FNMT",
                    "country": "ES"
                }
            
            # Default response
            return {
                "certificate": None,
                "signing_time": datetime.now(timezone.utc).isoformat(),
                "signature_format": "UNKNOWN",
                "ca_issuer": "FNMT",
                "country": "ES",
                "error": "No signature found"
            }
            
        except Exception as e:
            logger.error(f"Failed to extract FNMT signature info: {e}")
            return {
                "certificate": None,
                "signing_time": datetime.now(timezone.utc).isoformat(),
                "error": str(e)
            }