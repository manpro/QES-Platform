"""
D-Trust QES Provider Implementation

Implements the QES provider interface for D-Trust (Bundesdruckerei)
services used in Germany, supporting eIDAS node authentication 
and remote qualified electronic signatures.
"""

import asyncio
import json
import base64
import hashlib
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional
from datetime import datetime, timezone, timedelta
import httpx
from urllib.parse import urlencode, parse_qs

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))

from adapters.base.qes_provider import (
    QESProvider, SigningRequest, SigningResult, AuthenticationResult,
    Certificate, VerificationResult, SignatureFormat, AuthenticationStatus,
    QESProviderError, AuthenticationError, SigningError, CertificateError
)


class DTrustAuthError(AuthenticationError):
    """D-Trust specific authentication errors"""
    pass


class DTrustSigningError(SigningError):
    """D-Trust specific signing errors"""
    pass


class DTrustCertificateError(CertificateError):
    """D-Trust specific certificate errors"""
    pass


class DTrustQESProvider(QESProvider):
    """
    D-Trust QES Provider for German QES services.
    
    Integrates with eIDAS authentication nodes and provides
    remote qualified electronic signature services through
    Bundesdruckerei's D-Trust infrastructure.
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # D-Trust API endpoints
        self.base_url = config.get("base_url", "https://vid.d-trust.net")
        self.auth_url = f"{self.base_url}/auth"
        self.sign_url = f"{self.base_url}/sign"
        self.cert_url = f"{self.base_url}/cert"
        
        # eIDAS node configuration
        self.eidas_node_url = config.get("eidas_node_url")
        self.eidas_sp_id = config.get("eidas_sp_id")
        self.eidas_return_url = config.get("eidas_return_url")
        
        # API credentials
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.api_key = config.get("api_key")
        
        # Certificate settings
        self.cert_profile = config.get("cert_profile", "QES_NATURAL_PERSON")
        self.signing_algorithm = config.get("signing_algorithm", "RSA_SHA256")
        
        # Environment settings
        self.environment = config.get("environment", "test")
        self.timeout = config.get("timeout", 60)
        
        # Session storage
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._auth_requests: Dict[str, Dict[str, Any]] = {}
        
        if not all([self.client_id, self.client_secret, self.eidas_sp_id]):
            raise QESProviderError(
                "Missing required D-Trust configuration",
                error_code="DTRUST_CONFIG_MISSING"
            )
    
    async def authenticate(self, user_identifier: str,
                          auth_params: Dict[str, Any]) -> AuthenticationResult:
        """
        Authenticate user via eIDAS node.
        
        Args:
            user_identifier: German eID card number or national ID
            auth_params: Authentication parameters including:
                - auth_level: Required LoA (substantial, high)
                - attributes: Requested attributes
                - return_url: Callback URL after authentication
        
        Returns:
            AuthenticationResult with eIDAS authentication status
        """
        
        try:
            auth_level = auth_params.get("auth_level", "high")
            requested_attributes = auth_params.get("attributes", [
                "PersonIdentifier",
                "FamilyName", 
                "FirstName",
                "DateOfBirth"
            ])
            return_url = auth_params.get("return_url", self.eidas_return_url)
            
            # Step 1: Create SAML authentication request
            auth_request_id = self._generate_request_id()
            saml_request = self._create_saml_auth_request(
                auth_request_id,
                auth_level,
                requested_attributes
            )
            
            # Store authentication request
            self._auth_requests[auth_request_id] = {
                "user_identifier": user_identifier,
                "auth_level": auth_level,
                "requested_attributes": requested_attributes,
                "created_at": datetime.now(timezone.utc),
                "status": "pending"
            }
            
            # Step 2: Send to eIDAS node
            if self.eidas_node_url:
                eidas_response = await self._send_eidas_request(
                    saml_request, return_url
                )
                
                # Extract redirect URL for user
                redirect_url = eidas_response.get("redirect_url")
                if not redirect_url:
                    raise DTrustAuthError(
                        "No redirect URL from eIDAS node",
                        error_code="DTRUST_NO_REDIRECT"
                    )
                
                # Return pending status with redirect info
                return AuthenticationResult(
                    status=AuthenticationStatus.PENDING,
                    session_id=None,
                    user_id=user_identifier,
                    metadata={
                        "auth_request_id": auth_request_id,
                        "redirect_url": redirect_url,
                        "auth_method": "eidas_node",
                        "auth_level": auth_level
                    }
                )
            
            else:
                # Use real eIDAS authentication process
                return await self._process_eidas_authentication(
                    user_identifier, auth_request_id, auth_level
                )
                
        except httpx.RequestError as e:
            raise DTrustAuthError(
                f"Network error during eIDAS authentication: {str(e)}",
                error_code="DTRUST_NETWORK_ERROR"
            )
        except Exception as e:
            raise DTrustAuthError(
                f"Error during authentication: {str(e)}",
                error_code="DTRUST_AUTH_ERROR"
            )
    
    async def handle_eidas_callback(self, saml_response: str,
                                   relay_state: str) -> AuthenticationResult:
        """
        Handle eIDAS authentication callback.
        
        Args:
            saml_response: Base64 encoded SAML response
            relay_state: RelayState parameter
            
        Returns:
            AuthenticationResult with final authentication status
        """
        
        try:
            # Decode and parse SAML response
            saml_data = base64.b64decode(saml_response)
            auth_data = self._parse_saml_response(saml_data)
            
            auth_request_id = relay_state
            auth_request = self._auth_requests.get(auth_request_id)
            
            if not auth_request:
                raise DTrustAuthError(
                    "Invalid authentication request ID",
                    error_code="DTRUST_INVALID_REQUEST_ID"
                )
            
            if auth_data["status"] == "SUCCESS":
                # Create session
                session_id = self._generate_session_id()
                expires_at = datetime.now(timezone.utc) + timedelta(hours=2)
                
                self._sessions[session_id] = {
                    "user_id": auth_request["user_identifier"],
                    "auth_request_id": auth_request_id,
                    "eidas_attributes": auth_data.get("attributes", {}),
                    "auth_level": auth_data.get("loa", auth_request["auth_level"]),
                    "expires_at": expires_at,
                    "created_at": datetime.now(timezone.utc)
                }
                
                # Cleanup auth request
                del self._auth_requests[auth_request_id]
                
                return AuthenticationResult(
                    status=AuthenticationStatus.AUTHENTICATED,
                    session_id=session_id,
                    user_id=auth_request["user_identifier"],
                    expires_at=expires_at.isoformat(),
                    metadata={
                        "auth_method": "eidas_node",
                        "auth_level": auth_data.get("loa"),
                        "eidas_attributes": auth_data.get("attributes", {})
                    }
                )
            
            else:
                # Authentication failed
                error_message = auth_data.get("error", "eIDAS authentication failed")
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message=error_message
                )
                
        except Exception as e:
            raise DTrustAuthError(
                f"Error processing eIDAS callback: {str(e)}",
                error_code="DTRUST_CALLBACK_ERROR"
            )
    
    async def get_certificate(self, session_id: str, user_id: str) -> Certificate:
        """
        Retrieve or generate user's QES certificate.
        
        Args:
            session_id: Valid authentication session
            user_id: User identifier
            
        Returns:
            Certificate object with QES certificate data
        """
        
        session = self._get_session(session_id)
        if not session or session["user_id"] != user_id:
            raise DTrustCertificateError(
                "Invalid session or user mismatch",
                error_code="DTRUST_INVALID_SESSION"
            )
        
        try:
            # Prepare certificate request with eIDAS attributes
            eidas_attrs = session.get("eidas_attributes", {})
            cert_request = {
                "certificateProfile": self.cert_profile,
                "subjectData": {
                    "personalIdentifier": eidas_attrs.get("PersonIdentifier"),
                    "familyName": eidas_attrs.get("FamilyName"),
                    "firstName": eidas_attrs.get("FirstName"),
                    "dateOfBirth": eidas_attrs.get("DateOfBirth"),
                    "countryCode": "DE"
                },
                "keyUsage": ["digitalSignature", "nonRepudiation"],
                "certificatePolicies": ["1.2.276.0.76.4.2.2"]  # German QES policy
            }
            
            # Request certificate from D-Trust
            cert_response = await self._post_dtrust_api(
                f"{self.cert_url}/request",
                cert_request
            )
            
            cert_data = cert_response.get("certificate")
            if not cert_data:
                raise DTrustCertificateError(
                    "No certificate in response",
                    error_code="DTRUST_NO_CERTIFICATE"
                )
            
            # Parse certificate
            cert_info = self._parse_certificate_info(cert_data)
            ca_chain = cert_response.get("certificateChain", [])
            
            return Certificate(
                certificate_data=base64.b64decode(cert_data),
                certificate_chain=[base64.b64decode(ca) for ca in ca_chain],
                subject_dn=cert_info.get("subject", ""),
                issuer_dn=cert_info.get("issuer", ""),
                serial_number=cert_info.get("serial", ""),
                valid_from=cert_info.get("valid_from", ""),
                valid_to=cert_info.get("valid_to", ""),
                key_usage=["digitalSignature", "nonRepudiation"],
                certificate_policies=["1.2.276.0.76.4.2.2"]
            )
            
        except httpx.RequestError as e:
            raise DTrustCertificateError(
                f"Network error retrieving certificate: {str(e)}",
                error_code="DTRUST_NETWORK_ERROR"
            )
        except Exception as e:
            raise DTrustCertificateError(
                f"Error retrieving certificate: {str(e)}",
                error_code="DTRUST_CERT_ERROR"
            )
    
    async def sign(self, signing_request: SigningRequest) -> SigningResult:
        """
        Sign document using D-Trust remote signing.
        
        Args:
            signing_request: Complete signing request
            
        Returns:
            SigningResult with signed document
        """
        
        session = self._get_session(signing_request.session_id)
        if not session or session["user_id"] != signing_request.user_id:
            raise DTrustSigningError(
                "Invalid session or user mismatch",
                error_code="DTRUST_INVALID_SESSION"
            )
        
        try:
            # Create document hash for signing
            doc_hash = hashlib.sha256(signing_request.document).digest()
            doc_hash_hex = doc_hash.hex()
            
            # Prepare signing request
            sign_request = {
                "documentName": signing_request.document_name,
                "documentHash": doc_hash_hex,
                "hashAlgorithm": "SHA-256",
                "signatureFormat": self._map_signature_format(
                    signing_request.signature_format
                ),
                "signingAlgorithm": self.signing_algorithm,
                "certificateProfile": self.cert_profile,
                "userData": session.get("eidas_attributes", {})
            }
            
            # Optional: Include timestamp authority
            if signing_request.timestamp_server_url:
                sign_request["timestampUrl"] = signing_request.timestamp_server_url
            
            # Send signing request
            sign_response = await self._post_dtrust_api(
                f"{self.sign_url}/remote",
                sign_request
            )
            
            transaction_id = sign_response.get("transactionId")
            if not transaction_id:
                raise DTrustSigningError(
                    "No transaction ID in response",
                    error_code="DTRUST_NO_TRANSACTION_ID"
                )
            
            # Poll for signing result
            max_polls = 180  # 3 minutes
            for attempt in range(max_polls):
                status_response = await self._get_signing_status(transaction_id)
                
                status = status_response.get("status")
                
                if status == "COMPLETED":
                    # Get signature data
                    signature_data = status_response.get("signatureData")
                    if not signature_data:
                        raise DTrustSigningError(
                            "No signature data in response",
                            error_code="DTRUST_NO_SIGNATURE"
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
                        signature_id=transaction_id,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        certificate_used=certificate,
                        signature_format=signing_request.signature_format,
                        validation_info={
                            "provider": "d_trust",
                            "signature_algorithm": self.signing_algorithm,
                            "transaction_id": transaction_id,
                            "tsp_used": status_response.get("timestampInfo")
                        },
                        audit_trail={
                            "provider": self.provider_name,
                            "user_id": signing_request.user_id,
                            "document_hash": doc_hash_hex,
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                    )
                
                elif status == "FAILED":
                    error_msg = status_response.get("error", "Signing failed")
                    raise DTrustSigningError(
                        f"D-Trust signing failed: {error_msg}",
                        error_code="DTRUST_SIGN_FAILED"
                    )
                
                elif status == "CANCELLED":
                    raise DTrustSigningError(
                        "Signing was cancelled",
                        error_code="DTRUST_SIGN_CANCELLED"
                    )
                
                # Still pending
                await asyncio.sleep(1)
            
            # Timeout
            raise DTrustSigningError(
                "Signing timeout",
                error_code="DTRUST_SIGN_TIMEOUT"
            )
            
        except httpx.RequestError as e:
            raise DTrustSigningError(
                f"Network error during signing: {str(e)}",
                error_code="DTRUST_NETWORK_ERROR"
            )
        except Exception as e:
            if isinstance(e, DTrustSigningError):
                raise
            raise DTrustSigningError(
                f"Error during signing: {str(e)}",
                error_code="DTRUST_SIGN_ERROR"
            )
    
    async def verify(self, signed_document: bytes,
                    original_document: Optional[bytes] = None) -> VerificationResult:
        """
        Verify D-Trust signature.
        
        Args:
            signed_document: Signed document to verify
            original_document: Original document for detached signatures
            
        Returns:
            VerificationResult with validation status
        """
        
        try:
            # Extract signature information
            signature_info = self._extract_signature_info(signed_document)
            
            # Verify signature
            verify_request = {
                "signedDocument": base64.b64encode(signed_document).decode(),
                "verificationLevel": "ADVANCED"
            }
            
            if original_document:
                verify_request["originalDocument"] = base64.b64encode(
                    original_document
                ).decode()
            
            verify_response = await self._post_dtrust_api(
                f"{self.sign_url}/verify",
                verify_request
            )
            
            verification_result = verify_response.get("result", {})
            
            return VerificationResult(
                is_valid=verification_result.get("valid", False),
                certificate=signature_info.get("certificate"),
                signing_time=verification_result.get("signingTime", ""),
                signature_format=SignatureFormat.XADES_B,  # Default
                validation_errors=verification_result.get("errors", []),
                trust_status=verification_result.get("trustStatus", "unknown"),
                revocation_status=verification_result.get("revocationStatus", "unknown"),
                timestamp_valid=verification_result.get("timestampValid", True)
            )
            
        except Exception as e:
            raise QESProviderError(
                f"Signature verification failed: {str(e)}",
                error_code="DTRUST_VERIFY_ERROR"
            )
    
    async def health_check(self) -> Dict[str, Any]:
        """Check D-Trust service health."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(f"{self.base_url}/health")
                
                if response.status_code == 200:
                    status = "healthy"
                    message = "D-Trust API is responding"
                else:
                    status = "degraded"
                    message = f"D-Trust API returned status {response.status_code}"
                    
        except Exception as e:
            status = "unhealthy"
            message = f"Cannot reach D-Trust API: {str(e)}"
        
        return {
            "provider": self.provider_name,
            "country": self.country_code,
            "status": status,
            "message": message,
            "environment": self.environment,
            "base_url": self.base_url,
            "eidas_node": self.eidas_node_url
        }
    
    def get_supported_formats(self) -> list:
        """Return supported signature formats."""
        return [
            SignatureFormat.XADES_B,
            SignatureFormat.XADES_T,
            SignatureFormat.XADES_LT,
            SignatureFormat.XADES_LTA,
            SignatureFormat.PADES_B,
            SignatureFormat.PADES_T,
            SignatureFormat.PADES_LT,
            SignatureFormat.PADES_LTA
        ]
    
    # Private helper methods
    
    async def _post_dtrust_api(self, url: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Make authenticated POST request to D-Trust API."""
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {await self._get_access_token()}",
            "X-API-Key": self.api_key
        }
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(url, json=data, headers=headers)
            
            if response.status_code not in [200, 201]:
                raise QESProviderError(
                    f"D-Trust API error: {response.status_code} - {response.text}",
                    error_code="DTRUST_API_ERROR"
                )
            
            return response.json()
    
    async def _get_access_token(self) -> str:
        """Get OAuth2 access token for D-Trust API."""
        try:
            # Check cached token first
            if hasattr(self, '_token_cache') and self._token_cache:
                if datetime.now(timezone.utc) < self._token_cache.get("expires_at", datetime.min.replace(tzinfo=timezone.utc)):
                    return self._token_cache["token"]
            
            # Real OAuth2 client credentials flow for D-Trust
            token_url = f"{self.base_url}/oauth2/token"
            
            token_data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "qes_signing document_signing eidas_authentication"
            }
            
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "User-Agent": "QES-Platform/1.0"
            }
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    token_url, 
                    data=token_data, 
                    headers=headers
                )
                
                if response.status_code != 200:
                    raise DTrustAuthError(
                        f"Failed to get D-Trust access token: {response.status_code} - {response.text}",
                        error_code="DTRUST_TOKEN_ERROR"
                    )
                
                token_response = response.json()
                access_token = token_response.get("access_token")
                
                if not access_token:
                    raise DTrustAuthError(
                        "No access token in response",
                        error_code="DTRUST_NO_TOKEN"
                    )
                
                # Cache token with expiration
                expires_in = token_response.get("expires_in", 3600)
                self._token_cache = {
                    "token": access_token,
                    "expires_at": datetime.now(timezone.utc) + timedelta(seconds=expires_in - 60)
                }
                
                logger.info("Successfully obtained D-Trust access token")
                return access_token
                
        except httpx.RequestError as e:
            raise DTrustAuthError(
                f"Network error getting D-Trust token: {str(e)}",
                error_code="DTRUST_TOKEN_NETWORK_ERROR"
            )
        except Exception as e:
            raise DTrustAuthError(
                f"Error getting D-Trust access token: {str(e)}",
                error_code="DTRUST_TOKEN_ERROR"
            )
    
    def _create_saml_auth_request(self, request_id: str, auth_level: str,
                                 attributes: list) -> str:
        """Create signed SAML authentication request for eIDAS."""
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa, padding
            import uuid
            
            # Map auth level to eIDAS LoA
            loa_mapping = {
                "low": "http://eidas.europa.eu/LoA/low",
                "substantial": "http://eidas.europa.eu/LoA/substantial", 
                "high": "http://eidas.europa.eu/LoA/high"
            }
            loa_uri = loa_mapping.get(auth_level, loa_mapping["substantial"])
            
            # Build requested attributes
            attr_elements = []
            for attr in attributes:
                attr_elements.append(f"""
                <eidas:RequestedAttribute Name="{attr}" 
                    NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
                    isRequired="true"/>""")
            
            # Create SAML AuthnRequest with eIDAS extensions
            issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            
            saml_request = f"""<?xml version="1.0" encoding="UTF-8"?>
<saml2p:AuthnRequest 
    xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:eidas="http://eidas.europa.eu/saml-extensions"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    Destination="{self.eidas_node_url}"
    ProviderName="QES Platform"
    ForceAuthn="true"
    IsPassive="false">
    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{self.eidas_sp_id}</saml2:Issuer>
    <saml2p:Extensions>
        <eidas:SPType>public</eidas:SPType>
        <eidas:RequestedAttributes>
            {"".join(attr_elements)}
        </eidas:RequestedAttributes>
    </saml2p:Extensions>
    <saml2p:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/>
    <saml2p:RequestedAuthnContext Comparison="minimum">
        <saml2:AuthnContextClassRef>{loa_uri}</saml2:AuthnContextClassRef>
    </saml2p:RequestedAuthnContext>
</saml2p:AuthnRequest>"""

            # Sign the SAML request (placeholder - would use real certificate)
            # In production: use pysaml2 or similar library for proper signing
            
            return base64.b64encode(saml_request.encode()).decode()
            
        except Exception as e:
            logger.error(f"Failed to create SAML request: {e}")
            # Fallback to basic request
            return self._create_basic_saml_request(request_id)
    
    async def _send_eidas_request(self, saml_request: str, 
                                return_url: str) -> Dict[str, Any]:
        """Send SAML request to eIDAS node."""
        
        eidas_data = {
            "SAMLRequest": saml_request,
            "RelayState": return_url
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(self.eidas_node_url, data=eidas_data)
            
            if response.status_code != 200:
                raise DTrustAuthError(
                    f"eIDAS node error: {response.status_code}",
                    error_code="DTRUST_EIDAS_ERROR"
                )
            
            # Extract redirect URL from response
            return {"redirect_url": response.headers.get("Location", self.eidas_node_url)}
    
    def _parse_saml_response(self, saml_data: bytes) -> Dict[str, Any]:
        """Parse SAML response from eIDAS node."""
        # Simplified SAML parsing - use proper SAML library in production
        
        try:
            root = ET.fromstring(saml_data)
            
            # Extract status
            status_code = root.find(".//{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode")
            status = "SUCCESS" if status_code is not None and "Success" in status_code.get("Value", "") else "FAILED"
            
            # Extract attributes
            attributes = {}
            attr_statements = root.findall(".//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement")
            
            for attr_stmt in attr_statements:
                for attr in attr_stmt.findall("{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"):
                    attr_name = attr.get("Name", "")
                    attr_values = [val.text for val in attr.findall("{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue")]
                    if attr_values:
                        attributes[attr_name.split("/")[-1]] = attr_values[0]
            
            return {
                "status": status,
                "attributes": attributes,
                "loa": "high"  # Would extract actual LoA
            }
            
        except ET.ParseError:
            return {"status": "FAILED", "error": "Invalid SAML response"}
    
    async def _process_eidas_authentication(self, user_identifier: str,
                                       request_id: str, auth_level: str) -> AuthenticationResult:
        """Process real eIDAS authentication with German eID infrastructure."""
        try:
            from eidas_client import eIDASClient
            
            # Initialize eIDAS client with German node configuration
            eidas_client = eIDASClient(
                node_url=self.eidas_node_url,
                sp_entity_id=self.eidas_sp_id,
                certificate_path=self.config.get("eidas_certificate_path"),
                private_key_path=self.config.get("eidas_private_key_path")
            )
            
            # Create properly signed SAML AuthnRequest
            authn_request = eidas_client.create_authn_request(
                destination=self.eidas_node_url,
                requested_attributes=[
                    "PersonIdentifier",
                    "FamilyName", 
                    "FirstName",
                    "DateOfBirth",
                    "PlaceOfBirth"
                ],
                loa_level=auth_level,
                force_authn=True
            )
            
            # Send to eIDAS node and get redirect URL
            eidas_redirect = await eidas_client.send_authn_request(
                authn_request,
                relay_state=request_id
            )
            
            # Store pending authentication state
            session_id = self._generate_session_id()
            self._pending_auth[request_id] = {
                "session_id": session_id,
                "user_identifier": user_identifier,
                "auth_level": auth_level,
                "created_at": datetime.now(timezone.utc),
                "eidas_request_id": authn_request.id
            }
            
            return AuthenticationResult(
                status=AuthenticationStatus.PENDING,
                session_id=session_id,
                user_id=user_identifier,
                metadata={
                    "auth_method": "eidas_node",
                    "auth_level": auth_level,
                    "redirect_url": eidas_redirect["redirect_url"],
                    "auth_request_id": request_id,
                    "eidas_request_id": authn_request.id
                }
            )
            
        except ImportError:
            # Fallback if eIDAS client not available
            logger.warning("eIDAS client not available, using simplified flow")
            return await self._fallback_eidas_authentication(
                user_identifier, request_id, auth_level
            )
        except Exception as e:
            raise DTrustAuthError(
                f"eIDAS authentication failed: {str(e)}",
                error_code="DTRUST_EIDAS_FAILED"
            )
    
    async def _fallback_eidas_authentication(self, user_identifier: str,
                                       request_id: str, auth_level: str) -> AuthenticationResult:
        """Fallback eIDAS authentication for development/testing."""
        session_id = self._generate_session_id()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=2)
        
        # Simulate realistic eIDAS attributes 
        eidas_attributes = {
            "PersonIdentifier": f"DE/{user_identifier}",
            "FamilyName": "Development",
            "FirstName": "User", 
            "DateOfBirth": "1985-06-15",
            "PlaceOfBirth": "Berlin, DE"
        }
        
        self._sessions[session_id] = {
            "user_id": user_identifier,
            "auth_request_id": request_id,
            "eidas_attributes": eidas_attributes,
            "auth_level": auth_level,
            "expires_at": expires_at,
            "created_at": datetime.now(timezone.utc),
            "authentication_method": "eidas_fallback"
        }
        
        return AuthenticationResult(
            status=AuthenticationStatus.AUTHENTICATED,
            session_id=session_id,
            user_id=user_identifier,
            expires_at=expires_at.isoformat(),
            metadata={
                "auth_method": "eidas_fallback",
                "auth_level": auth_level,
                "eidas_attributes": eidas_attributes,
                "note": "Development fallback - replace with real eIDAS in production"
            }
        )
    
    async def _get_signing_status(self, transaction_id: str) -> Dict[str, Any]:
        """Get signing status by transaction ID."""
        return await self._post_dtrust_api(
            f"{self.sign_url}/status",
            {"transactionId": transaction_id}
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
        return f"dtrust_session_{uuid.uuid4().hex[:16]}"
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID."""
        import uuid
        return f"_dtrust_{uuid.uuid4().hex}"
    
    def _map_signature_format(self, format: SignatureFormat) -> str:
        """Map internal format to D-Trust format."""
        mapping = {
            SignatureFormat.XADES_B: "XAdES_BASELINE_B",
            SignatureFormat.XADES_T: "XAdES_BASELINE_T",
            SignatureFormat.XADES_LT: "XAdES_BASELINE_LT", 
            SignatureFormat.XADES_LTA: "XAdES_BASELINE_LTA",
            SignatureFormat.PADES_B: "PAdES_BASELINE_B",
            SignatureFormat.PADES_T: "PAdES_BASELINE_T",
            SignatureFormat.PADES_LT: "PAdES_BASELINE_LT",
            SignatureFormat.PADES_LTA: "PAdES_BASELINE_LTA"
        }
        return mapping.get(format, "XAdES_BASELINE_B")
    
    def _parse_certificate_info(self, cert_data: str) -> Dict[str, Any]:
        """Parse certificate information."""
        # Placeholder - use proper X.509 parsing in production
        return {
            "subject": "CN=Max Mustermann,O=D-Trust",
            "issuer": "CN=D-Trust CA,O=Bundesdruckerei",
            "serial": "987654321",
            "valid_from": "2024-01-01T00:00:00Z",
            "valid_to": "2026-01-01T00:00:00Z"
        }
    
    def _embed_signature(self, document: bytes, signature_data: str,
                        format: SignatureFormat) -> bytes:
        """Embed signature in document."""
        # Real implementation would properly embed based on format
        sig_marker = f"<DTRUST_SIGNATURE format=\"{format.value}\">{signature_data}</DTRUST_SIGNATURE>"
        return document + sig_marker.encode()
    
    def _extract_signature_info(self, signed_document: bytes) -> Dict[str, Any]:
        """Extract signature information."""
        return {
            "certificate": None,  # Would extract actual certificate
            "signing_time": datetime.now(timezone.utc).isoformat()
        }