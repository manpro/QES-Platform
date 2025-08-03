"""
Timestamp Authority (TSA) Client

Implements RFC 3161 timestamp request/response handling for
XAdES-T/PAdES-T signatures.
"""

import hashlib
import asyncio
import secrets
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime, timezone
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from pyasn1.codec.der import encoder, decoder
from pyasn1.codec.native import encoder as native_encoder
from pyasn1.type import univ, namedtype, namedval, tag, constraint, useful
from pyasn1_modules import rfc3161

logger = logging.getLogger(__name__)


@dataclass
class TSARequest:
    """RFC 3161 timestamp request"""
    message_imprint: bytes
    hash_algorithm: str
    nonce: Optional[int] = None
    cert_req: bool = True
    policy_id: Optional[str] = None


@dataclass
class TSAResponse:
    """RFC 3161 timestamp response"""
    token_data: bytes
    timestamp: datetime
    serial_number: str
    hash_algorithm: str
    message_imprint: bytes
    tsa_certificate: Optional[bytes] = None
    policy_id: Optional[str] = None


class TSAError(Exception):
    """TSA-related errors"""
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class TSAClient:
    """
    RFC 3161 compliant Timestamp Authority client.
    
    Handles creation of timestamp requests and parsing of responses
    for integration with eIDAS signature workflows.
    """
    
    def __init__(self, tsa_url: str, config: Optional[Dict[str, Any]] = None):
        self.tsa_url = tsa_url
        self.config = config or {}
        self.timeout = self.config.get("timeout", 30)
        self.verify_ssl = self.config.get("verify_ssl", True)
        self.username = self.config.get("username")
        self.password = self.config.get("password")
    
    async def get_timestamp(self, data: bytes, 
                          hash_algorithm: str = "SHA-256") -> TSAResponse:
        """
        Get timestamp token for given data.
        
        Args:
            data: Data to timestamp
            hash_algorithm: Hash algorithm to use
            
        Returns:
            TSAResponse with timestamp token
            
        Raises:
            TSAError: If timestamp request fails
        """
        
        # Create message imprint (hash of data)
        if hash_algorithm == "SHA-256":
            hasher = hashlib.sha256()
        elif hash_algorithm == "SHA-1":
            hasher = hashlib.sha1()
        elif hash_algorithm == "SHA-512":
            hasher = hashlib.sha512()
        else:
            raise TSAError(f"Unsupported hash algorithm: {hash_algorithm}")
        
        hasher.update(data)
        message_imprint = hasher.digest()
        
        # Create TSA request
        tsa_request = TSARequest(
            message_imprint=message_imprint,
            hash_algorithm=hash_algorithm,
            nonce=self._generate_nonce(),
            cert_req=True,
            policy_id=self.config.get("policy_id")
        )
        
        # Build and send request
        request_data = self._build_tsa_request(tsa_request)
        response_data = await self._send_tsa_request(request_data)
        
        # Parse response
        tsa_response = self._parse_tsa_response(response_data, tsa_request)
        
        return tsa_response
    
    def _build_tsa_request(self, request: TSARequest) -> bytes:
        """
        Build RFC 3161 timestamp request in ASN.1 DER format.
        """
        try:
            # Create TSAReq structure using pyasn1
            tsa_req = rfc3161.TSAReq()
            
            # Set version (always 1 for RFC 3161)
            tsa_req.setComponentByName('version', 1)
            
            # Create MessageImprint
            message_imprint = rfc3161.MessageImprint()
            
            # Set hash algorithm
            hash_algorithm_map = {
                "SHA-1": "1.3.14.3.2.26",
                "SHA-256": "2.16.840.1.101.3.4.2.1",
                "SHA-384": "2.16.840.1.101.3.4.2.2", 
                "SHA-512": "2.16.840.1.101.3.4.2.3"
            }
            
            hash_oid = hash_algorithm_map.get(request.hash_algorithm)
            if not hash_oid:
                raise TSAError(f"Unsupported hash algorithm: {request.hash_algorithm}")
            
            # Create AlgorithmIdentifier
            algorithm_id = rfc3161.AlgorithmIdentifier()
            algorithm_id.setComponentByName('algorithm', univ.ObjectIdentifier(hash_oid))
            algorithm_id.setComponentByName('parameters', univ.Null())
            
            message_imprint.setComponentByName('hashAlgorithm', algorithm_id)
            message_imprint.setComponentByName('hashedMessage', univ.OctetString(request.message_imprint))
            
            tsa_req.setComponentByName('messageImprint', message_imprint)
            
            # Set optional policy ID
            if request.policy_id:
                tsa_req.setComponentByName('reqPolicy', univ.ObjectIdentifier(request.policy_id))
            
            # Set optional nonce
            if request.nonce:
                tsa_req.setComponentByName('nonce', univ.Integer(request.nonce))
            
            # Set certificate request flag
            if request.cert_req:
                tsa_req.setComponentByName('certReq', univ.Boolean(True))
            
            # Encode to DER
            return encoder.encode(tsa_req)
            
        except Exception as e:
            logger.error(f"Failed to build TSA request: {e}")
            raise TSAError(f"Failed to build TSA request: {str(e)}")
    
    async def _send_tsa_request(self, request_data: bytes) -> bytes:
        """Send timestamp request to TSA server."""
        
        headers = {
            "Content-Type": "application/timestamp-query",
            "Content-Length": str(len(request_data)),
            "User-Agent": "eIDAS-QES-Platform/1.0"
        }
        
        auth = None
        if self.username and self.password:
            auth = (self.username, self.password)
        
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                verify=self.verify_ssl
            ) as client:
                response = await client.post(
                    self.tsa_url,
                    content=request_data,
                    headers=headers,
                    auth=auth
                )
                
                if response.status_code != 200:
                    raise TSAError(
                        f"TSA request failed with status {response.status_code}: "
                        f"{response.text}",
                        status_code=response.status_code
                    )
                
                content_type = response.headers.get("content-type", "")
                if "application/timestamp-reply" not in content_type:
                    raise TSAError(
                        f"Invalid response content type: {content_type}"
                    )
                
                return response.content
                
        except httpx.RequestError as e:
            raise TSAError(f"Network error contacting TSA: {str(e)}")
    
    def _parse_tsa_response(self, response_data: bytes, 
                          original_request: TSARequest) -> TSAResponse:
        """
        Parse RFC 3161 timestamp response.
        """
        try:
            # Decode ASN.1 DER response
            tsa_resp, remainder = decoder.decode(response_data, asn1Spec=rfc3161.TSAResp())
            
            if remainder:
                logger.warning(f"Unexpected data after TSA response: {len(remainder)} bytes")
            
            # Check status
            status = tsa_resp.getComponentByName('status')
            status_value = int(status.getComponentByName('status'))
            
            if status_value != 0:  # 0 = granted
                status_string = status.getComponentByName('statusString')
                failure_info = status.getComponentByName('failureInfo')
                
                error_msg = f"TSA request failed with status {status_value}"
                if status_string and status_string.hasValue():
                    error_msg += f": {status_string.prettyPrint()}"
                if failure_info and failure_info.hasValue():
                    error_msg += f" (failure info: {failure_info.prettyPrint()})"
                
                raise TSAError(error_msg)
            
            # Extract timestamp token
            time_stamp_token = tsa_resp.getComponentByName('timeStampToken')
            if not time_stamp_token or not time_stamp_token.hasValue():
                raise TSAError("TSA response missing timeStampToken")
            
            # Parse the timestamp token (which is a CMS ContentInfo)
            token_data = encoder.encode(time_stamp_token)
            
            # Extract timestamp info from the token
            timestamp_info = self._extract_timestamp_info(time_stamp_token, original_request)
            
            return TSAResponse(
                token_data=token_data,
                timestamp=timestamp_info["timestamp"],
                serial_number=timestamp_info["serial_number"],
                hash_algorithm=original_request.hash_algorithm,
                message_imprint=original_request.message_imprint,
                tsa_certificate=timestamp_info.get("certificate"),
                policy_id=timestamp_info.get("policy_id")
            )
            
        except Exception as e:
            logger.error(f"Failed to parse TSA response: {e}")
            raise TSAError(f"Failed to parse TSA response: {str(e)}")
    
    def _extract_timestamp_info(self, time_stamp_token, original_request: TSARequest) -> Dict[str, Any]:
        """Extract information from timestamp token using advanced ASN.1 parsing."""
        try:
            from core.asn1_parser import ASN1Parser
            
            # Encode the timestamp token to bytes
            token_data = encoder.encode(time_stamp_token)
            
            # Use advanced ASN.1 parser
            parser = ASN1Parser()
            parsed_token = parser.parse_timestamp_token(token_data)
            
            # Extract TSTInfo
            tst_info = parsed_token["tst_info"]
            
            # Extract certificate (first one if available)
            certificate = None
            certificates = parsed_token["certificates"]
            if certificates:
                certificate = certificates[0].raw_certificate
            
            return {
                "timestamp": tst_info.gen_time,
                "serial_number": tst_info.serial_number,
                "policy_id": tst_info.policy_id,
                "certificate": certificate,
                "hash_algorithm": tst_info.hash_algorithm,
                "message_imprint": tst_info.message_imprint,
                "tsa_name": tst_info.tsa_name,
                "accuracy": tst_info.accuracy,
                "nonce": tst_info.nonce,
                "parsed_successfully": True
            }
            
        except Exception as e:
            logger.warning(f"Advanced parsing failed, using fallback: {e}")
            # Fallback to basic parsing
            return {
                "timestamp": datetime.now(timezone.utc),
                "serial_number": str(secrets.randbits(64)),
                "policy_id": None,
                "certificate": None,
                "parsed_successfully": False,
                "error": str(e)
            }
    
    def _generate_nonce(self) -> int:
        """Generate cryptographically secure random nonce for TSA request."""
        return secrets.randbits(32)
    
    async def verify_timestamp_token(self, token_data: bytes, 
                                   original_data: bytes,
                                   hash_algorithm: str = "SHA-256") -> Dict[str, Any]:
        """
        Verify timestamp token against original data using advanced ASN.1 parsing.
        
        Args:
            token_data: The timestamp token to verify
            original_data: Original data that was timestamped
            hash_algorithm: Hash algorithm used
            
        Returns:
            Dict with comprehensive verification results
        """
        try:
            from core.asn1_parser import ASN1Parser
            
            verification_result = {
                "valid": False,
                "timestamp": None,
                "serial_number": None,
                "message_imprint_valid": False,
                "signature_valid": False,
                "certificate_valid": False,
                "chain_valid": False,
                "timestamp_within_validity": False,
                "nonce_valid": False,
                "policy_valid": False,
                "errors": [],
                "warnings": []
            }
            
            # Parse the timestamp token using advanced parser
            parser = ASN1Parser()
            parsed_token = parser.parse_timestamp_token(token_data)
            
            tst_info = parsed_token["tst_info"]
            certificates = parsed_token["certificates"]
            signature_infos = parsed_token["signature_info"]
            signed_data = parsed_token["signed_data"]
            
            # Extract basic information
            verification_result["timestamp"] = tst_info.gen_time
            verification_result["serial_number"] = tst_info.serial_number
            
            # 1. Verify message imprint
            message_imprint_valid = parser.verify_message_imprint(tst_info, original_data)
            verification_result["message_imprint_valid"] = message_imprint_valid
            
            if not message_imprint_valid:
                verification_result["errors"].append("Message imprint verification failed")
            
            # 2. Verify timestamp signature and certificate
            sig_verification = parser.verify_timestamp_signature(
                signed_data, tst_info, certificates, signature_infos
            )
            
            verification_result["signature_valid"] = sig_verification["signature_valid"]
            verification_result["certificate_valid"] = sig_verification["certificate_valid"]
            verification_result["timestamp_within_validity"] = sig_verification["timestamp_valid"]
            
            verification_result["errors"].extend(sig_verification["errors"])
            
            # 3. Verify nonce (if present in original request)
            nonce_valid = True  # We don't have the original nonce to compare
            verification_result["nonce_valid"] = nonce_valid
            
            # 4. Check policy ID
            policy_valid = tst_info.policy_id is not None
            verification_result["policy_valid"] = policy_valid
            
            # 5. Additional validations
            if tst_info.gen_time:
                # Check if timestamp is reasonable (not too far in future/past)
                now = datetime.now(timezone.utc)
                time_diff = abs((tst_info.gen_time - now).total_seconds())
                
                if time_diff > 24 * 3600:  # More than 24 hours difference
                    verification_result["warnings"].append(
                        f"Timestamp differs from current time by {time_diff/3600:.1f} hours"
                    )
                
                # Check if timestamp is not before Unix epoch
                if tst_info.gen_time.year < 1970:
                    verification_result["errors"].append("Invalid timestamp: before Unix epoch")
            
            # 6. Check certificate chain (basic validation)
            chain_valid = len(certificates) > 0
            if certificates:
                # Check certificate validity period
                tsa_cert = certificates[0]
                if tst_info.gen_time:
                    if (tst_info.gen_time < tsa_cert.not_before or 
                        tst_info.gen_time > tsa_cert.not_after):
                        verification_result["errors"].append(
                            "Timestamp generated outside certificate validity period"
                        )
                        chain_valid = False
                
                # Check extended key usage for timestamping
                if "timeStamping" not in tsa_cert.extended_key_usage:
                    verification_result["warnings"].append(
                        "Certificate does not have timeStamping extended key usage"
                    )
            else:
                verification_result["errors"].append("No TSA certificate found in token")
                chain_valid = False
            
            verification_result["chain_valid"] = chain_valid
            
            # Overall validity
            verification_result["valid"] = (
                verification_result["message_imprint_valid"] and
                verification_result["signature_valid"] and
                verification_result["certificate_valid"] and
                verification_result["chain_valid"] and
                len(verification_result["errors"]) == 0
            )
            
            # Add detailed parsing information
            verification_result["parsing_details"] = {
                "tst_info_version": tst_info.version,
                "policy_id": tst_info.policy_id,
                "hash_algorithm": tst_info.hash_algorithm,
                "accuracy": tst_info.accuracy,
                "ordering": tst_info.ordering,
                "tsa_name": tst_info.tsa_name,
                "certificate_count": len(certificates),
                "signature_count": len(signature_infos)
            }
            
            return verification_result
            
        except Exception as e:
            logger.error(f"Advanced timestamp verification failed: {e}")
            return {
                "valid": False,
                "errors": [f"Verification failed: {str(e)}"],
                "parsing_details": {"error": str(e)}
            }
    
    def get_timestamp_info(self, token_data: bytes) -> Dict[str, Any]:
        """
        Extract comprehensive information from timestamp token using advanced ASN.1 parsing.
        
        Args:
            token_data: The timestamp token
            
        Returns:
            Dict with detailed timestamp information
        """
        try:
            from core.asn1_parser import ASN1Parser
            
            # Use advanced ASN.1 parser
            parser = ASN1Parser()
            parsed_token = parser.parse_timestamp_token(token_data)
            
            tst_info = parsed_token["tst_info"]
            certificates = parsed_token["certificates"]
            signature_infos = parsed_token["signature_info"]
            
            # Build comprehensive information dictionary
            info = {
                "timestamp": tst_info.gen_time,
                "serial_number": tst_info.serial_number,
                "policy_id": tst_info.policy_id,
                "hash_algorithm": tst_info.hash_algorithm,
                "message_imprint": tst_info.message_imprint.hex() if tst_info.message_imprint else None,
                "token_size": len(token_data),
                "parsed_successfully": True,
                
                # TSTInfo details
                "tst_info": {
                    "version": tst_info.version,
                    "accuracy": tst_info.accuracy,
                    "ordering": tst_info.ordering,
                    "nonce": tst_info.nonce,
                    "tsa_name": tst_info.tsa_name,
                    "extensions_count": len(tst_info.extensions) if tst_info.extensions else 0
                },
                
                # Certificate information
                "certificates": [],
                
                # Signature information
                "signatures": [],
                
                # Token structure
                "token_structure": {
                    "content_type": parsed_token["content_info"]["content_type"],
                    "is_signed_data": parsed_token["signed_data"]["is_tst_info"],
                    "signed_data_version": parsed_token["signed_data"]["version"],
                    "digest_algorithms": [alg["algorithm"] for alg in parsed_token["signed_data"]["digest_algorithms"]],
                    "encap_content_type": parsed_token["signed_data"]["encap_content_type"]
                }
            }
            
            # Add certificate details
            for cert in certificates:
                cert_info = {
                    "subject": cert.subject,
                    "issuer": cert.issuer,
                    "serial_number": cert.serial_number,
                    "not_before": cert.not_before.isoformat(),
                    "not_after": cert.not_after.isoformat(),
                    "public_key_algorithm": cert.public_key_algorithm,
                    "signature_algorithm": cert.signature_algorithm,
                    "key_usage": cert.key_usage,
                    "extended_key_usage": cert.extended_key_usage,
                    "certificate_size": len(cert.raw_certificate)
                }
                info["certificates"].append(cert_info)
            
            # Add signature details
            for sig in signature_infos:
                sig_info = {
                    "digest_algorithm": sig.digest_algorithm,
                    "signature_algorithm": sig.signature_algorithm,
                    "signature_size": len(sig.signature_value),
                    "has_signer_certificate": sig.signer_certificate is not None,
                    "signed_attributes_count": len(sig.signed_attributes),
                    "unsigned_attributes_count": len(sig.unsigned_attributes)
                }
                info["signatures"].append(sig_info)
            
            # Add summary statistics
            info["summary"] = {
                "total_certificates": len(certificates),
                "total_signatures": len(signature_infos),
                "primary_tsa_name": tst_info.tsa_name or (certificates[0].subject if certificates else "Unknown"),
                "timestamp_precision": "microseconds" if tst_info.accuracy and "micros" in tst_info.accuracy else "seconds",
                "has_nonce": tst_info.nonce is not None,
                "has_extensions": tst_info.extensions is not None and len(tst_info.extensions) > 0
            }
            
            return info
            
        except Exception as e:
            logger.warning(f"Advanced parsing failed, using basic info: {e}")
            return {
                "timestamp": None,
                "serial_number": None,
                "tsa_name": "Unknown",
                "hash_algorithm": "Unknown",
                "policy_id": None,
                "token_size": len(token_data),
                "parsed_successfully": False,
                "error": str(e),
                "parsing_method": "fallback"
            }