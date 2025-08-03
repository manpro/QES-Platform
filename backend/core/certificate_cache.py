"""
Certificate Cache Management

Specialized caching for QES certificates, HSM keys, and cryptographic materials
with security-conscious TTL management and automatic validation.
"""

import logging
import hashlib
import json
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .redis_cache import get_cache, SerializationFormat
from adapters.base.qes_provider import Certificate

logger = logging.getLogger(__name__)


class CertificateStatus(str, Enum):
    """Certificate cache status"""
    VALID = "valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


@dataclass
class CachedCertificate:
    """Cached certificate with metadata"""
    certificate_data: bytes
    certificate_pem: str
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    key_usage: List[str]
    extended_key_usage: List[str]
    fingerprint_sha256: str
    provider: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    cached_at: datetime = None
    last_validated: datetime = None
    validation_count: int = 0
    status: CertificateStatus = CertificateStatus.VALID


class CertificateCache:
    """
    Certificate-specific cache with security features:
    - Automatic expiration based on certificate validity
    - Certificate validation on retrieval
    - Provider-specific certificate management
    - HSM key caching with secure TTL
    - Revocation status caching
    """
    
    def __init__(self):
        self.cache = None
        self.namespace = "certificates"
        
        # Cache TTL settings (in seconds)
        self.default_cert_ttl = 3600        # 1 hour for regular certificates
        self.hsm_key_ttl = 1800              # 30 minutes for HSM keys
        self.revocation_ttl = 900            # 15 minutes for revocation status
        self.provider_metadata_ttl = 7200    # 2 hours for provider metadata
        
        # Security settings
        self.max_cert_age_days = 30          # Don't cache certs older than 30 days
        self.validation_interval_hours = 6   # Re-validate every 6 hours
    
    async def initialize(self):
        """Initialize certificate cache"""
        self.cache = await get_cache()
        logger.info("Certificate cache initialized")
    
    def _get_certificate_cache_key(self, provider: str, identifier: str) -> str:
        """Generate cache key for certificate"""
        # Hash the identifier for consistent key length
        id_hash = hashlib.sha256(identifier.encode()).hexdigest()[:16]
        return f"{provider}:cert:{id_hash}"
    
    def _get_hsm_key_cache_key(self, hsm_provider: str, key_id: str) -> str:
        """Generate cache key for HSM key"""
        key_hash = hashlib.sha256(key_id.encode()).hexdigest()[:16]
        return f"{hsm_provider}:hsm_key:{key_hash}"
    
    def _get_revocation_cache_key(self, cert_serial: str, issuer_hash: str) -> str:
        """Generate cache key for revocation status"""
        return f"revocation:{issuer_hash}:{cert_serial}"
    
    def _calculate_certificate_ttl(self, cert: x509.Certificate) -> int:
        """Calculate appropriate TTL based on certificate validity"""
        now = datetime.utcnow()
        
        # Don't cache expired certificates
        if cert.not_valid_after <= now:
            return 0
        
        # Don't cache certificates that are too old
        cert_age = now - cert.not_valid_before
        if cert_age.days > self.max_cert_age_days:
            logger.warning(f"Certificate too old to cache: {cert_age.days} days")
            return 0
        
        # Calculate time until expiration
        time_to_expiry = cert.not_valid_after - now
        
        # Cache for minimum of default TTL or 10% of remaining validity
        cache_duration = min(
            self.default_cert_ttl,
            int(time_to_expiry.total_seconds() * 0.1)
        )
        
        # Ensure minimum cache time of 5 minutes for valid certificates
        return max(cache_duration, 300)
    
    def _parse_certificate_metadata(self, cert_data: bytes) -> CachedCertificate:
        """Parse certificate and extract metadata"""
        try:
            # Parse certificate
            cert = x509.load_der_x509_certificate(cert_data)
            
            # Extract basic information
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            serial_number = str(cert.serial_number)
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after
            
            # Extract key usage
            key_usage = []
            try:
                key_usage_ext = cert.extensions.get_extension_for_oid(
                    x509.ExtensionOID.KEY_USAGE
                ).value
                
                usage_attrs = [
                    'digital_signature', 'content_commitment', 'key_encipherment',
                    'data_encipherment', 'key_agreement', 'key_cert_sign',
                    'crl_sign', 'encipher_only', 'decipher_only'
                ]
                
                for attr in usage_attrs:
                    if hasattr(key_usage_ext, attr) and getattr(key_usage_ext, attr):
                        key_usage.append(attr)
                        
            except x509.ExtensionNotFound:
                pass
            
            # Extract extended key usage
            extended_key_usage = []
            try:
                ext_key_usage_ext = cert.extensions.get_extension_for_oid(
                    x509.ExtensionOID.EXTENDED_KEY_USAGE
                ).value
                
                extended_key_usage = [oid._name for oid in ext_key_usage_ext]
                
            except x509.ExtensionNotFound:
                pass
            
            # Calculate fingerprint
            fingerprint = hashlib.sha256(cert_data).hexdigest()
            
            # Convert to PEM
            pem_data = cert.public_bytes(serialization.Encoding.PEM).decode()
            
            return CachedCertificate(
                certificate_data=cert_data,
                certificate_pem=pem_data,
                subject=subject,
                issuer=issuer,
                serial_number=serial_number,
                not_before=not_before,
                not_after=not_after,
                key_usage=key_usage,
                extended_key_usage=extended_key_usage,
                fingerprint_sha256=fingerprint,
                provider="unknown",
                cached_at=datetime.utcnow(),
                last_validated=datetime.utcnow(),
                validation_count=1
            )
            
        except Exception as e:
            logger.error(f"Failed to parse certificate metadata: {e}")
            raise
    
    async def cache_certificate(
        self,
        provider: str,
        identifier: str,
        certificate: Certificate,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> bool:
        """Cache a QES certificate"""
        
        try:
            # Parse certificate metadata
            cached_cert = self._parse_certificate_metadata(certificate.certificate_data)
            cached_cert.provider = provider
            cached_cert.user_id = user_id
            cached_cert.session_id = session_id
            
            # Calculate appropriate TTL
            cert = x509.load_der_x509_certificate(certificate.certificate_data)
            ttl = self._calculate_certificate_ttl(cert)
            
            if ttl <= 0:
                logger.warning(f"Certificate not cached due to validity issues: {identifier}")
                return False
            
            # Store in cache
            cache_key = self._get_certificate_cache_key(provider, identifier)
            
            success = await self.cache.set(
                cache_key,
                cached_cert.__dict__,
                ttl=ttl,
                namespace=self.namespace,
                serialization_format=SerializationFormat.GZIP_JSON
            )
            
            if success:
                logger.info(f"Certificate cached: {provider}:{identifier} (TTL: {ttl}s)")
                
                # Cache certificate metadata separately for quick lookups
                metadata_key = f"{cache_key}:metadata"
                metadata = {
                    "subject": cached_cert.subject,
                    "issuer": cached_cert.issuer,
                    "serial_number": cached_cert.serial_number,
                    "fingerprint": cached_cert.fingerprint_sha256,
                    "not_after": cached_cert.not_after.isoformat(),
                    "provider": provider,
                    "cached_at": cached_cert.cached_at.isoformat()
                }
                
                await self.cache.set(
                    metadata_key,
                    metadata,
                    ttl=ttl,
                    namespace=self.namespace
                )
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to cache certificate {provider}:{identifier}: {e}")
            return False
    
    async def get_certificate(
        self,
        provider: str,
        identifier: str,
        validate: bool = True
    ) -> Optional[CachedCertificate]:
        """Retrieve cached certificate"""
        
        try:
            cache_key = self._get_certificate_cache_key(provider, identifier)
            
            # Get from cache
            cached_data = await self.cache.get(cache_key, namespace=self.namespace)
            
            if not cached_data:
                return None
            
            # Reconstruct CachedCertificate object
            cached_cert = CachedCertificate(**cached_data)
            
            # Validate certificate if requested
            if validate:
                validation_needed = (
                    cached_cert.last_validated is None or
                    (datetime.utcnow() - cached_cert.last_validated).total_seconds() > 
                    self.validation_interval_hours * 3600
                )
                
                if validation_needed:
                    is_valid = await self._validate_certificate(cached_cert)
                    if not is_valid:
                        # Remove invalid certificate from cache
                        await self.invalidate_certificate(provider, identifier)
                        return None
                    
                    # Update validation timestamp
                    cached_cert.last_validated = datetime.utcnow()
                    cached_cert.validation_count += 1
                    
                    # Update cache with new validation info
                    await self.cache.set(
                        cache_key,
                        cached_cert.__dict__,
                        namespace=self.namespace,
                        serialization_format=SerializationFormat.GZIP_JSON
                    )
            
            logger.debug(f"Certificate retrieved from cache: {provider}:{identifier}")
            return cached_cert
            
        except Exception as e:
            logger.error(f"Failed to get certificate {provider}:{identifier}: {e}")
            return None
    
    async def _validate_certificate(self, cached_cert: CachedCertificate) -> bool:
        """Validate cached certificate"""
        
        try:
            # Parse certificate
            cert = x509.load_der_x509_certificate(cached_cert.certificate_data)
            
            # Check expiration
            now = datetime.utcnow()
            if cert.not_valid_after <= now:
                logger.info(f"Certificate expired: {cached_cert.serial_number}")
                cached_cert.status = CertificateStatus.EXPIRED
                return False
            
            # Check if certificate is not yet valid
            if cert.not_valid_before > now:
                logger.warning(f"Certificate not yet valid: {cached_cert.serial_number}")
                return False
            
            # Check revocation status (if we have it cached)
            issuer_hash = hashlib.sha256(cached_cert.issuer.encode()).hexdigest()[:16]
            revocation_key = self._get_revocation_cache_key(
                cached_cert.serial_number, 
                issuer_hash
            )
            
            revocation_status = await self.cache.get(revocation_key, namespace=self.namespace)
            if revocation_status and revocation_status.get("revoked", False):
                logger.warning(f"Certificate revoked: {cached_cert.serial_number}")
                cached_cert.status = CertificateStatus.REVOKED
                return False
            
            cached_cert.status = CertificateStatus.VALID
            return True
            
        except Exception as e:
            logger.error(f"Certificate validation failed: {e}")
            cached_cert.status = CertificateStatus.UNKNOWN
            return False
    
    async def cache_hsm_key(
        self,
        hsm_provider: str,
        key_id: str,
        key_data: Dict[str, Any],
        ttl: Optional[int] = None
    ) -> bool:
        """Cache HSM key information"""
        
        try:
            cache_key = self._get_hsm_key_cache_key(hsm_provider, key_id)
            ttl = ttl or self.hsm_key_ttl
            
            # Add metadata
            cached_key_data = {
                **key_data,
                "cached_at": datetime.utcnow().isoformat(),
                "hsm_provider": hsm_provider,
                "key_id": key_id
            }
            
            success = await self.cache.set(
                cache_key,
                cached_key_data,
                ttl=ttl,
                namespace=self.namespace,
                serialization_format=SerializationFormat.GZIP_JSON
            )
            
            if success:
                logger.info(f"HSM key cached: {hsm_provider}:{key_id} (TTL: {ttl}s)")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to cache HSM key {hsm_provider}:{key_id}: {e}")
            return False
    
    async def get_hsm_key(self, hsm_provider: str, key_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached HSM key"""
        
        try:
            cache_key = self._get_hsm_key_cache_key(hsm_provider, key_id)
            
            key_data = await self.cache.get(cache_key, namespace=self.namespace)
            
            if key_data:
                logger.debug(f"HSM key retrieved from cache: {hsm_provider}:{key_id}")
            
            return key_data
            
        except Exception as e:
            logger.error(f"Failed to get HSM key {hsm_provider}:{key_id}: {e}")
            return None
    
    async def cache_revocation_status(
        self,
        certificate_serial: str,
        issuer: str,
        is_revoked: bool,
        revocation_date: Optional[datetime] = None,
        reason: Optional[str] = None
    ) -> bool:
        """Cache certificate revocation status"""
        
        try:
            issuer_hash = hashlib.sha256(issuer.encode()).hexdigest()[:16]
            cache_key = self._get_revocation_cache_key(certificate_serial, issuer_hash)
            
            revocation_data = {
                "revoked": is_revoked,
                "revocation_date": revocation_date.isoformat() if revocation_date else None,
                "reason": reason,
                "checked_at": datetime.utcnow().isoformat(),
                "certificate_serial": certificate_serial,
                "issuer": issuer
            }
            
            success = await self.cache.set(
                cache_key,
                revocation_data,
                ttl=self.revocation_ttl,
                namespace=self.namespace
            )
            
            if success:
                status = "revoked" if is_revoked else "valid"
                logger.info(f"Revocation status cached: {certificate_serial} - {status}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to cache revocation status for {certificate_serial}: {e}")
            return False
    
    async def get_revocation_status(
        self,
        certificate_serial: str,
        issuer: str
    ) -> Optional[Dict[str, Any]]:
        """Get cached revocation status"""
        
        try:
            issuer_hash = hashlib.sha256(issuer.encode()).hexdigest()[:16]
            cache_key = self._get_revocation_cache_key(certificate_serial, issuer_hash)
            
            revocation_data = await self.cache.get(cache_key, namespace=self.namespace)
            
            if revocation_data:
                logger.debug(f"Revocation status retrieved from cache: {certificate_serial}")
            
            return revocation_data
            
        except Exception as e:
            logger.error(f"Failed to get revocation status for {certificate_serial}: {e}")
            return None
    
    async def invalidate_certificate(self, provider: str, identifier: str) -> bool:
        """Remove certificate from cache"""
        
        try:
            cache_key = self._get_certificate_cache_key(provider, identifier)
            metadata_key = f"{cache_key}:metadata"
            
            # Delete both certificate and metadata
            success1 = await self.cache.delete(cache_key, namespace=self.namespace)
            success2 = await self.cache.delete(metadata_key, namespace=self.namespace)
            
            if success1 or success2:
                logger.info(f"Certificate invalidated: {provider}:{identifier}")
            
            return success1 or success2
            
        except Exception as e:
            logger.error(f"Failed to invalidate certificate {provider}:{identifier}: {e}")
            return False
    
    async def invalidate_provider_certificates(self, provider: str) -> int:
        """Remove all certificates for a provider"""
        
        try:
            pattern = f"{provider}:cert:*"
            deleted_count = await self.cache.delete_pattern(pattern, namespace=self.namespace)
            
            # Also delete metadata
            metadata_pattern = f"{provider}:cert:*:metadata"
            deleted_metadata = await self.cache.delete_pattern(metadata_pattern, namespace=self.namespace)
            
            total_deleted = deleted_count + deleted_metadata
            
            if total_deleted > 0:
                logger.info(f"Invalidated {total_deleted} certificate entries for provider {provider}")
            
            return total_deleted
            
        except Exception as e:
            logger.error(f"Failed to invalidate certificates for provider {provider}: {e}")
            return 0
    
    async def list_cached_certificates(
        self,
        provider: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List cached certificates with metadata"""
        
        try:
            if provider:
                pattern = f"{provider}:cert:*:metadata"
            else:
                pattern = "*:cert:*:metadata"
            
            # Get all metadata keys
            metadata_keys = await self.cache.async_redis_client.keys(
                self.cache._build_key(self.namespace, pattern)
            )
            
            if not metadata_keys:
                return []
            
            # Get metadata for all certificates
            pipe = self.cache.async_redis_client.pipeline()
            for key in metadata_keys:
                pipe.get(key)
            
            results = await pipe.execute()
            
            certificates = []
            for i, metadata_json in enumerate(results):
                if metadata_json:
                    try:
                        metadata = json.loads(metadata_json)
                        certificates.append(metadata)
                    except Exception as e:
                        logger.error(f"Failed to parse certificate metadata: {e}")
            
            return certificates
            
        except Exception as e:
            logger.error(f"Failed to list cached certificates: {e}")
            return []
    
    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get certificate cache statistics"""
        
        try:
            # Get all certificate-related keys
            all_keys = await self.cache.async_redis_client.keys(
                self.cache._build_key(self.namespace, "*")
            )
            
            # Categorize keys
            cert_keys = [k for k in all_keys if b":cert:" in k and not k.endswith(b":metadata")]
            metadata_keys = [k for k in all_keys if k.endswith(b":metadata")]
            hsm_keys = [k for k in all_keys if b":hsm_key:" in k]
            revocation_keys = [k for k in all_keys if b":revocation:" in k]
            
            # Get memory usage for certificate data
            pipe = self.cache.async_redis_client.pipeline()
            for key in cert_keys:
                pipe.memory_usage(key)
            
            memory_usages = await pipe.execute()
            total_memory = sum(usage or 0 for usage in memory_usages)
            
            return {
                "total_certificates": len(cert_keys),
                "total_metadata_entries": len(metadata_keys),
                "total_hsm_keys": len(hsm_keys),
                "total_revocation_entries": len(revocation_keys),
                "total_memory_bytes": total_memory,
                "average_cert_size_bytes": total_memory // len(cert_keys) if cert_keys else 0,
                "namespace": self.namespace,
                "ttl_settings": {
                    "default_cert_ttl": self.default_cert_ttl,
                    "hsm_key_ttl": self.hsm_key_ttl,
                    "revocation_ttl": self.revocation_ttl,
                    "provider_metadata_ttl": self.provider_metadata_ttl
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get certificate cache stats: {e}")
            return {}


# Global certificate cache instance
_cert_cache_instance: Optional[CertificateCache] = None


async def get_certificate_cache() -> CertificateCache:
    """Get global certificate cache instance"""
    global _cert_cache_instance
    
    if _cert_cache_instance is None:
        _cert_cache_instance = CertificateCache()
        await _cert_cache_instance.initialize()
    
    return _cert_cache_instance