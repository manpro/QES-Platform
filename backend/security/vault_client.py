"""
HashiCorp Vault Client

Provides secure secret management and PKI services for the
eIDAS QES platform with HSM integration capabilities.
"""

import asyncio
import json
import base64
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone, timedelta
import httpx
import hvac
from hvac.exceptions import VaultError


class VaultError(Exception):
    """Vault-related errors"""
    def __init__(self, message: str, error_code: Optional[str] = None):
        super().__init__(message)
        self.error_code = error_code


class VaultClient:
    """
    HashiCorp Vault client for secure secret and key management.
    
    Provides integration with Vault PKI engine and HSM backends
    for qualified electronic signature operations.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.vault_url = config["vault_url"]
        self.vault_token = config.get("vault_token")
        self.vault_role_id = config.get("vault_role_id")
        self.vault_secret_id = config.get("vault_secret_id")
        
        # PKI configuration
        self.pki_mount_path = config.get("pki_mount_path", "pki")
        self.intermediate_pki_path = config.get("intermediate_pki_path", "pki_int")
        
        # HSM configuration
        self.hsm_enabled = config.get("hsm_enabled", False)
        self.hsm_mount_path = config.get("hsm_mount_path", "hsm")
        
        # Timeout settings
        self.timeout = config.get("timeout", 30)
        
        # Initialize Vault client
        self.client = hvac.Client(
            url=self.vault_url,
            timeout=self.timeout
        )
        
        # Authentication state
        self._authenticated = False
        self._token_expires_at = None
    
    async def authenticate(self) -> bool:
        """
        Authenticate with Vault using AppRole method.
        
        Returns:
            True if authentication successful
        """
        
        try:
            if self.vault_token:
                # Use provided token
                self.client.token = self.vault_token
                if self.client.is_authenticated():
                    self._authenticated = True
                    return True
            
            elif self.vault_role_id and self.vault_secret_id:
                # Use AppRole authentication
                auth_response = self.client.auth.approle.login(
                    role_id=self.vault_role_id,
                    secret_id=self.vault_secret_id
                )
                
                if auth_response and "auth" in auth_response:
                    self.client.token = auth_response["auth"]["client_token"]
                    lease_duration = auth_response["auth"].get("lease_duration", 3600)
                    self._token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=lease_duration)
                    self._authenticated = True
                    return True
            
            else:
                raise VaultError("No authentication method configured")
                
        except VaultError as e:
            raise VaultError(f"Vault authentication failed: {str(e)}")
        except Exception as e:
            raise VaultError(f"Vault authentication error: {str(e)}")
        
        return False
    
    async def ensure_authenticated(self):
        """Ensure Vault client is authenticated and token is valid."""
        
        if not self._authenticated:
            await self.authenticate()
        
        # Check token expiration
        if self._token_expires_at and datetime.now(timezone.utc) >= self._token_expires_at:
            await self.authenticate()
        
        if not self.client.is_authenticated():
            raise VaultError("Failed to authenticate with Vault")
    
    async def create_pki_ca(self, common_name: str, ttl: str = "8760h") -> Dict[str, Any]:
        """
        Create PKI Certificate Authority.
        
        Args:
            common_name: CA common name
            ttl: Certificate time-to-live
            
        Returns:
            CA certificate and key information
        """
        
        await self.ensure_authenticated()
        
        try:
            # Generate root CA
            ca_response = self.client.secrets.pki.generate_ca_certificate(
                mount_point=self.pki_mount_path,
                common_name=common_name,
                ttl=ttl,
                key_type="rsa",
                key_bits=4096
            )
            
            # Configure CA and CRL URLs
            urls_response = self.client.secrets.pki.set_urls(
                mount_point=self.pki_mount_path,
                issuing_certificates=[f"{self.vault_url}/v1/{self.pki_mount_path}/ca"],
                crl_distribution_points=[f"{self.vault_url}/v1/{self.pki_mount_path}/crl"]
            )
            
            return {
                "certificate": ca_response["data"]["certificate"],
                "issuing_ca": ca_response["data"]["issuing_ca"],
                "serial_number": ca_response["data"]["serial_number"],
                "ca_chain": ca_response["data"].get("ca_chain", []),
                "urls_configured": urls_response is not None
            }
            
        except VaultError as e:
            raise VaultError(f"Failed to create PKI CA: {str(e)}")
    
    async def create_intermediate_ca(self, common_name: str, ttl: str = "4380h") -> Dict[str, Any]:
        """
        Create intermediate PKI Certificate Authority.
        
        Args:
            common_name: Intermediate CA common name
            ttl: Certificate time-to-live
            
        Returns:
            Intermediate CA certificate information
        """
        
        await self.ensure_authenticated()
        
        try:
            # Generate intermediate CSR
            csr_response = self.client.secrets.pki.generate_intermediate_csr(
                mount_point=self.intermediate_pki_path,
                common_name=common_name,
                key_type="rsa",
                key_bits=4096
            )
            
            # Sign intermediate with root CA
            signed_response = self.client.secrets.pki.sign_intermediate_ca_certificate(
                mount_point=self.pki_mount_path,
                csr=csr_response["data"]["csr"],
                common_name=common_name,
                ttl=ttl
            )
            
            # Set signed certificate
            set_response = self.client.secrets.pki.set_signed_intermediate_ca_certificate(
                mount_point=self.intermediate_pki_path,
                certificate=signed_response["data"]["certificate"]
            )
            
            return {
                "certificate": signed_response["data"]["certificate"],
                "issuing_ca": signed_response["data"]["issuing_ca"],
                "serial_number": signed_response["data"]["serial_number"],
                "ca_chain": signed_response["data"].get("ca_chain", []),
                "csr": csr_response["data"]["csr"],
                "intermediate_set": set_response is not None
            }
            
        except VaultError as e:
            raise VaultError(f"Failed to create intermediate CA: {str(e)}")
    
    async def create_pki_role(self, role_name: str, role_config: Dict[str, Any]) -> bool:
        """
        Create PKI role for certificate issuance.
        
        Args:
            role_name: Name of the PKI role
            role_config: Role configuration parameters
            
        Returns:
            True if role created successfully
        """
        
        await self.ensure_authenticated()
        
        try:
            # Default QES-compatible role configuration
            default_config = {
                "allowed_domains": ["qes.example.com"],
                "allow_subdomains": True,
                "allow_any_name": False,
                "enforce_hostnames": True,
                "allow_ip_sans": False,
                "key_type": "rsa",
                "key_bits": 4096,
                "max_ttl": "8760h",  # 1 year
                "ttl": "2160h",      # 90 days
                "allow_localhost": False,
                "allowed_uri_sans": [],
                "key_usage": ["digital_signature", "key_encipherment"],
                "ext_key_usage": ["server_auth", "client_auth"],
                "basic_constraints_valid_for_non_ca": True,
                "require_cn": True
            }
            
            # Merge with provided config
            final_config = {**default_config, **role_config}
            
            response = self.client.secrets.pki.create_or_update_role(
                mount_point=self.intermediate_pki_path,
                name=role_name,
                **final_config
            )
            
            return response is not None
            
        except VaultError as e:
            raise VaultError(f"Failed to create PKI role {role_name}: {str(e)}")
    
    async def issue_certificate(self, role_name: str, common_name: str,
                              alt_names: Optional[List[str]] = None,
                              ttl: Optional[str] = None) -> Dict[str, Any]:
        """
        Issue certificate using PKI role.
        
        Args:
            role_name: PKI role to use
            common_name: Certificate common name
            alt_names: Subject alternative names
            ttl: Certificate time-to-live
            
        Returns:
            Certificate and private key information
        """
        
        await self.ensure_authenticated()
        
        try:
            params = {
                "mount_point": self.intermediate_pki_path,
                "name": role_name,
                "common_name": common_name
            }
            
            if alt_names:
                params["alternative_names"] = ",".join(alt_names)
            if ttl:
                params["ttl"] = ttl
            
            response = self.client.secrets.pki.generate_certificate(**params)
            
            return {
                "certificate": response["data"]["certificate"],
                "private_key": response["data"]["private_key"],
                "issuing_ca": response["data"]["issuing_ca"],
                "ca_chain": response["data"].get("ca_chain", []),
                "serial_number": response["data"]["serial_number"]
            }
            
        except VaultError as e:
            raise VaultError(f"Failed to issue certificate: {str(e)}")
    
    async def revoke_certificate(self, serial_number: str) -> bool:
        """
        Revoke certificate by serial number.
        
        Args:
            serial_number: Certificate serial number to revoke
            
        Returns:
            True if revocation successful
        """
        
        await self.ensure_authenticated()
        
        try:
            response = self.client.secrets.pki.revoke_certificate(
                mount_point=self.intermediate_pki_path,
                serial_number=serial_number
            )
            
            return "revocation_time" in response.get("data", {})
            
        except VaultError as e:
            raise VaultError(f"Failed to revoke certificate {serial_number}: {str(e)}")
    
    async def get_ca_certificate(self, mount_point: Optional[str] = None) -> str:
        """
        Get CA certificate in PEM format.
        
        Args:
            mount_point: PKI mount point (default: intermediate)
            
        Returns:
            CA certificate in PEM format
        """
        
        await self.ensure_authenticated()
        
        if mount_point is None:
            mount_point = self.intermediate_pki_path
        
        try:
            response = self.client.secrets.pki.read_ca_certificate(
                mount_point=mount_point
            )
            
            return response["data"]["certificate"]
            
        except VaultError as e:
            raise VaultError(f"Failed to get CA certificate: {str(e)}")
    
    async def get_crl(self, mount_point: Optional[str] = None) -> str:
        """
        Get Certificate Revocation List.
        
        Args:
            mount_point: PKI mount point
            
        Returns:
            CRL in PEM format
        """
        
        await self.ensure_authenticated()
        
        if mount_point is None:
            mount_point = self.intermediate_pki_path
        
        try:
            response = self.client.secrets.pki.read_crl(
                mount_point=mount_point
            )
            
            return response["data"]["crl"]
            
        except VaultError as e:
            raise VaultError(f"Failed to get CRL: {str(e)}")
    
    async def store_secret(self, path: str, secret_data: Dict[str, Any]) -> bool:
        """
        Store secret in Vault KV store.
        
        Args:
            path: Secret path
            secret_data: Secret key-value pairs
            
        Returns:
            True if storage successful
        """
        
        await self.ensure_authenticated()
        
        try:
            response = self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=secret_data
            )
            
            return "created_time" in response.get("data", {})
            
        except VaultError as e:
            raise VaultError(f"Failed to store secret at {path}: {str(e)}")
    
    async def get_secret(self, path: str, version: Optional[int] = None) -> Dict[str, Any]:
        """
        Retrieve secret from Vault KV store.
        
        Args:
            path: Secret path
            version: Secret version (latest if None)
            
        Returns:
            Secret data
        """
        
        await self.ensure_authenticated()
        
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                version=version
            )
            
            return response["data"]["data"]
            
        except VaultError as e:
            raise VaultError(f"Failed to get secret at {path}: {str(e)}")
    
    async def delete_secret(self, path: str) -> bool:
        """
        Delete secret from Vault KV store.
        
        Args:
            path: Secret path
            
        Returns:
            True if deletion successful
        """
        
        await self.ensure_authenticated()
        
        try:
            response = self.client.secrets.kv.v2.delete_latest_version_of_secret(
                path=path
            )
            
            return response is not None
            
        except VaultError as e:
            raise VaultError(f"Failed to delete secret at {path}: {str(e)}")
    
    async def hsm_generate_key(self, key_name: str, key_type: str = "rsa-4096") -> Dict[str, Any]:
        """
        Generate key using HSM backend.
        
        Args:
            key_name: Name for the HSM key
            key_type: Type of key to generate
            
        Returns:
            Key generation result
        """
        
        if not self.hsm_enabled:
            raise VaultError("HSM is not enabled")
        
        await self.ensure_authenticated()
        
        try:
            # This would interact with Vault's HSM plugin
            # Actual implementation depends on HSM type (PKCS#11, etc.)
            
            response = self.client.write(
                path=f"{self.hsm_mount_path}/keys/{key_name}",
                key_type=key_type,
                exportable=False
            )
            
            return {
                "key_name": key_name,
                "key_type": key_type,
                "public_key": response.get("data", {}).get("public_key"),
                "key_id": response.get("data", {}).get("key_id")
            }
            
        except VaultError as e:
            raise VaultError(f"Failed to generate HSM key {key_name}: {str(e)}")
    
    async def hsm_sign(self, key_name: str, data: bytes, 
                      algorithm: str = "pkcs1v15") -> bytes:
        """
        Sign data using HSM key.
        
        Args:
            key_name: HSM key name
            data: Data to sign
            algorithm: Signing algorithm
            
        Returns:
            Signature bytes
        """
        
        if not self.hsm_enabled:
            raise VaultError("HSM is not enabled")
        
        await self.ensure_authenticated()
        
        try:
            data_b64 = base64.b64encode(data).decode()
            
            response = self.client.write(
                path=f"{self.hsm_mount_path}/sign/{key_name}",
                input=data_b64,
                algorithm=algorithm
            )
            
            signature_b64 = response["data"]["signature"]
            return base64.b64decode(signature_b64)
            
        except VaultError as e:
            raise VaultError(f"Failed to sign with HSM key {key_name}: {str(e)}")
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Check Vault health status.
        
        Returns:
            Health status information
        """
        
        try:
            health = self.client.sys.read_health_status()
            
            return {
                "initialized": health.get("initialized", False),
                "sealed": health.get("sealed", True),
                "standby": health.get("standby", False),
                "performance_standby": health.get("performance_standby", False),
                "replication_performance_mode": health.get("replication_performance_mode", "unknown"),
                "replication_dr_mode": health.get("replication_dr_mode", "unknown"),
                "server_time_utc": health.get("server_time_utc"),
                "version": health.get("version", "unknown")
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "status": "unhealthy"
            }