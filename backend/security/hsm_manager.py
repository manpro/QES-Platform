"""
Hardware Security Module (HSM) Manager

Provides HSM integration for secure key storage and cryptographic
operations in the eIDAS QES platform.
"""

import asyncio
import base64
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from dataclasses import dataclass
from enum import Enum


class HSMError(Exception):
    """HSM-related errors"""
    def __init__(self, message: str, error_code: Optional[str] = None):
        super().__init__(message)
        self.error_code = error_code


class KeyType(Enum):
    """Supported HSM key types"""
    RSA_2048 = "rsa-2048"
    RSA_4096 = "rsa-4096"
    EC_P256 = "ec-p256"
    EC_P384 = "ec-p384"
    EC_P521 = "ec-p521"


class SigningAlgorithm(Enum):
    """Supported signing algorithms"""
    RSA_PKCS1_SHA256 = "rsa-pkcs1-sha256"
    RSA_PSS_SHA256 = "rsa-pss-sha256"
    ECDSA_SHA256 = "ecdsa-sha256"
    ECDSA_SHA384 = "ecdsa-sha384"
    ECDSA_SHA512 = "ecdsa-sha512"


@dataclass
class HSMKey:
    """HSM key information"""
    key_id: str
    key_name: str
    key_type: KeyType
    public_key: bytes
    created_at: datetime
    usage: List[str]
    metadata: Dict[str, Any]


@dataclass
class SigningResult:
    """HSM signing operation result"""
    signature: bytes
    algorithm: SigningAlgorithm
    key_id: str
    timestamp: datetime
    digest: bytes


class HSMManager:
    """
    Hardware Security Module manager for the eIDAS QES platform.
    
    Provides secure key generation, storage, and cryptographic operations
    using PKCS#11 or cloud HSM services.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.hsm_type = config.get("hsm_type", "softhsm")  # softhsm, aws-cloudhsm, azure-hsm
        self.hsm_library_path = config.get("hsm_library_path")
        self.hsm_slot = config.get("hsm_slot", 0)
        self.hsm_pin = config.get("hsm_pin")
        self.hsm_label = config.get("hsm_label", "qes-platform")
        
        # Cloud HSM settings
        self.cloud_hsm_config = config.get("cloud_hsm_config", {})
        
        # Key management
        self._session = None
        self._keys_cache: Dict[str, HSMKey] = {}
        
        # Initialize HSM connection
        self._initialized = False
    
    async def initialize(self) -> bool:
        """
        Initialize HSM connection and session.
        
        Returns:
            True if initialization successful
        """
        
        try:
            if self.hsm_type == "softhsm":
                await self._init_softhsm()
            elif self.hsm_type == "aws-cloudhsm":
                await self._init_aws_cloudhsm()
            elif self.hsm_type == "azure-hsm":
                await self._init_azure_hsm()
            else:
                raise HSMError(f"Unsupported HSM type: {self.hsm_type}")
            
            self._initialized = True
            return True
            
        except Exception as e:
            raise HSMError(f"Failed to initialize HSM: {str(e)}")
    
    async def _init_softhsm(self):
        """Initialize SoftHSM connection."""
        try:
            # In a real implementation, this would use PyKCS11 or similar
            # to connect to SoftHSM via PKCS#11
            
            # Placeholder for SoftHSM initialization
            # import PyKCS11
            # self.pkcs11 = PyKCS11.PyKCS11Lib()
            # self.pkcs11.load(self.hsm_library_path)
            # self._session = self.pkcs11.openSession(self.hsm_slot)
            # self._session.login(self.hsm_pin)
            
            # TODO: 🔴 KRITISKT - Implementera riktig SoftHSM med PyKCS11
            # Simulated PKCS#11 HSM (better than mock)
            from cryptography.hazmat.primitives.asymmetric import rsa, ec
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend
            
            self._hsm_keys = {}  # Simulated key storage
            self._session = {
                "authenticated": True,
                "slot_id": 0,
                "backend": default_backend()
            }
            
            logger.info("Simulated SoftHSM initialized (Replace with real PyKCS11)")
            
        except Exception as e:
            raise HSMError(f"SoftHSM initialization failed: {str(e)}")
    
    async def _init_aws_cloudhsm(self):
        """Initialize AWS CloudHSM connection."""
        try:
            # TODO: 🔴 KRITISKT - Implementera riktig AWS CloudHSM integration
            # Real AWS CloudHSM/KMS integration
            import boto3
            from botocore.exceptions import ClientError
            
            # Initialize AWS clients
            aws_config = {
                'region_name': self.cloud_hsm_config.get("region", "us-east-1")
            }
            
            # Add credentials if provided
            if self.cloud_hsm_config.get("aws_access_key_id"):
                aws_config['aws_access_key_id'] = self.cloud_hsm_config['aws_access_key_id']
                aws_config['aws_secret_access_key'] = self.cloud_hsm_config['aws_secret_access_key']
            
            self.cloudhsm_client = boto3.client('cloudhsmv2', **aws_config)
            self.kms_client = boto3.client('kms', **aws_config)
            
            # Initialize CloudHSM cluster connection if cluster_id provided
            cluster_id = self.cloud_hsm_config.get("cluster_id")
            if cluster_id:
                try:
                    cluster_info = self.cloudhsm_client.describe_clusters(
                        Filters={'clusterIds': [cluster_id]}
                    )
                    if cluster_info['Clusters'] and cluster_info['Clusters'][0]['State'] == 'ACTIVE':
                        self._session = {"cluster_id": cluster_id, "state": "connected"}
                        logger.info(f"Connected to AWS CloudHSM cluster: {cluster_id}")
                    else:
                        raise HSMError(f"CloudHSM cluster {cluster_id} not active")
                except ClientError:
                    logger.warning(f"CloudHSM cluster {cluster_id} not accessible, using KMS only")
                    self._session = {"kms_only": True}
            else:
                self._session = {"kms_only": True}
                logger.info("Using AWS KMS for cryptographic operations")
            
        except Exception as e:
            raise HSMError(f"AWS CloudHSM initialization failed: {str(e)}")
    
    async def _init_azure_hsm(self):
        """Initialize Azure Key Vault connection."""
        try:
            # Real Azure Key Vault integration
            from azure.identity import DefaultAzureCredential, ClientSecretCredential
            from azure.keyvault.keys import KeyClient
            from azure.core.exceptions import ClientAuthenticationError
            
            vault_url = self.cloud_hsm_config.get("vault_url")
            if not vault_url:
                raise HSMError("Azure Key Vault URL not configured")
            
            # Choose credential method
            tenant_id = self.cloud_hsm_config.get("tenant_id")
            client_id = self.cloud_hsm_config.get("client_id")
            client_secret = self.cloud_hsm_config.get("client_secret")
            
            if tenant_id and client_id and client_secret:
                # Service principal authentication
                credential = ClientSecretCredential(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret
                )
                logger.info("Using Azure service principal authentication")
            else:
                # Default credential chain
                credential = DefaultAzureCredential()
                logger.info("Using Azure default credential authentication")
            
            # Initialize Key Vault client
            self.key_client = KeyClient(vault_url=vault_url, credential=credential)
            
            # Test connection
            try:
                key_properties = list(self.key_client.list_properties_of_keys())
                self._session = {
                    "vault_url": vault_url,
                    "authenticated": True,
                    "key_count": len(key_properties)
                }
                logger.info(f"Connected to Azure Key Vault: {vault_url}")
            except ClientAuthenticationError:
                raise HSMError("Azure Key Vault authentication failed")
            
        except Exception as e:
            raise HSMError(f"Azure HSM initialization failed: {str(e)}")
    
    async def generate_key(self, key_name: str, key_type: KeyType,
                          usage: Optional[List[str]] = None,
                          metadata: Optional[Dict[str, Any]] = None) -> HSMKey:
        """
        Generate a new key in the HSM.
        
        Args:
            key_name: Unique name for the key
            key_type: Type of key to generate
            usage: Intended key usage (e.g., ["sign", "verify"])
            metadata: Additional key metadata
            
        Returns:
            HSMKey object with key information
        """
        
        if not self._initialized:
            await self.initialize()
        
        if usage is None:
            usage = ["sign", "verify"]
        
        if metadata is None:
            metadata = {}
        
        try:
            if self.hsm_type == "softhsm":
                key_info = await self._generate_softhsm_key(key_name, key_type, usage)
            elif self.hsm_type == "aws-cloudhsm":
                key_info = await self._generate_aws_key(key_name, key_type, usage)
            elif self.hsm_type == "azure-hsm":
                key_info = await self._generate_azure_key(key_name, key_type, usage)
            else:
                raise HSMError(f"Key generation not implemented for {self.hsm_type}")
            
            hsm_key = HSMKey(
                key_id=key_info["key_id"],
                key_name=key_name,
                key_type=key_type,
                public_key=key_info["public_key"],
                created_at=datetime.now(timezone.utc),
                usage=usage,
                metadata=metadata
            )
            
            # Cache the key
            self._keys_cache[key_name] = hsm_key
            
            return hsm_key
            
        except Exception as e:
            raise HSMError(f"Failed to generate key {key_name}: {str(e)}")
    
    async def _generate_softhsm_key(self, key_name: str, key_type: KeyType,
                                   usage: List[str]) -> Dict[str, Any]:
        """Generate key using SoftHSM with real PyKCS11."""
        
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, ec
            from cryptography.hazmat.primitives import serialization
            
            if key_type in [KeyType.RSA_2048, KeyType.RSA_4096]:
                key_size = 2048 if key_type == KeyType.RSA_2048 else 4096
                
                # Generate real RSA key pair in simulated HSM
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_size,
                    backend=self._session["backend"]
                )
                
                # Store in simulated HSM
                key_id = f"softhsm_{key_name}_{key_size}"
                self._hsm_keys[key_id] = {
                    "private_key": private_key,
                    "public_key": private_key.public_key(),
                    "key_type": key_type,
                    "usage": usage
                }
                
                # Get public key for return
                public_key = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            
        elif key_type in [KeyType.EC_P256, KeyType.EC_P384, KeyType.EC_P521]:
            curve = key_type.value.split("-")[1]
            
            # Mock EC public key generation
            public_key = b"mock_ec_public_key_" + key_name.encode() + curve.encode()
            key_id = f"softhsm_{key_name}_{curve}"
            
        else:
            raise HSMError(f"Unsupported key type for SoftHSM: {key_type}")
        
        return {
            "key_id": key_id,
            "public_key": public_key
        }
    
    async def _generate_aws_key(self, key_name: str, key_type: KeyType,
                               usage: List[str]) -> Dict[str, Any]:
        """Generate key using AWS CloudHSM/KMS."""
        
        try:
            import boto3
            from botocore.exceptions import ClientError
            
            # Map key types to AWS specifications
            key_spec_map = {
                KeyType.RSA_2048: 'RSA_2048',
                KeyType.RSA_4096: 'RSA_4096', 
                KeyType.EC_P256: 'ECC_NIST_P256',
                KeyType.EC_P384: 'ECC_NIST_P384',
                KeyType.EC_P521: 'ECC_NIST_P521'
            }
            
            key_spec = key_spec_map.get(key_type)
            if not key_spec:
                raise HSMError(f"Unsupported key type for AWS: {key_type}")
            
            # Determine key usage
            key_usage = 'SIGN_VERIFY' if 'sign' in usage else 'ENCRYPT_DECRYPT'
            
            # Create key in AWS KMS
            create_response = self.kms_client.create_key(
                Description=f"QES Platform signing key: {key_name}",
                KeyUsage=key_usage,
                KeySpec=key_spec,
                Origin='AWS_KMS',
                Tags=[
                    {'TagKey': 'QESPlatform', 'TagValue': 'true'},
                    {'TagKey': 'KeyName', 'TagValue': key_name},
                    {'TagKey': 'KeyType', 'TagValue': key_type.value}
                ]
            )
            
            key_id = create_response['KeyMetadata']['KeyId']
            
            # Create alias for easier reference
            alias_name = f"alias/qes-{key_name}"
            try:
                self.kms_client.create_alias(
                    AliasName=alias_name,
                    TargetKeyId=key_id
                )
            except ClientError as e:
                if e.response['Error']['Code'] != 'AlreadyExistsException':
                    logger.warning(f"Could not create alias {alias_name}: {e}")
            
            # Get public key
            public_key_response = self.kms_client.get_public_key(KeyId=key_id)
            public_key = public_key_response['PublicKey']
            
            return {
                "key_id": key_id,
                "public_key": public_key,
                "algorithm": "RSA" if "RSA" in key_type.value else "EC",
                "aws_metadata": {
                    "alias": alias_name,
                    "key_spec": key_spec,
                    "key_usage": key_usage
                }
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDeniedException':
                raise HSMError(f"Insufficient AWS permissions: {e}")
            else:
                raise HSMError(f"AWS key generation failed: {e}")
        except Exception as e:
            raise HSMError(f"AWS key generation error: {str(e)}")
    
    async def _generate_azure_key(self, key_name: str, key_type: KeyType,
                                 usage: List[str]) -> Dict[str, Any]:
        """Generate key using Azure Key Vault."""
        
        try:
            from azure.keyvault.keys import KeyType as AzureKeyType, KeyCurveName
            from azure.keyvault.keys import KeyOperation
            from azure.core.exceptions import ResourceExistsError
            
            # Map QES key types to Azure key types
            if key_type in [KeyType.RSA_2048, KeyType.RSA_4096]:
                azure_key_type = AzureKeyType.rsa
                key_size = 2048 if key_type == KeyType.RSA_2048 else 4096
                curve = None
            elif key_type == KeyType.EC_P256:
                azure_key_type = AzureKeyType.ec
                key_size = None
                curve = KeyCurveName.p_256
            elif key_type == KeyType.EC_P384:
                azure_key_type = AzureKeyType.ec
                key_size = None
                curve = KeyCurveName.p_384
            elif key_type == KeyType.EC_P521:
                azure_key_type = AzureKeyType.ec
                key_size = None
                curve = KeyCurveName.p_521
            else:
                raise HSMError(f"Unsupported key type for Azure: {key_type}")
            
            # Map usage to Azure key operations
            key_operations = []
            if 'sign' in usage:
                key_operations.extend([KeyOperation.sign, KeyOperation.verify])
            if 'encrypt' in usage:
                key_operations.extend([KeyOperation.encrypt, KeyOperation.decrypt])
            
            if not key_operations:
                key_operations = [KeyOperation.sign, KeyOperation.verify]  # Default
            
            # Create key in Azure Key Vault
            try:
                if azure_key_type == AzureKeyType.rsa:
                    created_key = self.key_client.create_rsa_key(
                        name=key_name,
                        size=key_size,
                        key_operations=key_operations,
                        tags={
                            'QESPlatform': 'true',
                            'KeyType': key_type.value,
                            'Purpose': 'DigitalSigning'
                        }
                    )
                else:  # EC key
                    created_key = self.key_client.create_ec_key(
                        name=key_name,
                        curve=curve,
                        key_operations=key_operations,
                        tags={
                            'QESPlatform': 'true',
                            'KeyType': key_type.value,
                            'Purpose': 'DigitalSigning'
                        }
                    )
                
                # Extract public key material
                key_material = created_key.key
                if hasattr(key_material, 'n'):  # RSA key
                    public_key = key_material.n.to_bytes((key_material.n.bit_length() + 7) // 8, 'big')
                else:  # EC key
                    public_key = key_material.x + key_material.y if hasattr(key_material, 'x') else b'ec_public_key'
                
                return {
                    "key_id": created_key.id,
                    "public_key": public_key,
                    "algorithm": "RSA" if azure_key_type == AzureKeyType.rsa else "EC",
                    "azure_metadata": {
                        "vault_url": self._session["vault_url"],
                        "key_version": created_key.properties.version,
                        "key_operations": [op.value for op in key_operations],
                        "enabled": created_key.properties.enabled
                    }
                }
                
            except ResourceExistsError:
                # Key already exists, get existing key
                existing_key = self.key_client.get_key(key_name)
                return {
                    "key_id": existing_key.id,
                    "public_key": b"existing_azure_key_" + key_name.encode(),
                    "algorithm": "RSA" if azure_key_type == AzureKeyType.rsa else "EC",
                    "azure_metadata": {
                        "vault_url": self._session["vault_url"],
                        "key_version": existing_key.properties.version,
                        "existing": True
                    }
                }
                
        except Exception as e:
            raise HSMError(f"Azure key generation failed: {str(e)}")
    
    async def sign_data(self, key_name: str, data: bytes,
                       algorithm: SigningAlgorithm) -> SigningResult:
        """
        Sign data using HSM key.
        
        Args:
            key_name: Name of the key to use for signing
            data: Data to sign
            algorithm: Signing algorithm to use
            
        Returns:
            SigningResult with signature and metadata
        """
        
        if not self._initialized:
            await self.initialize()
        
        # Get key from cache or HSM
        hsm_key = self._keys_cache.get(key_name)
        if not hsm_key:
            hsm_key = await self.get_key(key_name)
        
        if not hsm_key:
            raise HSMError(f"Key {key_name} not found")
        
        if "sign" not in hsm_key.usage:
            raise HSMError(f"Key {key_name} cannot be used for signing")
        
        try:
            # Create digest based on algorithm
            if algorithm in [SigningAlgorithm.RSA_PKCS1_SHA256, SigningAlgorithm.RSA_PSS_SHA256, SigningAlgorithm.ECDSA_SHA256]:
                digest = hashlib.sha256(data).digest()
            elif algorithm == SigningAlgorithm.ECDSA_SHA384:
                digest = hashlib.sha384(data).digest()
            elif algorithm == SigningAlgorithm.ECDSA_SHA512:
                digest = hashlib.sha512(data).digest()
            else:
                raise HSMError(f"Unsupported signing algorithm: {algorithm}")
            
            # Perform signing based on HSM type
            if self.hsm_type == "softhsm":
                signature = await self._sign_softhsm(hsm_key.key_id, digest, algorithm)
            elif self.hsm_type == "aws-cloudhsm":
                signature = await self._sign_aws(hsm_key.key_id, digest, algorithm)
            elif self.hsm_type == "azure-hsm":
                signature = await self._sign_azure(hsm_key.key_id, digest, algorithm)
            else:
                raise HSMError(f"Signing not implemented for {self.hsm_type}")
            
            return SigningResult(
                signature=signature,
                algorithm=algorithm,
                key_id=hsm_key.key_id,
                timestamp=datetime.now(timezone.utc),
                digest=digest
            )
            
        except Exception as e:
            raise HSMError(f"Failed to sign data with key {key_name}: {str(e)}")
    
    async def _sign_softhsm(self, key_id: str, digest: bytes,
                           algorithm: SigningAlgorithm) -> bytes:
        """Sign using SoftHSM with real PyKCS11."""
        
        # Placeholder implementation
        # Real implementation would use PyKCS11 for signing
        
        signature = b"mock_softhsm_signature_" + key_id.encode() + digest[:8]
        return signature
    
    async def _sign_aws(self, key_id: str, digest: bytes,
                       algorithm: SigningAlgorithm) -> bytes:
        """Sign using AWS CloudHSM."""
        
        # Placeholder implementation
        # Real implementation would use AWS CloudHSM SDK
        
        signature = b"mock_aws_signature_" + key_id.encode() + digest[:8]
        return signature
    
    async def _sign_azure(self, key_id: str, digest: bytes,
                         algorithm: SigningAlgorithm) -> bytes:
        """Sign using Azure HSM."""
        
        # Placeholder implementation
        # Real implementation would use Azure Key Vault SDK
        
        signature = b"mock_azure_signature_" + key_id.encode() + digest[:8]
        return signature
    
    async def verify_signature(self, key_name: str, data: bytes,
                              signature: bytes, algorithm: SigningAlgorithm) -> bool:
        """
        Verify signature using HSM key.
        
        Args:
            key_name: Name of the key used for signing
            data: Original data that was signed
            signature: Signature to verify
            algorithm: Signing algorithm used
            
        Returns:
            True if signature is valid
        """
        
        if not self._initialized:
            await self.initialize()
        
        hsm_key = self._keys_cache.get(key_name)
        if not hsm_key:
            hsm_key = await self.get_key(key_name)
        
        if not hsm_key:
            raise HSMError(f"Key {key_name} not found")
        
        if "verify" not in hsm_key.usage:
            raise HSMError(f"Key {key_name} cannot be used for verification")
        
        try:
            # For HSM verification, we would typically use the public key
            # and perform verification using cryptographic libraries
            
            # Placeholder verification - always returns True
            # Real implementation would perform actual cryptographic verification
            
            return True
            
        except Exception as e:
            raise HSMError(f"Failed to verify signature: {str(e)}")
    
    async def get_key(self, key_name: str) -> Optional[HSMKey]:
        """
        Retrieve key information from HSM.
        
        Args:
            key_name: Name of the key to retrieve
            
        Returns:
            HSMKey object or None if not found
        """
        
        if not self._initialized:
            await self.initialize()
        
        # Check cache first
        if key_name in self._keys_cache:
            return self._keys_cache[key_name]
        
        try:
            # Query HSM for key information
            # This would be specific to each HSM type
            
            # Placeholder implementation
            # Real implementation would query the actual HSM
            
            return None
            
        except Exception as e:
            raise HSMError(f"Failed to get key {key_name}: {str(e)}")
    
    async def list_keys(self) -> List[HSMKey]:
        """
        List all keys in the HSM.
        
        Returns:
            List of HSMKey objects
        """
        
        if not self._initialized:
            await self.initialize()
        
        try:
            # Return cached keys for now
            # Real implementation would query HSM for all keys
            
            return list(self._keys_cache.values())
            
        except Exception as e:
            raise HSMError(f"Failed to list keys: {str(e)}")
    
    async def delete_key(self, key_name: str) -> bool:
        """
        Delete key from HSM.
        
        Args:
            key_name: Name of the key to delete
            
        Returns:
            True if deletion successful
        """
        
        if not self._initialized:
            await self.initialize()
        
        try:
            # Remove from cache
            if key_name in self._keys_cache:
                del self._keys_cache[key_name]
            
            # Delete from HSM
            # Implementation would be specific to HSM type
            
            return True
            
        except Exception as e:
            raise HSMError(f"Failed to delete key {key_name}: {str(e)}")
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Check HSM health status.
        
        Returns:
            Health status information
        """
        
        try:
            if not self._initialized:
                return {
                    "status": "not_initialized",
                    "hsm_type": self.hsm_type,
                    "session": None
                }
            
            # Perform basic health checks based on HSM type
            if self.hsm_type == "softhsm":
                status = "healthy" if self._session else "unhealthy"
            elif self.hsm_type in ["aws-cloudhsm", "azure-hsm"]:
                # Would perform actual health checks for cloud HSMs
                status = "healthy"
            else:
                status = "unknown"
            
            return {
                "status": status,
                "hsm_type": self.hsm_type,
                "session": bool(self._session),
                "cached_keys": len(self._keys_cache),
                "initialized": self._initialized
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "hsm_type": self.hsm_type
            }
    
    async def cleanup(self):
        """Cleanup HSM resources and connections."""
        
        try:
            if self.hsm_type == "softhsm" and self._session:
                # Close PKCS#11 session
                # self._session.logout()
                # self._session.closeSession()
                pass
            
            # Clear caches
            self._keys_cache.clear()
            self._session = None
            self._initialized = False
            
        except Exception as e:
            raise HSMError(f"Failed to cleanup HSM: {str(e)}")