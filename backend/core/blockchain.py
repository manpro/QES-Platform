"""
Blockchain Integration for QES Platform

Provides blockchain-anchored signatures for immutable proof and audit trails.
"""

import json
import logging
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

import asyncio
from web3 import Web3
from eth_account import Account
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

# Import blockchain helpers
from .blockchain_helpers import BlockchainHelpers, TransactionReceipt

logger = logging.getLogger(__name__)


class BlockchainNetwork(Enum):
    """Supported blockchain networks"""
    ETHEREUM_MAINNET = "ethereum_mainnet"
    ETHEREUM_SEPOLIA = "ethereum_sepolia"
    POLYGON_MAINNET = "polygon_mainnet"
    POLYGON_MUMBAI = "polygon_mumbai"
    HYPERLEDGER_FABRIC = "hyperledger_fabric"
    PRIVATE_CHAIN = "private_chain"


class AnchorStatus(Enum):
    """Blockchain anchor status"""
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    REVOKED = "revoked"


@dataclass
class BlockchainConfig:
    """Blockchain configuration"""
    network: BlockchainNetwork
    rpc_url: str
    contract_address: Optional[str] = None
    private_key: Optional[str] = None
    gas_limit: int = 100000
    confirmation_blocks: int = 12
    timeout_seconds: int = 300
    
    # Hyperledger Fabric specific
    fabric_network_path: Optional[str] = None
    fabric_user_name: Optional[str] = None
    fabric_msp_id: Optional[str] = None
    
    def __post_init__(self):
        """Configure network-specific settings"""
        if self.network == BlockchainNetwork.ETHEREUM_MAINNET:
            self.chain_id = 1
            if not self.rpc_url:
                self.rpc_url = "https://mainnet.infura.io/v3/YOUR_PROJECT_ID"
        elif self.network == BlockchainNetwork.ETHEREUM_SEPOLIA:
            self.chain_id = 11155111
            if not self.rpc_url:
                self.rpc_url = "https://sepolia.infura.io/v3/YOUR_PROJECT_ID"
        elif self.network == BlockchainNetwork.POLYGON_MAINNET:
            self.chain_id = 137
            if not self.rpc_url:
                self.rpc_url = "https://polygon-rpc.com"
        elif self.network == BlockchainNetwork.POLYGON_MUMBAI:
            self.chain_id = 80001
            if not self.rpc_url:
                self.rpc_url = "https://rpc-mumbai.maticvigil.com"


@dataclass
class SignatureAnchor:
    """Blockchain-anchored signature record"""
    anchor_id: str
    signature_hash: str
    document_hash: str
    signer_address: str
    timestamp: datetime
    block_number: Optional[int] = None
    transaction_hash: Optional[str] = None
    status: AnchorStatus = AnchorStatus.PENDING
    network: str = ""
    
    # Metadata
    qes_provider: Optional[str] = None
    signature_format: Optional[str] = None
    certificate_fingerprint: Optional[str] = None
    regulatory_compliance: Dict[str, Any] = field(default_factory=dict)
    
    # Verification data
    merkle_proof: Optional[List[str]] = None
    batch_id: Optional[str] = None
    
    # Gas and cost information
    gas_used: Optional[int] = None
    gas_price: Optional[int] = None
    cost_wei: Optional[int] = None


@dataclass
class BlockchainVerificationResult:
    """Blockchain verification result"""
    is_valid: bool
    anchor: Optional[SignatureAnchor] = None
    verification_time: datetime = field(default_factory=datetime.utcnow)
    confirmations: int = 0
    error_message: Optional[str] = None
    
    # Immutability proof
    block_timestamp: Optional[datetime] = None
    merkle_path: Optional[List[str]] = None
    inclusion_proof: Optional[Dict] = None


class BlockchainAnchoringService:
    """
    Blockchain Anchoring Service for QES Platform
    
    Provides immutable blockchain-based proof of signature existence and integrity.
    """
    
    def __init__(self, config: BlockchainConfig):
        """Initialize blockchain anchoring service"""
        self.config = config
        self.web3 = None
        self.contract = None
        self.account = None
        
        if config.network.value.startswith("ethereum") or config.network.value.startswith("polygon"):
            self._init_web3()
        elif config.network == BlockchainNetwork.HYPERLEDGER_FABRIC:
            self._init_fabric()
        
        logger.info(f"Initialized blockchain anchoring for {config.network.value}")
    
    def _init_web3(self):
        """Initialize Web3 connection"""
        try:
            self.web3 = Web3(Web3.HTTPProvider(self.config.rpc_url))
            
            if not self.web3.is_connected():
                raise ConnectionError("Failed to connect to blockchain network")
            
            if self.config.private_key:
                self.account = Account.from_key(self.config.private_key)
                logger.info(f"Loaded account: {self.account.address}")
            
            # Load smart contract if address provided
            if self.config.contract_address:
                # Load QES Anchor contract ABI
                contract_abi = BlockchainHelpers._get_qes_anchor_abi()
                
                self.contract = self.web3.eth.contract(
                    address=self.config.contract_address,
                    abi=contract_abi
                )
                
        except Exception as e:
            logger.error(f"Failed to initialize Web3: {e}")
            raise
    
    def _init_fabric(self):
        """Initialize Hyperledger Fabric connection"""
        # Placeholder for Hyperledger Fabric initialization
        # Would require fabric-sdk-py or similar library
        logger.info("Hyperledger Fabric initialization - placeholder")
        pass
    
    async def anchor_signature(
        self, 
        signature_hash: str,
        document_hash: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SignatureAnchor:
        """
        Anchor signature to blockchain
        
        Args:
            signature_hash: Hash of the signature
            document_hash: Hash of the signed document
            metadata: Additional metadata to store
            
        Returns:
            Signature anchor record
        """
        try:
            anchor_id = self._generate_anchor_id(signature_hash, document_hash)
            
            anchor = SignatureAnchor(
                anchor_id=anchor_id,
                signature_hash=signature_hash,
                document_hash=document_hash,
                signer_address=self.account.address if self.account else "",
                timestamp=datetime.utcnow(),
                network=self.config.network.value,
                qes_provider=metadata.get("qes_provider") if metadata else None,
                signature_format=metadata.get("signature_format") if metadata else None,
                certificate_fingerprint=metadata.get("certificate_fingerprint") if metadata else None,
                regulatory_compliance=metadata.get("regulatory_compliance", {}) if metadata else {}
            )
            
            if self.config.network.value.startswith("ethereum") or self.config.network.value.startswith("polygon"):
                return await self._anchor_to_ethereum(anchor, metadata)
            elif self.config.network == BlockchainNetwork.HYPERLEDGER_FABRIC:
                return await self._anchor_to_fabric(anchor, metadata)
            else:
                raise ValueError(f"Unsupported network: {self.config.network}")
                
        except Exception as e:
            logger.error(f"Failed to anchor signature: {e}")
            anchor.status = AnchorStatus.FAILED
            raise
    
    async def _anchor_to_ethereum(self, anchor: SignatureAnchor, metadata: Optional[Dict]) -> SignatureAnchor:
        """Anchor signature to Ethereum-based network"""
        if not self.contract or not self.account:
            raise ValueError("Contract and account required for Ethereum anchoring")
        
        try:
            # Prepare metadata JSON
            metadata_json = json.dumps(metadata or {}, separators=(',', ':'))
            
            # Build transaction
            function = self.contract.functions.anchorSignature(
                Web3.to_bytes(hexstr=anchor.signature_hash),
                Web3.to_bytes(hexstr=anchor.document_hash),
                metadata_json
            )
            
            # Estimate gas
            gas_estimate = function.estimate_gas({'from': self.account.address})
            gas_limit = min(gas_estimate * 2, self.config.gas_limit)
            
            # Get current gas price
            gas_price = self.web3.eth.gas_price
            
            # Build transaction
            transaction = function.build_transaction({
                'chainId': self.config.chain_id,
                'gas': gas_limit,
                'gasPrice': gas_price,
                'nonce': self.web3.eth.get_transaction_count(self.account.address),
            })
            
            # Sign and send transaction
            signed_txn = self.web3.eth.account.sign_transaction(transaction, self.config.private_key)
            tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            anchor.transaction_hash = tx_hash.hex()
            anchor.gas_used = gas_estimate
            anchor.gas_price = gas_price
            anchor.cost_wei = gas_estimate * gas_price
            
            logger.info(f"Signature anchored to blockchain: {anchor.transaction_hash}")
            
            # Wait for confirmation if configured
            if self.config.confirmation_blocks > 0:
                receipt = await self._wait_for_confirmation(tx_hash)
                anchor.block_number = receipt['blockNumber']
                anchor.status = AnchorStatus.CONFIRMED if receipt['status'] == 1 else AnchorStatus.FAILED
            
            return anchor
            
        except Exception as e:
            logger.error(f"Ethereum anchoring failed: {e}")
            anchor.status = AnchorStatus.FAILED
            raise
    
    async def _anchor_to_fabric(self, anchor: SignatureAnchor, metadata: Optional[Dict]) -> SignatureAnchor:
        """Anchor signature to Hyperledger Fabric"""
        # Placeholder for Hyperledger Fabric anchoring
        logger.info("Anchoring to Hyperledger Fabric - placeholder")
        anchor.status = AnchorStatus.CONFIRMED
        return anchor
    
    async def _wait_for_confirmation(self, tx_hash: bytes) -> Dict:
        """Wait for transaction confirmation"""
        start_time = datetime.utcnow()
        timeout = timedelta(seconds=self.config.timeout_seconds)
        
        while datetime.utcnow() - start_time < timeout:
            try:
                receipt = self.web3.eth.get_transaction_receipt(tx_hash)
                
                # Check if we have enough confirmations
                current_block = self.web3.eth.block_number
                confirmations = current_block - receipt['blockNumber']
                
                if confirmations >= self.config.confirmation_blocks:
                    return receipt
                    
                await asyncio.sleep(15)  # Wait 15 seconds before checking again
                
            except Exception:
                await asyncio.sleep(15)
        
        raise TimeoutError("Transaction confirmation timeout")
    
    async def verify_anchor(self, anchor_id: str) -> BlockchainVerificationResult:
        """
        Verify signature anchor on blockchain
        
        Args:
            anchor_id: Anchor ID to verify
            
        Returns:
            Verification result
        """
        try:
            if self.config.network.value.startswith("ethereum") or self.config.network.value.startswith("polygon"):
                return await self._verify_ethereum_anchor(anchor_id)
            elif self.config.network == BlockchainNetwork.HYPERLEDGER_FABRIC:
                return await self._verify_fabric_anchor(anchor_id)
            else:
                raise ValueError(f"Unsupported network: {self.config.network}")
                
        except Exception as e:
            logger.error(f"Anchor verification failed: {e}")
            return BlockchainVerificationResult(
                is_valid=False,
                error_message=str(e)
            )
    
    async def _verify_ethereum_anchor(self, anchor_id: str) -> BlockchainVerificationResult:
        """Verify anchor on Ethereum-based network"""
        if not self.contract:
            raise ValueError("Contract required for Ethereum verification")
        
        try:
            # Query contract for anchor data
            anchor_data = self.contract.functions.getAnchor(
                Web3.to_bytes(hexstr=anchor_id)
            ).call()
            
            if not anchor_data[0]:  # Empty signature hash means not found
                return BlockchainVerificationResult(
                    is_valid=False,
                    error_message="Anchor not found on blockchain"
                )
            
            # Parse anchor data
            signature_hash = anchor_data[0].hex()
            document_hash = anchor_data[1].hex()
            timestamp = datetime.fromtimestamp(anchor_data[2])
            block_number = anchor_data[3]
            metadata = json.loads(anchor_data[4]) if anchor_data[4] else {}
            
            # Get current confirmations
            current_block = self.web3.eth.block_number
            confirmations = current_block - block_number
            
            # Get block timestamp for immutability proof
            block = self.web3.eth.get_block(block_number)
            block_timestamp = datetime.fromtimestamp(block['timestamp'])
            
            anchor = SignatureAnchor(
                anchor_id=anchor_id,
                signature_hash=signature_hash,
                document_hash=document_hash,
                signer_address="",  # Would need to get from transaction
                timestamp=timestamp,
                block_number=block_number,
                status=AnchorStatus.CONFIRMED,
                network=self.config.network.value
            )
            
            return BlockchainVerificationResult(
                is_valid=True,
                anchor=anchor,
                confirmations=confirmations,
                block_timestamp=block_timestamp,
                inclusion_proof={
                    "block_number": block_number,
                    "block_hash": block['hash'].hex(),
                    "transaction_index": 0,  # Would need actual transaction lookup
                    "confirmations": confirmations
                }
            )
            
        except Exception as e:
            logger.error(f"Ethereum verification failed: {e}")
            return BlockchainVerificationResult(
                is_valid=False,
                error_message=str(e)
            )
    
    async def _verify_fabric_anchor(self, anchor_id: str) -> BlockchainVerificationResult:
        """Verify anchor on Hyperledger Fabric"""
        # Placeholder for Hyperledger Fabric verification
        logger.info("Verifying Fabric anchor - placeholder")
        return BlockchainVerificationResult(is_valid=True)
    
    async def batch_anchor_signatures(self, anchors: List[Dict[str, str]]) -> List[SignatureAnchor]:
        """
        Batch anchor multiple signatures for cost efficiency
        
        Args:
            anchors: List of signature and document hashes to anchor
            
        Returns:
            List of anchor records
        """
        batch_id = secrets.token_hex(16)
        results = []
        
        try:
            # Create Merkle tree of all signature hashes
            merkle_root = self._calculate_merkle_root([a["signature_hash"] for a in anchors])
            
            # Anchor only the Merkle root to save gas
            root_anchor = await self.anchor_signature(
                signature_hash=merkle_root,
                document_hash="batch_" + batch_id,
                metadata={
                    "batch_id": batch_id,
                    "batch_size": len(anchors),
                    "anchor_type": "merkle_batch"
                }
            )
            
            # Generate proofs for each signature
            for i, anchor_data in enumerate(anchors):
                merkle_proof = self._generate_merkle_proof(
                    [a["signature_hash"] for a in anchors], i
                )
                
                anchor = SignatureAnchor(
                    anchor_id=f"{batch_id}_{i}",
                    signature_hash=anchor_data["signature_hash"],
                    document_hash=anchor_data["document_hash"],
                    signer_address=self.account.address if self.account else "",
                    timestamp=datetime.utcnow(),
                    network=self.config.network.value,
                    status=AnchorStatus.CONFIRMED,
                    batch_id=batch_id,
                    merkle_proof=merkle_proof
                )
                
                results.append(anchor)
            
            logger.info(f"Batch anchored {len(anchors)} signatures with root {merkle_root}")
            return results
            
        except Exception as e:
            logger.error(f"Batch anchoring failed: {e}")
            # Mark all as failed
            for anchor in results:
                anchor.status = AnchorStatus.FAILED
            raise
    
    def _generate_anchor_id(self, signature_hash: str, document_hash: str) -> str:
        """Generate unique anchor ID"""
        combined = f"{signature_hash}{document_hash}{datetime.utcnow().isoformat()}"
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def _calculate_merkle_root(self, hashes: List[str]) -> str:
        """Calculate Merkle root of hash list"""
        if not hashes:
            return ""
        
        if len(hashes) == 1:
            return hashes[0]
        
        # Pad to power of 2
        while len(hashes) & (len(hashes) - 1):
            hashes.append(hashes[-1])
        
        # Build Merkle tree
        level = hashes[:]
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                combined = level[i] + level[i + 1]
                hash_obj = hashlib.sha256(combined.encode())
                next_level.append(hash_obj.hexdigest())
            level = next_level
        
        return level[0]
    
    def _generate_merkle_proof(self, hashes: List[str], index: int) -> List[str]:
        """Generate Merkle proof for specific index"""
        if index >= len(hashes):
            return []
        
        # Pad to power of 2
        working_hashes = hashes[:]
        while len(working_hashes) & (len(working_hashes) - 1):
            working_hashes.append(working_hashes[-1])
        
        proof = []
        current_index = index
        level = working_hashes[:]
        
        while len(level) > 1:
            # Find sibling
            if current_index % 2 == 0:
                sibling_index = current_index + 1
            else:
                sibling_index = current_index - 1
                
            if sibling_index < len(level):
                proof.append(level[sibling_index])
            
            # Move up to next level
            next_level = []
            for i in range(0, len(level), 2):
                combined = level[i] + level[i + 1] if i + 1 < len(level) else level[i] + level[i]
                hash_obj = hashlib.sha256(combined.encode())
                next_level.append(hash_obj.hexdigest())
            
            level = next_level
            current_index = current_index // 2
        
        return proof
    
    async def revoke_anchor(self, anchor_id: str, reason: str = "") -> bool:
        """
        Revoke a signature anchor (mark as invalid)
        
        Args:
            anchor_id: Anchor to revoke
            reason: Revocation reason
            
        Returns:
            Success status
        """
        try:
            # Note: Actual blockchain data cannot be modified, but we can
            # add a revocation record or maintain an off-chain revocation list
            
            revocation_hash = hashlib.sha256(f"REVOKE:{anchor_id}:{reason}".encode()).hexdigest()
            
            revocation_anchor = await self.anchor_signature(
                signature_hash=revocation_hash,
                document_hash=anchor_id,
                metadata={
                    "action": "revocation",
                    "target_anchor": anchor_id,
                    "reason": reason,
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
            
            logger.info(f"Revocation anchored for {anchor_id}: {revocation_anchor.anchor_id}")
            return True
            
        except Exception as e:
            logger.error(f"Anchor revocation failed: {e}")
            return False