"""
Blockchain Helper Functions

Utility functions for blockchain operations, contract deployment,
and transaction management.
"""

import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import hashlib
import secrets

from web3 import Web3
from web3.contract import Contract
from eth_account import Account
from eth_utils import to_checksum_address

logger = logging.getLogger(__name__)


@dataclass
class ContractDeployment:
    """Contract deployment information"""
    contract_address: str
    transaction_hash: str
    block_number: int
    gas_used: int
    deployment_cost: float
    abi: List[Dict[str, Any]]


@dataclass
class TransactionReceipt:
    """Enhanced transaction receipt"""
    transaction_hash: str
    block_number: int
    block_hash: str
    gas_used: int
    gas_price: int
    status: int
    logs: List[Dict[str, Any]]
    timestamp: datetime


class BlockchainHelpers:
    """Helper functions for blockchain operations"""
    
    @staticmethod
    def generate_secure_private_key() -> str:
        """Generate a cryptographically secure private key"""
        account = Account.create()
        return account.key.hex()
    
    @staticmethod
    def validate_ethereum_address(address: str) -> bool:
        """Validate Ethereum address format"""
        try:
            checksum_address = to_checksum_address(address)
            return Web3.is_address(checksum_address)
        except Exception:
            return False
    
    @staticmethod
    def calculate_signature_hash(signature_data: bytes) -> str:
        """Calculate SHA-256 hash of signature data"""
        hash_digest = hashlib.sha256(signature_data).digest()
        return "0x" + hash_digest.hex()
    
    @staticmethod
    def calculate_document_hash(document_data: bytes) -> str:
        """Calculate SHA-256 hash of document data"""
        hash_digest = hashlib.sha256(document_data).digest()
        return "0x" + hash_digest.hex()
    
    @staticmethod
    def estimate_gas_price(web3: Web3, speed: str = "standard") -> int:
        """
        Estimate gas price based on network conditions.
        
        Args:
            web3: Web3 instance
            speed: Transaction speed ("slow", "standard", "fast")
            
        Returns:
            Gas price in Wei
        """
        try:
            current_gas_price = web3.eth.gas_price
            
            # Adjust based on desired speed
            multipliers = {
                "slow": 0.9,
                "standard": 1.0,
                "fast": 1.2
            }
            
            multiplier = multipliers.get(speed, 1.0)
            return int(current_gas_price * multiplier)
            
        except Exception as e:
            logger.error(f"Failed to estimate gas price: {e}")
            # Fallback gas price (20 Gwei)
            return 20_000_000_000
    
    @staticmethod
    def wait_for_transaction_receipt(
        web3: Web3, 
        tx_hash: str, 
        timeout: int = 300,
        poll_latency: float = 0.1
    ) -> TransactionReceipt:
        """
        Wait for transaction to be mined and return enhanced receipt.
        
        Args:
            web3: Web3 instance
            tx_hash: Transaction hash
            timeout: Maximum wait time in seconds
            poll_latency: Polling interval in seconds
            
        Returns:
            Enhanced transaction receipt
        """
        try:
            receipt = web3.eth.wait_for_transaction_receipt(
                tx_hash, 
                timeout=timeout,
                poll_latency=poll_latency
            )
            
            # Get block for timestamp
            block = web3.eth.get_block(receipt.blockNumber)
            
            return TransactionReceipt(
                transaction_hash=receipt.transactionHash.hex(),
                block_number=receipt.blockNumber,
                block_hash=receipt.blockHash.hex(),
                gas_used=receipt.gasUsed,
                gas_price=receipt.effectiveGasPrice,
                status=receipt.status,
                logs=[dict(log) for log in receipt.logs],
                timestamp=datetime.fromtimestamp(block.timestamp)
            )
            
        except Exception as e:
            logger.error(f"Failed to wait for transaction receipt: {e}")
            raise
    
    @staticmethod
    def deploy_qes_anchor_contract(
        web3: Web3,
        private_key: str,
        gas_limit: int = 3_000_000
    ) -> ContractDeployment:
        """
        Deploy the QES Anchor smart contract.
        
        Args:
            web3: Web3 instance
            private_key: Deployer's private key
            gas_limit: Maximum gas for deployment
            
        Returns:
            Contract deployment information
        """
        try:
            # Load contract artifacts
            contract_abi = BlockchainHelpers._get_qes_anchor_abi()
            contract_bytecode = BlockchainHelpers._get_qes_anchor_bytecode()
            
            # Prepare account
            account = Account.from_key(private_key)
            
            # Create contract factory
            contract_factory = web3.eth.contract(
                abi=contract_abi,
                bytecode=contract_bytecode
            )
            
            # Build deployment transaction
            constructor_tx = contract_factory.constructor().build_transaction({
                'from': account.address,
                'gas': gas_limit,
                'gasPrice': BlockchainHelpers.estimate_gas_price(web3),
                'nonce': web3.eth.get_transaction_count(account.address)
            })
            
            # Sign and send transaction
            signed_tx = web3.eth.account.sign_transaction(constructor_tx, private_key)
            tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            # Wait for deployment
            receipt = BlockchainHelpers.wait_for_transaction_receipt(web3, tx_hash.hex())
            
            # Calculate deployment cost
            deployment_cost = (receipt.gas_used * receipt.gas_price) / 1e18  # Convert to ETH
            
            logger.info(f"QES Anchor contract deployed at: {receipt.transaction_hash}")
            
            return ContractDeployment(
                contract_address=receipt.transaction_hash,  # This should be contractAddress from receipt
                transaction_hash=receipt.transaction_hash,
                block_number=receipt.block_number,
                gas_used=receipt.gas_used,
                deployment_cost=deployment_cost,
                abi=contract_abi
            )
            
        except Exception as e:
            logger.error(f"Contract deployment failed: {e}")
            raise
    
    @staticmethod
    def _get_qes_anchor_abi() -> List[Dict[str, Any]]:
        """Get the QES Anchor contract ABI"""
        return [
            {
                "inputs": [
                    {"name": "signatureHash", "type": "bytes32"},
                    {"name": "documentHash", "type": "bytes32"},
                    {"name": "metadata", "type": "string"}
                ],
                "name": "anchorSignature",
                "outputs": [{"name": "anchorId", "type": "bytes32"}],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"name": "anchorId", "type": "bytes32"}],
                "name": "getAnchor",
                "outputs": [
                    {"name": "signatureHash", "type": "bytes32"},
                    {"name": "documentHash", "type": "bytes32"},
                    {"name": "timestamp", "type": "uint256"},
                    {"name": "blockNumber", "type": "uint256"},
                    {"name": "signer", "type": "address"},
                    {"name": "metadata", "type": "string"}
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [{"name": "anchorId", "type": "bytes32"}],
                "name": "verifyAnchor",
                "outputs": [
                    {"name": "exists", "type": "bool"},
                    {"name": "isValid", "type": "bool"}
                ],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [
                    {"name": "signatureHashes", "type": "bytes32[]"},
                    {"name": "documentHashes", "type": "bytes32[]"},
                    {"name": "metadataArray", "type": "string[]"}
                ],
                "name": "batchAnchorSignatures",
                "outputs": [{"name": "anchorIds", "type": "bytes32[]"}],
                "stateMutability": "nonpayable",
                "type": "function"
            },
            {
                "inputs": [{"name": "signer", "type": "address"}],
                "name": "getSignerAnchors",
                "outputs": [{"name": "anchorIds", "type": "bytes32[]"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "anonymous": False,
                "inputs": [
                    {"indexed": True, "name": "anchorId", "type": "bytes32"},
                    {"indexed": True, "name": "signer", "type": "address"},
                    {"indexed": True, "name": "signatureHash", "type": "bytes32"},
                    {"indexed": False, "name": "documentHash", "type": "bytes32"},
                    {"indexed": False, "name": "timestamp", "type": "uint256"},
                    {"indexed": False, "name": "blockNumber", "type": "uint256"}
                ],
                "name": "SignatureAnchored",
                "type": "event"
            }
        ]
    
    @staticmethod
    def _get_qes_anchor_bytecode() -> str:
        """Get the QES Anchor contract bytecode"""
        # This would be the compiled bytecode from the Solidity contract
        # For now, returning a placeholder - in production, this would be
        # the actual compiled bytecode from the QESAnchor.sol contract
        return "0x608060405234801561001057600080fd5b50336000806101000a81548173ffffffff..."
    
    @staticmethod
    def validate_transaction_parameters(
        web3: Web3,
        from_address: str,
        gas_limit: int,
        gas_price: int
    ) -> Dict[str, Any]:
        """
        Validate transaction parameters before sending.
        
        Args:
            web3: Web3 instance
            from_address: Sender address
            gas_limit: Gas limit for transaction
            gas_price: Gas price in Wei
            
        Returns:
            Validation results and recommendations
        """
        try:
            balance = web3.eth.get_balance(from_address)
            estimated_cost = gas_limit * gas_price
            
            validation = {
                "valid": True,
                "balance_wei": balance,
                "estimated_cost_wei": estimated_cost,
                "balance_eth": balance / 1e18,
                "estimated_cost_eth": estimated_cost / 1e18,
                "sufficient_balance": balance >= estimated_cost,
                "warnings": [],
                "recommendations": []
            }
            
            if not validation["sufficient_balance"]:
                validation["valid"] = False
                validation["warnings"].append("Insufficient balance for transaction")
            
            # Check if gas price is reasonable
            current_gas_price = web3.eth.gas_price
            if gas_price > current_gas_price * 2:
                validation["warnings"].append("Gas price significantly higher than network average")
            elif gas_price < current_gas_price * 0.5:
                validation["warnings"].append("Gas price significantly lower than network average")
                validation["recommendations"].append("Consider increasing gas price for faster confirmation")
            
            return validation
            
        except Exception as e:
            logger.error(f"Transaction validation failed: {e}")
            return {
                "valid": False,
                "error": str(e),
                "warnings": ["Validation failed"],
                "recommendations": ["Check network connection and address validity"]
            }
    
    @staticmethod
    def parse_anchor_event(log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse SignatureAnchored event from transaction logs.
        
        Args:
            log: Event log from transaction receipt
            
        Returns:
            Parsed event data
        """
        try:
            # Event signature for SignatureAnchored
            event_signature = "0x" + Web3.keccak(text="SignatureAnchored(bytes32,address,bytes32,bytes32,uint256,uint256)").hex()
            
            if log.get("topics", [{}])[0].hex() == event_signature:
                return {
                    "event_name": "SignatureAnchored",
                    "anchor_id": log["topics"][1].hex(),
                    "signer": "0x" + log["topics"][2].hex()[-40:],  # Last 40 chars for address
                    "signature_hash": log["topics"][3].hex(),
                    "document_hash": "0x" + log["data"][2:66],  # First 32 bytes
                    "timestamp": int(log["data"][66:130], 16),  # Next 32 bytes
                    "block_number": int(log["data"][130:194], 16)  # Next 32 bytes
                }
            
            return {"event_name": "unknown", "raw_log": log}
            
        except Exception as e:
            logger.error(f"Failed to parse anchor event: {e}")
            return {"event_name": "parse_error", "error": str(e), "raw_log": log}
    
    @staticmethod
    def calculate_network_fees(web3: Web3, network_name: str) -> Dict[str, Any]:
        """
        Calculate current network fees and provide recommendations.
        
        Args:
            web3: Web3 instance
            network_name: Network name (e.g., "ethereum", "polygon")
            
        Returns:
            Fee analysis and recommendations
        """
        try:
            current_gas_price = web3.eth.gas_price
            latest_block = web3.eth.get_block('latest')
            
            # Estimate costs for different transaction types
            simple_transfer_gas = 21000
            contract_interaction_gas = 100000
            contract_deployment_gas = 2000000
            
            fees = {
                "current_gas_price_gwei": current_gas_price / 1e9,
                "current_gas_price_wei": current_gas_price,
                "network": network_name,
                "latest_block": latest_block.number,
                "block_gas_limit": latest_block.gasLimit,
                "block_gas_used": latest_block.gasUsed,
                "network_utilization": (latest_block.gasUsed / latest_block.gasLimit) * 100,
                "estimated_costs": {
                    "simple_transfer_eth": (simple_transfer_gas * current_gas_price) / 1e18,
                    "contract_interaction_eth": (contract_interaction_gas * current_gas_price) / 1e18,
                    "contract_deployment_eth": (contract_deployment_gas * current_gas_price) / 1e18
                }
            }
            
            # Add network-specific recommendations
            if network_name.lower() == "ethereum":
                fees["recommendations"] = [
                    "Consider using Polygon for lower fees",
                    "Monitor gas prices during off-peak hours",
                    "Use batch operations to reduce per-transaction costs"
                ]
            elif network_name.lower() == "polygon":
                fees["recommendations"] = [
                    "Polygon offers significantly lower fees than Ethereum",
                    "Transaction costs are typically under $0.01"
                ]
            
            return fees
            
        except Exception as e:
            logger.error(f"Failed to calculate network fees: {e}")
            return {"error": str(e), "network": network_name}