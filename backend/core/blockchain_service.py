"""
Blockchain Service Integration

High-level service for integrating blockchain anchoring with the QES platform.
Manages multiple blockchain networks and provides unified interface.
"""

import logging
import asyncio
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from core.blockchain import (
    BlockchainAnchoringService, BlockchainConfig, BlockchainNetwork,
    SignatureAnchor, AnchorStatus
)
from core.blockchain_helpers import BlockchainHelpers
from core.audit_logger import AuditLogger, AuditEvent, AuditEventType

logger = logging.getLogger(__name__)


class NetworkPriority(Enum):
    """Network priority for multi-chain anchoring"""
    PRIMARY = "primary"
    SECONDARY = "secondary"
    BACKUP = "backup"


@dataclass
class NetworkConfiguration:
    """Configuration for a blockchain network"""
    network: BlockchainNetwork
    priority: NetworkPriority
    rpc_url: str
    contract_address: Optional[str]
    private_key: Optional[str]
    gas_limit: int = 200000
    enabled: bool = True


class BlockchainServiceManager:
    """
    High-level blockchain service manager.
    
    Manages multiple blockchain networks, provides failover,
    and integrates with the QES platform audit system.
    """
    
    def __init__(self, network_configs: List[NetworkConfiguration]):
        """Initialize blockchain service manager"""
        self.network_configs = network_configs
        self.services: Dict[str, BlockchainAnchoringService] = {}
        self.audit_logger = AuditLogger({
            "postgres_enabled": True,
            "loki_enabled": True
        })
        
        self._initialize_services()
    
    def _initialize_services(self):
        """Initialize blockchain services for all configured networks"""
        for config in self.network_configs:
            if not config.enabled:
                continue
                
            try:
                blockchain_config = BlockchainConfig(
                    network=config.network,
                    rpc_url=config.rpc_url,
                    contract_address=config.contract_address,
                    private_key=config.private_key,
                    gas_limit=config.gas_limit
                )
                
                service = BlockchainAnchoringService(blockchain_config)
                self.services[config.network.value] = service
                
                logger.info(f"Initialized blockchain service for {config.network.value}")
                
            except Exception as e:
                logger.error(f"Failed to initialize {config.network.value}: {e}")
    
    async def anchor_signature_multi_chain(
        self,
        signature_hash: str,
        document_hash: str,
        metadata: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None
    ) -> Dict[str, SignatureAnchor]:
        """
        Anchor signature to multiple blockchain networks based on priority.
        
        Args:
            signature_hash: Hash of the digital signature
            document_hash: Hash of the signed document
            metadata: Additional metadata
            user_id: User ID for audit logging
            
        Returns:
            Dict mapping network names to anchor results
        """
        results = {}
        primary_success = False
        
        # Sort networks by priority
        sorted_configs = sorted(
            [c for c in self.network_configs if c.enabled],
            key=lambda x: (x.priority.value, x.network.value)
        )
        
        for config in sorted_configs:
            network_name = config.network.value
            
            if network_name not in self.services:
                continue
            
            try:
                # Add network info to metadata
                enhanced_metadata = metadata.copy() if metadata else {}
                enhanced_metadata.update({
                    "network": network_name,
                    "priority": config.priority.value,
                    "anchor_timestamp": datetime.utcnow().isoformat(),
                    "service_version": "1.0.0"
                })
                
                # Anchor to this network
                service = self.services[network_name]
                anchor = await service.anchor_signature(
                    signature_hash, 
                    document_hash, 
                    enhanced_metadata
                )
                
                results[network_name] = anchor
                
                # Log successful anchor
                await self.audit_logger.log_event(AuditEvent(
                    event_type=AuditEventType.SYSTEM_ERROR,  # We need to add BLOCKCHAIN_ANCHOR
                    user_id=user_id,
                    resource_id=anchor.anchor_id,
                    details={
                        "network": network_name,
                        "transaction_hash": anchor.transaction_hash,
                        "block_number": anchor.block_number,
                        "status": anchor.status.value,
                        "signature_hash": signature_hash[:16] + "...",  # Truncated for privacy
                        "document_hash": document_hash[:16] + "..."
                    }
                ))
                
                if config.priority == NetworkPriority.PRIMARY:
                    primary_success = True
                    logger.info(f"Primary network anchor successful: {network_name}")
                
            except Exception as e:
                logger.error(f"Failed to anchor to {network_name}: {e}")
                
                # Create failed anchor record
                failed_anchor = SignatureAnchor(
                    anchor_id="",
                    signature_hash=signature_hash,
                    document_hash=document_hash,
                    status=AnchorStatus.FAILED,
                    error_message=str(e)
                )
                results[network_name] = failed_anchor
                
                # Log failure
                await self.audit_logger.log_event(AuditEvent(
                    event_type=AuditEventType.SYSTEM_ERROR,
                    user_id=user_id,
                    details={
                        "network": network_name,
                        "error": str(e),
                        "operation": "blockchain_anchor_failed"
                    }
                ))
        
        # Check if at least primary network succeeded
        if not primary_success and any(
            config.priority == NetworkPriority.PRIMARY for config in sorted_configs
        ):
            logger.warning("Primary blockchain network anchoring failed")
        
        return results
    
    async def verify_signature_anchor(
        self,
        anchor_id: str,
        network_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify signature anchor across networks.
        
        Args:
            anchor_id: Anchor identifier
            network_name: Specific network to check (if None, checks all)
            
        Returns:
            Verification results across networks
        """
        verification_results = {}
        
        networks_to_check = [network_name] if network_name else list(self.services.keys())
        
        for network in networks_to_check:
            if network not in self.services:
                continue
            
            try:
                service = self.services[network]
                result = await service.verify_anchor(anchor_id)
                
                verification_results[network] = {
                    "network": network,
                    "is_valid": result.is_valid,
                    "exists": result.exists,
                    "block_number": result.block_number,
                    "confirmations": result.confirmations,
                    "timestamp": result.timestamp.isoformat() if result.timestamp else None,
                    "error": result.error_message
                }
                
            except Exception as e:
                logger.error(f"Verification failed for {network}: {e}")
                verification_results[network] = {
                    "network": network,
                    "is_valid": False,
                    "exists": False,
                    "error": str(e)
                }
        
        return verification_results
    
    async def get_network_status(self) -> Dict[str, Any]:
        """Get status of all configured blockchain networks"""
        status = {}
        
        for config in self.network_configs:
            network_name = config.network.value
            
            if network_name not in self.services:
                status[network_name] = {
                    "enabled": config.enabled,
                    "priority": config.priority.value,
                    "status": "not_initialized",
                    "error": "Service not available"
                }
                continue
            
            try:
                service = self.services[network_name]
                
                # Check if Web3 connection is active
                if hasattr(service, 'web3') and service.web3:
                    is_connected = service.web3.is_connected()
                    latest_block = service.web3.eth.block_number if is_connected else None
                    network_id = service.web3.eth.chain_id if is_connected else None
                else:
                    is_connected = False
                    latest_block = None
                    network_id = None
                
                status[network_name] = {
                    "enabled": config.enabled,
                    "priority": config.priority.value,
                    "status": "connected" if is_connected else "disconnected",
                    "latest_block": latest_block,
                    "network_id": network_id,
                    "rpc_url": config.rpc_url,
                    "contract_address": config.contract_address,
                    "has_private_key": config.private_key is not None
                }
                
            except Exception as e:
                status[network_name] = {
                    "enabled": config.enabled,
                    "priority": config.priority.value,
                    "status": "error",
                    "error": str(e)
                }
        
        return status
    
    async def estimate_costs(self, network_name: str) -> Dict[str, Any]:
        """Estimate transaction costs for a specific network"""
        if network_name not in self.services:
            return {"error": "Network not available"}
        
        try:
            service = self.services[network_name]
            
            if hasattr(service, 'web3') and service.web3:
                fees = BlockchainHelpers.calculate_network_fees(
                    service.web3, 
                    network_name
                )
                return fees
            else:
                return {"error": "Web3 connection not available"}
                
        except Exception as e:
            return {"error": str(e)}
    
    def get_supported_networks(self) -> List[Dict[str, Any]]:
        """Get list of supported blockchain networks"""
        networks = []
        
        for config in self.network_configs:
            networks.append({
                "network": config.network.value,
                "name": config.network.value.replace("_", " ").title(),
                "priority": config.priority.value,
                "enabled": config.enabled,
                "rpc_url": config.rpc_url,
                "has_contract": config.contract_address is not None,
                "description": self._get_network_description(config.network)
            })
        
        return networks
    
    def _get_network_description(self, network: BlockchainNetwork) -> str:
        """Get human-readable description of blockchain network"""
        descriptions = {
            BlockchainNetwork.ETHEREUM_MAINNET: "Ethereum mainnet - Most secure, highest fees",
            BlockchainNetwork.ETHEREUM_SEPOLIA: "Ethereum Sepolia testnet - For testing only",
            BlockchainNetwork.POLYGON_MAINNET: "Polygon mainnet - Low fees, fast confirmation",
            BlockchainNetwork.POLYGON_MUMBAI: "Polygon Mumbai testnet - For testing only",
            BlockchainNetwork.HYPERLEDGER_FABRIC: "Hyperledger Fabric - Enterprise permissioned network",
            BlockchainNetwork.PRIVATE_CHAIN: "Private blockchain - Custom enterprise solution"
        }
        
        return descriptions.get(network, "Custom blockchain network")
    
    async def batch_anchor_signatures(
        self,
        signature_data: List[Dict[str, str]],
        network_name: str,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Batch anchor multiple signatures for gas optimization.
        
        Args:
            signature_data: List of signature/document hash pairs
            network_name: Target network for batching
            user_id: User ID for audit logging
            
        Returns:
            Batch operation results
        """
        if network_name not in self.services:
            return {"error": "Network not available"}
        
        try:
            service = self.services[network_name]
            
            # Extract hashes for batch operation
            signature_hashes = [data["signature_hash"] for data in signature_data]
            document_hashes = [data["document_hash"] for data in signature_data]
            metadata_array = [
                json.dumps(data.get("metadata", {})) for data in signature_data
            ]
            
            # If service supports batch operations, use them
            if hasattr(service, 'batch_anchor_signatures'):
                results = await service.batch_anchor_signatures(
                    signature_hashes,
                    document_hashes,
                    metadata_array
                )
            else:
                # Fallback to individual anchoring
                results = []
                for data in signature_data:
                    anchor = await service.anchor_signature(
                        data["signature_hash"],
                        data["document_hash"],
                        data.get("metadata", {})
                    )
                    results.append(anchor)
            
            # Log batch operation
            await self.audit_logger.log_event(AuditEvent(
                event_type=AuditEventType.SYSTEM_ERROR,  # Should be BLOCKCHAIN_BATCH_ANCHOR
                user_id=user_id,
                details={
                    "operation": "batch_anchor",
                    "network": network_name,
                    "batch_size": len(signature_data),
                    "success_count": len([r for r in results if r.status == AnchorStatus.CONFIRMED])
                }
            ))
            
            return {
                "success": True,
                "network": network_name,
                "batch_size": len(signature_data),
                "results": results
            }
            
        except Exception as e:
            logger.error(f"Batch anchoring failed for {network_name}: {e}")
            return {"error": str(e), "network": network_name}


def create_blockchain_service_manager() -> BlockchainServiceManager:
    """Create blockchain service manager with default configuration"""
    
    # Default configuration - should be loaded from environment/config
    network_configs = [
        NetworkConfiguration(
            network=BlockchainNetwork.POLYGON_MAINNET,
            priority=NetworkPriority.PRIMARY,
            rpc_url="https://polygon-rpc.com",
            contract_address=None,  # Set from environment
            private_key=None,  # Set from environment
            enabled=True
        ),
        NetworkConfiguration(
            network=BlockchainNetwork.ETHEREUM_MAINNET,
            priority=NetworkPriority.SECONDARY,
            rpc_url="https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY",
            contract_address=None,  # Set from environment
            private_key=None,  # Set from environment
            enabled=False  # Disabled by default due to high fees
        ),
        NetworkConfiguration(
            network=BlockchainNetwork.POLYGON_MUMBAI,
            priority=NetworkPriority.BACKUP,
            rpc_url="https://rpc-mumbai.maticvigil.com",
            contract_address=None,  # Set from environment
            private_key=None,  # Set from environment
            enabled=True  # For testing
        )
    ]
    
    return BlockchainServiceManager(network_configs)