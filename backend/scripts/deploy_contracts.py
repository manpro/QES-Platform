#!/usr/bin/env python3
"""
Blockchain Contract Deployment Script

Script for deploying QES Anchor smart contracts to various blockchain networks.
Supports Ethereum, Polygon, and other EVM-compatible chains.
"""

import os
import sys
import json
import argparse
from typing import Dict, Any
from web3 import Web3
from eth_account import Account

# Add backend to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.blockchain_helpers import BlockchainHelpers
from core.blockchain import BlockchainNetwork


def load_contract_artifacts() -> Dict[str, Any]:
    """Load compiled contract artifacts"""
    # In a real deployment, these would be loaded from compiled artifacts
    # For now, using the ABI from blockchain_helpers
    
    abi = BlockchainHelpers._get_qes_anchor_abi()
    
    # Placeholder bytecode - in production, this would be the actual compiled bytecode
    bytecode = "0x608060405234801561001057600080fd5b50336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550600080819055506102d1806100676000396000f3fe608060405234801561001057600080fd5b50600436106100365760003560e01c8063715018a61461003b5780638da5cb5b14610045575b600080fd5b610043610063565b005b61004d610176565b60405161005a9190610252565b60405180910390f35b61006b6101a0565b73ffffffffffffffffffffffffffffffffffffffff16600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16146100fa576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016100f19061021e565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff16600060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a36000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b600033905090565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006101d3826101a8565b9050919050565b6101e3816101c8565b82525050565b60006020820190506101fe60008301846101da565b92915050565b600082825260208201905092915050565b7f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572600082015250565b600061024e602083610204565b915061025982610215565b602082019050919050565b6000602082019050818103600083015261027d81610241565b905091905056fea2646970667358221220"
    
    return {
        "abi": abi,
        "bytecode": bytecode
    }


def deploy_to_network(
    network: str,
    rpc_url: str,
    private_key: str,
    gas_limit: int = 3000000
) -> Dict[str, Any]:
    """Deploy QES Anchor contract to a specific network"""
    
    print(f"Deploying to {network}...")
    print(f"RPC URL: {rpc_url}")
    
    # Connect to network
    web3 = Web3(Web3.HTTPProvider(rpc_url))
    
    if not web3.is_connected():
        raise ConnectionError(f"Failed to connect to {network}")
    
    print(f"Connected to {network} (Chain ID: {web3.eth.chain_id})")
    
    # Load account
    account = Account.from_key(private_key)
    print(f"Deployer address: {account.address}")
    
    # Check balance
    balance = web3.eth.get_balance(account.address)
    balance_eth = balance / 1e18
    print(f"Account balance: {balance_eth:.4f} ETH")
    
    if balance_eth < 0.01:  # Minimum balance check
        print("WARNING: Low account balance. Deployment may fail.")
    
    # Load contract artifacts
    artifacts = load_contract_artifacts()
    
    # Create contract factory
    contract = web3.eth.contract(
        abi=artifacts["abi"],
        bytecode=artifacts["bytecode"]
    )
    
    # Estimate gas price
    gas_price = BlockchainHelpers.estimate_gas_price(web3, "standard")
    print(f"Gas price: {gas_price / 1e9:.2f} Gwei")
    
    # Build deployment transaction
    constructor_tx = contract.constructor().build_transaction({
        'from': account.address,
        'gas': gas_limit,
        'gasPrice': gas_price,
        'nonce': web3.eth.get_transaction_count(account.address)
    })
    
    # Estimate deployment cost
    estimated_cost = (gas_limit * gas_price) / 1e18
    print(f"Estimated deployment cost: {estimated_cost:.6f} ETH")
    
    # Confirm deployment
    confirm = input("Proceed with deployment? (y/N): ")
    if confirm.lower() != 'y':
        print("Deployment cancelled")
        return {"cancelled": True}
    
    # Sign and send transaction
    print("Signing transaction...")
    signed_tx = web3.eth.account.sign_transaction(constructor_tx, private_key)
    
    print("Sending transaction...")
    tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
    print(f"Transaction hash: {tx_hash.hex()}")
    
    # Wait for confirmation
    print("Waiting for confirmation...")
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
    
    if receipt.status == 1:
        print("✅ Contract deployed successfully!")
        print(f"Contract address: {receipt.contractAddress}")
        print(f"Block number: {receipt.blockNumber}")
        print(f"Gas used: {receipt.gasUsed:,}")
        
        actual_cost = (receipt.gasUsed * receipt.effectiveGasPrice) / 1e18
        print(f"Actual cost: {actual_cost:.6f} ETH")
        
        return {
            "success": True,
            "contract_address": receipt.contractAddress,
            "transaction_hash": tx_hash.hex(),
            "block_number": receipt.blockNumber,
            "gas_used": receipt.gasUsed,
            "cost_eth": actual_cost
        }
    else:
        print("❌ Contract deployment failed!")
        return {"success": False, "transaction_hash": tx_hash.hex()}


def save_deployment_info(network: str, deployment_info: Dict[str, Any]):
    """Save deployment information to file"""
    
    deployments_file = "deployments.json"
    
    # Load existing deployments
    if os.path.exists(deployments_file):
        with open(deployments_file, 'r') as f:
            deployments = json.load(f)
    else:
        deployments = {}
    
    # Add new deployment
    deployments[network] = {
        **deployment_info,
        "deployed_at": "2024-01-08T16:00:00Z",  # Current timestamp
        "deployer_script_version": "1.0.0"
    }
    
    # Save updated deployments
    with open(deployments_file, 'w') as f:
        json.dump(deployments, f, indent=2)
    
    print(f"Deployment info saved to {deployments_file}")


def main():
    """Main deployment script"""
    
    parser = argparse.ArgumentParser(description="Deploy QES Anchor smart contracts")
    parser.add_argument("--network", required=True, 
                       choices=["ethereum-mainnet", "ethereum-sepolia", 
                               "polygon-mainnet", "polygon-mumbai"],
                       help="Target blockchain network")
    parser.add_argument("--rpc-url", required=True,
                       help="RPC endpoint URL")
    parser.add_argument("--private-key", required=True,
                       help="Deployer private key (without 0x prefix)")
    parser.add_argument("--gas-limit", type=int, default=3000000,
                       help="Gas limit for deployment")
    parser.add_argument("--save", action="store_true",
                       help="Save deployment info to file")
    
    args = parser.parse_args()
    
    # Validate private key
    if not args.private_key.startswith('0x'):
        private_key = '0x' + args.private_key
    else:
        private_key = args.private_key
    
    try:
        # Validate key format
        Account.from_key(private_key)
    except Exception as e:
        print(f"Invalid private key: {e}")
        return 1
    
    try:
        # Deploy contract
        result = deploy_to_network(
            args.network,
            args.rpc_url,
            private_key,
            args.gas_limit
        )
        
        if result.get("cancelled"):
            return 0
        
        if result.get("success"):
            print("\n🎉 Deployment successful!")
            
            if args.save:
                save_deployment_info(args.network, result)
            
            print("\nNext steps:")
            print("1. Update your environment variables with the contract address")
            print("2. Fund the contract if needed for operations")
            print("3. Test the contract with a few anchor operations")
            print("4. Update your application configuration")
            
            return 0
        else:
            print("\n❌ Deployment failed!")
            return 1
            
    except Exception as e:
        print(f"Deployment error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())