# QES Anchor Smart Contracts

This directory contains smart contracts for blockchain-based signature anchoring in the QES platform.

## QESAnchor.sol

The main smart contract for anchoring qualified electronic signatures to blockchain networks.

### Features

- **Immutable Anchoring**: Store signature and document hashes with timestamp proof
- **Batch Operations**: Gas-optimized batch anchoring for multiple signatures
- **Event Logging**: Comprehensive event emission for off-chain indexing
- **Access Control**: Owner-based administration with emergency controls
- **Multi-Network**: Compatible with Ethereum, Polygon, and other EVM chains

### Functions

#### Core Functions

- `anchorSignature(bytes32 signatureHash, bytes32 documentHash, string metadata)`: Anchor a single signature
- `getAnchor(bytes32 anchorId)`: Retrieve anchor information
- `verifyAnchor(bytes32 anchorId)`: Verify anchor existence and validity
- `batchAnchorSignatures(...)`: Batch anchor multiple signatures for gas efficiency

#### Administrative Functions

- `transferOwnership(address newOwner)`: Transfer contract ownership
- `emergencyPause()`: Emergency pause functionality (placeholder)
- `getContractStats()`: Get contract usage statistics

#### Query Functions

- `getSignerAnchors(address signer)`: Get all anchors created by a signer
- `getSignerAnchorCount(address signer)`: Get anchor count for a signer

### Events

- `SignatureAnchored`: Emitted when a signature is anchored
- `OwnershipTransferred`: Emitted when ownership changes

### Deployment

Use the deployment script to deploy to various networks:

```bash
# Deploy to Polygon Mumbai (testnet)
python backend/scripts/deploy_contracts.py \
  --network polygon-mumbai \
  --rpc-url https://rpc-mumbai.maticvigil.com \
  --private-key YOUR_PRIVATE_KEY \
  --save

# Deploy to Polygon Mainnet
python backend/scripts/deploy_contracts.py \
  --network polygon-mainnet \
  --rpc-url https://polygon-rpc.com \
  --private-key YOUR_PRIVATE_KEY \
  --save

# Deploy to Ethereum Sepolia (testnet)
python backend/scripts/deploy_contracts.py \
  --network ethereum-sepolia \
  --rpc-url https://sepolia.infura.io/v3/YOUR_PROJECT_ID \
  --private-key YOUR_PRIVATE_KEY \
  --save
```

### Gas Costs

Estimated gas costs on different networks:

| Operation | Ethereum | Polygon | Cost (USD)* |
|-----------|----------|---------|-------------|
| Deploy Contract | ~2,000,000 gas | ~2,000,000 gas | $80 / $0.02 |
| Single Anchor | ~100,000 gas | ~100,000 gas | $4 / $0.001 |
| Batch Anchor (10) | ~600,000 gas | ~600,000 gas | $24 / $0.006 |

*Estimated costs based on 20 Gwei gas price for Ethereum and 30 Gwei for Polygon

### Security Considerations

- **Private Key Management**: Never commit private keys to version control
- **Gas Limits**: Set appropriate gas limits to prevent failed transactions
- **Network Validation**: Always verify you're deploying to the correct network
- **Contract Verification**: Verify contracts on block explorers after deployment

### Environment Configuration

Set these environment variables for production deployment:

```bash
# Ethereum
ETHEREUM_RPC_URL=https://mainnet.infura.io/v3/YOUR_PROJECT_ID
ETHEREUM_CONTRACT_ADDRESS=0x...
ETHEREUM_PRIVATE_KEY=0x...

# Polygon
POLYGON_RPC_URL=https://polygon-rpc.com
POLYGON_CONTRACT_ADDRESS=0x...
POLYGON_PRIVATE_KEY=0x...
```

### Testing

Run tests with:

```bash
# Unit tests
pytest backend/tests/test_blockchain.py

# Integration tests with testnet
pytest backend/tests/test_blockchain_integration.py
```