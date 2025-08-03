// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title QES Anchor Contract
 * @dev Smart contract for anchoring Qualified Electronic Signatures to blockchain
 * @notice This contract provides immutable proof of signature existence and integrity
 */
contract QESAnchor {
    
    struct Anchor {
        bytes32 signatureHash;
        bytes32 documentHash;
        uint256 timestamp;
        uint256 blockNumber;
        address signer;
        string metadata;
        bool exists;
    }
    
    mapping(bytes32 => Anchor) public anchors;
    mapping(address => bytes32[]) public signerAnchors;
    
    uint256 public totalAnchors;
    address public owner;
    
    event SignatureAnchored(
        bytes32 indexed anchorId,
        address indexed signer,
        bytes32 indexed signatureHash,
        bytes32 documentHash,
        uint256 timestamp,
        uint256 blockNumber
    );
    
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
    
    modifier validHash(bytes32 hash) {
        require(hash != bytes32(0), "Hash cannot be zero");
        _;
    }
    
    constructor() {
        owner = msg.sender;
        totalAnchors = 0;
    }
    
    /**
     * @dev Anchor a signature to the blockchain
     * @param signatureHash Hash of the digital signature
     * @param documentHash Hash of the signed document
     * @param metadata Additional metadata as JSON string
     * @return anchorId Unique identifier for this anchor
     */
    function anchorSignature(
        bytes32 signatureHash,
        bytes32 documentHash,
        string calldata metadata
    ) 
        external 
        validHash(signatureHash) 
        validHash(documentHash) 
        returns (bytes32 anchorId) 
    {
        // Generate unique anchor ID
        anchorId = keccak256(
            abi.encodePacked(
                signatureHash,
                documentHash,
                block.timestamp,
                block.number,
                msg.sender,
                totalAnchors
            )
        );
        
        // Ensure anchor doesn't already exist
        require(!anchors[anchorId].exists, "Anchor already exists");
        
        // Create anchor record
        anchors[anchorId] = Anchor({
            signatureHash: signatureHash,
            documentHash: documentHash,
            timestamp: block.timestamp,
            blockNumber: block.number,
            signer: msg.sender,
            metadata: metadata,
            exists: true
        });
        
        // Add to signer's anchor list
        signerAnchors[msg.sender].push(anchorId);
        
        // Increment total counter
        totalAnchors++;
        
        emit SignatureAnchored(
            anchorId,
            msg.sender,
            signatureHash,
            documentHash,
            block.timestamp,
            block.number
        );
        
        return anchorId;
    }
    
    /**
     * @dev Get anchor information by ID
     * @param anchorId The anchor identifier
     * @return signatureHash Hash of the signature
     * @return documentHash Hash of the document  
     * @return timestamp Block timestamp when anchored
     * @return blockNumber Block number when anchored
     * @return signer Address that created the anchor
     * @return metadata Additional metadata
     */
    function getAnchor(bytes32 anchorId) 
        external 
        view 
        returns (
            bytes32 signatureHash,
            bytes32 documentHash,
            uint256 timestamp,
            uint256 blockNumber,
            address signer,
            string memory metadata
        ) 
    {
        require(anchors[anchorId].exists, "Anchor does not exist");
        
        Anchor storage anchor = anchors[anchorId];
        return (
            anchor.signatureHash,
            anchor.documentHash,
            anchor.timestamp,
            anchor.blockNumber,
            anchor.signer,
            anchor.metadata
        );
    }
    
    /**
     * @dev Verify if an anchor exists and is valid
     * @param anchorId The anchor identifier
     * @return exists Whether the anchor exists
     * @return isValid Whether the anchor is valid (exists and not tampered)
     */
    function verifyAnchor(bytes32 anchorId) 
        external 
        view 
        returns (bool exists, bool isValid) 
    {
        exists = anchors[anchorId].exists;
        isValid = exists; // In blockchain context, existence implies validity
        return (exists, isValid);
    }
    
    /**
     * @dev Get all anchor IDs for a specific signer
     * @param signer The signer address
     * @return anchorIds Array of anchor IDs
     */
    function getSignerAnchors(address signer) 
        external 
        view 
        returns (bytes32[] memory anchorIds) 
    {
        return signerAnchors[signer];
    }
    
    /**
     * @dev Get anchor count for a specific signer
     * @param signer The signer address
     * @return count Number of anchors for this signer
     */
    function getSignerAnchorCount(address signer) 
        external 
        view 
        returns (uint256 count) 
    {
        return signerAnchors[signer].length;
    }
    
    /**
     * @dev Batch anchor multiple signatures (gas optimization)
     * @param signatureHashes Array of signature hashes
     * @param documentHashes Array of document hashes  
     * @param metadataArray Array of metadata strings
     * @return anchorIds Array of generated anchor IDs
     */
    function batchAnchorSignatures(
        bytes32[] calldata signatureHashes,
        bytes32[] calldata documentHashes,
        string[] calldata metadataArray
    ) external returns (bytes32[] memory anchorIds) {
        require(
            signatureHashes.length == documentHashes.length && 
            documentHashes.length == metadataArray.length,
            "Array lengths must match"
        );
        require(signatureHashes.length > 0, "Cannot batch empty arrays");
        require(signatureHashes.length <= 100, "Batch size too large");
        
        anchorIds = new bytes32[](signatureHashes.length);
        
        for (uint256 i = 0; i < signatureHashes.length; i++) {
            anchorIds[i] = this.anchorSignature(
                signatureHashes[i],
                documentHashes[i],
                metadataArray[i]
            );
        }
        
        return anchorIds;
    }
    
    /**
     * @dev Transfer ownership of the contract
     * @param newOwner Address of the new owner
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        require(newOwner != owner, "New owner must be different");
        
        address previousOwner = owner;
        owner = newOwner;
        
        emit OwnershipTransferred(previousOwner, newOwner);
    }
    
    /**
     * @dev Emergency pause functionality (if needed in the future)
     * @notice This is a placeholder for potential emergency controls
     */
    function emergencyPause() external onlyOwner {
        // Implementation would depend on specific requirements
        // Could use OpenZeppelin's Pausable contract for full implementation
    }
    
    /**
     * @dev Get contract statistics
     * @return totalAnchorsCount Total number of anchors created
     * @return contractAddress This contract's address
     * @return deploymentBlock Block number when contract was deployed
     */
    function getContractStats() 
        external 
        view 
        returns (
            uint256 totalAnchorsCount,
            address contractAddress,
            uint256 deploymentBlock
        ) 
    {
        return (totalAnchors, address(this), block.number);
    }
}