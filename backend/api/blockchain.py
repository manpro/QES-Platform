"""
Blockchain API Endpoints

FastAPI endpoints for blockchain anchoring functionality.
"""

import logging
from datetime import datetime
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, Field

from ..core.blockchain import (
    BlockchainAnchoringService, BlockchainConfig, SignatureAnchor,
    BlockchainVerificationResult, BlockchainNetwork, AnchorStatus
)
from ..auth.dependencies import get_current_tenant
from ..models.tenant import Tenant

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/blockchain", tags=["blockchain"])


# Pydantic models for API
class AnchorRequest(BaseModel):
    """Request to anchor signature to blockchain"""
    signature_hash: str = Field(..., description="Hash of the signature to anchor")
    document_hash: str = Field(..., description="Hash of the signed document")
    qes_provider: Optional[str] = Field(None, description="QES provider used")
    signature_format: Optional[str] = Field(None, description="Signature format (PAdES, XAdES, etc.)")
    certificate_fingerprint: Optional[str] = Field(None, description="Certificate fingerprint")
    regulatory_compliance: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Regulatory compliance info")


class BatchAnchorRequest(BaseModel):
    """Request to batch anchor multiple signatures"""
    anchors: List[Dict[str, str]] = Field(..., description="List of signature and document hashes")


class AnchorResponse(BaseModel):
    """Response containing anchor information"""
    anchor_id: str
    signature_hash: str
    document_hash: str
    signer_address: str
    timestamp: datetime
    status: str
    network: str
    transaction_hash: Optional[str] = None
    block_number: Optional[int] = None
    gas_used: Optional[int] = None
    cost_wei: Optional[int] = None
    batch_id: Optional[str] = None
    merkle_proof: Optional[List[str]] = None
    
    @classmethod
    def from_anchor(cls, anchor: SignatureAnchor) -> "AnchorResponse":
        return cls(
            anchor_id=anchor.anchor_id,
            signature_hash=anchor.signature_hash,
            document_hash=anchor.document_hash,
            signer_address=anchor.signer_address,
            timestamp=anchor.timestamp,
            status=anchor.status.value,
            network=anchor.network,
            transaction_hash=anchor.transaction_hash,
            block_number=anchor.block_number,
            gas_used=anchor.gas_used,
            cost_wei=anchor.cost_wei,
            batch_id=anchor.batch_id,
            merkle_proof=anchor.merkle_proof
        )


class VerificationResponse(BaseModel):
    """Response containing verification result"""
    is_valid: bool
    anchor: Optional[AnchorResponse] = None
    verification_time: datetime
    confirmations: int = 0
    error_message: Optional[str] = None
    block_timestamp: Optional[datetime] = None
    inclusion_proof: Optional[Dict] = None
    
    @classmethod
    def from_verification_result(cls, result: BlockchainVerificationResult) -> "VerificationResponse":
        return cls(
            is_valid=result.is_valid,
            anchor=AnchorResponse.from_anchor(result.anchor) if result.anchor else None,
            verification_time=result.verification_time,
            confirmations=result.confirmations,
            error_message=result.error_message,
            block_timestamp=result.block_timestamp,
            inclusion_proof=result.inclusion_proof
        )


class RevocationRequest(BaseModel):
    """Request to revoke an anchor"""
    anchor_id: str = Field(..., description="Anchor ID to revoke")
    reason: str = Field(..., description="Reason for revocation")


# Global blockchain service instance (would be dependency injected in production)
blockchain_service: Optional[BlockchainAnchoringService] = None


def get_blockchain_service() -> BlockchainAnchoringService:
    """Get blockchain service instance"""
    if not blockchain_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Blockchain service not configured"
        )
    return blockchain_service


@router.post("/anchor", response_model=AnchorResponse)
async def anchor_signature(
    request: AnchorRequest,
    tenant: Tenant = Depends(get_current_tenant),
    blockchain: BlockchainAnchoringService = Depends(get_blockchain_service)
):
    """
    Anchor a signature to the blockchain for immutable proof
    """
    try:
        metadata = {
            "tenant_id": tenant.id,
            "qes_provider": request.qes_provider,
            "signature_format": request.signature_format,
            "certificate_fingerprint": request.certificate_fingerprint,
            "regulatory_compliance": request.regulatory_compliance,
            "anchored_at": datetime.utcnow().isoformat()
        }
        
        anchor = await blockchain.anchor_signature(
            signature_hash=request.signature_hash,
            document_hash=request.document_hash,
            metadata=metadata
        )
        
        logger.info(f"Signature anchored for tenant {tenant.id}: {anchor.anchor_id}")
        
        return AnchorResponse.from_anchor(anchor)
        
    except Exception as e:
        logger.error(f"Signature anchoring failed for tenant {tenant.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Anchoring failed: {str(e)}"
        )


@router.post("/anchor/batch", response_model=List[AnchorResponse])
async def batch_anchor_signatures(
    request: BatchAnchorRequest,
    tenant: Tenant = Depends(get_current_tenant),
    blockchain: BlockchainAnchoringService = Depends(get_blockchain_service)
):
    """
    Batch anchor multiple signatures for cost efficiency
    """
    try:
        if len(request.anchors) > 100:  # Reasonable batch limit
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Batch size too large (max 100)"
            )
        
        anchors = await blockchain.batch_anchor_signatures(request.anchors)
        
        logger.info(f"Batch anchored {len(anchors)} signatures for tenant {tenant.id}")
        
        return [AnchorResponse.from_anchor(anchor) for anchor in anchors]
        
    except Exception as e:
        logger.error(f"Batch anchoring failed for tenant {tenant.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch anchoring failed: {str(e)}"
        )


@router.get("/verify/{anchor_id}", response_model=VerificationResponse)
async def verify_anchor(
    anchor_id: str,
    tenant: Tenant = Depends(get_current_tenant),
    blockchain: BlockchainAnchoringService = Depends(get_blockchain_service)
):
    """
    Verify a signature anchor on the blockchain
    """
    try:
        result = await blockchain.verify_anchor(anchor_id)
        
        logger.info(f"Anchor verification for {anchor_id}: valid={result.is_valid}")
        
        return VerificationResponse.from_verification_result(result)
        
    except Exception as e:
        logger.error(f"Anchor verification failed for {anchor_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Verification failed: {str(e)}"
        )


@router.post("/revoke")
async def revoke_anchor(
    request: RevocationRequest,
    tenant: Tenant = Depends(get_current_tenant),
    blockchain: BlockchainAnchoringService = Depends(get_blockchain_service)
):
    """
    Revoke a signature anchor (mark as invalid)
    """
    try:
        success = await blockchain.revoke_anchor(
            anchor_id=request.anchor_id,
            reason=request.reason
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Revocation failed"
            )
        
        logger.info(f"Anchor revoked by tenant {tenant.id}: {request.anchor_id}")
        
        return {"success": True, "message": "Anchor revoked successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Anchor revocation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Revocation failed: {str(e)}"
        )


@router.get("/config")
async def get_blockchain_config(
    tenant: Tenant = Depends(get_current_tenant),
    blockchain: BlockchainAnchoringService = Depends(get_blockchain_service)
):
    """
    Get blockchain configuration information
    """
    return {
        "network": blockchain.config.network.value,
        "contract_address": blockchain.config.contract_address,
        "confirmation_blocks": blockchain.config.confirmation_blocks,
        "supported_networks": [network.value for network in BlockchainNetwork],
        "batch_anchoring_available": True,
        "revocation_supported": True
    }