"""
QES Platform Signatures Manager

Handles digital signature operations including document signing,
signature retrieval, and batch operations.
"""

import logging
from typing import List, Optional, Dict, Any, Union, BinaryIO
from pathlib import Path

from .models import (
    SigningRequest, SigningResponse, SignatureInfo,
    BatchSigningRequest, BatchSigningResponse
)
from .exceptions import QESSigningException, QESValidationException


logger = logging.getLogger(__name__)


class SignatureManager:
    """
    Manager for signature operations.
    
    Provides methods for signing documents, retrieving signature information,
    and managing signature lifecycle.
    """
    
    def __init__(self, client):
        """Initialize with QES client."""
        self.client = client
    
    def sign(
        self,
        document: Union[bytes, BinaryIO, str, Path],
        document_name: str,
        signature_format: str = "PAdES-LTA",
        certificate_id: Optional[str] = None,
        timestamp_url: Optional[str] = None,
        signature_policy: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> SigningResponse:
        """
        Sign a document with qualified electronic signature.
        
        Args:
            document: Document to sign (bytes, file object, or file path)
            document_name: Name of the document
            signature_format: Signature format (XAdES-B, XAdES-T, XAdES-LTA, 
                             PAdES-B, PAdES-T, PAdES-LTA)
            certificate_id: Specific certificate to use for signing
            timestamp_url: Custom timestamp authority URL
            signature_policy: Signature policy identifier
            metadata: Additional metadata for the signature
            **kwargs: Additional signing parameters
            
        Returns:
            SigningResponse with signature details
            
        Raises:
            QESSigningException: If signing fails
            QESValidationException: If parameters are invalid
            
        Example:
            >>> with open("document.pdf", "rb") as f:
            ...     result = client.signatures.sign(
            ...         document=f,
            ...         document_name="contract.pdf",
            ...         signature_format="PAdES-LTA"
            ...     )
            >>> print(f"Signature ID: {result.signature_id}")
        """
        # Validate signature format
        valid_formats = [
            "XAdES-B", "XAdES-T", "XAdES-LTA",
            "PAdES-B", "PAdES-T", "PAdES-LTA"
        ]
        if signature_format not in valid_formats:
            raise QESValidationException(
                f"Invalid signature format: {signature_format}. "
                f"Valid formats: {', '.join(valid_formats)}"
            )
        
        # Handle different document input types
        document_data = self._prepare_document_data(document)
        
        # Prepare request data
        data = {
            "document_name": document_name,
            "signature_format": signature_format,
        }
        
        if certificate_id:
            data["certificate_id"] = certificate_id
        if timestamp_url:
            data["timestamp_url"] = timestamp_url
        if signature_policy:
            data["signature_policy"] = signature_policy
        if metadata:
            data["metadata"] = metadata
        
        # Add any additional parameters
        data.update(kwargs)
        
        # Prepare files for upload
        files = {
            "document": (document_name, document_data, "application/octet-stream")
        }
        
        try:
            logger.info(f"Signing document: {document_name} with format: {signature_format}")
            response = self.client.post("/sign", data=data, files=files)
            response.raise_for_status()
            
            result_data = response.json()
            logger.info(f"Document signed successfully. Signature ID: {result_data.get('signature_id')}")
            
            return SigningResponse(**result_data)
            
        except Exception as e:
            logger.error(f"Signing failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_data = e.response.json()
                    raise QESSigningException(error_data.get('message', str(e)))
                except ValueError:
                    pass
            raise QESSigningException(f"Signing failed: {e}")
    
    def sign_batch(
        self,
        requests: List[SigningRequest],
        **kwargs
    ) -> BatchSigningResponse:
        """
        Sign multiple documents in a batch operation.
        
        Args:
            requests: List of signing requests
            **kwargs: Additional batch parameters
            
        Returns:
            BatchSigningResponse with results for all documents
            
        Raises:
            QESSigningException: If batch signing fails
            QESValidationException: If requests are invalid
            
        Example:
            >>> requests = [
            ...     SigningRequest(
            ...         document=doc1_bytes,
            ...         document_name="doc1.pdf",
            ...         signature_format="PAdES-LTA"
            ...     ),
            ...     SigningRequest(
            ...         document=doc2_bytes,
            ...         document_name="doc2.pdf", 
            ...         signature_format="XAdES-T"
            ...     )
            ... ]
            >>> result = client.signatures.sign_batch(requests)
        """
        if not requests:
            raise QESValidationException("At least one signing request is required")
        
        if len(requests) > 100:  # Reasonable batch limit
            raise QESValidationException("Batch size cannot exceed 100 documents")
        
        # Prepare batch request
        batch_data = BatchSigningRequest(requests=requests, **kwargs)
        
        try:
            logger.info(f"Starting batch signing of {len(requests)} documents")
            response = self.client.post("/sign/batch", data=batch_data.model_dump())
            response.raise_for_status()
            
            result_data = response.json()
            logger.info(f"Batch signing completed. Success: {result_data.get('success_count', 0)}")
            
            return BatchSigningResponse(**result_data)
            
        except Exception as e:
            logger.error(f"Batch signing failed: {e}")
            raise QESSigningException(f"Batch signing failed: {e}")
    
    def get_signature(self, signature_id: str) -> SignatureInfo:
        """
        Get information about a signature.
        
        Args:
            signature_id: Unique signature identifier
            
        Returns:
            SignatureInfo with signature details
            
        Raises:
            QESSigningException: If signature not found or access denied
            
        Example:
            >>> signature = client.signatures.get_signature("123e4567-e89b-12d3-a456-426614174000")
            >>> print(f"Status: {signature.status}")
        """
        try:
            response = self.client.get(f"/signatures/{signature_id}")
            response.raise_for_status()
            
            signature_data = response.json()
            return SignatureInfo(**signature_data)
            
        except Exception as e:
            logger.error(f"Failed to get signature {signature_id}: {e}")
            raise QESSigningException(f"Failed to get signature: {e}")
    
    def list_signatures(
        self,
        user_id: Optional[str] = None,
        status: Optional[str] = None,
        signature_format: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        **kwargs
    ) -> List[SignatureInfo]:
        """
        List signatures with optional filtering.
        
        Args:
            user_id: Filter by user ID
            status: Filter by signature status
            signature_format: Filter by signature format
            limit: Maximum number of results
            offset: Number of results to skip
            **kwargs: Additional filter parameters
            
        Returns:
            List of SignatureInfo objects
            
        Example:
            >>> signatures = client.signatures.list_signatures(
            ...     status="completed",
            ...     limit=50
            ... )
        """
        params = {
            "limit": limit,
            "offset": offset,
        }
        
        if user_id:
            params["user_id"] = user_id
        if status:
            params["status"] = status
        if signature_format:
            params["signature_format"] = signature_format
        
        params.update(kwargs)
        
        try:
            response = self.client.get("/signatures", params=params)
            response.raise_for_status()
            
            data = response.json()
            signatures = [SignatureInfo(**sig) for sig in data.get("signatures", [])]
            
            logger.info(f"Retrieved {len(signatures)} signatures")
            return signatures
            
        except Exception as e:
            logger.error(f"Failed to list signatures: {e}")
            raise QESSigningException(f"Failed to list signatures: {e}")
    
    def download_signed_document(
        self,
        signature_id: str,
        include_timestamps: bool = True
    ) -> bytes:
        """
        Download the signed document.
        
        Args:
            signature_id: Signature identifier
            include_timestamps: Whether to include timestamp tokens
            
        Returns:
            Signed document as bytes
            
        Raises:
            QESSigningException: If download fails
        """
        params = {"include_timestamps": include_timestamps}
        
        try:
            response = self.client.get(
                f"/signatures/{signature_id}/download",
                params=params
            )
            response.raise_for_status()
            
            logger.info(f"Downloaded signed document for signature {signature_id}")
            return response.content
            
        except Exception as e:
            logger.error(f"Failed to download signed document: {e}")
            raise QESSigningException(f"Failed to download signed document: {e}")
    
    def revoke_signature(self, signature_id: str, reason: str = "") -> bool:
        """
        Revoke a signature.
        
        Args:
            signature_id: Signature identifier
            reason: Reason for revocation
            
        Returns:
            True if revocation successful
            
        Raises:
            QESSigningException: If revocation fails
        """
        data = {"reason": reason} if reason else {}
        
        try:
            response = self.client.delete(f"/signatures/{signature_id}", data=data)
            response.raise_for_status()
            
            logger.info(f"Signature {signature_id} revoked successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke signature {signature_id}: {e}")
            raise QESSigningException(f"Failed to revoke signature: {e}")
    
    def get_signing_session(self, session_id: str) -> Dict[str, Any]:
        """
        Get information about a signing session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session information
        """
        try:
            response = self.client.get(f"/signing-sessions/{session_id}")
            response.raise_for_status()
            
            return response.json()
            
        except Exception as e:
            logger.error(f"Failed to get signing session {session_id}: {e}")
            raise QESSigningException(f"Failed to get signing session: {e}")
    
    def _prepare_document_data(self, document: Union[bytes, BinaryIO, str, Path]) -> bytes:
        """
        Convert document input to bytes.
        
        Args:
            document: Document in various formats
            
        Returns:
            Document as bytes
            
        Raises:
            QESValidationException: If document format is invalid
        """
        if isinstance(document, bytes):
            return document
        elif hasattr(document, 'read'):
            # File-like object
            if hasattr(document, 'mode') and 'b' not in document.mode:
                raise QESValidationException("File must be opened in binary mode")
            return document.read()
        elif isinstance(document, (str, Path)):
            # File path
            path = Path(document)
            if not path.exists():
                raise QESValidationException(f"File not found: {path}")
            return path.read_bytes()
        else:
            raise QESValidationException(
                "Document must be bytes, file object, or file path"
            )