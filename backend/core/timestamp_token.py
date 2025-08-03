"""
Timestamp Token Data Structure

Represents RFC 3161 timestamp tokens for digital signatures.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class TimestampToken:
    """
    RFC 3161 Timestamp Token
    
    Contains the timestamp token data and metadata for digital signatures.
    """
    token_data: bytes
    timestamp: datetime
    tsa_url: str
    hash_algorithm: str
    issuer: str
    serial_number: Optional[str] = None
    policy_id: Optional[str] = None
    
    def __post_init__(self):
        """Validate timestamp token data"""
        if not self.token_data:
            raise ValueError("Token data cannot be empty")
        if not self.tsa_url:
            raise ValueError("TSA URL is required")
        if not self.hash_algorithm:
            raise ValueError("Hash algorithm is required")
    
    @property
    def token_size(self) -> int:
        """Get size of token data in bytes"""
        return len(self.token_data)
    
    def to_dict(self) -> dict:
        """Convert to dictionary representation"""
        return {
            "token_size": self.token_size,
            "timestamp": self.timestamp.isoformat(),
            "tsa_url": self.tsa_url,
            "hash_algorithm": self.hash_algorithm,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "policy_id": self.policy_id
        }