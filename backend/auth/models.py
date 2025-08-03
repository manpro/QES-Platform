"""
Authentication related Pydantic models
"""

from typing import Optional
from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    """Base user model"""
    email: EmailStr
    first_name: str
    last_name: str
    is_active: bool = True


class UserCreate(UserBase):
    """User creation model"""
    password: str
    tenant_id: Optional[str] = None


class UserLogin(BaseModel):
    """User login model"""
    email: EmailStr
    password: str


class UserResponse(UserBase):
    """User response model (no password)"""
    id: str
    tenant_id: str
    is_verified: bool = False
    
    class Config:
        from_attributes = True


class Token(BaseModel):
    """JWT token response"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600


class TokenData(BaseModel):
    """Token payload data"""
    user_id: Optional[str] = None
    email: Optional[str] = None
    tenant_id: Optional[str] = None