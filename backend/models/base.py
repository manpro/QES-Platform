"""
Base database model with common fields and functionality.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Column, DateTime, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import declarative_mixin


Base = declarative_base()


@declarative_mixin
class TimestampMixin:
    """Mixin to add created_at and updated_at timestamps."""
    
    created_at = Column(
        DateTime, 
        default=datetime.utcnow, 
        nullable=False,
        doc="When the record was created"
    )
    updated_at = Column(
        DateTime, 
        default=datetime.utcnow, 
        onupdate=datetime.utcnow, 
        nullable=False,
        doc="When the record was last updated"
    )


@declarative_mixin 
class UUIDMixin:
    """Mixin to add UUID primary key."""
    
    id = Column(
        UUID(as_uuid=True), 
        primary_key=True, 
        default=uuid.uuid4,
        unique=True,
        nullable=False,
        doc="Unique identifier"
    )


class BaseModel(Base, UUIDMixin, TimestampMixin):
    """Base model class with common functionality."""
    
    __abstract__ = True
    
    def to_dict(self) -> dict[str, Any]:
        """Convert model instance to dictionary."""
        return {
            column.key: getattr(self, column.key)
            for column in self.__table__.columns
        }
    
    def __repr__(self) -> str:
        """String representation of the model."""
        class_name = self.__class__.__name__
        return f"<{class_name}(id={self.id})>"