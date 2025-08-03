"""
Audit Log API Endpoints

FastAPI endpoints for accessing audit logs for compliance reporting.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from auth.jwt_auth import get_current_user
from models.user import User
from core.audit_logger import AuditLogger, AuditEventType


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/audit", tags=["audit"])


class AuditEventResponse(BaseModel):
    """Response model for audit events"""
    event_id: str
    event_type: str
    timestamp: datetime
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    provider_name: Optional[str] = None
    resource_id: Optional[str] = None
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class AuditSearchResponse(BaseModel):
    """Response model for audit search results"""
    events: List[AuditEventResponse]
    total: int
    page: int
    size: int
    has_next: bool
    has_prev: bool


class AuditSearchRequest(BaseModel):
    """Request model for audit search"""
    start_time: datetime
    end_time: datetime
    event_types: Optional[List[str]] = None
    user_id: Optional[str] = None
    provider_name: Optional[str] = None
    page: int = Field(default=1, ge=1)
    size: int = Field(default=50, ge=1, le=1000)


# Initialize audit logger
audit_logger = AuditLogger({
    "enable_postgres": True,
    "enable_loki": True,
    "enable_file": True,
    "log_file_path": "audit.log",
    "buffer_size": 50,
    "loki_url": "http://localhost:3100"
})


@router.get("/events", response_model=AuditSearchResponse)
async def search_audit_events(
    start_time: datetime = Query(..., description="Start time for search (ISO format)"),
    end_time: datetime = Query(..., description="End time for search (ISO format)"),
    event_types: Optional[List[str]] = Query(None, description="Filter by event types"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    provider_name: Optional[str] = Query(None, description="Filter by QES provider"),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(50, ge=1, le=1000, description="Page size"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Search audit events for compliance reporting.
    
    Requires appropriate permissions for audit access.
    """
    try:
        # Check if user has audit access permission
        # TODO: Implement proper role-based access control
        if not _has_audit_access(current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions for audit access"
            )
        
        # Validate time range
        if end_time <= start_time:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="End time must be after start time"
            )
        
        # Limit search range to 1 year
        max_range = timedelta(days=365)
        if end_time - start_time > max_range:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Search range cannot exceed 365 days"
            )
        
        # Convert event type strings to enums
        event_type_enums = None
        if event_types:
            try:
                event_type_enums = [AuditEventType(et) for et in event_types]
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid event type: {e}"
                )
        
        # Search audit events
        search_result = await audit_logger.search_events(
            start_time=start_time,
            end_time=end_time,
            event_types=event_type_enums,
            user_id=user_id,
            provider_name=provider_name,
            page=page,
            size=size
        )
        
        # Convert to response format
        events = []
        for event in search_result.get("events", []):
            events.append(AuditEventResponse(
                event_id=event.event_id,
                event_type=event.event_type.value,
                timestamp=event.timestamp,
                user_id=event.user_id,
                session_id=event.session_id,
                provider_name=event.provider_name,
                resource_id=event.resource_id,
                client_ip=event.client_ip,
                user_agent=event.user_agent,
                trace_id=event.trace_id,
                span_id=event.span_id,
                details=event.details
            ))
        
        return AuditSearchResponse(
            events=events,
            total=search_result.get("total", 0),
            page=search_result.get("page", page),
            size=search_result.get("size", size),
            has_next=search_result.get("has_next", False),
            has_prev=search_result.get("has_prev", False)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Audit search failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Audit search failed"
        )


@router.get("/events/export")
async def export_audit_events(
    start_time: datetime = Query(..., description="Start time for export"),
    end_time: datetime = Query(..., description="End time for export"),
    format: str = Query("json", regex="^(json|csv)$", description="Export format"),
    event_types: Optional[List[str]] = Query(None, description="Filter by event types"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    provider_name: Optional[str] = Query(None, description="Filter by QES provider"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Export audit events for compliance reporting.
    
    Supports JSON and CSV formats for external analysis.
    """
    try:
        # Check audit access permission
        if not _has_audit_access(current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions for audit export"
            )
        
        # Validate time range (stricter limits for export)
        if end_time <= start_time:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="End time must be after start time"
            )
        
        # Limit export range to 90 days for performance
        max_range = timedelta(days=90)
        if end_time - start_time > max_range:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Export range cannot exceed 90 days"
            )
        
        # Convert event types
        event_type_enums = None
        if event_types:
            try:
                event_type_enums = [AuditEventType(et) for et in event_types]
            except ValueError as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid event type: {e}"
                )
        
        # Get all events (no pagination for export)
        search_result = await audit_logger.search_events(
            start_time=start_time,
            end_time=end_time,
            event_types=event_type_enums,
            user_id=user_id,
            provider_name=provider_name,
            page=1,
            size=10000  # Large size for export
        )
        
        events = search_result.get("events", [])
        
        # Log the export for audit trail using validation check as system event
        await audit_logger.log_validation_check(
            user_id=current_user.id,
            resource_id="audit_export",
            check_type="audit_export",
            result=True,
            details={
                "action": "audit_export",
                "format": format,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "event_count": len(events),
                "filters": {
                    "event_types": event_types,
                    "user_id": user_id,
                    "provider_name": provider_name
                }
            }
        )
        
        if format == "csv":
            # Generate CSV response
            from io import StringIO
            import csv
            from fastapi.responses import StreamingResponse
            
            output = StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                "event_id", "event_type", "timestamp", "user_id", "session_id",
                "provider_name", "resource_id", "client_ip", "user_agent",
                "trace_id", "span_id", "details"
            ])
            
            # Write data
            for event in events:
                writer.writerow([
                    event.event_id,
                    event.event_type.value,
                    event.timestamp.isoformat(),
                    event.user_id,
                    event.session_id,
                    event.provider_name,
                    event.resource_id,
                    event.client_ip,
                    event.user_agent,
                    event.trace_id,
                    event.span_id,
                    str(event.details) if event.details else ""
                ])
            
            output.seek(0)
            
            return StreamingResponse(
                iter([output.getvalue()]),
                media_type="text/csv",
                headers={
                    "Content-Disposition": f"attachment; filename=audit_export_{start_time.strftime('%Y%m%d')}_{end_time.strftime('%Y%m%d')}.csv"
                }
            )
        
        else:
            # Return JSON format
            events_dict = []
            for event in events:
                events_dict.append({
                    "event_id": event.event_id,
                    "event_type": event.event_type.value,
                    "timestamp": event.timestamp.isoformat(),
                    "user_id": event.user_id,
                    "session_id": event.session_id,
                    "provider_name": event.provider_name,
                    "resource_id": event.resource_id,
                    "client_ip": event.client_ip,
                    "user_agent": event.user_agent,
                    "trace_id": event.trace_id,
                    "span_id": event.span_id,
                    "details": event.details
                })
            
            return {
                "events": events_dict,
                "export_info": {
                    "format": "json",
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat(),
                    "total_events": len(events),
                    "exported_at": datetime.now(timezone.utc).isoformat(),
                    "exported_by": current_user.id
                }
            }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Audit export failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Audit export failed"
        )


@router.get("/event-types")
async def get_audit_event_types(
    current_user: User = Depends(get_current_user)
):
    """Get all available audit event types for filtering"""
    if not _has_audit_access(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions for audit access"
        )
    
    return {
        "event_types": [
            {
                "value": event_type.value,
                "name": event_type.value.replace("_", " ").title()
            }
            for event_type in AuditEventType
        ]
    }


def _has_audit_access(user: User) -> bool:
    """Check if user has audit access permissions"""
    # TODO: Implement proper role-based access control
    # For now, allow all authenticated users
    # In production, this should check for admin/auditor roles
    return True  # Placeholder - implement proper RBAC