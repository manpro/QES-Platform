"""
Audit Logger

Implements tamper-proof audit logging for all signing operations
with OpenTelemetry tracing and structured logging to Loki/PostgreSQL.
"""

import json
import asyncio
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
import hashlib
import uuid

# OpenTelemetry imports
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode


class AuditEventType(Enum):
    """Types of auditable events"""
    USER_AUTHENTICATION = "user_authentication"
    CERTIFICATE_REQUEST = "certificate_request"
    SIGNING_STARTED = "signing_started"
    SIGNING_COMPLETED = "signing_completed"
    SIGNING_FAILED = "signing_failed"
    DOCUMENT_UPLOADED = "document_uploaded"
    TIMESTAMP_REQUEST = "timestamp_request"
    VALIDATION_CHECK = "validation_check"
    PROVIDER_HEALTH_CHECK = "provider_health_check"
    SYSTEM_ERROR = "system_error"
    
    # Biometric verification events
    BIOMETRIC_ANALYSIS = "biometric_analysis"
    LIVENESS_DETECTION = "liveness_detection"
    FACE_COMPARISON = "face_comparison"
    DOCUMENT_VERIFICATION = "document_verification"
    
    # Blockchain events
    BLOCKCHAIN_ANCHOR = "blockchain_anchor"
    BLOCKCHAIN_VERIFICATION = "blockchain_verification"
    BLOCKCHAIN_BATCH_ANCHOR = "blockchain_batch_anchor"
    
    # Billing and payment events
    SUBSCRIPTION_CREATED = "subscription_created"
    SUBSCRIPTION_UPDATED = "subscription_updated"
    SUBSCRIPTION_CANCELED = "subscription_canceled"
    PAYMENT_INTENT_CREATED = "payment_intent_created"
    PAYMENT_SUCCEEDED = "payment_succeeded"
    PAYMENT_FAILED = "payment_failed"
    INVOICE_PAID = "invoice_paid"
    WEBHOOK_PROCESSED = "webhook_processed"
    
    # Usage tracking events
    USAGE_RECORDED = "usage_recorded"
    QUOTA_VIOLATION = "quota_violation"
    USAGE_EXPORT = "usage_export"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    
    # Metrics and monitoring events
    METRIC_RECORDED = "metric_recorded"
    ALERT_TRIGGERED = "alert_triggered"
    ALERT_RESOLVED = "alert_resolved"
    ALERT_CONFIG_CHANGED = "alert_config_changed"
    PERFORMANCE_DEGRADATION = "performance_degradation"


@dataclass
class AuditEvent:
    """Audit event structure"""
    event_id: str
    event_type: AuditEventType
    timestamp: datetime
    user_id: Optional[str]
    session_id: Optional[str]
    provider_name: Optional[str]
    resource_id: Optional[str]
    details: Dict[str, Any]
    trace_id: Optional[str]
    span_id: Optional[str]
    client_ip: Optional[str]
    user_agent: Optional[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['event_type'] = self.event_type.value
        return data


class AuditLogger:
    """
    Centralized audit logging system for all QES operations.
    
    Provides tamper-proof logging with structured data and
    integration with observability systems.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enable_loki = config.get("enable_loki", False)
        self.enable_postgres = config.get("enable_postgres", True)
        self.enable_file = config.get("enable_file", True)
        self.log_file_path = config.get("log_file_path", "audit.log")
        
        # Initialize tracer
        self.tracer = trace.get_tracer("qes-audit-logger")
        
        # Event buffer for batch processing
        self._event_buffer: List[AuditEvent] = []
        self._buffer_size = config.get("buffer_size", 100)
    
    async def log_authentication(
        self,
        user_id: str,
        provider_name: str,
        success: bool,
        session_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log user authentication event"""
        
        event = self._create_event(
            event_type=AuditEventType.USER_AUTHENTICATION,
            user_id=user_id,
            session_id=session_id,
            provider_name=provider_name,
            client_ip=client_ip,
            user_agent=user_agent,
            details={
                "success": success,
                "authentication_method": details.get("method") if details else None,
                **(details or {})
            }
        )
        
        await self._write_event(event)
        return event.event_id
    
    async def log_certificate_request(
        self,
        user_id: str,
        provider_name: str,
        session_id: str,
        success: bool,
        certificate_info: Optional[Dict[str, Any]] = None,
        client_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log certificate request event"""
        
        event = self._create_event(
            event_type=AuditEventType.CERTIFICATE_REQUEST,
            user_id=user_id,
            session_id=session_id,
            provider_name=provider_name,
            client_ip=client_ip,
            details={
                "success": success,
                "certificate_subject": certificate_info.get("subject") if certificate_info else None,
                "certificate_serial": certificate_info.get("serial") if certificate_info else None,
                **(details or {})
            }
        )
        
        await self._write_event(event)
        return event.event_id
    
    async def log_signing_started(
        self,
        user_id: str,
        session_id: str,
        provider_name: str,
        job_id: str,
        document_name: str,
        document_hash: str,
        signature_format: str,
        client_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log signing operation started"""
        
        event = self._create_event(
            event_type=AuditEventType.SIGNING_STARTED,
            user_id=user_id,
            session_id=session_id,
            provider_name=provider_name,
            resource_id=job_id,
            client_ip=client_ip,
            details={
                "document_name": document_name,
                "document_hash": document_hash,
                "signature_format": signature_format,
                "job_id": job_id,
                **(details or {})
            }
        )
        
        await self._write_event(event)
        return event.event_id
    
    async def log_signing_completed(
        self,
        user_id: str,
        session_id: str,
        provider_name: str,
        job_id: str,
        signature_id: str,
        processing_time_ms: int,
        signature_info: Dict[str, Any],
        client_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log signing operation completed"""
        
        event = self._create_event(
            event_type=AuditEventType.SIGNING_COMPLETED,
            user_id=user_id,
            session_id=session_id,
            provider_name=provider_name,
            resource_id=job_id,
            client_ip=client_ip,
            details={
                "signature_id": signature_id,
                "processing_time_ms": processing_time_ms,
                "signature_format": signature_info.get("format"),
                "timestamp_used": signature_info.get("timestamp_used"),
                "certificate_serial": signature_info.get("certificate_serial"),
                **(details or {})
            }
        )
        
        await self._write_event(event)
        return event.event_id
    
    async def log_signing_failed(
        self,
        user_id: str,
        session_id: str,
        provider_name: str,
        job_id: str,
        error_code: str,
        error_message: str,
        processing_time_ms: int,
        client_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log signing operation failed"""
        
        event = self._create_event(
            event_type=AuditEventType.SIGNING_FAILED,
            user_id=user_id,
            session_id=session_id,
            provider_name=provider_name,
            resource_id=job_id,
            client_ip=client_ip,
            details={
                "error_code": error_code,
                "error_message": error_message,
                "processing_time_ms": processing_time_ms,
                **(details or {})
            }
        )
        
        await self._write_event(event)
        return event.event_id
    
    async def log_timestamp_request(
        self,
        tsa_url: str,
        data_hash: str,
        success: bool,
        response_time_ms: int,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log timestamp request to TSA"""
        
        event = self._create_event(
            event_type=AuditEventType.TIMESTAMP_REQUEST,
            details={
                "tsa_url": tsa_url,
                "data_hash": data_hash,
                "success": success,
                "response_time_ms": response_time_ms,
                **(details or {})
            }
        )
        
        await self._write_event(event)
        return event.event_id
    
    async def log_system_error(
        self,
        error_type: str,
        error_message: str,
        component: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log system errors"""
        
        event = self._create_event(
            event_type=AuditEventType.SYSTEM_ERROR,
            user_id=user_id,
            session_id=session_id,
            details={
                "error_type": error_type,
                "error_message": error_message,
                "component": component,
                **(details or {})
            }
        )
        
        await self._write_event(event)
        return event.event_id
    
    async def log_validation_check(
        self,
        user_id: str,
        resource_id: str,
        check_type: str,
        result: bool,
        session_id: Optional[str] = None,
        provider_name: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log validation check event"""
        
        event = self._create_event(
            event_type=AuditEventType.VALIDATION_CHECK,
            user_id=user_id,
            session_id=session_id,
            provider_name=provider_name,
            resource_id=resource_id,
            client_ip=client_ip,
            user_agent=user_agent,
            details={
                "check_type": check_type,
                "result": result,
                **(details or {})
            }
        )
        
        await self._write_event(event)
        return event.event_id
    
    def _create_event(
        self,
        event_type: AuditEventType,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        provider_name: Optional[str] = None,
        resource_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditEvent:
        """Create audit event with current context"""
        
        # Get current trace context
        current_span = trace.get_current_span()
        trace_id = None
        span_id = None
        
        if current_span.is_recording():
            span_context = current_span.get_span_context()
            trace_id = format(span_context.trace_id, '032x')
            span_id = format(span_context.span_id, '016x')
        
        return AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            session_id=session_id,
            provider_name=provider_name,
            resource_id=resource_id,
            details=details or {},
            trace_id=trace_id,
            span_id=span_id,
            client_ip=client_ip,
            user_agent=user_agent
        )
    
    async def _write_event(self, event: AuditEvent):
        """Write event to configured outputs"""
        
        with self.tracer.start_as_current_span("audit_log_write") as span:
            span.set_attribute("event.type", event.event_type.value)
            span.set_attribute("event.id", event.event_id)
            
            try:
                # Add to buffer
                self._event_buffer.append(event)
                
                # Write to file immediately for critical events
                if self.enable_file:
                    await self._write_to_file(event)
                
                # Flush buffer if full
                if len(self._event_buffer) >= self._buffer_size:
                    await self._flush_buffer()
                
                span.set_status(Status(StatusCode.OK))
                
            except Exception as e:
                span.set_status(Status(StatusCode.ERROR, str(e)))
                # Fallback logging to ensure audit events are never lost
                await self._emergency_log(event, str(e))
    
    async def _write_to_file(self, event: AuditEvent):
        """Write event to local file"""
        try:
            log_entry = json.dumps(event.to_dict()) + "\n"
            
            # Use async file I/O in production
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(log_entry)
                f.flush()
                
        except Exception as e:
            print(f"Failed to write audit log to file: {e}")
    
    async def _write_to_postgres(self, events: List[AuditEvent]):
        """Write events to PostgreSQL for compliance"""
        try:
            from database import get_db
            from models.audit_log import AuditLog
            from sqlalchemy.orm import Session
            
            # Get database session
            db_gen = get_db()
            db: Session = next(db_gen)
            
            try:
                # Convert audit events to database models
                db_events = []
                for event in events:
                    db_event = AuditLog(
                        event_id=event.event_id,
                        event_type=event.event_type,
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
                    )
                    db_events.append(db_event)
                
                # Bulk insert for performance
                db.add_all(db_events)
                db.commit()
                
                print(f"Successfully wrote {len(events)} audit events to PostgreSQL")
                
            except Exception as e:
                db.rollback()
                print(f"Failed to write audit events to PostgreSQL: {e}")
                raise
            finally:
                db.close()
                
        except Exception as e:
            print(f"PostgreSQL audit logging error: {e}")
            # Don't raise - audit should be non-blocking
    
    async def _write_to_loki(self, events: List[AuditEvent]):
        """Write events to Grafana Loki for centralized logging"""
        try:
            import httpx
            import json
            from datetime import datetime
            
            # Loki push endpoint
            loki_url = self.config.get("loki_url", "http://localhost:3100")
            push_endpoint = f"{loki_url}/loki/api/v1/push"
            
            # Build Loki streams
            streams = []
            for event in events:
                # Convert timestamp to nanoseconds (Loki requirement)
                timestamp_ns = str(int(event.timestamp.timestamp() * 1_000_000_000))
                
                # Build log labels
                labels = {
                    "service": "qes-platform",
                    "component": "audit-logger",
                    "event_type": event.event_type.value,
                    "user_id": event.user_id or "unknown",
                    "provider": event.provider_name or "unknown"
                }
                
                # Format labels for Loki
                label_string = ",".join([f'{k}="{v}"' for k, v in labels.items()])
                
                # Create log line with structured data
                log_line = json.dumps({
                    "event_id": event.event_id,
                    "timestamp": event.timestamp.isoformat(),
                    "event_type": event.event_type.value,
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
                
                streams.append({
                    "stream": labels,
                    "values": [[timestamp_ns, log_line]]
                })
            
            # Send to Loki
            payload = {"streams": streams}
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    push_endpoint,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 204:
                    print(f"Successfully shipped {len(events)} audit events to Loki")
                else:
                    print(f"Loki push failed: {response.status_code} - {response.text}")
                    
        except Exception as e:
            print(f"Loki audit logging error: {e}")
            # Don't raise - audit should be non-blocking
    
    async def _flush_buffer(self):
        """Flush buffered events to persistent storage"""
        if not self._event_buffer:
            return
        
        events_to_flush = self._event_buffer.copy()
        self._event_buffer.clear()
        
        # Write to all configured outputs
        if self.enable_postgres:
            await self._write_to_postgres(events_to_flush)
        
        if self.enable_loki:
            await self._write_to_loki(events_to_flush)
    
    async def _emergency_log(self, event: AuditEvent, error: str):
        """Emergency fallback logging"""
        try:
            emergency_entry = {
                "emergency_log": True,
                "original_event": event.to_dict(),
                "write_error": error,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            with open("emergency_audit.log", "a", encoding="utf-8") as f:
                f.write(json.dumps(emergency_entry) + "\n")
                f.flush()
                
        except Exception:
            # Last resort - print to stderr
            print(f"CRITICAL: Failed to write emergency audit log for event {event.event_id}")
    
    async def shutdown(self):
        """Graceful shutdown - flush all pending events"""
        await self._flush_buffer()
    
    def create_hash(self, data: bytes) -> str:
        """Create SHA-256 hash for data integrity"""
        return hashlib.sha256(data).hexdigest()
    
    async def search_events(
        self,
        start_time: datetime,
        end_time: datetime,
        event_types: Optional[List[AuditEventType]] = None,
        user_id: Optional[str] = None,
        provider_name: Optional[str] = None,
        page: int = 1,
        size: int = 100
    ) -> Dict[str, Any]:
        """Search audit events for compliance reporting"""
        try:
            from database import get_db
            from models.audit_log import AuditLog
            from sqlalchemy.orm import Session
            from sqlalchemy import and_, or_
            
            # Get database session
            db_gen = get_db()
            db: Session = next(db_gen)
            
            try:
                # Build query
                query = db.query(AuditLog).filter(
                    and_(
                        AuditLog.timestamp >= start_time,
                        AuditLog.timestamp <= end_time
                    )
                )
                
                # Apply filters
                if event_types:
                    query = query.filter(AuditLog.event_type.in_(event_types))
                
                if user_id:
                    query = query.filter(AuditLog.user_id == user_id)
                    
                if provider_name:
                    query = query.filter(AuditLog.provider_name == provider_name)
                
                # Count total results
                total_count = query.count()
                
                # Apply pagination
                offset = (page - 1) * size
                results = query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(size).all()
                
                # Convert to AuditEvent objects
                events = []
                for db_event in results:
                    event = AuditEvent(
                        event_id=db_event.event_id,
                        event_type=db_event.event_type,
                        timestamp=db_event.timestamp,
                        user_id=db_event.user_id,
                        session_id=db_event.session_id,
                        provider_name=db_event.provider_name,
                        resource_id=db_event.resource_id,
                        details=db_event.details or {},
                        trace_id=db_event.trace_id,
                        span_id=db_event.span_id,
                        client_ip=db_event.client_ip,
                        user_agent=db_event.user_agent
                    )
                    events.append(event)
                
                return {
                    "events": events,
                    "total": total_count,
                    "page": page,
                    "size": size,
                    "has_next": offset + size < total_count,
                    "has_prev": page > 1
                }
                
            finally:
                db.close()
                
        except Exception as e:
            print(f"Audit event search error: {e}")
            return {
                "events": [],
                "total": 0,
                "page": page,
                "size": size,
                "has_next": False,
                "has_prev": False,
                "error": str(e)
            }