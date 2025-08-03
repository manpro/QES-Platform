"""
Document Verification Webhooks

Webhook handlers for external document verification providers
(Onfido, Jumio, IDnow, Veriff) to receive asynchronous verification results.
"""

import logging
import json
import hmac
import hashlib
from typing import Dict, Any, Optional
from datetime import datetime

from fastapi import APIRouter, Request, HTTPException, status, Depends, Header
from pydantic import BaseModel
import httpx

from auth.jwt_auth import get_current_user_optional
from models.user import User
from core.audit_logger import AuditLogger, AuditEvent, AuditEventType
from core.external_document_verifiers import DocumentVerificationProvider

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/webhooks", tags=["webhooks"])

# Initialize audit logger
audit_logger = AuditLogger({
    "enable_postgres": True,
    "enable_loki": True,
    "enable_file": True
})


class WebhookEvent(BaseModel):
    """Base webhook event model"""
    event_type: str
    timestamp: datetime
    provider: str
    verification_id: str
    data: Dict[str, Any]


@router.post("/onfido")
async def onfido_webhook(
    request: Request,
    x_sha2_signature: Optional[str] = Header(None, alias="X-SHA2-Signature")
):
    """
    Onfido webhook handler for receiving verification results.
    
    Onfido sends webhooks for various events like check completion,
    report completion, and watchlist monitor matches.
    """
    
    try:
        # Get raw body for signature verification
        body = await request.body()
        
        # Verify webhook signature
        webhook_token = request.app.state.config.get("onfido", {}).get("webhook_token", "")
        if webhook_token and x_sha2_signature:
            expected_signature = hmac.new(
                webhook_token.encode(),
                body,
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(f"sha256={expected_signature}", x_sha2_signature):
                logger.warning("Onfido webhook signature verification failed")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid webhook signature"
                )
        
        # Parse webhook payload
        payload = json.loads(body.decode())
        
        event_type = payload.get("action")
        resource_type = payload.get("resource_type")
        object_data = payload.get("object", {})
        
        verification_id = object_data.get("id", "unknown")
        
        logger.info(f"Received Onfido webhook: {event_type} for {resource_type} {verification_id}")
        
        # Process different event types
        if event_type == "check.completed" and resource_type == "check":
            await _process_onfido_check_completed(object_data)
            
        elif event_type == "report.completed" and resource_type == "report":
            await _process_onfido_report_completed(object_data)
            
        elif event_type == "watchlist_monitor.matches_found":
            await _process_onfido_watchlist_match(object_data)
            
        else:
            logger.info(f"Unhandled Onfido webhook event: {event_type}")
        
        # Log webhook event
        await audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.EXTERNAL_API_CALL,
            user_id="system",
            details={
                "provider": "onfido",
                "event_type": event_type,
                "resource_type": resource_type,
                "verification_id": verification_id,
                "webhook_received": True
            }
        ))
        
        return {"status": "received"}
        
    except Exception as e:
        logger.error(f"Onfido webhook processing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook processing failed"
        )


@router.post("/jumio")
async def jumio_webhook(
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """
    Jumio webhook handler for receiving verification results.
    
    Jumio sends webhooks when transactions are completed,
    including successful verifications and fraud detections.
    """
    
    try:
        body = await request.body()
        
        # Verify Jumio webhook authentication
        webhook_secret = request.app.state.config.get("jumio", {}).get("webhook_secret", "")
        if webhook_secret and authorization:
            if authorization != f"Bearer {webhook_secret}":
                logger.warning("Jumio webhook authentication failed")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid webhook authentication"
                )
        
        # Parse webhook payload
        payload = json.loads(body.decode())
        
        event_type = payload.get("eventType")
        transaction_data = payload.get("transaction", {})
        verification_id = transaction_data.get("merchantIdScanReference", "unknown")
        
        logger.info(f"Received Jumio webhook: {event_type} for transaction {verification_id}")
        
        # Process different event types
        if event_type == "NETVERIFY_CALLBACK":
            await _process_jumio_netverify_callback(transaction_data)
            
        elif event_type == "DOCUMENT_VERIFICATION_CALLBACK":
            await _process_jumio_document_callback(transaction_data)
            
        else:
            logger.info(f"Unhandled Jumio webhook event: {event_type}")
        
        # Log webhook event
        await audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.EXTERNAL_API_CALL,
            user_id="system",
            details={
                "provider": "jumio",
                "event_type": event_type,
                "verification_id": verification_id,
                "transaction_status": transaction_data.get("status"),
                "webhook_received": True
            }
        ))
        
        return {"status": "received"}
        
    except Exception as e:
        logger.error(f"Jumio webhook processing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook processing failed"
        )


@router.post("/idnow")
async def idnow_webhook(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-KEY")
):
    """
    IDnow webhook handler for receiving identification results.
    
    IDnow sends webhooks for identification status changes,
    including successful completions and rejections.
    """
    
    try:
        body = await request.body()
        
        # Verify IDnow API key
        expected_api_key = request.app.state.config.get("idnow", {}).get("webhook_api_key", "")
        if expected_api_key and x_api_key != expected_api_key:
            logger.warning("IDnow webhook API key verification failed")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key"
            )
        
        # Parse webhook payload
        payload = json.loads(body.decode())
        
        event_type = payload.get("event")
        identification_data = payload.get("identification", {})
        verification_id = identification_data.get("transactionNumber", "unknown")
        
        logger.info(f"Received IDnow webhook: {event_type} for identification {verification_id}")
        
        # Process different event types
        if event_type == "IDENTIFICATION_SUCCESSFUL":
            await _process_idnow_successful(identification_data)
            
        elif event_type == "IDENTIFICATION_FAILED":
            await _process_idnow_failed(identification_data)
            
        elif event_type == "IDENTIFICATION_CANCELED":
            await _process_idnow_canceled(identification_data)
            
        else:
            logger.info(f"Unhandled IDnow webhook event: {event_type}")
        
        # Log webhook event
        await audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.EXTERNAL_API_CALL,
            user_id="system",
            details={
                "provider": "idnow",
                "event_type": event_type,
                "verification_id": verification_id,
                "result": identification_data.get("result"),
                "webhook_received": True
            }
        ))
        
        return {"status": "received"}
        
    except Exception as e:
        logger.error(f"IDnow webhook processing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook processing failed"
        )


@router.post("/veriff")
async def veriff_webhook(
    request: Request,
    x_auth_client: Optional[str] = Header(None, alias="X-AUTH-CLIENT"),
    x_hmac_signature: Optional[str] = Header(None, alias="X-HMAC-SIGNATURE"),
    x_auth_timestamp: Optional[str] = Header(None, alias="X-AUTH-TIMESTAMP")
):
    """
    Veriff webhook handler for receiving verification results.
    
    Veriff sends webhooks for verification decision updates,
    including approved, declined, and review decisions.
    """
    
    try:
        body = await request.body()
        
        # Verify Veriff HMAC signature
        api_key = request.app.state.config.get("veriff", {}).get("api_key", "")
        api_secret = request.app.state.config.get("veriff", {}).get("api_secret", "")
        
        if api_secret and x_hmac_signature and x_auth_timestamp:
            message = f"{x_auth_timestamp}{api_key}{body.decode()}"
            expected_signature = hmac.new(
                api_secret.encode(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(expected_signature, x_hmac_signature):
                logger.warning("Veriff webhook HMAC verification failed")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid HMAC signature"
                )
        
        # Parse webhook payload
        payload = json.loads(body.decode())
        
        verification_data = payload.get("verification", {})
        verification_id = verification_data.get("id", "unknown")
        status_value = verification_data.get("status")
        decision = verification_data.get("decision")
        
        logger.info(f"Received Veriff webhook for verification {verification_id}: status={status_value}, decision={decision}")
        
        # Process verification status updates
        if status_value == "approved":
            await _process_veriff_approved(verification_data)
            
        elif status_value == "declined":
            await _process_veriff_declined(verification_data)
            
        elif status_value == "review":
            await _process_veriff_review(verification_data)
            
        else:
            logger.info(f"Unhandled Veriff status: {status_value}")
        
        # Log webhook event
        await audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.EXTERNAL_API_CALL,
            user_id="system",
            details={
                "provider": "veriff",
                "verification_id": verification_id,
                "status": status_value,
                "decision": decision,
                "webhook_received": True
            }
        ))
        
        return {"status": "received"}
        
    except Exception as e:
        logger.error(f"Veriff webhook processing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook processing failed"
        )


# Webhook processing functions

async def _process_onfido_check_completed(check_data: Dict[str, Any]):
    """Process Onfido check completion"""
    
    check_id = check_data.get("id")
    status_value = check_data.get("status")
    result = check_data.get("result")
    
    logger.info(f"Onfido check {check_id} completed: status={status_value}, result={result}")
    
    # Update internal verification record
    # Implementation would update database with final results
    
    # Trigger any necessary follow-up actions
    if result == "clear":
        # Verification successful - continue with signing workflow
        await _trigger_signing_workflow_continuation(check_id, "onfido")
    elif result in ["consider", "unidentified"]:
        # Manual review required or verification failed
        await _trigger_manual_review(check_id, "onfido", result)


async def _process_onfido_report_completed(report_data: Dict[str, Any]):
    """Process Onfido report completion"""
    
    report_id = report_data.get("id")
    name = report_data.get("name")
    result = report_data.get("result")
    
    logger.info(f"Onfido report {report_id} ({name}) completed: result={result}")
    
    # Process specific report types
    if name == "document":
        # Document verification report completed
        await _update_document_verification_status(report_id, result, "onfido")
    elif name == "facial_similarity":
        # Face comparison report completed
        await _update_face_verification_status(report_id, result, "onfido")


async def _process_onfido_watchlist_match(match_data: Dict[str, Any]):
    """Process Onfido watchlist match"""
    
    monitor_id = match_data.get("id")
    matches = match_data.get("matches", [])
    
    logger.warning(f"Onfido watchlist matches found for monitor {monitor_id}: {len(matches)} matches")
    
    # Handle PEP/sanctions matches
    for match in matches:
        match_type = match.get("match_types", [])
        person_name = match.get("person", {}).get("name")
        
        await audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.COMPLIANCE_ALERT,
            user_id="system",
            details={
                "alert_type": "watchlist_match",
                "provider": "onfido",
                "monitor_id": monitor_id,
                "match_types": match_type,
                "person_name": person_name,
                "severity": "high"
            }
        ))


async def _process_jumio_netverify_callback(transaction_data: Dict[str, Any]):
    """Process Jumio Netverify callback"""
    
    transaction_id = transaction_data.get("merchantIdScanReference")
    status_value = transaction_data.get("verificationStatus")
    
    logger.info(f"Jumio Netverify callback for {transaction_id}: status={status_value}")
    
    if status_value == "APPROVED_VERIFIED":
        await _trigger_signing_workflow_continuation(transaction_id, "jumio")
    elif status_value == "DENIED_FRAUD":
        await _trigger_fraud_alert(transaction_id, "jumio", transaction_data)
    elif status_value == "ERROR_NOT_READABLE_ID":
        await _trigger_manual_review(transaction_id, "jumio", "document_not_readable")


async def _process_jumio_document_callback(document_data: Dict[str, Any]):
    """Process Jumio document verification callback"""
    
    transaction_id = document_data.get("merchantIdScanReference")
    extraction_method = document_data.get("extractionMethod")
    
    logger.info(f"Jumio document callback for {transaction_id}: extraction={extraction_method}")
    
    # Update document extraction results
    await _update_document_extraction_results(transaction_id, document_data, "jumio")


async def _process_idnow_successful(identification_data: Dict[str, Any]):
    """Process IDnow successful identification"""
    
    transaction_number = identification_data.get("transactionNumber")
    result = identification_data.get("result")
    
    logger.info(f"IDnow identification {transaction_number} successful: result={result}")
    
    await _trigger_signing_workflow_continuation(transaction_number, "idnow")


async def _process_idnow_failed(identification_data: Dict[str, Any]):
    """Process IDnow failed identification"""
    
    transaction_number = identification_data.get("transactionNumber")
    reason = identification_data.get("reason")
    
    logger.info(f"IDnow identification {transaction_number} failed: reason={reason}")
    
    await _trigger_manual_review(transaction_number, "idnow", reason)


async def _process_idnow_canceled(identification_data: Dict[str, Any]):
    """Process IDnow canceled identification"""
    
    transaction_number = identification_data.get("transactionNumber")
    
    logger.info(f"IDnow identification {transaction_number} was canceled by user")
    
    # Handle user-canceled verification
    await _handle_verification_cancellation(transaction_number, "idnow")


async def _process_veriff_approved(verification_data: Dict[str, Any]):
    """Process Veriff approved verification"""
    
    verification_id = verification_data.get("id")
    
    logger.info(f"Veriff verification {verification_id} approved")
    
    await _trigger_signing_workflow_continuation(verification_id, "veriff")


async def _process_veriff_declined(verification_data: Dict[str, Any]):
    """Process Veriff declined verification"""
    
    verification_id = verification_data.get("id")
    reason = verification_data.get("reason")
    
    logger.info(f"Veriff verification {verification_id} declined: reason={reason}")
    
    await _trigger_manual_review(verification_id, "veriff", reason)


async def _process_veriff_review(verification_data: Dict[str, Any]):
    """Process Veriff review required"""
    
    verification_id = verification_data.get("id")
    
    logger.info(f"Veriff verification {verification_id} requires manual review")
    
    await _trigger_manual_review(verification_id, "veriff", "manual_review_required")


# Helper functions

async def _trigger_signing_workflow_continuation(verification_id: str, provider: str):
    """Trigger continuation of signing workflow after successful verification"""
    
    logger.info(f"Triggering signing workflow continuation for {verification_id} from {provider}")
    
    # Implementation would:
    # 1. Update verification status in database
    # 2. Notify user of successful verification
    # 3. Continue with certificate issuance/signing process
    # 4. Send success notification
    
    await audit_logger.log_event(AuditEvent(
        event_type=AuditEventType.WORKFLOW_STEP_COMPLETED,
        user_id="system",
        details={
            "workflow": "document_verification",
            "step": "verification_completed",
            "provider": provider,
            "verification_id": verification_id,
            "result": "success"
        }
    ))


async def _trigger_manual_review(verification_id: str, provider: str, reason: str):
    """Trigger manual review process"""
    
    logger.info(f"Triggering manual review for {verification_id} from {provider}: {reason}")
    
    # Implementation would:
    # 1. Flag verification for manual review
    # 2. Notify compliance team
    # 3. Update user about review status
    # 4. Set appropriate timeouts
    
    await audit_logger.log_event(AuditEvent(
        event_type=AuditEventType.COMPLIANCE_ALERT,
        user_id="system",
        details={
            "alert_type": "manual_review_required",
            "provider": provider,
            "verification_id": verification_id,
            "reason": reason,
            "severity": "medium"
        }
    ))


async def _trigger_fraud_alert(verification_id: str, provider: str, data: Dict[str, Any]):
    """Trigger fraud alert"""
    
    logger.warning(f"FRAUD ALERT: {verification_id} from {provider}")
    
    # Implementation would:
    # 1. Immediately flag account for fraud review
    # 2. Block any further verification attempts
    # 3. Alert security team
    # 4. Log detailed fraud indicators
    
    await audit_logger.log_event(AuditEvent(
        event_type=AuditEventType.SECURITY_ALERT,
        user_id="system",
        details={
            "alert_type": "fraud_detected",
            "provider": provider,
            "verification_id": verification_id,
            "fraud_indicators": data,
            "severity": "critical"
        }
    ))


async def _update_document_verification_status(verification_id: str, result: str, provider: str):
    """Update document verification status in database"""
    
    logger.info(f"Updating document verification status: {verification_id} -> {result}")
    
    # Implementation would update database record with final status


async def _update_face_verification_status(verification_id: str, result: str, provider: str):
    """Update face verification status in database"""
    
    logger.info(f"Updating face verification status: {verification_id} -> {result}")
    
    # Implementation would update database record with face verification result


async def _update_document_extraction_results(verification_id: str, data: Dict[str, Any], provider: str):
    """Update document extraction results in database"""
    
    logger.info(f"Updating document extraction results for {verification_id}")
    
    # Implementation would store extracted document data


async def _handle_verification_cancellation(verification_id: str, provider: str):
    """Handle user cancellation of verification"""
    
    logger.info(f"Handling verification cancellation: {verification_id}")
    
    # Implementation would:
    # 1. Update status to canceled
    # 2. Clean up any temporary data
    # 3. Notify user about cancellation options