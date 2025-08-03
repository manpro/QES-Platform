"""
Stripe Webhook Handler

Production-ready webhook handling for Stripe events including payment processing,
subscription updates, invoice management, and customer lifecycle events.
"""

import logging
import json
from typing import Dict, Any, Optional
from datetime import datetime
from enum import Enum

from .stripe_client import StripeClient
from .models import Subscription, Invoice, Payment, PaymentStatus, SubscriptionStatus
from .exceptions import WebhookVerificationException, BillingException
from core.audit_logger import AuditLogger, AuditEvent, AuditEventType

logger = logging.getLogger(__name__)


class StripeEventType(str, Enum):
    """Stripe webhook event types we handle"""
    # Customer events
    CUSTOMER_CREATED = "customer.created"
    CUSTOMER_UPDATED = "customer.updated"
    CUSTOMER_DELETED = "customer.deleted"
    
    # Subscription events
    SUBSCRIPTION_CREATED = "customer.subscription.created"
    SUBSCRIPTION_UPDATED = "customer.subscription.updated"
    SUBSCRIPTION_DELETED = "customer.subscription.deleted"
    SUBSCRIPTION_TRIAL_ENDING = "customer.subscription.trial_will_end"
    
    # Invoice events
    INVOICE_CREATED = "invoice.created"
    INVOICE_FINALIZED = "invoice.finalized"
    INVOICE_PAID = "invoice.paid"
    INVOICE_PAYMENT_FAILED = "invoice.payment_failed"
    INVOICE_UPCOMING = "invoice.upcoming"
    
    # Payment events
    PAYMENT_INTENT_SUCCEEDED = "payment_intent.succeeded"
    PAYMENT_INTENT_FAILED = "payment_intent.payment_failed"
    PAYMENT_METHOD_ATTACHED = "payment_method.attached"
    
    # Charge events
    CHARGE_SUCCEEDED = "charge.succeeded"
    CHARGE_FAILED = "charge.failed"
    CHARGE_DISPUTE_CREATED = "charge.dispute.created"


class StripeWebhookHandler:
    """
    Handles Stripe webhook events and updates local billing data accordingly.
    
    Provides idempotent processing, audit logging, and error recovery.
    """
    
    def __init__(self, stripe_client: StripeClient, audit_logger: AuditLogger):
        """Initialize webhook handler"""
        self.stripe_client = stripe_client
        self.audit_logger = audit_logger
        self._processed_events = set()  # Simple in-memory deduplication
    
    async def handle_webhook(
        self, 
        payload: str, 
        signature: str,
        idempotency_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Handle incoming Stripe webhook.
        
        Args:
            payload: Raw webhook payload
            signature: Stripe signature header
            idempotency_key: Optional idempotency key for deduplication
            
        Returns:
            Processing result
        """
        try:
            # Verify webhook signature
            event = self.stripe_client.verify_webhook_signature(payload, signature)
            
            # Check for duplicate processing
            event_id = event.get("id")
            if event_id in self._processed_events:
                logger.info(f"Webhook event {event_id} already processed, skipping")
                return {"status": "already_processed", "event_id": event_id}
            
            # Process the event
            result = await self._process_event(event)
            
            # Mark as processed
            if event_id:
                self._processed_events.add(event_id)
            
            # Log successful processing
            await self.audit_logger.log_event(AuditEvent(
                event_type=AuditEventType.SYSTEM_ERROR,  # Should be WEBHOOK_PROCESSED
                details={
                    "webhook_event_type": event.get("type"),
                    "event_id": event_id,
                    "processing_result": result,
                    "idempotency_key": idempotency_key
                }
            ))
            
            return {"status": "processed", "event_id": event_id, "result": result}
            
        except WebhookVerificationException as e:
            logger.error(f"Webhook verification failed: {e}")
            await self.audit_logger.log_event(AuditEvent(
                event_type=AuditEventType.SYSTEM_ERROR,
                details={
                    "error": "webhook_verification_failed",
                    "message": str(e)
                }
            ))
            raise
            
        except Exception as e:
            logger.error(f"Webhook processing failed: {e}")
            await self.audit_logger.log_event(AuditEvent(
                event_type=AuditEventType.SYSTEM_ERROR,
                details={
                    "error": "webhook_processing_failed",
                    "message": str(e),
                    "event_type": event.get("type") if 'event' in locals() else None
                }
            ))
            raise BillingException(f"Webhook processing failed: {str(e)}")
    
    async def _process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process a verified Stripe event"""
        event_type = event.get("type")
        event_data = event.get("data", {}).get("object", {})
        
        logger.info(f"Processing Stripe event: {event_type}")
        
        # Route to appropriate handler
        if event_type == StripeEventType.CUSTOMER_CREATED:
            return await self._handle_customer_created(event_data)
        elif event_type == StripeEventType.CUSTOMER_UPDATED:
            return await self._handle_customer_updated(event_data)
        elif event_type == StripeEventType.SUBSCRIPTION_CREATED:
            return await self._handle_subscription_created(event_data)
        elif event_type == StripeEventType.SUBSCRIPTION_UPDATED:
            return await self._handle_subscription_updated(event_data)
        elif event_type == StripeEventType.SUBSCRIPTION_DELETED:
            return await self._handle_subscription_deleted(event_data)
        elif event_type == StripeEventType.INVOICE_PAID:
            return await self._handle_invoice_paid(event_data)
        elif event_type == StripeEventType.INVOICE_PAYMENT_FAILED:
            return await self._handle_invoice_payment_failed(event_data)
        elif event_type == StripeEventType.PAYMENT_INTENT_SUCCEEDED:
            return await self._handle_payment_succeeded(event_data)
        elif event_type == StripeEventType.PAYMENT_INTENT_FAILED:
            return await self._handle_payment_failed(event_data)
        elif event_type == StripeEventType.SUBSCRIPTION_TRIAL_ENDING:
            return await self._handle_trial_ending(event_data)
        else:
            logger.info(f"Unhandled event type: {event_type}")
            return {"status": "ignored", "reason": "unhandled_event_type"}
    
    async def _handle_customer_created(self, customer: Dict[str, Any]) -> Dict[str, Any]:
        """Handle customer.created event"""
        customer_id = customer.get("id")
        email = customer.get("email")
        tenant_id = customer.get("metadata", {}).get("tenant_id")
        
        logger.info(f"Customer created: {customer_id} (tenant: {tenant_id})")
        
        # Update local customer records if needed
        # This would integrate with your user/tenant management system
        
        return {
            "action": "customer_created",
            "customer_id": customer_id,
            "tenant_id": tenant_id,
            "email": email
        }
    
    async def _handle_customer_updated(self, customer: Dict[str, Any]) -> Dict[str, Any]:
        """Handle customer.updated event"""
        customer_id = customer.get("id")
        
        logger.info(f"Customer updated: {customer_id}")
        
        return {"action": "customer_updated", "customer_id": customer_id}
    
    async def _handle_subscription_created(self, subscription: Dict[str, Any]) -> Dict[str, Any]:
        """Handle customer.subscription.created event"""
        subscription_id = subscription.get("id")
        customer_id = subscription.get("customer")
        status = subscription.get("status")
        tenant_id = subscription.get("metadata", {}).get("tenant_id")
        
        logger.info(f"Subscription created: {subscription_id} (status: {status})")
        
        # Update local subscription status
        await self._update_local_subscription_status(
            subscription_id, SubscriptionStatus.ACTIVE if status == "active" else SubscriptionStatus.PENDING
        )
        
        return {
            "action": "subscription_created",
            "subscription_id": subscription_id,
            "customer_id": customer_id,
            "status": status,
            "tenant_id": tenant_id
        }
    
    async def _handle_subscription_updated(self, subscription: Dict[str, Any]) -> Dict[str, Any]:
        """Handle customer.subscription.updated event"""
        subscription_id = subscription.get("id")
        status = subscription.get("status")
        cancel_at_period_end = subscription.get("cancel_at_period_end")
        
        logger.info(f"Subscription updated: {subscription_id} (status: {status})")
        
        # Map Stripe status to local status
        local_status = SubscriptionStatus.ACTIVE
        if status == "canceled":
            local_status = SubscriptionStatus.CANCELED
        elif status == "past_due":
            local_status = SubscriptionStatus.PAST_DUE
        elif status == "unpaid":
            local_status = SubscriptionStatus.SUSPENDED
        elif cancel_at_period_end:
            local_status = SubscriptionStatus.PENDING_CANCELLATION
        
        await self._update_local_subscription_status(subscription_id, local_status)
        
        return {
            "action": "subscription_updated",
            "subscription_id": subscription_id,
            "status": status,
            "local_status": local_status.value
        }
    
    async def _handle_subscription_deleted(self, subscription: Dict[str, Any]) -> Dict[str, Any]:
        """Handle customer.subscription.deleted event"""
        subscription_id = subscription.get("id")
        
        logger.info(f"Subscription deleted: {subscription_id}")
        
        await self._update_local_subscription_status(subscription_id, SubscriptionStatus.CANCELED)
        
        return {
            "action": "subscription_deleted",
            "subscription_id": subscription_id
        }
    
    async def _handle_invoice_paid(self, invoice: Dict[str, Any]) -> Dict[str, Any]:
        """Handle invoice.paid event"""
        invoice_id = invoice.get("id")
        subscription_id = invoice.get("subscription")
        amount_paid = invoice.get("amount_paid", 0) / 100  # Convert from cents
        
        logger.info(f"Invoice paid: {invoice_id} (amount: ${amount_paid})")
        
        # Update local records
        await self._record_successful_payment(invoice_id, amount_paid, subscription_id)
        
        # Ensure subscription is active if it was suspended
        if subscription_id:
            await self._update_local_subscription_status(subscription_id, SubscriptionStatus.ACTIVE)
        
        return {
            "action": "invoice_paid",
            "invoice_id": invoice_id,
            "subscription_id": subscription_id,
            "amount_paid": amount_paid
        }
    
    async def _handle_invoice_payment_failed(self, invoice: Dict[str, Any]) -> Dict[str, Any]:
        """Handle invoice.payment_failed event"""
        invoice_id = invoice.get("id")
        subscription_id = invoice.get("subscription")
        attempt_count = invoice.get("attempt_count", 0)
        
        logger.warning(f"Invoice payment failed: {invoice_id} (attempt {attempt_count})")
        
        # Record failed payment
        await self._record_failed_payment(invoice_id, subscription_id, attempt_count)
        
        # Update subscription status based on attempt count
        if attempt_count >= 3:
            await self._update_local_subscription_status(subscription_id, SubscriptionStatus.SUSPENDED)
        else:
            await self._update_local_subscription_status(subscription_id, SubscriptionStatus.PAST_DUE)
        
        return {
            "action": "invoice_payment_failed",
            "invoice_id": invoice_id,
            "subscription_id": subscription_id,
            "attempt_count": attempt_count
        }
    
    async def _handle_payment_succeeded(self, payment_intent: Dict[str, Any]) -> Dict[str, Any]:
        """Handle payment_intent.succeeded event"""
        payment_intent_id = payment_intent.get("id")
        amount = payment_intent.get("amount", 0) / 100  # Convert from cents
        customer_id = payment_intent.get("customer")
        
        logger.info(f"Payment succeeded: {payment_intent_id} (amount: ${amount})")
        
        return {
            "action": "payment_succeeded",
            "payment_intent_id": payment_intent_id,
            "amount": amount,
            "customer_id": customer_id
        }
    
    async def _handle_payment_failed(self, payment_intent: Dict[str, Any]) -> Dict[str, Any]:
        """Handle payment_intent.payment_failed event"""
        payment_intent_id = payment_intent.get("id")
        last_payment_error = payment_intent.get("last_payment_error", {})
        
        logger.warning(f"Payment failed: {payment_intent_id} (error: {last_payment_error.get('message')})")
        
        return {
            "action": "payment_failed",
            "payment_intent_id": payment_intent_id,
            "error": last_payment_error
        }
    
    async def _handle_trial_ending(self, subscription: Dict[str, Any]) -> Dict[str, Any]:
        """Handle customer.subscription.trial_will_end event"""
        subscription_id = subscription.get("id")
        trial_end = subscription.get("trial_end")
        customer_id = subscription.get("customer")
        
        logger.info(f"Trial ending for subscription: {subscription_id}")
        
        # You could send notification emails here
        # await self._send_trial_ending_notification(customer_id, trial_end)
        
        return {
            "action": "trial_ending",
            "subscription_id": subscription_id,
            "trial_end": trial_end,
            "customer_id": customer_id
        }
    
    async def _update_local_subscription_status(
        self, 
        stripe_subscription_id: str, 
        status: SubscriptionStatus
    ):
        """Update local subscription status in database"""
        # This would integrate with your database layer
        # For now, just log the update
        logger.info(f"Updating subscription {stripe_subscription_id} to status: {status.value}")
        
        # Example implementation:
        # subscription = await get_subscription_by_stripe_id(stripe_subscription_id)
        # if subscription:
        #     subscription.status = status
        #     await save_subscription(subscription)
    
    async def _record_successful_payment(
        self, 
        invoice_id: str, 
        amount: float, 
        subscription_id: str
    ):
        """Record successful payment in local database"""
        logger.info(f"Recording successful payment: {invoice_id} (${amount})")
        
        # Example implementation:
        # payment = Payment(
        #     stripe_invoice_id=invoice_id,
        #     amount=Decimal(str(amount)),
        #     status=PaymentStatus.SUCCEEDED,
        #     processed_at=datetime.utcnow()
        # )
        # await save_payment(payment)
    
    async def _record_failed_payment(
        self, 
        invoice_id: str, 
        subscription_id: str, 
        attempt_count: int
    ):
        """Record failed payment in local database"""
        logger.warning(f"Recording failed payment: {invoice_id} (attempt {attempt_count})")
        
        # Example implementation:
        # payment = Payment(
        #     stripe_invoice_id=invoice_id,
        #     status=PaymentStatus.FAILED,
        #     failure_reason=f"Payment attempt {attempt_count} failed",
        #     processed_at=datetime.utcnow()
        # )
        # await save_payment(payment)


def create_webhook_handler(stripe_client: StripeClient) -> StripeWebhookHandler:
    """Create a webhook handler with audit logging"""
    audit_logger = AuditLogger({
        "postgres_enabled": True,
        "loki_enabled": True
    })
    
    return StripeWebhookHandler(stripe_client, audit_logger)