"""
Billing API Endpoints

Production-ready FastAPI endpoints for billing, subscriptions, and payment processing
with comprehensive Stripe webhook handling.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends, status, Request, Header
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from auth.jwt_auth import get_current_user
from models.user import User
from billing.stripe_client import StripeClient
from billing.webhook_handler import StripeWebhookHandler, create_webhook_handler
from billing.stripe_config import get_stripe_config, validate_stripe_setup
from billing.models import BillingPlan, Subscription, Invoice
from billing.subscription_manager import SubscriptionManager
from billing.usage_tracker import UsageTracker
from core.audit_logger import AuditLogger, AuditEvent, AuditEventType

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/billing", tags=["billing"])


class CreateSubscriptionRequest(BaseModel):
    """Request to create a new subscription"""
    plan_id: str = Field(..., description="Billing plan identifier")
    billing_cycle: str = Field("monthly", description="Billing cycle (monthly/yearly)")
    payment_method_id: Optional[str] = Field(None, description="Stripe payment method ID")
    customer_name: Optional[str] = Field(None, description="Customer name")


class UpdateSubscriptionRequest(BaseModel):
    """Request to update subscription"""
    plan_id: Optional[str] = Field(None, description="New plan ID")
    billing_cycle: Optional[str] = Field(None, description="New billing cycle")


class CreatePaymentIntentRequest(BaseModel):
    """Request to create payment intent"""
    amount: float = Field(..., description="Payment amount")
    currency: str = Field("usd", description="Currency code")
    description: Optional[str] = Field(None, description="Payment description")


class SubscriptionResponse(BaseModel):
    """Subscription response"""
    subscription_id: str
    plan_id: str
    status: str
    current_period_start: datetime
    current_period_end: datetime
    trial_start: Optional[datetime]
    trial_end: Optional[datetime]
    is_active: bool
    is_in_trial: bool


def get_billing_services():
    """Get billing service dependencies"""
    config = get_stripe_config()
    stripe_client = StripeClient()
    usage_tracker = UsageTracker()
    subscription_manager = SubscriptionManager(stripe_client, usage_tracker)
    return subscription_manager, usage_tracker


def get_audit_logger() -> AuditLogger:
    """Get audit logger instance"""
    return AuditLogger({
        "postgres_enabled": True,
        "loki_enabled": True
    })


@router.get("/config")
async def get_billing_config(
    current_user: User = Depends(get_current_user)
):
    """
    Get billing configuration and status.
    
    Returns Stripe configuration status and available features.
    """
    try:
        # Check if user has admin access for sensitive info
        include_sensitive = current_user.role == "admin"
        
        config = get_stripe_config()
        setup_validation = validate_stripe_setup()
        
        response = {
            "environment": config.environment.value,
            "is_production": config.is_production,
            "features": {
                "webhooks_enabled": config.enable_webhooks,
                "payment_intents_enabled": config.enable_payment_intents,
                "automatic_tax_enabled": config.enable_automatic_tax
            },
            "billing_settings": {
                "default_currency": config.default_currency,
                "trial_period_days": config.trial_period_days,
                "grace_period_days": config.grace_period_days
            },
            "setup_status": setup_validation
        }
        
        if include_sensitive:
            response["webhook_url"] = config.webhook_url
            response["publishable_key"] = config.publishable_key
        
        return response
        
    except Exception as e:
        logger.error(f"Failed to get billing config: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve billing configuration"
        )


@router.get("/plans")
async def get_billing_plans():
    """Get all available billing plans"""
    try:
        subscription_manager, _ = get_billing_services()
        plans = subscription_manager.get_billing_plans()
        
        return [
            {
                "id": plan.id,
                "name": plan.name,
                "type": plan.type.value,
                "description": plan.description,
                "price_monthly": float(plan.price_monthly),
                "price_yearly": float(plan.price_yearly),
                "currency": plan.currency,
                "features": plan.features,
                "limits": {
                    "signatures_included": plan.signatures_included,
                    "documents_included": plan.documents_included,
                    "api_calls_included": plan.api_calls_included,
                    "storage_gb_included": plan.storage_gb_included
                }
            }
            for plan in plans
        ]
        
    except Exception as e:
        logger.error(f"Failed to get billing plans: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve billing plans"
        )


@router.post("/subscription")
async def create_subscription(
    request: CreateSubscriptionRequest,
    current_user: User = Depends(get_current_user),
    audit_logger: AuditLogger = Depends(get_audit_logger)
):
    """Create a new subscription for the current user's tenant"""
    try:
        subscription_manager, _ = get_billing_services()
        
        # Create subscription
        subscription = subscription_manager.create_subscription(
            tenant_id=current_user.tenant_id,
            plan_id=request.plan_id,
            billing_cycle=request.billing_cycle,
            customer_email=current_user.email,
            customer_name=request.customer_name or f"{current_user.first_name} {current_user.last_name}"
        )
        
        # Log subscription creation
        await audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.SYSTEM_ERROR,  # Should be SUBSCRIPTION_CREATED
            user_id=str(current_user.id),
            details={
                "subscription_id": str(subscription.id),
                "plan_id": request.plan_id,
                "billing_cycle": request.billing_cycle,
                "tenant_id": str(current_user.tenant_id)
            }
        ))
        
        return SubscriptionResponse(
            subscription_id=str(subscription.id),
            plan_id=subscription.plan.id,
            status=subscription.status.value,
            current_period_start=subscription.current_period_start,
            current_period_end=subscription.current_period_end,
            trial_start=subscription.trial_start,
            trial_end=subscription.trial_end,
            is_active=subscription.is_active,
            is_in_trial=subscription.is_in_trial
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to create subscription: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create subscription"
        )


@router.get("/subscription")
async def get_current_subscription(
    current_user: User = Depends(get_current_user)
):
    """Get current subscription for the user's tenant"""
    try:
        subscription_manager, _ = get_billing_services()
        subscription = subscription_manager.get_tenant_subscription(current_user.tenant_id)
        
        if not subscription:
            return None
        
        return SubscriptionResponse(
            subscription_id=str(subscription.id),
            plan_id=subscription.plan.id,
            status=subscription.status.value,
            current_period_start=subscription.current_period_start,
            current_period_end=subscription.current_period_end,
            trial_start=subscription.trial_start,
            trial_end=subscription.trial_end,
            is_active=subscription.is_active,
            is_in_trial=subscription.is_in_trial
        )
        
    except Exception as e:
        logger.error(f"Failed to get subscription: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve subscription"
        )


@router.post("/payment-intent")
async def create_payment_intent(
    request: CreatePaymentIntentRequest,
    current_user: User = Depends(get_current_user),
    audit_logger: AuditLogger = Depends(get_audit_logger)
):
    """Create a Stripe payment intent for one-time payments"""
    try:
        stripe_client = StripeClient()
        
        payment_intent = stripe_client.create_payment_intent(
            amount=request.amount,
            currency=request.currency,
            metadata={
                "user_id": str(current_user.id),
                "tenant_id": str(current_user.tenant_id),
                "description": request.description or "QES Platform Payment"
            }
        )
        
        # Log payment intent creation
        await audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.SYSTEM_ERROR,  # Should be PAYMENT_INTENT_CREATED
            user_id=str(current_user.id),
            details={
                "payment_intent_id": payment_intent["id"],
                "amount": request.amount,
                "currency": request.currency
            }
        ))
        
        return {
            "payment_intent_id": payment_intent["id"],
            "client_secret": payment_intent["client_secret"],
            "amount": payment_intent["amount"],
            "currency": payment_intent["currency"],
            "status": payment_intent["status"]
        }
        
    except Exception as e:
        logger.error(f"Failed to create payment intent: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create payment intent"
        )


@router.post("/webhooks/stripe", response_class=PlainTextResponse)
async def handle_stripe_webhook(
    request: Request,
    stripe_signature: str = Header(None, alias="stripe-signature"),
    audit_logger: AuditLogger = Depends(get_audit_logger)
):
    """
    Handle Stripe webhook events.
    
    This endpoint receives and processes Stripe webhook events for
    subscription updates, payment notifications, and other billing events.
    """
    try:
        # Read raw body
        body = await request.body()
        payload = body.decode('utf-8')
        
        if not stripe_signature:
            logger.error("Missing Stripe signature header")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing stripe-signature header"
            )
        
        # Create webhook handler
        stripe_client = StripeClient()
        webhook_handler = create_webhook_handler(stripe_client)
        
        # Process webhook
        result = await webhook_handler.handle_webhook(payload, stripe_signature)
        
        logger.info(f"Webhook processed successfully: {result}")
        return "ok"
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Webhook processing failed: {e}")
        
        # Log webhook failure
        await audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.SYSTEM_ERROR,
            details={
                "error": "webhook_processing_failed",
                "message": str(e)
            }
        ))
        
        # Return 500 to trigger Stripe retry
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook processing failed"
        )


@router.get("/invoices")
async def get_invoices(
    limit: int = 10,
    current_user: User = Depends(get_current_user)
):
    """Get invoices for the current user's tenant"""
    try:
        subscription_manager, _ = get_billing_services()
        
        # Get tenant subscription to find Stripe customer
        subscription = subscription_manager.get_tenant_subscription(current_user.tenant_id)
        
        if not subscription or not subscription.stripe_customer_id:
            return []
        
        stripe_client = StripeClient()
        invoices = stripe_client.list_invoices(
            customer_id=subscription.stripe_customer_id,
            limit=limit
        )
        
        return invoices
        
    except Exception as e:
        logger.error(f"Failed to get invoices: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve invoices"
        )


@router.get("/usage")
async def get_current_usage(
    current_user: User = Depends(get_current_user)
):
    """Get current usage statistics for the tenant"""
    try:
        _, usage_tracker = get_billing_services()
        
        usage = usage_tracker.get_current_month_usage(current_user.tenant_id)
        
        return {
            "tenant_id": str(current_user.tenant_id),
            "current_month_usage": usage,
            "billing_period": {
                "start": datetime.utcnow().replace(day=1).isoformat(),
                "end": datetime.utcnow().isoformat()
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get usage: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve usage information"
        )


@router.post("/webhook-test")
async def test_webhook_configuration(
    current_user: User = Depends(get_current_user)
):
    """
    Test webhook configuration (admin only).
    
    Validates webhook URL accessibility and configuration.
    """
    try:
        if current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        
        validation = validate_stripe_setup()
        
        return {
            "webhook_validation": validation["webhook_validation"],
            "configuration_status": validation["configuration_status"],
            "required_events": validation["required_events"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Webhook test failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook test failed"
        )


@router.get("/health")
async def billing_service_health():
    """Health check for billing service"""
    try:
        config = get_stripe_config()
        setup_validation = validate_stripe_setup()
        
        # Test Stripe API connectivity
        stripe_client = StripeClient()
        
        # Simple API test - list products
        import stripe
        products = stripe.Product.list(limit=1)
        api_accessible = True
        
        is_healthy = (
            setup_validation["configuration_status"]["secret_key_configured"] and
            setup_validation["configuration_status"]["publishable_key_configured"] and
            api_accessible
        )
        
        return {
            "status": "healthy" if is_healthy else "degraded",
            "service": "billing",
            "environment": config.environment.value,
            "stripe_api_accessible": api_accessible,
            "configuration_valid": setup_validation["webhook_validation"]["valid"],
            "webhook_configured": setup_validation["configuration_status"]["webhook_secret_configured"]
        }
        
    except Exception as e:
        logger.error(f"Billing health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Billing service unhealthy: {str(e)}"
        )