"""
Stripe API client for QES Platform billing
Production-ready Stripe integration with webhooks, error handling, and monitoring.
"""

import logging
import stripe
from decimal import Decimal
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

from .models import BillingPlan, Subscription, Invoice, Payment, DEFAULT_BILLING_PLANS
from .exceptions import (
    StripeException,
    PaymentFailedException,
    WebhookVerificationException
)
from .stripe_config import get_stripe_config


logger = logging.getLogger(__name__)


class StripeClient:
    """
    Production-ready Stripe API client for handling payments, subscriptions, and billing.
    
    Features:
    - Environment-aware configuration
    - Comprehensive error handling
    - Audit logging integration
    - Webhook signature verification
    - Retry logic with exponential backoff
    """
    
    def __init__(self, api_key: str = None, webhook_secret: str = None):
        """
        Initialize Stripe client
        
        Args:
            api_key: Stripe secret API key (optional, will use config if not provided)
            webhook_secret: Stripe webhook endpoint secret (optional, will use config if not provided)
        """
        # Load configuration
        self.config = get_stripe_config()
        
        # Use provided keys or fall back to configuration
        self.api_key = api_key or self.config.secret_key
        self.webhook_secret = webhook_secret or self.config.webhook_secret
        
        # Configure Stripe
        stripe.api_key = self.api_key
        stripe.api_version = self.config.api_version
        stripe.max_network_retries = self.config.max_retries
        
        logger.info(f"Stripe client initialized for {self.config.environment.value} environment")
    
    def create_customer(
        self,
        email: str,
        name: str = None,
        metadata: Dict[str, str] = None
    ) -> str:
        """
        Create a new Stripe customer
        
        Args:
            email: Customer email
            name: Customer name
            metadata: Additional metadata
            
        Returns:
            Stripe customer ID
            
        Raises:
            StripeException: If customer creation fails
        """
        try:
            customer_data = {
                "email": email,
                "metadata": metadata or {}
            }
            
            if name:
                customer_data["name"] = name
            
            customer = stripe.Customer.create(**customer_data)
            
            logger.info(f"Created Stripe customer: {customer.id}")
            return customer.id
            
        except stripe.error.StripeError as e:
            logger.error(f"Failed to create Stripe customer: {e}")
            raise StripeException(
                message=str(e),
                stripe_error_code=e.code,
                stripe_error_type=e.error.type if hasattr(e, 'error') else None
            )
    
    def create_product(self, plan: BillingPlan) -> str:
        """
        Create a Stripe product for a billing plan
        
        Args:
            plan: Billing plan configuration
            
        Returns:
            Stripe product ID
        """
        try:
            product = stripe.Product.create(
                name=plan.name,
                description=plan.description,
                metadata={
                    "plan_id": plan.id,
                    "plan_type": plan.type.value
                }
            )
            
            logger.info(f"Created Stripe product: {product.id} for plan: {plan.id}")
            return product.id
            
        except stripe.error.StripeError as e:
            logger.error(f"Failed to create Stripe product: {e}")
            raise StripeException(str(e))
    
    def create_price(
        self,
        product_id: str,
        amount: Decimal,
        currency: str,
        interval: str,
        nickname: str = None
    ) -> str:
        """
        Create a Stripe price for a product
        
        Args:
            product_id: Stripe product ID
            amount: Price amount
            currency: Currency code
            interval: Billing interval (month/year)
            nickname: Price nickname
            
        Returns:
            Stripe price ID
        """
        try:
            # Convert decimal to cents
            amount_cents = int(amount * 100)
            
            price = stripe.Price.create(
                product=product_id,
                unit_amount=amount_cents,
                currency=currency.lower(),
                recurring={"interval": interval},
                nickname=nickname
            )
            
            logger.info(f"Created Stripe price: {price.id}")
            return price.id
            
        except stripe.error.StripeError as e:
            logger.error(f"Failed to create Stripe price: {e}")
            raise StripeException(str(e))
    
    def create_subscription(
        self,
        customer_id: str,
        price_id: str,
        trial_period_days: int = None,
        metadata: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        Create a Stripe subscription
        
        Args:
            customer_id: Stripe customer ID
            price_id: Stripe price ID
            trial_period_days: Trial period in days
            metadata: Additional metadata
            
        Returns:
            Subscription data
        """
        try:
            subscription_data = {
                "customer": customer_id,
                "items": [{"price": price_id}],
                "metadata": metadata or {}
            }
            
            if trial_period_days:
                subscription_data["trial_period_days"] = trial_period_days
            
            subscription = stripe.Subscription.create(**subscription_data)
            
            logger.info(f"Created Stripe subscription: {subscription.id}")
            
            return {
                "id": subscription.id,
                "status": subscription.status,
                "current_period_start": datetime.fromtimestamp(
                    subscription.current_period_start
                ),
                "current_period_end": datetime.fromtimestamp(
                    subscription.current_period_end
                ),
                "trial_start": datetime.fromtimestamp(
                    subscription.trial_start
                ) if subscription.trial_start else None,
                "trial_end": datetime.fromtimestamp(
                    subscription.trial_end
                ) if subscription.trial_end else None,
                "cancel_at_period_end": subscription.cancel_at_period_end
            }
            
        except stripe.error.StripeError as e:
            logger.error(f"Failed to create Stripe subscription: {e}")
            raise StripeException(str(e))
    
    def cancel_subscription(
        self,
        subscription_id: str,
        at_period_end: bool = True
    ) -> Dict[str, Any]:
        """
        Cancel a Stripe subscription
        
        Args:
            subscription_id: Stripe subscription ID
            at_period_end: Whether to cancel at period end
            
        Returns:
            Updated subscription data
        """
        try:
            if at_period_end:
                subscription = stripe.Subscription.modify(
                    subscription_id,
                    cancel_at_period_end=True
                )
            else:
                subscription = stripe.Subscription.delete(subscription_id)
            
            logger.info(f"Canceled Stripe subscription: {subscription_id}")
            
            return {
                "id": subscription.id,
                "status": subscription.status,
                "cancel_at_period_end": subscription.cancel_at_period_end,
                "canceled_at": datetime.fromtimestamp(
                    subscription.canceled_at
                ) if subscription.canceled_at else None
            }
            
        except stripe.error.StripeError as e:
            logger.error(f"Failed to cancel Stripe subscription: {e}")
            raise StripeException(str(e))
    
    def create_payment_intent(
        self,
        amount: Decimal,
        currency: str,
        customer_id: str = None,
        metadata: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        Create a Stripe payment intent
        
        Args:
            amount: Payment amount
            currency: Currency code
            customer_id: Stripe customer ID
            metadata: Additional metadata
            
        Returns:
            Payment intent data
        """
        try:
            # Convert decimal to cents
            amount_cents = int(amount * 100)
            
            payment_intent_data = {
                "amount": amount_cents,
                "currency": currency.lower(),
                "metadata": metadata or {}
            }
            
            if customer_id:
                payment_intent_data["customer"] = customer_id
            
            payment_intent = stripe.PaymentIntent.create(**payment_intent_data)
            
            logger.info(f"Created payment intent: {payment_intent.id}")
            
            return {
                "id": payment_intent.id,
                "client_secret": payment_intent.client_secret,
                "status": payment_intent.status,
                "amount": Decimal(payment_intent.amount) / 100,
                "currency": payment_intent.currency.upper()
            }
            
        except stripe.error.StripeError as e:
            logger.error(f"Failed to create payment intent: {e}")
            raise StripeException(str(e))
    
    def retrieve_invoice(self, invoice_id: str) -> Dict[str, Any]:
        """
        Retrieve a Stripe invoice
        
        Args:
            invoice_id: Stripe invoice ID
            
        Returns:
            Invoice data
        """
        try:
            invoice = stripe.Invoice.retrieve(invoice_id)
            
            return {
                "id": invoice.id,
                "status": invoice.status,
                "amount_due": Decimal(invoice.amount_due) / 100,
                "amount_paid": Decimal(invoice.amount_paid) / 100,
                "currency": invoice.currency.upper(),
                "created": datetime.fromtimestamp(invoice.created),
                "due_date": datetime.fromtimestamp(
                    invoice.due_date
                ) if invoice.due_date else None,
                "paid_at": datetime.fromtimestamp(
                    invoice.status_transitions.paid_at
                ) if invoice.status_transitions.paid_at else None
            }
            
        except stripe.error.StripeError as e:
            logger.error(f"Failed to retrieve invoice: {e}")
            raise StripeException(str(e))
    
    def list_invoices(
        self,
        customer_id: str = None,
        subscription_id: str = None,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        List Stripe invoices
        
        Args:
            customer_id: Filter by customer ID
            subscription_id: Filter by subscription ID
            limit: Maximum number of invoices
            
        Returns:
            List of invoice data
        """
        try:
            params = {"limit": limit}
            
            if customer_id:
                params["customer"] = customer_id
            if subscription_id:
                params["subscription"] = subscription_id
            
            invoices = stripe.Invoice.list(**params)
            
            return [
                {
                    "id": invoice.id,
                    "status": invoice.status,
                    "amount_due": Decimal(invoice.amount_due) / 100,
                    "currency": invoice.currency.upper(),
                    "created": datetime.fromtimestamp(invoice.created)
                }
                for invoice in invoices.data
            ]
            
        except stripe.error.StripeError as e:
            logger.error(f"Failed to list invoices: {e}")
            raise StripeException(str(e))
    
    def verify_webhook_signature(
        self,
        payload: str,
        signature: str
    ) -> Dict[str, Any]:
        """
        Verify Stripe webhook signature and parse event
        
        Args:
            payload: Webhook payload
            signature: Stripe signature header
            
        Returns:
            Parsed webhook event
            
        Raises:
            WebhookVerificationException: If verification fails
        """
        if not self.webhook_secret:
            raise WebhookVerificationException(
                "Webhook secret not configured"
            )
        
        try:
            event = stripe.Webhook.construct_event(
                payload,
                signature,
                self.webhook_secret
            )
            
            logger.info(f"Verified webhook event: {event['type']}")
            return event
            
        except ValueError as e:
            logger.error(f"Invalid webhook payload: {e}")
            raise WebhookVerificationException("Invalid payload")
        except stripe.error.SignatureVerificationError as e:
            logger.error(f"Invalid webhook signature: {e}")
            raise WebhookVerificationException("Invalid signature")
    
    def setup_billing_plans(self) -> Dict[str, str]:
        """
        Setup default billing plans in Stripe
        
        Returns:
            Dictionary mapping plan IDs to Stripe product IDs
        """
        product_ids = {}
        
        for plan in DEFAULT_BILLING_PLANS:
            if plan.type == "free":
                # Skip creating Stripe products for free plans
                continue
                
            try:
                # Create product
                product_id = self.create_product(plan)
                product_ids[plan.id] = product_id
                
                # Create monthly price
                monthly_price_id = self.create_price(
                    product_id,
                    plan.price_monthly,
                    plan.currency,
                    "month",
                    f"{plan.name} Monthly"
                )
                
                # Create yearly price
                yearly_price_id = self.create_price(
                    product_id,
                    plan.price_yearly,
                    plan.currency,
                    "year",
                    f"{plan.name} Yearly"
                )
                
                logger.info(
                    f"Setup billing plan {plan.id}: "
                    f"product={product_id}, "
                    f"monthly={monthly_price_id}, "
                    f"yearly={yearly_price_id}"
                )
                
            except Exception as e:
                logger.error(f"Failed to setup billing plan {plan.id}: {e}")
                raise
        
        return product_ids