"""
Subscription management for QES Platform
"""

import logging
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from ..database import get_db_connection
from ..middleware.tenant_resolver import get_current_tenant
from .models import (
    BillingPlan, 
    Subscription, 
    SubscriptionStatus, 
    Invoice,
    DEFAULT_BILLING_PLANS
)
from .stripe_client import StripeClient
from .usage_tracker import UsageTracker
from .exceptions import (
    SubscriptionNotFoundException,
    InvalidBillingPlanException,
    PlanLimitExceededException
)


logger = logging.getLogger(__name__)


class SubscriptionManager:
    """
    Manages tenant subscriptions and billing plans
    """
    
    def __init__(self, stripe_client: StripeClient, usage_tracker: UsageTracker):
        """
        Initialize subscription manager
        
        Args:
            stripe_client: Stripe API client
            usage_tracker: Usage tracking service
        """
        self.stripe_client = stripe_client
        self.usage_tracker = usage_tracker
        
    def get_billing_plans(self) -> List[BillingPlan]:
        """
        Get all available billing plans
        
        Returns:
            List of billing plans
        """
        return DEFAULT_BILLING_PLANS.copy()
    
    def get_billing_plan(self, plan_id: str) -> BillingPlan:
        """
        Get a specific billing plan
        
        Args:
            plan_id: Plan identifier
            
        Returns:
            Billing plan
            
        Raises:
            InvalidBillingPlanException: If plan not found
        """
        for plan in DEFAULT_BILLING_PLANS:
            if plan.id == plan_id:
                return plan
        
        raise InvalidBillingPlanException(plan_id)
    
    def create_subscription(
        self,
        tenant_id: UUID,
        plan_id: str,
        billing_cycle: str = "monthly",
        trial_days: int = None,
        customer_email: str = None,
        customer_name: str = None
    ) -> Subscription:
        """
        Create a new subscription for a tenant
        
        Args:
            tenant_id: Tenant identifier
            plan_id: Billing plan ID
            billing_cycle: "monthly" or "yearly"
            trial_days: Trial period in days
            customer_email: Customer email for Stripe
            customer_name: Customer name for Stripe
            
        Returns:
            Created subscription
            
        Raises:
            InvalidBillingPlanException: If plan not found
        """
        plan = self.get_billing_plan(plan_id)
        
        # Check if tenant already has a subscription
        existing_subscription = self.get_tenant_subscription(tenant_id)
        if existing_subscription and existing_subscription.is_active:
            raise ValueError(f"Tenant {tenant_id} already has an active subscription")
        
        subscription_id = uuid4()
        now = datetime.utcnow()
        
        # Calculate billing period
        if billing_cycle == "monthly":
            period_end = now + timedelta(days=30)
        else:  # yearly
            period_end = now + timedelta(days=365)
        
        # Handle trial period
        trial_start = None
        trial_end = None
        if trial_days and trial_days > 0:
            trial_start = now
            trial_end = now + timedelta(days=trial_days)
            # Extend billing period after trial
            period_end = trial_end + (period_end - now)
        
        # Create Stripe customer and subscription for paid plans
        stripe_customer_id = None
        stripe_subscription_id = None
        
        if plan.type != "free" and self.stripe_client:
            try:
                # Create Stripe customer
                stripe_customer_id = self.stripe_client.create_customer(
                    email=customer_email or f"tenant-{tenant_id}@qes-platform.com",
                    name=customer_name,
                    metadata={
                        "tenant_id": str(tenant_id),
                        "plan_id": plan_id
                    }
                )
                
                # Get appropriate price ID based on billing cycle
                price_id = (plan.stripe_price_monthly_id if billing_cycle == "monthly" 
                           else plan.stripe_price_yearly_id)
                
                if price_id:
                    # Create Stripe subscription
                    stripe_subscription = self.stripe_client.create_subscription(
                        customer_id=stripe_customer_id,
                        price_id=price_id,
                        trial_period_days=trial_days,
                        metadata={
                            "tenant_id": str(tenant_id),
                            "subscription_id": str(subscription_id)
                        }
                    )
                    stripe_subscription_id = stripe_subscription["id"]
                    
            except Exception as e:
                logger.error(f"Failed to create Stripe subscription: {e}")
                # Continue with local subscription creation
                # Stripe integration is optional for development
        
        # Create subscription record
        subscription = Subscription(
            id=subscription_id,
            tenant_id=tenant_id,
            plan=plan,
            status=SubscriptionStatus.TRIALING if trial_days else SubscriptionStatus.ACTIVE,
            billing_cycle=billing_cycle,
            current_period_start=now,
            current_period_end=period_end,
            trial_start=trial_start,
            trial_end=trial_end,
            stripe_subscription_id=stripe_subscription_id,
            stripe_customer_id=stripe_customer_id,
            created_at=now,
            updated_at=now
        )
        
        # Store subscription in database
        self._save_subscription(subscription)
        
        logger.info(f"Created subscription {subscription_id} for tenant {tenant_id}")
        return subscription
    
    def get_tenant_subscription(self, tenant_id: UUID) -> Optional[Subscription]:
        """
        Get the current subscription for a tenant
        
        Args:
            tenant_id: Tenant identifier
            
        Returns:
            Subscription if found, None otherwise
        """
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, tenant_id, plan_id, status, billing_cycle,
                       current_period_start, current_period_end,
                       trial_start, trial_end, cancel_at_period_end,
                       canceled_at, stripe_subscription_id, stripe_customer_id,
                       created_at, updated_at, metadata
                FROM subscriptions 
                WHERE tenant_id = %s AND status NOT IN ('canceled')
                ORDER BY created_at DESC
                LIMIT 1
            """, (str(tenant_id),))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            # Get billing plan
            plan = self.get_billing_plan(row[2])  # plan_id
            
            return Subscription(
                id=UUID(row[0]),
                tenant_id=UUID(row[1]),
                plan=plan,
                status=SubscriptionStatus(row[3]),
                billing_cycle=row[4],
                current_period_start=row[5],
                current_period_end=row[6],
                trial_start=row[7],
                trial_end=row[8],
                cancel_at_period_end=row[9],
                canceled_at=row[10],
                stripe_subscription_id=row[11],
                stripe_customer_id=row[12],
                created_at=row[13],
                updated_at=row[14],
                metadata=row[15] or {}
            )
    
    def update_subscription_plan(
        self,
        tenant_id: UUID,
        new_plan_id: str,
        prorate: bool = True
    ) -> Subscription:
        """
        Update subscription to a new plan
        
        Args:
            tenant_id: Tenant identifier
            new_plan_id: New billing plan ID
            prorate: Whether to prorate the change
            
        Returns:
            Updated subscription
        """
        subscription = self.get_tenant_subscription(tenant_id)
        if not subscription:
            raise SubscriptionNotFoundException(str(tenant_id))
        
        new_plan = self.get_billing_plan(new_plan_id)
        
        # Update Stripe subscription if applicable
        if subscription.stripe_subscription_id and self.stripe_client:
            try:
                # This would update the Stripe subscription
                # Implementation depends on specific Stripe integration needs
                pass
            except Exception as e:
                logger.error(f"Failed to update Stripe subscription: {e}")
        
        # Update local subscription
        subscription.plan = new_plan
        subscription.updated_at = datetime.utcnow()
        
        self._save_subscription(subscription)
        
        logger.info(f"Updated subscription {subscription.id} to plan {new_plan_id}")
        return subscription
    
    def cancel_subscription(
        self,
        tenant_id: UUID,
        at_period_end: bool = True,
        reason: str = None
    ) -> Subscription:
        """
        Cancel a subscription
        
        Args:
            tenant_id: Tenant identifier
            at_period_end: Whether to cancel at period end
            reason: Cancellation reason
            
        Returns:
            Updated subscription
        """
        subscription = self.get_tenant_subscription(tenant_id)
        if not subscription:
            raise SubscriptionNotFoundException(str(tenant_id))
        
        # Cancel Stripe subscription if applicable
        if subscription.stripe_subscription_id and self.stripe_client:
            try:
                self.stripe_client.cancel_subscription(
                    subscription.stripe_subscription_id,
                    at_period_end=at_period_end
                )
            except Exception as e:
                logger.error(f"Failed to cancel Stripe subscription: {e}")
        
        # Update local subscription
        now = datetime.utcnow()
        if at_period_end:
            subscription.cancel_at_period_end = True
        else:
            subscription.status = SubscriptionStatus.CANCELED
            subscription.canceled_at = now
        
        subscription.updated_at = now
        
        # Add cancellation reason to metadata
        if reason:
            subscription.metadata["cancellation_reason"] = reason
            subscription.metadata["canceled_by"] = "user"  # or system/admin
        
        self._save_subscription(subscription)
        
        logger.info(f"Canceled subscription {subscription.id}")
        return subscription
    
    def check_usage_limits(
        self,
        tenant_id: UUID,
        metric_type: str,
        requested_quantity: int = 1
    ) -> Tuple[bool, Dict[str, int]]:
        """
        Check if usage would exceed plan limits
        
        Args:
            tenant_id: Tenant identifier
            metric_type: Usage metric type
            requested_quantity: Requested usage quantity
            
        Returns:
            Tuple of (allowed, usage_info)
            
        Raises:
            SubscriptionNotFoundException: If no subscription found
        """
        subscription = self.get_tenant_subscription(tenant_id)
        if not subscription:
            raise SubscriptionNotFoundException(str(tenant_id))
        
        # Get current usage for billing period
        current_usage = self.usage_tracker.get_period_usage(
            tenant_id,
            subscription.current_period_start,
            subscription.current_period_end
        )
        
        # Get plan limits
        plan = subscription.plan
        limits = {
            "signatures": plan.signatures_included,
            "documents": plan.documents_included,
            "api_calls": plan.api_calls_included,
            "storage_gb": plan.storage_gb_included
        }
        
        # Check specific metric
        current_count = current_usage.get(metric_type, 0)
        limit = limits.get(metric_type, 0)
        
        # For unlimited plans (enterprise/custom), allow usage
        if limit == 0:  # 0 means unlimited
            allowed = True
        else:
            allowed = (current_count + requested_quantity) <= limit
        
        usage_info = {
            "current": current_count,
            "limit": limit,
            "remaining": max(0, limit - current_count) if limit > 0 else -1,
            "would_exceed": not allowed
        }
        
        return allowed, usage_info
    
    def enforce_usage_limits(
        self,
        tenant_id: UUID,
        metric_type: str,
        requested_quantity: int = 1
    ) -> None:
        """
        Enforce usage limits, raise exception if exceeded
        
        Args:
            tenant_id: Tenant identifier
            metric_type: Usage metric type
            requested_quantity: Requested usage quantity
            
        Raises:
            PlanLimitExceededException: If usage would exceed limits
        """
        allowed, usage_info = self.check_usage_limits(
            tenant_id, metric_type, requested_quantity
        )
        
        if not allowed:
            raise PlanLimitExceededException(
                metric=metric_type,
                limit=usage_info["limit"],
                current_usage=usage_info["current"]
            )
    
    def _save_subscription(self, subscription: Subscription) -> None:
        """
        Save subscription to database
        
        Args:
            subscription: Subscription to save
        """
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO subscriptions (
                    id, tenant_id, plan_id, status, billing_cycle,
                    current_period_start, current_period_end,
                    trial_start, trial_end, cancel_at_period_end,
                    canceled_at, stripe_subscription_id, stripe_customer_id,
                    created_at, updated_at, metadata
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    plan_id = EXCLUDED.plan_id,
                    status = EXCLUDED.status,
                    billing_cycle = EXCLUDED.billing_cycle,
                    current_period_start = EXCLUDED.current_period_start,
                    current_period_end = EXCLUDED.current_period_end,
                    trial_start = EXCLUDED.trial_start,
                    trial_end = EXCLUDED.trial_end,
                    cancel_at_period_end = EXCLUDED.cancel_at_period_end,
                    canceled_at = EXCLUDED.canceled_at,
                    stripe_subscription_id = EXCLUDED.stripe_subscription_id,
                    stripe_customer_id = EXCLUDED.stripe_customer_id,
                    updated_at = EXCLUDED.updated_at,
                    metadata = EXCLUDED.metadata
            """, (
                str(subscription.id),
                str(subscription.tenant_id),
                subscription.plan.id,
                subscription.status.value,
                subscription.billing_cycle,
                subscription.current_period_start,
                subscription.current_period_end,
                subscription.trial_start,
                subscription.trial_end,
                subscription.cancel_at_period_end,
                subscription.canceled_at,
                subscription.stripe_subscription_id,
                subscription.stripe_customer_id,
                subscription.created_at,
                subscription.updated_at,
                subscription.metadata
            ))
            conn.commit()