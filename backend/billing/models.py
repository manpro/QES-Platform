"""
Billing data models for QES Platform
"""

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Dict, List, Optional, Any
from uuid import UUID


class BillingPlanType(str, Enum):
    """Billing plan types"""
    FREE = "free"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"


class SubscriptionStatus(str, Enum):
    """Subscription status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    CANCELED = "canceled"
    PAST_DUE = "past_due"
    UNPAID = "unpaid"
    TRIALING = "trialing"


class PaymentStatus(str, Enum):
    """Payment status"""
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELED = "canceled"
    REFUNDED = "refunded"


class UsageMetricType(str, Enum):
    """Usage metric types"""
    SIGNATURES = "signatures"
    DOCUMENTS = "documents"
    API_CALLS = "api_calls"
    STORAGE_GB = "storage_gb"
    BANDWIDTH_GB = "bandwidth_gb"


@dataclass
class BillingPlan:
    """Billing plan configuration"""
    id: str
    name: str
    type: BillingPlanType
    description: str
    price_monthly: Decimal
    price_yearly: Decimal
    currency: str = "EUR"
    
    # Usage limits
    signatures_included: int = 0
    documents_included: int = 0
    api_calls_included: int = 0
    storage_gb_included: int = 0
    
    # Overage pricing (per unit)
    signature_overage_price: Decimal = Decimal("0.10")
    document_overage_price: Decimal = Decimal("0.05")
    api_call_overage_price: Decimal = Decimal("0.001")
    storage_gb_overage_price: Decimal = Decimal("1.00")
    
    # Features
    features: List[str] = None
    
    # Stripe configuration
    stripe_product_id: Optional[str] = None
    stripe_price_monthly_id: Optional[str] = None
    stripe_price_yearly_id: Optional[str] = None
    
    # Metadata
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.features is None:
            self.features = []


@dataclass
class Subscription:
    """Tenant subscription"""
    id: UUID
    tenant_id: UUID
    plan: BillingPlan
    status: SubscriptionStatus
    
    # Billing cycle
    billing_cycle: str  # "monthly" or "yearly"
    current_period_start: datetime
    current_period_end: datetime
    
    # Trial information
    trial_start: Optional[datetime] = None
    trial_end: Optional[datetime] = None
    
    # Cancellation
    cancel_at_period_end: bool = False
    canceled_at: Optional[datetime] = None
    
    # Stripe integration
    stripe_subscription_id: Optional[str] = None
    stripe_customer_id: Optional[str] = None
    
    # Metadata
    created_at: datetime
    updated_at: datetime
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    @property
    def is_active(self) -> bool:
        """Check if subscription is active"""
        return self.status in [SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING]
    
    @property
    def is_in_trial(self) -> bool:
        """Check if subscription is in trial period"""
        if not self.trial_end:
            return False
        return datetime.utcnow() < self.trial_end


@dataclass
class Invoice:
    """Billing invoice"""
    id: UUID
    tenant_id: UUID
    subscription_id: UUID
    
    # Invoice details
    invoice_number: str
    status: PaymentStatus
    amount_due: Decimal
    amount_paid: Decimal
    currency: str
    
    # Billing period
    period_start: datetime
    period_end: datetime
    
    # Due dates
    created_at: datetime
    due_date: datetime
    paid_at: Optional[datetime] = None
    
    # Line items
    line_items: List[Dict[str, Any]] = None
    
    # Stripe integration
    stripe_invoice_id: Optional[str] = None
    stripe_payment_intent_id: Optional[str] = None
    
    # Metadata
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.line_items is None:
            self.line_items = []
        if self.metadata is None:
            self.metadata = {}
    
    @property
    def is_paid(self) -> bool:
        """Check if invoice is paid"""
        return self.status == PaymentStatus.SUCCEEDED
    
    @property
    def is_overdue(self) -> bool:
        """Check if invoice is overdue"""
        return (self.status == PaymentStatus.PENDING and 
                datetime.utcnow() > self.due_date)


@dataclass
class Payment:
    """Payment transaction"""
    id: UUID
    tenant_id: UUID
    invoice_id: Optional[UUID]
    
    # Payment details
    amount: Decimal
    currency: str
    status: PaymentStatus
    payment_method: str
    
    # Stripe integration
    stripe_payment_intent_id: Optional[str] = None
    stripe_charge_id: Optional[str] = None
    
    # Timestamps
    created_at: datetime
    processed_at: Optional[datetime] = None
    
    # Failure information
    failure_code: Optional[str] = None
    failure_message: Optional[str] = None
    
    # Metadata
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class UsageRecord:
    """Usage tracking record"""
    id: UUID
    tenant_id: UUID
    subscription_id: UUID
    
    # Usage details
    metric_type: UsageMetricType
    quantity: int
    timestamp: datetime
    
    # Billing period
    billing_period_start: datetime
    billing_period_end: datetime
    
    # Associated resources
    resource_id: Optional[str] = None  # e.g., signature_id, document_id
    user_id: Optional[UUID] = None
    
    # Billing status
    billed: bool = False
    billed_at: Optional[datetime] = None
    invoice_id: Optional[UUID] = None
    
    # Metadata
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class BillingEvent:
    """Billing system event"""
    id: UUID
    tenant_id: UUID
    event_type: str
    
    # Event data
    data: Dict[str, Any]
    timestamp: datetime
    
    # Processing status
    processed: bool = False
    processed_at: Optional[datetime] = None
    
    # Stripe webhook
    stripe_event_id: Optional[str] = None
    
    # Metadata
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


# Predefined billing plans
DEFAULT_BILLING_PLANS = [
    BillingPlan(
        id="free",
        name="Free",
        type=BillingPlanType.FREE,
        description="Perfect for trying out QES Platform",
        price_monthly=Decimal("0.00"),
        price_yearly=Decimal("0.00"),
        signatures_included=10,
        documents_included=10,
        api_calls_included=1000,
        storage_gb_included=1,
        features=[
            "10 signatures per month",
            "Basic QES support",
            "Email support",
            "1GB storage"
        ]
    ),
    BillingPlan(
        id="professional",
        name="Professional",
        type=BillingPlanType.PROFESSIONAL,
        description="For growing businesses and teams",
        price_monthly=Decimal("99.00"),
        price_yearly=Decimal("990.00"),
        signatures_included=1000,
        documents_included=1000,
        api_calls_included=100000,
        storage_gb_included=10,
        features=[
            "1,000 signatures per month",
            "All QES providers",
            "Priority support",
            "10GB storage",
            "API access",
            "Webhooks",
            "SLA guarantee"
        ]
    ),
    BillingPlan(
        id="enterprise",
        name="Enterprise",
        type=BillingPlanType.ENTERPRISE,
        description="For large organizations with high volumes",
        price_monthly=Decimal("499.00"),
        price_yearly=Decimal("4990.00"),
        signatures_included=10000,
        documents_included=10000,
        api_calls_included=1000000,
        storage_gb_included=100,
        features=[
            "10,000 signatures per month",
            "All QES providers",
            "24/7 phone support",
            "100GB storage",
            "Advanced API features",
            "Custom integrations",
            "Dedicated account manager",
            "SLA guarantee",
            "SAML SSO",
            "Advanced reporting"
        ]
    )
]