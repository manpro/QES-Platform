"""
Billing-specific exceptions for QES Platform
"""


class BillingException(Exception):
    """Base exception for billing operations"""
    
    def __init__(self, message: str, code: str = None, details: dict = None):
        super().__init__(message)
        self.message = message
        self.code = code or "BILLING_ERROR"
        self.details = details or {}


class PaymentFailedException(BillingException):
    """Raised when a payment fails"""
    
    def __init__(self, message: str, payment_intent_id: str = None, 
                 failure_code: str = None, **kwargs):
        super().__init__(message, code="PAYMENT_FAILED", **kwargs)
        self.payment_intent_id = payment_intent_id
        self.failure_code = failure_code


class SubscriptionNotFoundException(BillingException):
    """Raised when a subscription is not found"""
    
    def __init__(self, subscription_id: str, **kwargs):
        message = f"Subscription not found: {subscription_id}"
        super().__init__(message, code="SUBSCRIPTION_NOT_FOUND", **kwargs)
        self.subscription_id = subscription_id


class InsufficientFundsException(BillingException):
    """Raised when insufficient funds for operation"""
    
    def __init__(self, required_amount: float, available_amount: float = None, **kwargs):
        message = f"Insufficient funds. Required: {required_amount}"
        if available_amount is not None:
            message += f", Available: {available_amount}"
        super().__init__(message, code="INSUFFICIENT_FUNDS", **kwargs)
        self.required_amount = required_amount
        self.available_amount = available_amount


class PlanLimitExceededException(BillingException):
    """Raised when plan limits are exceeded"""
    
    def __init__(self, metric: str, limit: int, current_usage: int, **kwargs):
        message = f"Plan limit exceeded for {metric}. Limit: {limit}, Current: {current_usage}"
        super().__init__(message, code="PLAN_LIMIT_EXCEEDED", **kwargs)
        self.metric = metric
        self.limit = limit
        self.current_usage = current_usage


class InvalidBillingPlanException(BillingException):
    """Raised when an invalid billing plan is specified"""
    
    def __init__(self, plan_id: str, **kwargs):
        message = f"Invalid billing plan: {plan_id}"
        super().__init__(message, code="INVALID_BILLING_PLAN", **kwargs)
        self.plan_id = plan_id


class StripeException(BillingException):
    """Raised when Stripe API operations fail"""
    
    def __init__(self, message: str, stripe_error_code: str = None, 
                 stripe_error_type: str = None, **kwargs):
        super().__init__(message, code="STRIPE_ERROR", **kwargs)
        self.stripe_error_code = stripe_error_code
        self.stripe_error_type = stripe_error_type


class WebhookVerificationException(BillingException):
    """Raised when webhook verification fails"""
    
    def __init__(self, message: str = "Webhook verification failed", **kwargs):
        super().__init__(message, code="WEBHOOK_VERIFICATION_FAILED", **kwargs)


class InvoiceGenerationException(BillingException):
    """Raised when invoice generation fails"""
    
    def __init__(self, message: str, tenant_id: str = None, **kwargs):
        super().__init__(message, code="INVOICE_GENERATION_FAILED", **kwargs)
        self.tenant_id = tenant_id


class UsageTrackingException(BillingException):
    """Raised when usage tracking operations fail"""
    
    def __init__(self, message: str, metric_type: str = None, **kwargs):
        super().__init__(message, code="USAGE_TRACKING_FAILED", **kwargs)
        self.metric_type = metric_type