# QES Platform Billing System

Production-ready billing and subscription management integrated with Stripe.

## Features

- **Multi-Plan Subscriptions**: Free, Professional, and Enterprise tiers
- **Usage-Based Billing**: Track signatures, documents, API calls, and storage
- **Webhook Processing**: Real-time Stripe event handling with idempotency
- **Payment Processing**: One-time payments and recurring subscriptions
- **Invoice Management**: Automatic invoice generation and retrieval
- **Audit Logging**: Complete audit trail for all billing operations

## Setup

### 1. Environment Configuration

Create environment variables for your Stripe configuration:

```bash
# Development/Test
STRIPE_TEST_SECRET_KEY=sk_test_...
STRIPE_TEST_PUBLISHABLE_KEY=pk_test_...
STRIPE_TEST_WEBHOOK_SECRET=whsec_...

# Production
STRIPE_LIVE_SECRET_KEY=sk_live_...
STRIPE_LIVE_PUBLISHABLE_KEY=pk_live_...
STRIPE_LIVE_WEBHOOK_SECRET=whsec_...

# Platform settings
QES_ENVIRONMENT=development  # or staging/production
QES_BASE_URL=http://localhost:8000
```

### 2. Initialize Stripe Products

Run the setup script to create products and prices:

```bash
# Test configuration
python backend/scripts/setup_stripe.py --test-config

# Create products and prices
python backend/scripts/setup_stripe.py --setup-products

# Setup webhook endpoint
python backend/scripts/setup_stripe.py --setup-webhook

# Run all setup steps
python backend/scripts/setup_stripe.py --all
```

### 3. Configure Webhooks

In your Stripe dashboard, create a webhook endpoint pointing to:
```
https://your-domain.com/api/v1/billing/webhooks/stripe
```

Subscribe to these events:
- `customer.created`, `customer.updated`, `customer.deleted`
- `customer.subscription.created`, `customer.subscription.updated`, `customer.subscription.deleted`
- `customer.subscription.trial_will_end`
- `invoice.created`, `invoice.finalized`, `invoice.paid`, `invoice.payment_failed`
- `payment_intent.succeeded`, `payment_intent.payment_failed`
- `charge.succeeded`, `charge.failed`, `charge.dispute.created`

## API Endpoints

### Configuration
- `GET /api/v1/billing/config` - Get billing configuration and status
- `GET /api/v1/billing/health` - Health check for billing service

### Plans and Subscriptions
- `GET /api/v1/billing/plans` - List all available billing plans
- `POST /api/v1/billing/subscription` - Create new subscription
- `GET /api/v1/billing/subscription` - Get current subscription
- `PUT /api/v1/billing/subscription` - Update subscription

### Payments
- `POST /api/v1/billing/payment-intent` - Create payment intent for one-time payments
- `GET /api/v1/billing/invoices` - List invoices for current tenant

### Usage and Analytics
- `GET /api/v1/billing/usage` - Get current usage statistics

### Webhooks
- `POST /api/v1/billing/webhooks/stripe` - Stripe webhook endpoint

## Billing Plans

### Free Plan
- **Price**: $0/month
- **Signatures**: 10/month
- **Documents**: 50/month
- **API Calls**: 1,000/month
- **Storage**: 1 GB

### Professional Plan
- **Price**: $29/month or $290/year
- **Signatures**: 100/month
- **Documents**: 1,000/month
- **API Calls**: 10,000/month
- **Storage**: 10 GB
- **Features**: Advanced signatures, API access

### Enterprise Plan
- **Price**: $99/month or $990/year
- **Signatures**: Unlimited
- **Documents**: Unlimited
- **API Calls**: Unlimited
- **Storage**: 100 GB
- **Features**: All features, priority support, compliance tools

## Usage Tracking

The system tracks usage across multiple metrics:

```python
# Example usage tracking
usage_tracker.record_usage(
    tenant_id=tenant_id,
    metric_type=UsageMetricType.SIGNATURES,
    quantity=1,
    metadata={"signature_id": signature_id}
)
```

## Webhook Event Handling

The webhook handler processes Stripe events and updates local state:

```python
# Subscription updated
async def _handle_subscription_updated(self, subscription):
    subscription_id = subscription.get("id")
    status = subscription.get("status")
    
    # Update local subscription status
    await self._update_local_subscription_status(subscription_id, status)
```

## Error Handling

All billing operations include comprehensive error handling:

- **Stripe API Errors**: Automatically retried with exponential backoff
- **Webhook Failures**: Logged and marked for manual review
- **Payment Failures**: Customer notifications and grace period handling
- **Usage Limits**: Soft limits with upgrade prompts

## Security

- **Webhook Verification**: All webhooks verified with Stripe signatures
- **API Key Management**: Environment-specific key rotation
- **Audit Logging**: Complete audit trail for compliance
- **Rate Limiting**: Protection against abuse

## Monitoring

Key metrics to monitor:

- **Subscription Health**: Active vs. churned subscriptions
- **Payment Success Rate**: Failed payment recovery
- **Webhook Processing**: Event processing latency and failures
- **Usage Patterns**: Feature adoption and limits

## Testing

```bash
# Unit tests
pytest backend/tests/test_billing.py

# Integration tests with Stripe test mode
pytest backend/tests/test_billing_integration.py

# Webhook testing
pytest backend/tests/test_webhooks.py
```

## Production Checklist

Before going live:

- [ ] Configure production Stripe keys
- [ ] Set up webhook endpoints with HTTPS
- [ ] Test payment flows end-to-end
- [ ] Configure monitoring and alerting
- [ ] Set up backup webhook endpoints
- [ ] Test subscription lifecycle events
- [ ] Verify tax calculation (if applicable)
- [ ] Configure customer notifications
- [ ] Test dispute handling
- [ ] Validate compliance requirements