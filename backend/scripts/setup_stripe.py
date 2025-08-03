#!/usr/bin/env python3
"""
Stripe Setup Script

Initialize Stripe products, prices, and webhook endpoints for the QES platform.
This script sets up the billing infrastructure required for production deployment.
"""

import os
import sys
import json
import argparse
from typing import Dict, Any

# Add backend to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from billing.stripe_client import StripeClient
from billing.stripe_config import get_stripe_config, validate_stripe_setup
from billing.models import DEFAULT_BILLING_PLANS


def setup_products_and_prices() -> Dict[str, Any]:
    """Setup Stripe products and prices for all billing plans"""
    
    print("Setting up Stripe products and prices...")
    
    config = get_stripe_config()
    stripe_client = StripeClient()
    
    print(f"Environment: {config.environment.value}")
    print(f"API Key: {config.secret_key[:7]}...")
    
    # Setup billing plans
    try:
        product_ids = stripe_client.setup_billing_plans()
        
        print(f"\n✅ Successfully created {len(product_ids)} products:")
        for plan_id, product_id in product_ids.items():
            print(f"  - {plan_id}: {product_id}")
        
        return {
            "success": True,
            "products_created": len(product_ids),
            "product_mapping": product_ids
        }
        
    except Exception as e:
        print(f"\n❌ Failed to setup products: {e}")
        return {"success": False, "error": str(e)}


def setup_webhook_endpoint(webhook_url: str = None) -> Dict[str, Any]:
    """Setup Stripe webhook endpoint"""
    
    print("\nSetting up Stripe webhook endpoint...")
    
    config = get_stripe_config()
    url = webhook_url or config.webhook_url
    
    try:
        import stripe
        
        # Get list of webhook events to subscribe to
        from billing.stripe_config import stripe_config_manager
        events = stripe_config_manager.get_webhook_events()
        
        # Create webhook endpoint
        webhook_endpoint = stripe.WebhookEndpoint.create(
            url=url,
            enabled_events=events,
            description="QES Platform Billing Webhooks"
        )
        
        print(f"✅ Webhook endpoint created:")
        print(f"  URL: {webhook_endpoint.url}")
        print(f"  Secret: {webhook_endpoint.secret}")
        print(f"  Events: {len(events)} subscribed")
        
        return {
            "success": True,
            "webhook_id": webhook_endpoint.id,
            "webhook_secret": webhook_endpoint.secret,
            "webhook_url": webhook_endpoint.url,
            "events_count": len(events)
        }
        
    except Exception as e:
        print(f"❌ Failed to setup webhook: {e}")
        return {"success": False, "error": str(e)}


def test_stripe_configuration() -> Dict[str, Any]:
    """Test Stripe configuration and connectivity"""
    
    print("\nTesting Stripe configuration...")
    
    try:
        # Validate setup
        validation = validate_stripe_setup()
        
        print("Configuration Status:")
        for key, value in validation["configuration_status"].items():
            status = "✅" if value else "❌"
            print(f"  {status} {key}: {value}")
        
        print(f"\nWebhook Validation:")
        webhook_validation = validation["webhook_validation"]
        print(f"  Valid: {'✅' if webhook_validation['valid'] else '❌'}")
        
        if webhook_validation.get("issues"):
            print("  Issues:")
            for issue in webhook_validation["issues"]:
                print(f"    - {issue}")
        
        if webhook_validation.get("recommendations"):
            print("  Recommendations:")
            for rec in webhook_validation["recommendations"]:
                print(f"    - {rec}")
        
        # Test API connectivity
        stripe_client = StripeClient()
        
        import stripe
        account = stripe.Account.retrieve()
        
        print(f"\n✅ Stripe API Connection Successful:")
        print(f"  Account ID: {account.id}")
        print(f"  Country: {account.country}")
        print(f"  Business Type: {account.business_type}")
        print(f"  Charges Enabled: {account.charges_enabled}")
        print(f"  Payouts Enabled: {account.payouts_enabled}")
        
        return {
            "success": True,
            "validation": validation,
            "account_info": {
                "id": account.id,
                "country": account.country,
                "charges_enabled": account.charges_enabled,
                "payouts_enabled": account.payouts_enabled
            }
        }
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return {"success": False, "error": str(e)}


def export_environment_template():
    """Export environment variable template"""
    
    print("\nGenerating environment template...")
    
    from billing.stripe_config import stripe_config_manager
    template = stripe_config_manager.export_environment_template()
    
    template_file = "stripe-env-template.txt"
    with open(template_file, "w") as f:
        f.write(template)
    
    print(f"✅ Environment template saved to: {template_file}")
    print("\nCopy this template and fill in your actual Stripe keys:")
    print(template)


def main():
    """Main setup script"""
    
    parser = argparse.ArgumentParser(description="Setup Stripe for QES Platform")
    parser.add_argument("--setup-products", action="store_true",
                       help="Create Stripe products and prices")
    parser.add_argument("--setup-webhook", action="store_true",
                       help="Create Stripe webhook endpoint")
    parser.add_argument("--webhook-url", type=str,
                       help="Custom webhook URL (if different from config)")
    parser.add_argument("--test-config", action="store_true",
                       help="Test Stripe configuration")
    parser.add_argument("--export-template", action="store_true",
                       help="Export environment variable template")
    parser.add_argument("--all", action="store_true",
                       help="Run all setup steps")
    
    args = parser.parse_args()
    
    print("🚀 QES Platform Stripe Setup")
    print("=" * 40)
    
    results = {}
    
    try:
        # Test configuration first
        if args.test_config or args.all:
            results["config_test"] = test_stripe_configuration()
            if not results["config_test"]["success"]:
                print("\n❌ Configuration test failed. Please fix issues before proceeding.")
                return 1
        
        # Setup products and prices
        if args.setup_products or args.all:
            results["products"] = setup_products_and_prices()
        
        # Setup webhook endpoint
        if args.setup_webhook or args.all:
            results["webhook"] = setup_webhook_endpoint(args.webhook_url)
        
        # Export template
        if args.export_template or args.all:
            export_environment_template()
        
        # Summary
        print("\n" + "=" * 40)
        print("Setup Summary:")
        
        for step, result in results.items():
            status = "✅" if result.get("success") else "❌"
            print(f"  {status} {step}: {'Success' if result.get('success') else 'Failed'}")
            
            if not result.get("success") and result.get("error"):
                print(f"      Error: {result['error']}")
        
        # Next steps
        if all(r.get("success", True) for r in results.values()):
            print("\n🎉 Setup completed successfully!")
            print("\nNext steps:")
            print("1. Update your application configuration with any new IDs")
            print("2. Test the billing flow in your application")
            print("3. Configure webhook endpoints in your deployment")
            print("4. Set up monitoring for billing events")
            return 0
        else:
            print("\n⚠️ Some setup steps failed. Please review and retry.")
            return 1
            
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user.")
        return 0
    except Exception as e:
        print(f"\n❌ Setup failed with unexpected error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())