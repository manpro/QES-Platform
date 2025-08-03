"""
Stripe Configuration Management

Secure configuration management for Stripe API keys, webhooks, and environment-specific settings.
"""

import os
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class StripeEnvironment(str, Enum):
    """Stripe environment types"""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


@dataclass
class StripeConfig:
    """Stripe configuration settings"""
    environment: StripeEnvironment
    secret_key: str
    publishable_key: str
    webhook_secret: str
    webhook_url: str
    
    # API settings
    api_version: str = "2023-10-16"
    max_retries: int = 3
    timeout: int = 30
    
    # Feature flags
    enable_webhooks: bool = True
    enable_payment_intents: bool = True
    enable_automatic_tax: bool = False
    
    # Billing settings
    default_currency: str = "usd"
    trial_period_days: int = 14
    grace_period_days: int = 3
    
    def __post_init__(self):
        """Validate configuration after initialization"""
        if self.environment == StripeEnvironment.PRODUCTION:
            # Production validation
            if not self.secret_key.startswith("sk_live_"):
                raise ValueError("Production environment requires live secret key")
            if not self.publishable_key.startswith("pk_live_"):
                raise ValueError("Production environment requires live publishable key")
        else:
            # Test environment validation
            if not self.secret_key.startswith("sk_test_"):
                logger.warning("Non-production environment should use test secret key")
            if not self.publishable_key.startswith("pk_test_"):
                logger.warning("Non-production environment should use test publishable key")
        
        # Validate webhook secret format
        if self.webhook_secret and not self.webhook_secret.startswith("whsec_"):
            raise ValueError("Invalid webhook secret format")
    
    @property
    def is_production(self) -> bool:
        """Check if this is a production configuration"""
        return self.environment == StripeEnvironment.PRODUCTION
    
    @property
    def is_test_mode(self) -> bool:
        """Check if this is a test mode configuration"""
        return not self.is_production


class StripeConfigManager:
    """Manages Stripe configuration across environments"""
    
    def __init__(self):
        self._config = None
        self._environment = self._detect_environment()
    
    def _detect_environment(self) -> StripeEnvironment:
        """Detect current environment"""
        env = os.getenv("QES_ENVIRONMENT", "development").lower()
        
        if env == "production":
            return StripeEnvironment.PRODUCTION
        elif env == "staging":
            return StripeEnvironment.STAGING
        else:
            return StripeEnvironment.DEVELOPMENT
    
    def get_config(self) -> StripeConfig:
        """Get Stripe configuration for current environment"""
        if self._config is None:
            self._config = self._load_config()
        
        return self._config
    
    def _load_config(self) -> StripeConfig:
        """Load configuration from environment variables"""
        
        # Environment-specific key prefixes
        if self._environment == StripeEnvironment.PRODUCTION:
            key_prefix = "STRIPE_LIVE_"
        else:
            key_prefix = "STRIPE_TEST_"
        
        # Load keys
        secret_key = os.getenv(f"{key_prefix}SECRET_KEY")
        publishable_key = os.getenv(f"{key_prefix}PUBLISHABLE_KEY")
        webhook_secret = os.getenv(f"{key_prefix}WEBHOOK_SECRET")
        
        if not secret_key:
            raise ValueError(f"Missing {key_prefix}SECRET_KEY environment variable")
        if not publishable_key:
            raise ValueError(f"Missing {key_prefix}PUBLISHABLE_KEY environment variable")
        
        # Webhook URL
        base_url = os.getenv("QES_BASE_URL", "http://localhost:8000")
        webhook_url = f"{base_url}/api/v1/billing/webhooks/stripe"
        
        config = StripeConfig(
            environment=self._environment,
            secret_key=secret_key,
            publishable_key=publishable_key,
            webhook_secret=webhook_secret or "",
            webhook_url=webhook_url,
            
            # Optional settings
            api_version=os.getenv("STRIPE_API_VERSION", "2023-10-16"),
            max_retries=int(os.getenv("STRIPE_MAX_RETRIES", "3")),
            timeout=int(os.getenv("STRIPE_TIMEOUT", "30")),
            
            # Feature flags
            enable_webhooks=os.getenv("STRIPE_ENABLE_WEBHOOKS", "true").lower() == "true",
            enable_payment_intents=os.getenv("STRIPE_ENABLE_PAYMENT_INTENTS", "true").lower() == "true",
            enable_automatic_tax=os.getenv("STRIPE_ENABLE_AUTOMATIC_TAX", "false").lower() == "true",
            
            # Billing settings
            default_currency=os.getenv("STRIPE_DEFAULT_CURRENCY", "usd").lower(),
            trial_period_days=int(os.getenv("STRIPE_TRIAL_PERIOD_DAYS", "14")),
            grace_period_days=int(os.getenv("STRIPE_GRACE_PERIOD_DAYS", "3"))
        )
        
        logger.info(f"Loaded Stripe configuration for {self._environment.value} environment")
        return config
    
    def validate_webhook_configuration(self) -> Dict[str, Any]:
        """Validate webhook configuration"""
        config = self.get_config()
        
        validation_result = {
            "valid": True,
            "issues": [],
            "recommendations": []
        }
        
        # Check webhook secret
        if not config.webhook_secret:
            validation_result["valid"] = False
            validation_result["issues"].append("Webhook secret not configured")
        
        # Check webhook URL accessibility
        if not config.webhook_url.startswith(("http://", "https://")):
            validation_result["valid"] = False
            validation_result["issues"].append("Invalid webhook URL format")
        
        # Production-specific checks
        if config.is_production:
            if not config.webhook_url.startswith("https://"):
                validation_result["issues"].append("Production webhooks should use HTTPS")
            
            if "localhost" in config.webhook_url:
                validation_result["valid"] = False
                validation_result["issues"].append("Production cannot use localhost for webhooks")
        
        # Recommendations
        if config.enable_webhooks and not config.webhook_secret:
            validation_result["recommendations"].append("Configure webhook secret for security")
        
        if config.trial_period_days > 30:
            validation_result["recommendations"].append("Consider shorter trial period for better conversion")
        
        return validation_result
    
    def get_webhook_events(self) -> List[str]:
        """Get list of webhook events to subscribe to"""
        return [
            # Customer events
            "customer.created",
            "customer.updated",
            "customer.deleted",
            
            # Subscription events
            "customer.subscription.created",
            "customer.subscription.updated",
            "customer.subscription.deleted",
            "customer.subscription.trial_will_end",
            
            # Invoice events
            "invoice.created",
            "invoice.finalized",
            "invoice.paid",
            "invoice.payment_failed",
            "invoice.upcoming",
            
            # Payment events
            "payment_intent.succeeded",
            "payment_intent.payment_failed",
            "payment_method.attached",
            
            # Charge events
            "charge.succeeded",
            "charge.failed",
            "charge.dispute.created"
        ]
    
    def export_environment_template(self) -> str:
        """Export environment variable template"""
        env_template = f"""
# Stripe Configuration for {self._environment.value.upper()}
# Copy this template and fill in your actual values

# API Keys ({'LIVE' if self._environment == StripeEnvironment.PRODUCTION else 'TEST'})
STRIPE_{'LIVE' if self._environment == StripeEnvironment.PRODUCTION else 'TEST'}_SECRET_KEY=sk_{'live' if self._environment == StripeEnvironment.PRODUCTION else 'test'}_...
STRIPE_{'LIVE' if self._environment == StripeEnvironment.PRODUCTION else 'TEST'}_PUBLISHABLE_KEY=pk_{'live' if self._environment == StripeEnvironment.PRODUCTION else 'test'}_...
STRIPE_{'LIVE' if self._environment == StripeEnvironment.PRODUCTION else 'TEST'}_WEBHOOK_SECRET=whsec_...

# API Settings (optional)
STRIPE_API_VERSION=2023-10-16
STRIPE_MAX_RETRIES=3
STRIPE_TIMEOUT=30

# Feature Flags (optional)
STRIPE_ENABLE_WEBHOOKS=true
STRIPE_ENABLE_PAYMENT_INTENTS=true
STRIPE_ENABLE_AUTOMATIC_TAX=false

# Billing Settings (optional)
STRIPE_DEFAULT_CURRENCY=usd
STRIPE_TRIAL_PERIOD_DAYS=14
STRIPE_GRACE_PERIOD_DAYS=3

# QES Platform Settings
QES_ENVIRONMENT={self._environment.value}
QES_BASE_URL={"https://your-domain.com" if self._environment == StripeEnvironment.PRODUCTION else "http://localhost:8000"}
"""
        
        return env_template.strip()


# Global config manager instance
stripe_config_manager = StripeConfigManager()


def get_stripe_config() -> StripeConfig:
    """Get current Stripe configuration"""
    return stripe_config_manager.get_config()


def validate_stripe_setup() -> Dict[str, Any]:
    """Validate complete Stripe setup"""
    config = get_stripe_config()
    webhook_validation = stripe_config_manager.validate_webhook_configuration()
    
    return {
        "environment": config.environment.value,
        "is_production": config.is_production,
        "webhook_validation": webhook_validation,
        "required_events": stripe_config_manager.get_webhook_events(),
        "configuration_status": {
            "secret_key_configured": bool(config.secret_key),
            "publishable_key_configured": bool(config.publishable_key),
            "webhook_secret_configured": bool(config.webhook_secret),
            "webhook_url": config.webhook_url
        }
    }