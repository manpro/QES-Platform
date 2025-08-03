# QES Platform Code Examples & Quick Start Tutorial

This directory contains comprehensive examples and tutorials for using the QES Platform API to create qualified electronic signatures.

## Table of Contents

1. [Quick Start Guide](#quick-start-guide)
2. [Authentication Examples](#authentication-examples)
3. [Signature Creation Examples](#signature-creation-examples)
4. [Signature Verification Examples](#signature-verification-examples)
5. [Multi-language SDKs](#multi-language-sdks)
6. [Integration Patterns](#integration-patterns)
7. [Best Practices](#best-practices)

## Quick Start Guide

### Prerequisites

1. **QES Platform Account**: Sign up at [qes-platform.com](https://qes-platform.com)
2. **API Access**: Obtain your tenant ID and API credentials
3. **QES Provider**: Register with a supported provider (Freja eID, D-Trust, FNMT)

### 1. Environment Setup

```bash
# Set your API credentials
export QES_API_URL="https://your-tenant.qes-platform.com/api/v1"
export QES_API_KEY="your-api-key"
export QES_TENANT_ID="your-tenant-id"
```

### 2. Basic Authentication

```bash
# Test API connectivity
curl -H "Authorization: Bearer $QES_API_KEY" \
     -H "X-Tenant-ID: $QES_TENANT_ID" \
     $QES_API_URL/health
```

### 3. Your First Signature

```bash
# Sign a simple PDF document
curl -X POST $QES_API_URL/sign \
  -H "Authorization: Bearer $QES_API_KEY" \
  -H "X-Tenant-ID: $QES_TENANT_ID" \
  -F "document=@sample.pdf" \
  -F "document_name=contract.pdf" \
  -F "signature_format=PAdES-LTA" \
  -F "certificate_id=cert_12345"
```

## Example Applications

### Web Application Integration

- [**React Frontend**](./frontend/react/) - Complete React.js application
- [**Vue.js Dashboard**](./frontend/vue/) - Vue.js admin dashboard
- [**Angular Client**](./frontend/angular/) - Angular enterprise client

### Backend Integration

- [**Python FastAPI**](./backend/python/) - FastAPI microservice
- [**Node.js Express**](./backend/nodejs/) - Express.js REST API
- [**Java Spring Boot**](./backend/java/) - Spring Boot application
- [**Go Gin**](./backend/go/) - Go web service

### Mobile Applications

- [**React Native**](./mobile/react-native/) - Cross-platform mobile app
- [**Flutter**](./mobile/flutter/) - Dart/Flutter application

### Enterprise Integration

- [**Webhook Handler**](./integrations/webhooks/) - Process signature events
- [**Batch Processing**](./integrations/batch/) - Handle bulk signatures
- [**Document Management**](./integrations/dms/) - DMS integration patterns

## Language-Specific Examples

### Python Examples

```python
# Quick start with Python SDK
from qes_platform import QESClient

client = QESClient(
    api_url="https://your-tenant.qes-platform.com/api/v1",
    api_key="your-api-key",
    tenant_id="your-tenant-id"
)

# Authenticate user with Freja eID
auth_result = client.authenticate(
    provider="freja-se",
    user_identifier="user@example.com",
    redirect_uri="https://your-app.com/callback"
)

# Sign document
signature = client.sign_document(
    document_path="contract.pdf",
    signature_format="PAdES-LTA",
    certificate_id="cert_12345"
)
```

### JavaScript Examples

```javascript
// Quick start with JavaScript SDK
import { QESClient } from '@qes-platform/sdk';

const client = new QESClient({
  apiUrl: 'https://your-tenant.qes-platform.com/api/v1',
  apiKey: 'your-api-key',
  tenantId: 'your-tenant-id'
});

// Authenticate and sign
const authResult = await client.authenticate({
  provider: 'freja-se',
  userIdentifier: 'user@example.com',
  redirectUri: 'https://your-app.com/callback'
});

const signature = await client.signDocument({
  document: documentBlob,
  documentName: 'contract.pdf',
  signatureFormat: 'PAdES-LTA',
  certificateId: 'cert_12345'
});
```

### Java Examples

```java
// Quick start with Java SDK
import com.qesplatform.QESClient;
import com.qesplatform.models.*;

QESClient client = new QESClient.Builder()
    .apiUrl("https://your-tenant.qes-platform.com/api/v1")
    .apiKey("your-api-key")
    .tenantId("your-tenant-id")
    .build();

// Authenticate user
AuthenticationRequest authRequest = AuthenticationRequest.builder()
    .provider("freja-se")
    .userIdentifier("user@example.com")
    .redirectUri("https://your-app.com/callback")
    .build();

AuthenticationResult authResult = client.authenticate(authRequest);

// Sign document
SigningRequest signingRequest = SigningRequest.builder()
    .document(documentBytes)
    .documentName("contract.pdf")
    .signatureFormat(SignatureFormat.PADES_LTA)
    .certificateId("cert_12345")
    .build();

SigningResult signature = client.signDocument(signingRequest);
```

### Go Examples

```go
// Quick start with Go SDK
package main

import (
    "github.com/qes-platform/go-sdk"
    "context"
)

func main() {
    client := qes.NewClient(&qes.Config{
        APIUrl:   "https://your-tenant.qes-platform.com/api/v1",
        APIKey:   "your-api-key",
        TenantID: "your-tenant-id",
    })

    // Authenticate user
    authResult, err := client.Authenticate(context.Background(), &qes.AuthRequest{
        Provider:        "freja-se",
        UserIdentifier: "user@example.com",
        RedirectURI:    "https://your-app.com/callback",
    })

    // Sign document
    signature, err := client.SignDocument(context.Background(), &qes.SignRequest{
        Document:        documentBytes,
        DocumentName:    "contract.pdf",
        SignatureFormat: qes.PAdESLTA,
        CertificateID:   "cert_12345",
    })
}
```

## Tutorials by Use Case

### 1. Document Signing Workflow

Complete end-to-end tutorial for implementing document signing:

- [**User Authentication**](./tutorials/01-authentication.md)
- [**Document Upload**](./tutorials/02-document-upload.md) 
- [**Signature Creation**](./tutorials/03-signature-creation.md)
- [**Result Handling**](./tutorials/04-result-handling.md)

### 2. Batch Document Processing

Tutorial for processing multiple documents:

- [**Batch Upload**](./tutorials/05-batch-upload.md)
- [**Parallel Processing**](./tutorials/06-parallel-processing.md)
- [**Status Monitoring**](./tutorials/07-status-monitoring.md)
- [**Error Handling**](./tutorials/08-error-handling.md)

### 3. Enterprise Integration

Advanced integration patterns:

- [**Webhook Integration**](./tutorials/09-webhooks.md)
- [**Single Sign-On**](./tutorials/10-sso-integration.md)
- [**Document Management Systems**](./tutorials/11-dms-integration.md)
- [**Compliance Reporting**](./tutorials/12-compliance.md)

## Provider-Specific Guides

### Freja eID (Sweden) Integration

Complete guide for integrating with Freja eID:

- [Setup & Configuration](./providers/freja/setup.md)
- [OAuth2 Authentication Flow](./providers/freja/oauth2.md)
- [Certificate Management](./providers/freja/certificates.md)
- [Remote Signing](./providers/freja/signing.md)
- [Testing & Sandbox](./providers/freja/testing.md)

### D-Trust (Germany) Integration

Complete guide for integrating with D-Trust:

- [Setup & Configuration](./providers/dtrust/setup.md)
- [eIDAS Authentication](./providers/dtrust/eidas.md)
- [Certificate Lifecycle](./providers/dtrust/certificates.md)
- [Remote Signing API](./providers/dtrust/api.md)
- [Compliance Requirements](./providers/dtrust/compliance.md)

### FNMT (Spain) Integration

Guide for integrating with FNMT:

- [Setup & Configuration](./providers/fnmt/setup.md)
- [Authentication Methods](./providers/fnmt/auth.md)
- [Certificate Management](./providers/fnmt/certificates.md)
- [Signature Creation](./providers/fnmt/signing.md)

## Testing & Development

### Local Development Setup

```bash
# Clone the QES Platform examples
git clone https://github.com/qes-platform/examples.git
cd examples

# Set up development environment
cp .env.example .env
# Edit .env with your credentials

# Run examples
npm install
npm run dev
```

### Testing with Mock Providers

For development and testing, use our mock providers:

```javascript
const client = new QESClient({
  apiUrl: 'http://localhost:8000/api/v1',
  apiKey: 'dev-api-key',
  tenantId: 'dev-tenant',
  environment: 'development' // Enables mock providers
});
```

### Postman Collection

Import our comprehensive Postman collection:

1. Download [QES Platform API Collection](./postman/qes-platform-collection.json)
2. Import into Postman
3. Set environment variables
4. Start testing!

## Production Deployment

### Environment Configuration

```bash
# Production environment variables
QES_API_URL=https://api.qes-platform.com/v1
QES_API_KEY=prod_xxxxxxxxxx
QES_TENANT_ID=your-production-tenant
QES_ENVIRONMENT=production

# Provider-specific configurations
FREJA_CLIENT_ID=your-freja-client-id
FREJA_CLIENT_SECRET=your-freja-client-secret
DTRUST_CLIENT_CERT_PATH=/path/to/dtrust-client.crt
DTRUST_CLIENT_KEY_PATH=/path/to/dtrust-client.key
```

### Error Handling Best Practices

```python
from qes_platform import QESClient, QESError, RateLimitError

try:
    signature = client.sign_document(request)
except RateLimitError as e:
    # Handle rate limiting
    wait_time = e.retry_after
    time.sleep(wait_time)
    signature = client.sign_document(request)
except QESError as e:
    # Handle API errors
    logger.error(f"Signature failed: {e.message}")
    raise
```

### Monitoring & Observability

```python
import logging
from qes_platform.observability import setup_monitoring

# Enable detailed logging
logging.basicConfig(level=logging.INFO)

# Set up monitoring (Prometheus metrics)
setup_monitoring(
    metrics_port=9090,
    enable_tracing=True
)
```

## Security Best Practices

### API Key Management

```python
# Use environment variables, never hardcode
import os
from qes_platform import QESClient

client = QESClient(
    api_key=os.getenv('QES_API_KEY'),
    tenant_id=os.getenv('QES_TENANT_ID')
)
```

### Certificate Validation

```python
# Always validate certificates in production
client = QESClient(
    verify_ssl=True,
    cert_validation_level='qualified'
)
```

### Rate Limiting Handling

```python
from qes_platform.retry import with_retry

@with_retry(max_attempts=3, backoff_factor=2)
def sign_with_retry(document):
    return client.sign_document(document)
```

## Support & Resources

### Documentation

- [API Reference](https://docs.qes-platform.com/api)
- [SDK Documentation](https://docs.qes-platform.com/sdk)
- [Integration Guides](https://docs.qes-platform.com/guides)

### Community

- [GitHub Repository](https://github.com/qes-platform/examples)
- [Discord Community](https://discord.gg/qes-platform)
- [Stack Overflow](https://stackoverflow.com/tags/qes-platform)

### Support

- [Support Portal](https://support.qes-platform.com)
- [Technical Support](mailto:support@qes-platform.com)
- [Enterprise Support](mailto:enterprise@qes-platform.com)

---

## Quick Reference

### Common Error Codes

| Code | Description | Solution |
|------|-------------|----------|
| 401 | Unauthorized | Check API key and tenant ID |
| 429 | Rate Limited | Implement exponential backoff |
| 400 | Bad Request | Validate request parameters |
| 404 | Not Found | Check resource IDs and endpoints |
| 500 | Server Error | Contact support if persistent |

### Signature Formats

| Format | Use Case | Long-term Validity |
|--------|----------|-------------------|
| XAdES-B | Basic XML signatures | Limited |
| XAdES-T | With timestamp | Good |
| XAdES-LTA | Archive with LTV | Excellent |
| PAdES-B | Basic PDF signatures | Limited |
| PAdES-T | With timestamp | Good |
| PAdES-LTA | Archive with LTV | Excellent |

### Provider Capabilities

| Provider | Country | Auth Methods | Signature Types |
|----------|---------|-------------|----------------|
| Freja eID | Sweden | OAuth2 | XAdES, PAdES |
| D-Trust | Germany | eIDAS, SAML | XAdES, PAdES |
| FNMT | Spain | Basic Auth | XAdES, PAdES |

---

*For more examples and updates, visit our [GitHub repository](https://github.com/qes-platform/examples) or [documentation site](https://docs.qes-platform.com).*