# Modular eIDAS QES Digital-Signing Platform

> A production-grade digital-signature service that complies with **eIDAS Qualified Electronic Signature (QES)**, deployable both as a multi-tenant SaaS and as an on-prem Docker/Kubernetes package.

## Project Vision

* **Zero-trust, data-sovereign signing** – documents never leave customer's boundary when self-hosted.
* **Plug-and-play adapters** for national QES providers (Freja eID QES, D-Trust, FNMT, Certinomis, itsme …).
* **Unified REST / gRPC API & Web UI** – same contract in SaaS and on-prem.
* **ETSI/ISO compliance** – XAdES-LTA & PAdES-LTA with long-term validation and TSA.
* **Auditability** – tamper-proof logs, OpenTelemetry tracing, WORM storage option.

## Architecture

```
┌────────────────────────────┐
│     API Gateway + UI       │
└────────────┬───────────────┘
             │JWT /OIDC
┌────────────▼───────────────┐
│      Signing Engine        │  ⇢ Core: flow, PKI, LTV, audit
└─┬─────────┬─────────┬──────┘
  │ gRPC    │ gRPC    │ gRPC   (plugin interface)
┌─▼──┐   ┌──▼──┐   ┌──▼──┐
│SE  │   │DE  │   │ES  │   …   ⇢ Country-specific adapters
└────┘   └────┘   └────┘
```

## Technology Stack

| Layer          | Tech                                                | Notes                           |
| -------------- | --------------------------------------------------- | ------------------------------- |
| API & Business | **Python (FastAPI)** (alt. Node + NestJS)           | Async, Swagger, pydantic        |
| Core Signing   | **EU DSS library**, Apache PDFBox, OpenSSL          | QES/AdES profiles               |
| DB & State     | **PostgreSQL**, Redis, MinIO (object store)         | Multi-tenant schemas            |
| Observability  | Grafana Loki, Prometheus, OpenTelemetry             | SaaS dashboard & on-prem bundle |
| Secrets & Keys | HashiCorp Vault + HSM/KMS                           | SoftHSM for dev                 |
| Packaging      | Docker, Helm Charts                                 | Air-gap friendly                |
| CI/CD          | GitHub Actions (SaaS) + self-hosted Drone (on-prem) | SBOM + SLSA build               |

## Project Structure

```
qes-platform/
├── backend/          # Core signing engine (FastAPI)
├── adapters/         # Country-specific QES provider adapters
│   ├── base/         # Abstract base interface
│   ├── freja-se/     # Freja eID QES (Sweden)
│   ├── dtrust-de/    # D-Trust (Germany)
│   └── fnmt-es/      # FNMT QES (Spain)
├── ui/               # Web interface
├── infra/            # Infrastructure as code
├── docs/             # Documentation
├── charts/           # Helm charts
├── quickstart/       # Docker Compose for quick start
└── tests/            # Integration and E2E tests
```

## Quick Start

### 🚀 Starting the Platform

1. **Navigate to quickstart directory:**
   ```bash
   cd quickstart
   ```

2. **Start all services:**
   ```bash
   docker-compose up -d
   ```

3. **Check status:**
   ```bash
   docker-compose ps
   ```

### 🌐 Access Web Interfaces

Once all services are running, you can access:

| Service | URL | Credentials | Description |
|---------|-----|-------------|-------------|
| **QES Platform Web UI** | http://localhost:3003 | - | **Main user interface** |
| **QES Platform API** | http://localhost:8000 | - | Backend API and docs |
| **Grafana Dashboard** | http://localhost:3002 | admin/admin | Observability dashboard |
| **MinIO Console** | http://localhost:9001 | admin/admin123456 | Object storage management |
| **Prometheus** | http://localhost:9090 | - | Metrics collection |
| **Jaeger Tracing** | http://localhost:16686 | - | Distributed tracing |
| **Loki Logs** | http://localhost:3100 | - | Log aggregation |

### 🔧 Database & Services

| Service | Connection | Credentials | Description |
|---------|------------|-------------|-------------|
| **PostgreSQL** | localhost:5432 | qes_admin/dev_password | Main database |
| **Redis** | localhost:6380 | - | Caching & sessions |
| **Vault** | localhost:8202 | dev-token-please-change | Secrets management |

### 📋 Service Status

The platform runs these containerized services:

- ✅ **QES Platform Frontend** (localhost:3003) - **Main React web interface**
- ✅ **QES Platform Backend** (localhost:8000) - FastAPI backend and API docs
- ✅ **PostgreSQL** (localhost:5432) - Multi-tenant database
- ✅ **Redis** (localhost:6380) - Session storage and caching  
- ✅ **MinIO** (localhost:9000-9001) - S3-compatible object storage
- ✅ **Prometheus** (localhost:9090) - Metrics collection
- ✅ **Loki** (localhost:3100) - Log aggregation
- ✅ **Jaeger** (localhost:16686) - Distributed tracing
- ✅ **Grafana** (localhost:3002) - Observability dashboard
- ✅ **SoftHSM** - HSM simulation for development
- ⚠️ **Vault** (localhost:8202) - Secrets management (may conflict with existing Vault)

## Development Status

### 🚧 Current Implementation Status

**✅ COMPLETED:**
- Infrastructure services (PostgreSQL, Redis, MinIO, etc.)
- QES Provider adapters (Freja, D-Trust, FNMT, etc.)
- Frontend demo with mock data
- Blockchain anchoring system
- eIDAS AL2 identity proofing
- Billing system integration

**⚠️ PARTIALLY IMPLEMENTED:**
- Core signing engine (logic exists but not connected to API)
- Audit logging (framework exists)
- Security infrastructure (Vault, HSM)

**❌ MISSING (CRITICAL):**
- Main document signing API endpoints
- Database models for core entities
- User document management interface
- Real file storage integration
- User authentication system

### 📋 Production Readiness TODO

See [Development TODOs](#development-todos) below for detailed implementation plan.

## Development

### 🛠️ Development Environment

The quickstart environment provides a complete development stack with:

- **Observability**: Full monitoring stack with Grafana, Prometheus, Loki, and Jaeger
- **Storage**: PostgreSQL with multi-tenant schemas, Redis for caching, MinIO for objects
- **Security**: Vault for secrets management, SoftHSM for development HSM simulation
- **Hot-reload**: Development containers support code changes without rebuilds

### 🔍 Monitoring & Debugging

1. **Application Metrics**: Visit Grafana at http://localhost:3002
2. **Log Analysis**: Loki aggregates all container logs
3. **Request Tracing**: Jaeger shows end-to-end request flows
4. **File Management**: MinIO console for document storage

### 🚨 Troubleshooting

**Port Conflicts:**
If services fail to start due to port conflicts, the following ports have been modified from defaults:
- Frontend: 3003 (instead of 3000)
- Grafana: 3002 (instead of 3000)
- Redis: 6380 (instead of 6379)
- Vault: 8202 (instead of 8200)

**Common Issues:**
```bash
# Stop all services
docker-compose down

# View service logs
docker-compose logs [service-name]

# Restart specific service
docker-compose restart [service-name]

# Remove all data and restart fresh
docker-compose down -v
docker-compose up -d
```

**Health Checks:**
```bash
# Check all service status
docker-compose ps

# Follow logs in real-time
docker-compose logs -f

# Test database connection
docker-compose exec postgres psql -U qes_admin -d qes_platform
```

## Development TODOs

### 🔴 CRITICAL Priority (System doesn't work without these)

1. **Create Core Signing API Endpoints**
- `POST /api/v1/documents/upload` - Upload document for signing
- `POST /api/v1/signatures` - Create new signature
- `GET /api/v1/signatures/{id}` - Get signature status
- `GET /api/v1/signatures/{id}/download` - Download signed document

**✅ EU DSS eIDAS-Compliant Signatures:**
- `POST /api/v1/eu-dss/create-signature` - Create XAdES/PAdES/CAdES signatures
- `POST /api/v1/eu-dss/validate-signature` - Validate eIDAS-compliant signatures
- `POST /api/v1/eu-dss/upload-and-sign` - Upload and sign in one operation
- `GET /api/v1/eu-dss/signature-levels` - Get supported signature levels

**✅ Advanced Document Verification:**
- `POST /api/v1/document-verification/verify` - Smart document verification (internal + external)
- `POST /api/v1/document-verification/verify-external` - Force external provider verification
- `GET /api/v1/document-verification/providers` - List available verification providers
- `GET /api/v1/document-verification/health/external` - External provider health check

**✅ Redis Cache Management:**
- `GET /api/v1/cache/stats` - Comprehensive cache statistics and performance metrics
- `GET /api/v1/cache/health` - Cache health check and diagnostics
- `POST /api/v1/cache/invalidate` - Selective cache invalidation by provider/pattern
- `GET /api/v1/cache/certificates` - List cached certificates with metadata
- `GET /api/v1/cache/memory-usage` - Detailed memory usage analysis

2. **Implement Database Models**
   - `Document` model (id, name, content_hash, user_id, created_at)
   - `Signature` model (id, document_id, status, provider, certificate_info)
   - `User` model (id, email, tenant_id, preferences)
   - `SigningSession` model (id, user_id, status, provider_session_id)

3. **Create User Document Manager** ⭐ *User specifically requested*
   - Document library interface
   - View signed/unsigned documents
   - Download capabilities
   - Signature status tracking

### 🟡 HIGH Priority (Major functionality missing)

4. **Connect QES Adapters to Backend**
   - Wire up existing QES providers to signing API
   - Handle provider-specific authentication flows
   - Manage QES certificates and sessions

5. **Implement User Authentication**
   - JWT-based authentication
   - User registration/login
   - Session management
   - Role-based access control

6. **Integrate File Storage (MinIO)**
   - Document upload handling
   - Secure file storage
   - File retrieval and serving
   - Cleanup of temporary files

### 🟠 MEDIUM Priority (Nice to have)

7. **Replace Frontend Mock Data**
   - Connect React components to real API endpoints
   - Handle loading states and errors
   - Real-time signature status updates

8. **Add Input Validation & Security**
   - File type validation
   - Size limits
   - Malware scanning
   - Input sanitization

9. **Enhance Audit Trail**
   - Complete audit logging implementation
   - Compliance reporting
   - Event correlation

### 🟢 LOW Priority (Polish & optimization)

10. **Improve User Experience**
    - Better progress indicators
    - Enhanced error messages
    - Drag-and-drop improvements
    - Mobile responsive design

11. **Production Configuration**
    - Environment-based configuration
    - Security hardening
    - Performance optimization
    - Monitoring setup

## License

TBD