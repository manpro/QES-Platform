# QES Platform Development Environment

This directory contains Docker Compose configuration for setting up a complete development environment for the QES Platform.

## Services Included

- **PostgreSQL**: Multi-tenant database with initialized schemas
- **Redis**: Session storage and caching
- **HashiCorp Vault**: Secrets management and PKI
- **SoftHSM**: Development HSM simulation
- **MinIO**: Object storage for signed documents
- **Grafana Loki**: Centralized logging
- **Prometheus**: Metrics collection
- **Grafana**: Observability dashboard
- **Jaeger**: Distributed tracing

## Quick Start

1. **Start all services:**
   ```bash
   docker-compose up -d
   ```

2. **Check service health:**
   ```bash
   docker-compose ps
   ```

3. **Access web interfaces:**
   - Grafana: http://localhost:3000 (admin/admin)
   - Vault UI: http://localhost:8200 (token: dev-token-please-change)
   - MinIO Console: http://localhost:9001 (admin/admin123456)
   - Prometheus: http://localhost:9090
   - Jaeger UI: http://localhost:16686

## Configuration

### Database
- **Host**: localhost:5432
- **Database**: qes_platform
- **Username**: qes_admin
- **Password**: dev_password

### Vault (Development Mode)
- **URL**: http://localhost:8200
- **Root Token**: dev-token-please-change

### SoftHSM
- **Token Label**: QES-DEV-TOKEN
- **SO PIN**: 1234
- **User PIN**: 5678
- **Library Path**: `/usr/lib/softhsm/libsofthsm2.so`

### MinIO
- **Access Key**: admin
- **Secret Key**: admin123456
- **S3 Endpoint**: http://localhost:9000

## Initial Setup

After starting the services, you'll need to:

1. **Configure Vault PKI:**
   ```bash
   # Enable PKI secrets engine
   vault auth -method=token token=dev-token-please-change
   vault secrets enable pki
   vault secrets tune -max-lease-ttl=87600h pki
   ```

2. **Create test certificates in SoftHSM:**
   ```bash
   docker exec -it qes-softhsm softhsm2-util --show-slots
   ```

3. **Import sample data:**
   ```bash
   # The database is automatically initialized with tenant schemas
   # You can connect and add test data as needed
   ```

## Development Workflow

1. Start the development environment
2. Run your backend application locally (pointing to these services)
3. Use the Grafana dashboard to monitor application metrics
4. Check logs in Loki via Grafana
5. Trace requests through Jaeger

## Stopping Services

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (clean slate)
docker-compose down -v
```

## Troubleshooting

### Service Won't Start
Check logs: `docker-compose logs <service-name>`

### Database Connection Issues
Ensure PostgreSQL is fully started: `docker-compose logs postgres`

### Vault Sealed
In development mode, Vault auto-unseals. If issues persist:
```bash
docker-compose restart vault
```

### HSM Issues
Restart SoftHSM container:
```bash
docker-compose restart softhsm
```