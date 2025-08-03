# QES Platform Operations Manual

## Table of Contents

1. [System Overview](#system-overview)
2. [Infrastructure Requirements](#infrastructure-requirements)
3. [Deployment](#deployment)
4. [Configuration Management](#configuration-management)
5. [Monitoring & Alerting](#monitoring--alerting)
6. [Backup & Recovery](#backup--recovery)
7. [Security Operations](#security-operations)
8. [Maintenance & Updates](#maintenance--updates)
9. [Troubleshooting](#troubleshooting)
10. [Incident Response](#incident-response)
11. [Capacity Planning](#capacity-planning)
12. [Compliance & Auditing](#compliance--auditing)

---

## System Overview

The QES Platform is a microservices-based application providing qualified electronic signature services compliant with eIDAS regulation and ETSI standards.

### Architecture Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Load Balancer / CDN                      │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                  QES Platform API                           │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐│
│  │ Auth Module │ │Sign Module  │ │   Verification Module   ││
│  └─────────────┘ └─────────────┘ └─────────────────────────┘│
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                 Infrastructure Layer                        │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────────┐ │
│ │PostgreSQL│ │  Redis   │ │  Vault   │ │   SoftHSM       │ │
│ └──────────┘ └──────────┘ └──────────┘ └─────────────────┘ │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────────┐ │
│ │  MinIO   │ │ Grafana  │ │Prometheus│ │     Jaeger      │ │
│ └──────────┘ └──────────┘ └──────────┘ └─────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Key Services

- **QES Platform API**: Main application server (FastAPI)
- **PostgreSQL**: Primary database with multi-tenant schemas
- **Redis**: Session storage and rate limiting
- **HashiCorp Vault**: Secrets management and PKI backend
- **SoftHSM**: Hardware Security Module simulation (dev/test)
- **MinIO**: Object storage for documents and artifacts
- **Prometheus**: Metrics collection
- **Grafana**: Monitoring dashboards
- **Loki**: Log aggregation
- **Jaeger**: Distributed tracing

---

## Infrastructure Requirements

### Minimum System Requirements

#### Production Environment
- **CPU**: 8 cores minimum, 16 cores recommended
- **Memory**: 32GB minimum, 64GB recommended
- **Storage**: 500GB SSD minimum, 1TB recommended
- **Network**: 1Gbps minimum bandwidth
- **OS**: Ubuntu 20.04 LTS or CentOS 8

#### Development Environment
- **CPU**: 4 cores minimum
- **Memory**: 16GB minimum
- **Storage**: 100GB SSD minimum
- **Network**: 100Mbps minimum

### Cloud Resource Sizing

#### AWS EKS Cluster
```yaml
Node Groups:
  - name: qes-platform-nodes
    instance_type: t3.xlarge
    min_size: 3
    max_size: 10
    desired_capacity: 5
    
  - name: qes-platform-compute
    instance_type: c5.2xlarge
    min_size: 2
    max_size: 8
    desired_capacity: 3
```

#### Database Requirements
- **RDS PostgreSQL**: db.r5.xlarge (4 vCPU, 32GB RAM)
- **ElastiCache Redis**: cache.r6g.large (2 vCPU, 12.93GB RAM)
- **Storage**: 500GB gp3 with 3000 IOPS baseline

### Network Configuration
- **Ingress**: 443/TCP (HTTPS), 80/TCP (redirect to HTTPS)
- **Internal**: 5432/TCP (PostgreSQL), 6379/TCP (Redis), 8200/TCP (Vault)
- **Egress**: 443/TCP (external APIs), 80/TCP (timestamp authorities)

---

## Deployment

### Kubernetes Deployment (Recommended)

#### Prerequisites
```bash
# Install required tools
kubectl version --client
helm version
terraform version

# Set up cluster context
kubectl config use-context qes-production
```

#### Initial Setup
```bash
# 1. Deploy infrastructure components
cd infra/terraform/aws-eks
terraform init
terraform plan -var-file="production.tfvars"
terraform apply

# 2. Install platform components
cd ../../..
helm repo add qes-platform ./charts
helm install qes-platform qes-platform/qes-platform \
  --namespace qes-platform \
  --create-namespace \
  --values charts/qes-platform/values-production.yaml

# 3. Initialize database schemas
kubectl exec -it deploy/qes-platform-api -- \
  python -m backend.core.db_migrations --init-schemas

# 4. Configure Vault
kubectl exec -it qes-platform-vault-0 -- vault auth -method=kubernetes
kubectl exec -it qes-platform-vault-0 -- vault write auth/kubernetes/config \
  kubernetes_host=https://kubernetes.default.svc.cluster.local:443
```

### Docker Compose Deployment (Development)

```bash
# Quick start for development
cd quickstart/
docker-compose up -d

# Initialize development environment
docker-compose exec api python -m backend.core.db_migrations --init-dev-data
```

### Health Check
```bash
# Verify deployment
curl -f https://your-domain.com/health

# Expected response
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "version": "1.0.0",
  "checks": {
    "database": {"status": "healthy"},
    "redis": {"status": "healthy"},
    "vault": {"status": "healthy"},
    "providers": {"status": "healthy"}
  }
}
```

---

## Configuration Management

### Environment Variables

#### Core Application
```bash
# Database
POSTGRES_URL=postgresql://user:pass@host:5432/qes_platform
REDIS_URL=redis://host:6379/0

# Vault Configuration
VAULT_URL=https://vault:8200
VAULT_TOKEN=<vault-token>
VAULT_MOUNT_PATH=qes-platform

# External Services
TSA_URL=http://timestamp.digicert.com
HSM_PKCS11_LIB=/usr/lib/softhsm/libsofthsm2.so

# Application Settings
DEBUG=false
LOG_LEVEL=INFO
CORS_ORIGINS=https://app.example.com
```

#### Security Settings
```bash
# JWT Configuration
JWT_SECRET_KEY=<secure-random-key>
JWT_ALGORITHM=RS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
JWT_REFRESH_TOKEN_EXPIRE_DAYS=30

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_DEFAULT_TIER=professional

# TLS Configuration
TLS_CERT_PATH=/etc/ssl/certs/qes-platform.crt
TLS_KEY_PATH=/etc/ssl/private/qes-platform.key
```

### Vault Configuration

#### PKI Backend Setup
```bash
# Enable PKI secret engine
vault secrets enable -path=qes-platform-pki pki

# Configure CA certificate
vault write qes-platform-pki/config/ca \
  pem_bundle=@ca-cert-and-key.pem

# Set up certificate roles
vault write qes-platform-pki/roles/qes-server \
  allowed_domains="qes-platform.com" \
  allow_subdomains=true \
  max_ttl="8760h"
```

#### Provider Secrets
```bash
# Freja eID Configuration
vault kv put secret/qes-platform/providers/freja-se \
  client_id="freja-client-id" \
  client_secret="freja-client-secret" \
  oauth_endpoint="https://services.test.frejaeid.com/oauth2" \
  scim_endpoint="https://services.test.frejaeid.com/scim" \
  environment="test"

# D-Trust Configuration  
vault kv put secret/qes-platform/providers/dtrust-de \
  client_certificate="@dtrust-client.crt" \
  client_key="@dtrust-client.key" \
  eidas_endpoint="https://www.d-trust.net/eidas" \
  signature_endpoint="https://api.d-trust.net/qes" \
  environment="production"
```

---

## Monitoring & Alerting

### Prometheus Metrics

#### Application Metrics
- `qes_requests_total`: Total HTTP requests
- `qes_request_duration_seconds`: Request duration histogram
- `qes_signatures_created_total`: Total signatures created
- `qes_signatures_verified_total`: Total signatures verified
- `qes_provider_requests_total`: Requests per QES provider
- `qes_rate_limit_hits_total`: Rate limit violations

#### Infrastructure Metrics
- `postgresql_up`: Database connectivity
- `redis_connected_clients`: Redis connections
- `vault_up`: Vault availability
- `kubernetes_pod_restart_total`: Pod restarts

### Grafana Dashboards

#### QES Platform Overview Dashboard
```json
{
  "dashboard": {
    "title": "QES Platform Overview",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [
          "rate(qes_requests_total[5m])"
        ]
      },
      {
        "title": "Error Rate",
        "targets": [
          "rate(qes_requests_total{status=~\"4..|5..\"}[5m])"
        ]
      },
      {
        "title": "Response Time",
        "targets": [
          "histogram_quantile(0.95, qes_request_duration_seconds_bucket)"
        ]
      }
    ]
  }
}
```

### Alert Rules

#### Critical Alerts
```yaml
groups:
- name: qes-platform-critical
  rules:
  - alert: QESPlatformDown
    expr: up{job="qes-platform"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "QES Platform is down"
      
  - alert: DatabaseConnectionFailed
    expr: postgresql_up == 0
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "Database connection failed"

  - alert: HighErrorRate
    expr: rate(qes_requests_total{status=~"5.."}[5m]) > 0.1
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High error rate detected"
```

#### Warning Alerts
```yaml
- name: qes-platform-warnings
  rules:
  - alert: HighResponseTime
    expr: histogram_quantile(0.95, qes_request_duration_seconds_bucket) > 2
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "High response time detected"

  - alert: RateLimitThresholdReached
    expr: rate(qes_rate_limit_hits_total[5m]) > 10
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Rate limit threshold reached"
```

---

## Backup & Recovery

### Database Backup Strategy

#### Automated Backups
```bash
#!/bin/bash
# backup-postgresql.sh

DATE=$(date +"%Y%m%d_%H%M%S")
BACKUP_DIR="/backups/postgresql"
DATABASE="qes_platform"

# Create backup
pg_dump -h $POSTGRES_HOST -U $POSTGRES_USER -d $DATABASE | \
  gzip > $BACKUP_DIR/qes_platform_$DATE.sql.gz

# Verify backup
gunzip -t $BACKUP_DIR/qes_platform_$DATE.sql.gz

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete

# Upload to S3
aws s3 cp $BACKUP_DIR/qes_platform_$DATE.sql.gz \
  s3://qes-platform-backups/postgresql/
```

#### Cron Schedule
```bash
# Daily backup at 2 AM
0 2 * * * /opt/qes-platform/scripts/backup-postgresql.sh

# Weekly full backup on Sunday at 1 AM  
0 1 * * 0 /opt/qes-platform/scripts/backup-postgresql-full.sh
```

### Vault Backup

#### Automated Vault Snapshots
```bash
#!/bin/bash
# backup-vault.sh

DATE=$(date +"%Y%m%d_%H%M%S")
BACKUP_DIR="/backups/vault"

# Create Vault snapshot
vault operator raft snapshot save $BACKUP_DIR/vault_snapshot_$DATE.snap

# Encrypt snapshot
gpg --cipher-algo AES256 --compress-algo 1 --s2k-mode 3 \
  --s2k-digest-algo SHA512 --s2k-count 65536 --symmetric \
  --output $BACKUP_DIR/vault_snapshot_$DATE.snap.gpg \
  $BACKUP_DIR/vault_snapshot_$DATE.snap

# Remove unencrypted snapshot
rm $BACKUP_DIR/vault_snapshot_$DATE.snap

# Upload to S3
aws s3 cp $BACKUP_DIR/vault_snapshot_$DATE.snap.gpg \
  s3://qes-platform-backups/vault/
```

### Disaster Recovery Procedures

#### Database Recovery
```bash
# Stop application
kubectl scale deployment qes-platform-api --replicas=0

# Restore from backup
gunzip -c qes_platform_20240101_020000.sql.gz | \
  psql -h $POSTGRES_HOST -U $POSTGRES_USER -d qes_platform

# Verify data integrity
psql -h $POSTGRES_HOST -U $POSTGRES_USER -d qes_platform \
  -c "SELECT COUNT(*) FROM platform.tenants;"

# Restart application
kubectl scale deployment qes-platform-api --replicas=3
```

#### Complete System Recovery
```bash
# 1. Restore infrastructure
cd infra/terraform/aws-eks
terraform apply

# 2. Restore Vault
vault operator raft snapshot restore vault_snapshot_20240101_010000.snap

# 3. Restore database
# (See database recovery above)

# 4. Redeploy application
helm upgrade qes-platform qes-platform/qes-platform \
  --values charts/qes-platform/values-production.yaml

# 5. Verify all services
kubectl get pods -n qes-platform
curl -f https://your-domain.com/health
```

### Recovery Time Objectives (RTO)

| Component | RTO Target | Recovery Procedure |
|-----------|------------|-------------------|
| API Service | 5 minutes | Auto-scaling, pod restart |
| Database | 30 minutes | Restore from latest backup |
| Vault | 15 minutes | Restore from snapshot |
| Complete System | 2 hours | Full infrastructure rebuild |

### Recovery Point Objectives (RPO)

| Component | RPO Target | Backup Frequency |
|-----------|------------|------------------|
| Database | 1 hour | Continuous WAL + Daily dumps |
| Vault | 1 hour | Hourly snapshots |
| Configuration | 1 day | Daily Git commits |
| Certificates | 4 hours | Sync with Vault backup |

---

## Security Operations

### Certificate Management

#### Certificate Lifecycle
```bash
# Generate new certificate for service
vault write qes-platform-pki/issue/qes-server \
  common_name="api.qes-platform.com" \
  ttl=8760h

# Auto-renewal script
#!/bin/bash
# renew-certificates.sh

CURRENT_CERT="/etc/ssl/certs/qes-platform.crt"
DAYS_UNTIL_EXPIRY=$(openssl x509 -in $CURRENT_CERT -noout -checkend $((30*24*3600)))

if [ $? -ne 0 ]; then
  echo "Certificate expires within 30 days, renewing..."
  
  # Request new certificate from Vault
  vault write -format=json qes-platform-pki/issue/qes-server \
    common_name="api.qes-platform.com" \
    ttl=8760h > new_cert.json
  
  # Extract certificate and key
  jq -r '.data.certificate' new_cert.json > /etc/ssl/certs/qes-platform.crt
  jq -r '.data.private_key' new_cert.json > /etc/ssl/private/qes-platform.key
  
  # Reload services
  kubectl rollout restart deployment/qes-platform-api
fi
```

### Secret Rotation

#### Database Credentials
```bash
# Rotate database password
NEW_PASSWORD=$(openssl rand -base64 32)

# Update in Vault
vault kv put secret/qes-platform/database \
  username="qes_user" \
  password="$NEW_PASSWORD"

# Update database
psql -h $POSTGRES_HOST -U postgres -c \
  "ALTER USER qes_user PASSWORD '$NEW_PASSWORD';"

# Rolling restart of application pods
kubectl rollout restart deployment/qes-platform-api
```

#### API Keys and Tokens
```bash
# Monthly rotation schedule
0 2 1 * * /opt/qes-platform/scripts/rotate-api-keys.sh
0 2 15 * * /opt/qes-platform/scripts/rotate-jwt-keys.sh
```

### Security Monitoring

#### Failed Authentication Attempts
```bash
# Monitor failed logins
kubectl logs -f deployment/qes-platform-api | \
  grep "authentication_failed" | \
  jq '.user_identifier, .source_ip, .timestamp'
```

#### Suspicious Activity Detection
```bash
# Rate limit violations
kubectl logs -f deployment/qes-platform-api | \
  grep "rate_limit_exceeded" | \
  jq '.tenant_id, .source_ip, .endpoint'

# Unusual signature patterns
kubectl logs -f deployment/qes-platform-api | \
  grep "signature_created" | \
  jq 'select(.metadata.batch_size > 50)'
```

---

## Maintenance & Updates

### Update Procedures

#### Application Updates
```bash
# 1. Pre-update health check
curl -f https://your-domain.com/health

# 2. Database migration (if needed)
kubectl exec -it deploy/qes-platform-api -- \
  python -m backend.core.db_migrations --migrate

# 3. Rolling update
helm upgrade qes-platform qes-platform/qes-platform \
  --set image.tag=v1.1.0 \
  --values charts/qes-platform/values-production.yaml

# 4. Post-update verification
kubectl rollout status deployment/qes-platform-api
curl -f https://your-domain.com/health
```

#### Infrastructure Updates
```bash
# Kubernetes cluster update
eksctl update cluster --name qes-platform-cluster --approve

# Node group update
eksctl update nodegroup --cluster qes-platform-cluster \
  --name qes-platform-nodes --approve

# Infrastructure components
cd infra/terraform/aws-eks
terraform plan -var-file="production.tfvars"
terraform apply
```

### Maintenance Windows

#### Weekly Maintenance
- **Time**: Sundays 02:00-04:00 UTC
- **Duration**: 2 hours maximum
- **Activities**: 
  - Security patches
  - Configuration updates
  - Certificate renewals
  - Backup verification

#### Monthly Maintenance
- **Time**: First Sunday of month 01:00-05:00 UTC
- **Duration**: 4 hours maximum
- **Activities**:
  - Major version updates
  - Database maintenance
  - Performance optimization
  - Security audits

### Rollback Procedures

#### Application Rollback
```bash
# Quick rollback to previous version
helm rollback qes-platform

# Specific version rollback
helm rollback qes-platform 3

# Database rollback (if needed)
kubectl exec -it deploy/qes-platform-api -- \
  python -m backend.core.db_migrations --rollback --version=1.0.0
```

#### Infrastructure Rollback
```bash
# Terraform state rollback
cd infra/terraform/aws-eks
terraform apply -var-file="production.tfvars" \
  -target="aws_eks_cluster.qes_platform"
```

---

## Troubleshooting

### Common Issues

#### 1. Database Connection Issues

**Symptoms:**
- 500 errors from API
- "database connection failed" in logs
- Health check failures

**Diagnosis:**
```bash
# Check database status
kubectl exec -it deploy/qes-platform-api -- \
  python -c "
import psycopg2
try:
    conn = psycopg2.connect('$POSTGRES_URL')
    print('Database connection successful')
except Exception as e:
    print(f'Database connection failed: {e}')
"

# Check network connectivity
kubectl exec -it deploy/qes-platform-api -- \
  nc -zv postgres-host 5432
```

**Resolution:**
```bash
# Restart database connection pools
kubectl rollout restart deployment/qes-platform-api

# Check and fix database configuration
kubectl describe service qes-platform-postgresql
```

#### 2. Vault Connectivity Issues

**Symptoms:**
- Authentication failures
- "vault connection timeout" errors
- Certificate provisioning failures

**Diagnosis:**
```bash
# Check Vault status
kubectl exec -it qes-platform-vault-0 -- vault status

# Test Vault connectivity
kubectl exec -it deploy/qes-platform-api -- \
  curl -k https://vault:8200/v1/sys/health
```

**Resolution:**
```bash
# Unseal Vault if needed
kubectl exec -it qes-platform-vault-0 -- vault operator unseal

# Restart Vault service
kubectl rollout restart statefulset/qes-platform-vault
```

#### 3. QES Provider Issues

**Symptoms:**
- Authentication timeouts with external providers
- Signature creation failures
- "provider unavailable" errors

**Diagnosis:**
```bash
# Check provider health
curl -f https://your-domain.com/providers/freja-se/health

# Test external connectivity
kubectl exec -it deploy/qes-platform-api -- \
  curl -I https://services.frejaeid.com/oauth2/authorize
```

**Resolution:**
```bash
# Update provider configuration
vault kv put secret/qes-platform/providers/freja-se \
  client_id="new-client-id" \
  client_secret="new-client-secret"

# Restart application to reload config
kubectl rollout restart deployment/qes-platform-api
```

### Performance Issues

#### High Memory Usage
```bash
# Monitor memory usage
kubectl top pods -n qes-platform

# Check for memory leaks
kubectl exec -it deploy/qes-platform-api -- \
  python -c "
import psutil
import gc
print(f'Memory usage: {psutil.virtual_memory().percent}%')
print(f'Garbage objects: {len(gc.get_objects())}')
"
```

#### High CPU Usage
```bash
# Profile CPU usage
kubectl exec -it deploy/qes-platform-api -- \
  python -m cProfile -s cumulative -m backend.main

# Scale up if needed
kubectl scale deployment qes-platform-api --replicas=5
```

### Log Analysis

#### Centralized Logging with Loki
```bash
# Query recent errors
logcli query '{app="qes-platform"} |= "ERROR"' --since=1h

# Query specific tenant logs
logcli query '{app="qes-platform"} | json | tenant_id="tenant-123"' --since=1h

# Query signature operation logs
logcli query '{app="qes-platform"} | json | operation="sign"' --since=24h
```

#### Debug Mode Activation
```bash
# Enable debug logging temporarily
kubectl set env deployment/qes-platform-api LOG_LEVEL=DEBUG

# Revert to normal logging
kubectl set env deployment/qes-platform-api LOG_LEVEL=INFO
```

---

## Incident Response

### Incident Classification

#### Severity Levels

**P0 - Critical (Complete Outage)**
- Service completely unavailable
- Data loss or corruption
- Security breach
- **Response Time**: Immediate (< 15 minutes)
- **Resolution Target**: 2 hours

**P1 - High (Major Degradation)**
- Significant performance degradation
- Core features unavailable
- Single provider failure
- **Response Time**: 30 minutes
- **Resolution Target**: 4 hours

**P2 - Medium (Minor Issues)**
- Non-critical features affected
- Performance impact < 20%
- **Response Time**: 2 hours
- **Resolution Target**: 24 hours

**P3 - Low (Cosmetic Issues)**
- Documentation issues
- Minor UI problems
- **Response Time**: Next business day
- **Resolution Target**: 1 week

### Incident Response Procedures

#### Initial Response (First 15 minutes)
```bash
# 1. Acknowledge incident
echo "Incident acknowledged at $(date)" >> /var/log/incidents/incident-$(date +%Y%m%d-%H%M%S).log

# 2. Assess impact
kubectl get pods -n qes-platform --show-labels
curl -f https://your-domain.com/health

# 3. Activate incident bridge
# - Notify on-call team via PagerDuty/Slack
# - Set up conference bridge
# - Create incident channel

# 4. Begin mitigation
# - Scale up resources if needed
# - Enable maintenance mode if necessary
```

#### Investigation Phase
```bash
# Collect diagnostic information
kubectl logs --previous deployment/qes-platform-api > incident-logs.txt
kubectl describe deployment qes-platform-api > incident-deployment.txt
kubectl top pods -n qes-platform > incident-resources.txt

# Check external dependencies
curl -w "%{http_code} %{time_total}" -o /dev/null -s \
  https://services.frejaeid.com/oauth2/authorize
```

#### Communication Templates

**Initial Notification (< 15 minutes)**
```
Subject: [P0 INCIDENT] QES Platform Service Disruption

We are currently experiencing issues with the QES Platform service.

Impact: [Describe impact]
Status: Investigating
Next Update: 30 minutes

Incident Response Team Activated
Incident ID: INC-2024-001
```

**Update Notification (Every 30 minutes)**
```
Subject: [P0 INCIDENT UPDATE] QES Platform Service Disruption

Status Update for Incident INC-2024-001

Current Status: [Investigating/Mitigating/Resolved]
Root Cause: [If known]
ETA for Resolution: [If available]
Next Update: 30 minutes
```

**Resolution Notification**
```
Subject: [RESOLVED] QES Platform Service Disruption

Incident INC-2024-001 has been resolved.

Resolution Summary: [Brief description]
Duration: [Total time]
Root Cause: [Identified cause]
Follow-up Actions: [If any]

Post-incident review scheduled for [date/time]
```

### Post-Incident Review

#### Review Meeting Agenda
1. **Timeline Review** (15 minutes)
   - Incident detection time
   - Response time
   - Key decisions and actions
   - Resolution time

2. **Root Cause Analysis** (20 minutes)
   - Contributing factors
   - Why detection was delayed
   - Why resolution took X time

3. **Action Items** (20 minutes)
   - Immediate fixes required
   - Process improvements
   - Monitoring enhancements
   - Documentation updates

4. **Follow-up** (5 minutes)
   - Action item owners
   - Due dates
   - Next review date

#### Post-Incident Report Template
```markdown
# Post-Incident Review: INC-2024-001

## Summary
Brief description of incident and impact.

## Timeline
- 14:00 UTC: First alert received
- 14:05 UTC: Investigation began
- 14:30 UTC: Root cause identified
- 15:00 UTC: Fix deployed
- 15:15 UTC: Service restored

## Root Cause
Detailed analysis of what caused the incident.

## Impact Assessment
- Duration: 1 hour 15 minutes
- Affected Users: 1,200 users
- Failed Requests: 4,500
- Revenue Impact: €15,000

## What Went Well
- Quick detection (5 minutes)
- Effective team coordination
- Clear communication

## What Could Be Improved
- Automated rollback procedure
- Better monitoring alerts
- Faster diagnosis tools

## Action Items
1. Implement automated rollback (Owner: DevOps, Due: 2024-01-15)
2. Enhanced monitoring alerts (Owner: SRE, Due: 2024-01-20)
3. Update runbook procedures (Owner: Ops, Due: 2024-01-10)
```

---

## Capacity Planning

### Performance Benchmarks

#### Load Testing Results
```bash
# Standard load test (1000 concurrent users)
Expected Performance:
- Requests/second: 2,000
- Average response time: < 200ms
- 95th percentile: < 500ms
- Error rate: < 0.1%

# Peak load test (5000 concurrent users)
Expected Performance:
- Requests/second: 8,000
- Average response time: < 500ms
- 95th percentile: < 1,000ms
- Error rate: < 1%
```

#### Resource Utilization Targets
| Resource | Normal Load | Peak Load | Alert Threshold |
|----------|-------------|-----------|-----------------|
| CPU | 40-60% | 70-80% | 85% |
| Memory | 50-70% | 75-85% | 90% |
| Database Connections | 20-40 | 60-80 | 90 |
| Network I/O | 100 Mbps | 500 Mbps | 800 Mbps |

### Scaling Strategies

#### Horizontal Pod Autoscaler
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: qes-platform-api-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: qes-platform-api
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

#### Database Scaling
```bash
# Read replicas for scaling read operations
CREATE_READ_REPLICA_COMMAND="
aws rds create-db-instance-read-replica \
  --db-instance-identifier qes-platform-read-replica-1 \
  --source-db-instance-identifier qes-platform-primary \
  --db-instance-class db.r5.xlarge
"

# Connection pooling optimization
PG_BOUNCER_CONFIG="
pool_mode = transaction
default_pool_size = 100
max_client_conn = 1000
server_lifetime = 3600
"
```

### Growth Projections

#### 12-Month Capacity Plan

| Month | Expected Users | Signatures/Day | Infrastructure Scaling |
|-------|---------------|----------------|------------------------|
| Month 1 | 1,000 | 5,000 | Current setup |
| Month 3 | 2,500 | 12,500 | +2 API pods |
| Month 6 | 5,000 | 25,000 | +1 DB replica, +4 API pods |
| Month 9 | 7,500 | 37,500 | +1 cache cluster |
| Month 12 | 10,000 | 50,000 | +2 DB replicas, +8 API pods |

#### Cost Projections
```bash
# Current monthly costs (estimated)
AWS_COSTS="
EKS Cluster: $150
RDS Primary: $400
ElastiCache: $200
Storage (S3/EBS): $300
Data Transfer: $100
Load Balancer: $50
Total: $1,200/month
"

# 12-month projection
PROJECTED_COSTS="
Month 1: $1,200
Month 6: $2,400
Month 12: $4,800
"
```

---

## Compliance & Auditing

### eIDAS Compliance Requirements

#### Technical Requirements Checklist
- [ ] **Qualified Electronic Signature Creation**
  - [ ] Cryptographic algorithms comply with ETSI TS 119 312
  - [ ] Signature creation data uniquely linked to signatory
  - [ ] Signature creation data under sole control of signatory
  - [ ] Signature detectable if data changed after signing

- [ ] **Qualified Certificate Requirements**
  - [ ] Certificate from qualified trust service provider
  - [ ] Certificate contains required attributes per EN 319 412-1
  - [ ] Certificate validation against trust lists
  - [ ] Real-time revocation status checking (OCSP)

- [ ] **Signature Validation**
  - [ ] Cryptographic signature verification
  - [ ] Certificate path validation
  - [ ] Certificate status verification
  - [ ] Time-stamp verification (for T and LTA levels)

#### Audit Trail Requirements
```sql
-- Audit log structure for compliance
CREATE TABLE platform.audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    user_id UUID,
    event_type VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    source_ip INET,
    user_agent TEXT,
    event_data JSONB NOT NULL,
    integrity_hash VARCHAR(128) NOT NULL
);

-- Required audit events
INSERT INTO platform.audit_event_types VALUES
('authentication_attempt', 'User authentication attempt'),
('authentication_success', 'Successful authentication'),
('authentication_failure', 'Failed authentication'),
('signature_request', 'Signature creation request'),
('signature_created', 'Signature successfully created'),
('signature_failed', 'Signature creation failed'),
('verification_request', 'Signature verification request'),
('certificate_issued', 'Certificate issued to user'),
('certificate_revoked', 'Certificate revocation'),
('admin_action', 'Administrative action performed');
```

### GDPR Compliance

#### Data Protection Measures
```bash
# Personal data encryption at rest
ENCRYPTION_CONFIG="
Database: AES-256 encryption
File Storage: AES-256 encryption
Backups: GPG encryption with 4096-bit keys
Key Management: HashiCorp Vault with auto-rotation
"

# Data retention policies
DATA_RETENTION="
User authentication logs: 3 years
Signature metadata: 10 years (legal requirement)
Personal identifiers: Until user deletion + 30 days
Audit logs: 7 years (compliance requirement)
"
```

#### User Data Rights Implementation
```python
# Data Subject Request Handler
class DataSubjectRequestHandler:
    def handle_data_export_request(self, user_id: str):
        """Export all user data in machine-readable format"""
        pass
    
    def handle_data_deletion_request(self, user_id: str):
        """Delete user data while preserving audit trail"""
        pass
    
    def handle_data_rectification_request(self, user_id: str, corrections: dict):
        """Update incorrect personal data"""
        pass
```

### SOC 2 Type II Compliance

#### Control Objectives

**Security Controls:**
- [ ] Multi-factor authentication for admin access
- [ ] Encryption of data in transit and at rest
- [ ] Regular security vulnerability assessments
- [ ] Incident response procedures documented and tested

**Availability Controls:**
- [ ] 99.9% uptime SLA monitoring
- [ ] Automated backup and recovery procedures
- [ ] Disaster recovery plan tested quarterly
- [ ] Capacity planning and performance monitoring

**Processing Integrity Controls:**
- [ ] Digital signature validation procedures
- [ ] Transaction logging and monitoring
- [ ] Error handling and retry mechanisms
- [ ] Data quality checks and validation

**Confidentiality Controls:**
- [ ] Role-based access controls
- [ ] Data classification and handling procedures
- [ ] Secure development lifecycle
- [ ] Third-party security assessments

**Privacy Controls:**
- [ ] Privacy impact assessments
- [ ] Data retention and disposal procedures
- [ ] User consent management
- [ ] Data subject rights implementation

### Audit Procedures

#### Annual Security Audit
```bash
# Security audit checklist
SECURITY_AUDIT_ITEMS="
1. Penetration testing (external)
2. Code security review
3. Infrastructure security assessment
4. Access control review
5. Cryptographic implementation review
6. Incident response testing
7. Backup and recovery testing
8. Vendor security assessments
"

# Compliance audit schedule
COMPLIANCE_SCHEDULE="
Q1: Internal SOC 2 readiness assessment
Q2: eIDAS technical compliance review
Q3: GDPR compliance audit
Q4: External SOC 2 Type II audit
"
```

#### Evidence Collection
```bash
# Automated evidence collection
#!/bin/bash
# collect-audit-evidence.sh

DATE=$(date +%Y%m%d)
EVIDENCE_DIR="/audit/evidence/$DATE"

mkdir -p $EVIDENCE_DIR

# System configuration
kubectl get all -n qes-platform -o yaml > $EVIDENCE_DIR/k8s-config.yaml
vault policy list > $EVIDENCE_DIR/vault-policies.txt

# Access logs
kubectl logs deployment/qes-platform-api --since=24h | \
  grep "authentication\|authorization" > $EVIDENCE_DIR/access-logs.txt

# Security scan results
trivy image qes-platform/api:latest > $EVIDENCE_DIR/vulnerability-scan.txt

# Compliance reports
python -m backend.compliance.generate_report > $EVIDENCE_DIR/compliance-report.json
```

---

## Contact Information

### Escalation Matrix

| Role | Contact | Responsibility |
|------|---------|----------------|
| **On-Call Engineer** | +1-555-0101 | First response, initial troubleshooting |
| **Platform Lead** | +1-555-0102 | Technical decisions, architecture issues |
| **Security Officer** | +1-555-0103 | Security incidents, compliance issues |
| **Operations Manager** | +1-555-0104 | Business decisions, external communication |

### Emergency Contacts

**24/7 Support:**
- **Phone**: +1-555-QES-HELP (+1-555-737-4357)
- **Email**: support@qes-platform.com
- **Slack**: #qes-platform-alerts

**Vendor Contacts:**
- **AWS Support**: Case #12345678
- **Freja eID**: support@frejaeid.com
- **D-Trust**: technical@d-trust.net

### Documentation Resources

- **Internal Wiki**: https://wiki.company.com/qes-platform
- **API Documentation**: https://docs.qes-platform.com
- **Monitoring Dashboard**: https://monitoring.qes-platform.com
- **Code Repository**: https://github.com/company/qes-platform

---

*This operations manual should be reviewed and updated quarterly to ensure accuracy and completeness.*

**Last Updated**: January 1, 2024  
**Version**: 1.0  
**Next Review**: April 1, 2024