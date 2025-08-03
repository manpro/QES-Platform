# QES Platform Monitoring and Metrics

Comprehensive monitoring, metrics collection, and alerting system for business intelligence and operational insights.

## Features

### 📊 Business Intelligence
- **Revenue Analytics**: Real-time revenue tracking, forecasting, and trend analysis
- **User Behavior Analytics**: User activity patterns, engagement metrics, and retention analysis
- **Feature Usage Metrics**: Detailed tracking of feature adoption and usage patterns
- **Performance Analytics**: Response times, error rates, and system performance trends

### 🚨 Advanced Alerting
- **Multi-Channel Notifications**: Email, Slack, Discord, Webhook, SMS, PagerDuty
- **Smart Escalation**: Automatic escalation based on severity and response times
- **Alert Throttling**: Intelligent deduplication and frequency limiting
- **Template-Based Messaging**: Customizable alert templates for different channels

### ⚡ Performance Monitoring
- **Real-Time Metrics**: Live performance dashboards with sub-second updates
- **Resource Utilization**: CPU, memory, disk, and network monitoring
- **Slow Query Detection**: Automatic detection and alerting for performance issues
- **Request Tracing**: Detailed request lifecycle tracking with unique IDs

### 🎯 Prometheus Integration
- **Native Metrics Export**: Full Prometheus metrics on port 8001
- **Grafana Dashboards**: Pre-configured dashboards for business and technical metrics
- **Custom Metrics**: Easy addition of business-specific metrics
- **Alertmanager Integration**: Professional alerting with Prometheus Alertmanager

## API Endpoints

### Dashboard and Analytics
- `GET /api/v1/metrics/dashboard?days=7` - Comprehensive dashboard data
- `GET /api/v1/metrics/business-intelligence?days=30` - Business intelligence analytics
- `GET /api/v1/metrics/performance?hours=24` - Performance metrics and trends

### Custom Metrics
- `POST /api/v1/metrics/record` - Record custom business metrics (admin only)
- `GET /api/v1/metrics/health` - Monitoring system health check

### Alerting Management
- `GET /api/v1/metrics/alerts?active_only=true` - Get active alerts
- `POST /api/v1/metrics/alerts/configure` - Configure notification channels (admin only)
- `POST /api/v1/metrics/alerts/test?channel=slack` - Test alert delivery (admin only)

## Metrics Types

### Business Metrics
```python
# Revenue tracking
await metrics_collector.record_metric(
    metric_type=MetricType.REVENUE,
    name="subscription_revenue",
    value=29.99,
    labels={"plan": "professional", "currency": "usd"}
)

# Feature usage
await metrics_collector.record_business_event(
    event_type="document_signed",
    tenant_id=tenant_id,
    value=1,
    metadata={"signature_type": "advanced"}
)
```

### Performance Metrics
```python
# Response time tracking (automatic via middleware)
await metrics_collector.record_performance_metric(
    operation="document_upload",
    duration=1.25,
    success=True,
    metadata={"file_size": 1024000}
)
```

### Custom Metrics
```python
# Custom business metrics
await metrics_collector.record_metric(
    metric_type=MetricType.FEATURE_USAGE,
    name="api_integration_usage",
    value=1,
    labels={"integration": "salesforce", "tenant": str(tenant_id)}
)
```

## Alert Configuration

### Email Alerts
```python
alerting_system.configure_channel(
    NotificationChannel.EMAIL,
    {
        'host': 'smtp.gmail.com',
        'port': 587,
        'use_tls': True,
        'from_email': 'alerts@qes-platform.com',
        'to_email': 'admin@qes-platform.com',
        'username': 'alerts@qes-platform.com',
        'password': 'your-app-password'  # Use environment variable
    }
)
```

### Slack Integration
```python
alerting_system.configure_channel(
    NotificationChannel.SLACK,
    {
        'webhook_url': 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK',
        'channel': '#alerts'
    }
)
```

### Webhook Notifications
```python
alerting_system.configure_channel(
    NotificationChannel.WEBHOOK,
    {
        'url': 'https://your-system.com/alerts',
        'headers': {
            'Authorization': 'Bearer your-token',
            'X-Source': 'QES-Platform'
        }
    }
)
```

## Prometheus Metrics

The system exposes comprehensive Prometheus metrics on port 8001:

### Business Metrics
- `qes_revenue_total{plan_type, currency}` - Total revenue by plan and currency
- `qes_subscriptions_active{plan_type}` - Active subscriptions by plan
- `qes_users_active{time_period}` - Active users by time period

### Performance Metrics
- `qes_request_duration_seconds{method, endpoint, status}` - Request duration histogram
- `qes_requests_total{method, endpoint, status}` - Total request counter
- `qes_error_rate{service, error_type}` - Error rate percentage

### Usage Metrics
- `qes_usage_total{tenant_id, metric_type}` - Usage by tenant and metric type
- `qes_quota_utilization{tenant_id, metric_type}` - Quota utilization percentage

### System Health
- `qes_database_connections{database}` - Database connection count
- `qes_external_api_response_time_seconds{provider, operation}` - External API response time

## Alert Conditions

### Pre-configured Alerts
1. **High Error Rate** (Critical): `error_rate > 5%`
2. **Slow Response Time** (Warning): `avg_response_time > 2s`
3. **Low Disk Space** (Warning): `disk_usage > 80%`
4. **Quota Exceeded** (Info): `quota_utilization > 90%`
5. **High CPU Usage** (Warning): `cpu_usage > 85%`
6. **Memory Usage** (Critical): `memory_usage > 95%`

### Custom Alert Example
```python
{
    "id": "custom_business_alert",
    "name": "Low Conversion Rate",
    "severity": AlertSeverity.WARNING,
    "condition": "conversion_rate < 2.5",
    "threshold": 2.5,
    "metric": "business_conversion_rate"
}
```

## Dashboard Data Structure

### Business Intelligence Dashboard
```json
{
    "tenant_id": "uuid",
    "period": {"start": "2024-01-01", "end": "2024-01-31", "days": 30},
    "business_metrics": {
        "revenue": {"total": 2500.00, "new": 500.00, "recurring": 2000.00},
        "usage": {"signatures": 1250, "documents": 5000},
        "activity": {"active_users": 150, "new_users": 25}
    },
    "performance_metrics": {
        "avg_response_time": 0.85,
        "error_rate": 1.2,
        "throughput": 1500,
        "uptime": 99.95
    },
    "alerts": {
        "active_count": 2,
        "alerts": [...]
    },
    "recommendations": [
        "Consider optimizing database queries for faster response times",
        "Monitor error rate trend - slight increase detected"
    ]
}
```

## Grafana Integration

### Pre-configured Dashboards
1. **Business Overview** - Revenue, users, subscriptions, usage trends
2. **System Performance** - Response times, error rates, throughput
3. **Infrastructure** - CPU, memory, disk, network utilization
4. **Security** - Authentication attempts, security violations
5. **Usage Analytics** - Feature usage, quota utilization, tenant activity

### Custom Dashboard Variables
- `$tenant_id` - Filter by specific tenant
- `$time_range` - Configurable time ranges
- `$service` - Filter by service component
- `$severity` - Alert severity filter

## Setup and Configuration

### 1. Environment Variables
```bash
# Prometheus metrics
PROMETHEUS_METRICS_PORT=8001

# Alert configuration
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
EMAIL_SMTP_HOST=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_FROM=alerts@qes-platform.com
EMAIL_TO=admin@qes-platform.com

# Monitoring settings
SLOW_REQUEST_THRESHOLD=2.0
RESOURCE_MONITORING_INTERVAL=60
```

### 2. Docker Compose Integration
The metrics system integrates with the existing Docker Compose setup:
- Prometheus scrapes metrics from port 8001
- Grafana connects to Prometheus for dashboards
- Redis stores real-time metrics cache

### 3. Production Deployment
```bash
# Start metrics collection
curl -X POST http://localhost:8000/api/v1/metrics/health

# Configure Slack alerts
curl -X POST http://localhost:8000/api/v1/metrics/alerts/configure \
  -H "Content-Type: application/json" \
  -d '{"channel": "slack", "enabled": true, "config": {...}}'

# Test alert delivery
curl -X POST http://localhost:8000/api/v1/metrics/alerts/test?channel=slack
```

## Monitoring Best Practices

### 1. Alert Fatigue Prevention
- Set appropriate thresholds to avoid noise
- Use escalation policies for critical alerts
- Implement alert acknowledgment and resolution tracking

### 2. Performance Optimization
- Monitor key business metrics regularly
- Set up predictive alerting for capacity planning
- Track user experience metrics (response times, errors)

### 3. Security Monitoring
- Monitor authentication failure rates
- Track unusual usage patterns
- Alert on security policy violations

### 4. Business Intelligence
- Review metrics dashboards weekly
- Analyze usage trends for product decisions
- Monitor conversion rates and user engagement

## Troubleshooting

### Common Issues
1. **Metrics not appearing**: Check port 8001 accessibility
2. **Alerts not firing**: Verify channel configuration
3. **High memory usage**: Adjust metrics buffer size
4. **Missing data**: Check Redis connectivity

### Debug Commands
```bash
# Check metrics service health
curl http://localhost:8000/api/v1/metrics/health

# View active alerts
curl http://localhost:8000/api/v1/metrics/alerts

# Test notification channels
curl -X POST http://localhost:8000/api/v1/metrics/alerts/test?channel=email
```