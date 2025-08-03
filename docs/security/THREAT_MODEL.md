# eIDAS QES Platform - Threat Model (STRIDE)

## Executive Summary

This document presents a comprehensive threat model for the eIDAS QES Digital Signing Platform using the STRIDE methodology. The platform handles qualified electronic signatures across multiple EU countries, making security paramount for regulatory compliance and user trust.

**Risk Level**: HIGH - Platform handles legally binding digital signatures
**Compliance Requirements**: eIDAS Regulation, ETSI standards, GDPR

---

## 1. System Overview

### Architecture Components

```
┌─────────────────────────────────────────────────────────┐
│                    Public Internet                      │
└─────────────────────┬───────────────────────────────────┘
                      │ HTTPS/TLS 1.3
┌─────────────────────▼───────────────────────────────────┐
│               API Gateway + WAF                        │
│           (Rate Limiting, DDoS Protection)             │
└─────────────────────┬───────────────────────────────────┘
                      │ JWT/OIDC
┌─────────────────────▼───────────────────────────────────┐
│                 Backend API                             │
│        (FastAPI + Signing Engine + Audit)              │
└─┬───────────────────┬───────────────────────────────────┘
  │                   │
  ▼                   ▼
┌─────────────────┐ ┌─────────────────────────────────────┐
│   PostgreSQL    │ │        QES Provider Adapters        │
│   + Redis       │ │   ┌─────┐ ┌─────┐ ┌─────┐          │
│   + MinIO       │ │   │ SE  │ │ DE  │ │ ES  │          │
└─────────────────┘ └───└─────┘─└─────┘─└─────┘──────────┘
        ▲                         │
        │                         ▼
┌─────────────────┐ ┌─────────────────────────────────────┐
│ HashiCorp Vault │ │        External Services            │
│    + HSM/KMS    │ │  • eIDAS Nodes  • TSA Servers      │
└─────────────────┘ └─────────────────────────────────────┘
```

### Trust Boundaries

1. **Internet ↔ API Gateway**: Public untrusted network
2. **API Gateway ↔ Backend**: Internal trusted network  
3. **Backend ↔ Database**: Encrypted internal comms
4. **Backend ↔ QES Providers**: Encrypted external APIs
5. **Backend ↔ Vault/HSM**: Encrypted key management

---

## 2. STRIDE Threat Analysis

### 2.1 Spoofing (S) - Identity Attacks

#### S1: User Identity Spoofing
**Threat**: Attacker impersonates legitimate user to obtain QES certificate
- **Attack Vector**: Compromised credentials, social engineering
- **Impact**: HIGH - Fraudulent legally binding signatures
- **Probability**: MEDIUM
- **Mitigations**:
  - Multi-factor authentication (MFA) mandatory
  - eIDAS Level of Assurance "HIGH" required
  - Biometric authentication where available
  - Real-time fraud detection algorithms
  - Certificate binding to eIDAS attributes

#### S2: Provider/Service Spoofing  
**Threat**: Malicious actor impersonates QES provider or eIDAS node
- **Attack Vector**: DNS hijacking, certificate substitution
- **Impact**: HIGH - Man-in-the-middle attacks on signing process
- **Probability**: LOW
- **Mitigations**:
  - Certificate pinning for all external services
  - Mutual TLS authentication
  - Regular certificate validation
  - Provider service health monitoring

#### S3: API Gateway Spoofing
**Threat**: Fake API endpoints to capture credentials/documents
- **Attack Vector**: Phishing, DNS poisoning
- **Impact**: HIGH - Credential theft, document interception
- **Probability**: MEDIUM
- **Mitigations**:
  - HSTS headers with long max-age
  - Certificate Transparency monitoring
  - Domain validation processes
  - User education on official domains

### 2.2 Tampering (T) - Data Integrity Attacks

#### T1: Document Tampering
**Threat**: Modification of documents during signing process
- **Attack Vector**: MITM attacks, compromised storage
- **Impact**: CRITICAL - Invalid signatures, legal disputes
- **Probability**: MEDIUM
- **Mitigations**:
  - Document hash verification at multiple stages
  - Immutable audit trail with cryptographic proofs
  - End-to-end encryption of document pipeline
  - Integrity checks using HMAC

#### T2: Signature Tampering
**Threat**: Modification of digital signatures post-creation
- **Attack Vector**: Database compromise, storage corruption
- **Impact**: CRITICAL - Signature invalidation
- **Probability**: LOW
- **Mitigations**:
  - XAdES-LTA with archival timestamps
  - Immutable storage (WORM - Write Once Read Many)
  - Blockchain-based signature anchoring (optional)
  - Regular signature validation jobs

#### T3: Configuration Tampering
**Threat**: Unauthorized changes to system configuration
- **Attack Vector**: Admin account compromise, privilege escalation
- **Impact**: HIGH - System compromise, backdoors
- **Probability**: MEDIUM
- **Mitigations**:
  - Infrastructure as Code (IaC) with version control
  - Configuration drift detection
  - Admin access logging and approval workflows
  - Immutable infrastructure where possible

### 2.3 Repudiation (R) - Non-repudiation Failures

#### R1: Signature Repudiation
**Threat**: User claims they didn't sign a document
- **Attack Vector**: Legal challenges, compromised keys
- **Impact**: CRITICAL - Legal validity questioned
- **Probability**: HIGH (business risk)
- **Mitigations**:
  - Comprehensive audit trails with timestamps
  - Video/photo evidence during signing (where applicable)
  - IP address and device fingerprinting
  - Legal framework documentation
  - Strong user authentication logs

#### R2: System Action Repudiation
**Threat**: System administrators deny performing actions
- **Attack Vector**: Insufficient logging, log tampering
- **Impact**: MEDIUM - Compliance violations
- **Probability**: LOW
- **Mitigations**:
  - Immutable audit logs in Loki/Grafana
  - Multi-signature admin operations
  - External log shipping and backup
  - Regular audit log reviews

### 2.4 Information Disclosure (I) - Confidentiality Breaches

#### I1: Document Exposure
**Threat**: Unauthorized access to user documents
- **Attack Vector**: Database breach, insufficient access controls
- **Impact**: HIGH - Privacy violations, GDPR breaches
- **Probability**: MEDIUM
- **Mitigations**:
  - Document encryption at rest (AES-256)
  - Document encryption in transit (TLS 1.3)
  - Zero-knowledge architecture where possible
  - Document retention policies and auto-deletion
  - Access control with principle of least privilege

#### I2: Personal Data Exposure
**Threat**: Leakage of PII from eIDAS attributes
- **Attack Vector**: Log exposure, database dump
- **Impact**: HIGH - GDPR violations, identity theft
- **Probability**: MEDIUM  
- **Mitigations**:
  - PII pseudonymization in logs
  - Data minimization principles
  - Encryption of PII fields in database
  - Regular data protection impact assessments
  - Access logging for all PII access

#### I3: Cryptographic Key Exposure
**Threat**: Exposure of signing keys or certificates
- **Attack Vector**: HSM compromise, key extraction
- **Impact**: CRITICAL - Complete system compromise
- **Probability**: LOW
- **Mitigations**:
  - Hardware Security Modules (HSM) for key storage
  - Key rotation policies
  - Multi-person key ceremony procedures
  - Key escrow for disaster recovery
  - Regular security audits of key management

### 2.5 Denial of Service (D) - Availability Attacks

#### D1: Application Layer DoS
**Threat**: Resource exhaustion through excessive requests
- **Attack Vector**: Distributed attacks, resource-intensive operations
- **Impact**: HIGH - Service unavailability
- **Probability**: HIGH
- **Mitigations**:
  - Rate limiting per IP/user/tenant
  - Request size limitations
  - Circuit breakers for external services
  - Auto-scaling infrastructure
  - DDoS protection at CDN level

#### D2: Database DoS
**Threat**: Database performance degradation or crash
- **Attack Vector**: SQL injection, excessive queries
- **Impact**: HIGH - Complete system unavailability
- **Probability**: MEDIUM
- **Mitigations**:
  - Database connection pooling
  - Query timeout configurations
  - Read replicas for load distribution
  - Database resource monitoring
  - SQL injection prevention (parameterized queries)

#### D3: External Service DoS
**Threat**: QES providers or eIDAS nodes become unavailable
- **Attack Vector**: Provider outages, network issues
- **Impact**: MEDIUM - Reduced functionality per country
- **Probability**: MEDIUM
- **Mitigations**:
  - Multiple provider support per country
  - Graceful degradation strategies
  - Provider health monitoring
  - User notification systems
  - Service level agreement monitoring

### 2.6 Elevation of Privilege (E) - Authorization Attacks

#### E1: Privilege Escalation
**Threat**: Users gain unauthorized administrative access
- **Attack Vector**: Software vulnerabilities, misconfigurations
- **Impact**: CRITICAL - Complete system compromise
- **Probability**: LOW
- **Mitigations**:
  - Principle of least privilege enforcement
  - Regular security patching
  - Role-based access control (RBAC)
  - Privilege escalation monitoring
  - Regular penetration testing

#### E2: Cross-Tenant Access
**Threat**: Multi-tenant isolation breach
- **Attack Vector**: Application bugs, injection attacks
- **Impact**: HIGH - Data breaches across customers
- **Probability**: MEDIUM
- **Mitigations**:
  - Database schema isolation per tenant
  - Row-level security policies
  - Tenant ID validation in all queries
  - Regular security testing of isolation
  - Tenant-specific encryption keys

#### E3: Container Escape
**Threat**: Escape from containerized environment
- **Attack Vector**: Container runtime vulnerabilities
- **Impact**: HIGH - Host system compromise
- **Probability**: LOW
- **Mitigations**:
  - Container image scanning
  - Runtime security monitoring
  - Non-root container execution
  - Security contexts and policies
  - Regular container updates

---

## 3. Risk Assessment Matrix

| Threat ID | Threat | Probability | Impact | Risk Level | Priority |
|-----------|---------|-------------|---------|------------|----------|
| T1 | Document Tampering | Medium | Critical | HIGH | 1 |
| T2 | Signature Tampering | Low | Critical | MEDIUM | 2 |
| I3 | Cryptographic Key Exposure | Low | Critical | MEDIUM | 3 |
| R1 | Signature Repudiation | High | Critical | HIGH | 4 |
| S1 | User Identity Spoofing | Medium | High | MEDIUM | 5 |
| E1 | Privilege Escalation | Low | Critical | MEDIUM | 6 |
| I1 | Document Exposure | Medium | High | MEDIUM | 7 |
| I2 | Personal Data Exposure | Medium | High | MEDIUM | 8 |
| D1 | Application Layer DoS | High | High | HIGH | 9 |
| E2 | Cross-Tenant Access | Medium | High | MEDIUM | 10 |

---

## 4. Security Controls Implementation

### 4.1 Preventive Controls
- Multi-factor authentication (MFA)
- End-to-end encryption (TLS 1.3, AES-256)
- Hardware Security Modules (HSM)
- Web Application Firewall (WAF)
- Input validation and sanitization
- Role-based access control (RBAC)
- Network segmentation
- Certificate pinning

### 4.2 Detective Controls
- Security Information and Event Management (SIEM)
- Intrusion Detection System (IDS)
- File integrity monitoring
- Audit logging with immutable storage
- Real-time monitoring and alerting
- Vulnerability scanning
- Penetration testing
- Security metrics and dashboards

### 4.3 Corrective Controls
- Incident response procedures
- Automated security patching
- Backup and disaster recovery
- Security incident escalation
- Forensic analysis capabilities
- Business continuity planning

---

## 5. Compliance Requirements

### eIDAS Regulation
- Qualified Electronic Signature (QES) standards
- Level of Assurance (LoA) HIGH for authentication
- Long-term signature validation (LTV)
- Audit trail requirements

### ETSI Standards
- ETSI EN 319 401 (General Policy Requirements)
- ETSI EN 319 411 (Certificate Policies)
- ETSI EN 319 421 (Policy and Security Requirements)
- ETSI TS 119 312 (Cryptographic Suites)

### GDPR Requirements
- Data minimization principles
- Consent management
- Right to erasure implementation
- Data protection by design
- Privacy impact assessments

---

## 6. Monitoring and Alerting

### Critical Security Events
1. **Failed authentication attempts** (>5 per user per hour)
2. **Privilege escalation attempts**
3. **Unusual API access patterns**
4. **Database integrity violations**
5. **Certificate validation failures**
6. **HSM/Vault access anomalies**
7. **Cross-tenant data access attempts**
8. **Signature verification failures**

### Security Metrics
- Authentication success/failure rates
- API response times and error rates
- Certificate expiration tracking
- Vault secret access frequency
- Database connection patterns
- Network traffic anomalies

---

## 7. Incident Response Plan

### Severity Levels
- **CRITICAL**: Active attack, data breach, system compromise
- **HIGH**: Security control failure, potential data exposure
- **MEDIUM**: Suspicious activity, policy violations
- **LOW**: Minor security issues, informational alerts

### Response Timeline
- **CRITICAL**: 15 minutes detection, 1 hour containment
- **HIGH**: 1 hour detection, 4 hours containment  
- **MEDIUM**: 4 hours detection, 24 hours resolution
- **LOW**: 24 hours detection, 72 hours resolution

### Response Team
- Security Officer (primary contact)
- Platform Administrator
- Legal/Compliance Officer
- Customer Communication Lead
- External Security Consultant (if needed)

---

## 8. Security Testing Strategy

### Regular Testing Schedule
- **Daily**: Automated vulnerability scans
- **Weekly**: Security regression tests
- **Monthly**: Penetration testing of external interfaces
- **Quarterly**: Full security assessment
- **Annually**: Third-party security audit

### Testing Scope
- Application security (OWASP Top 10)
- Infrastructure security
- Container and deployment security
- API security testing
- Social engineering assessments
- Physical security (for on-premises deployments)

---

## 9. Conclusion

The eIDAS QES Platform faces significant security challenges due to its role in providing legally binding digital signatures. The threat model identifies key risks and provides comprehensive mitigation strategies.

**Key Recommendations:**
1. Implement HSM-based key management immediately
2. Establish comprehensive audit logging before production
3. Conduct regular penetration testing
4. Implement real-time security monitoring
5. Ensure GDPR compliance for all PII handling

This threat model should be reviewed and updated quarterly as the platform evolves and new threats emerge.

---

**Document Version**: 1.0  
**Last Updated**: December 2024  
**Next Review**: March 2025  
**Owner**: Security Team  
**Approver**: CISO