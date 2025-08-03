# ETSI Compliance Policy - eIDAS QES Platform

## Document Information

**Document Title**: ETSI Compliance Policy for eIDAS QES Digital Signing Platform  
**Document Version**: 1.0  
**Date**: December 2024  
**Classification**: Internal  
**Owner**: Compliance Team  
**Approved by**: Technical Director  

---

## 1. Executive Summary

This document defines the compliance requirements and implementation strategy for the eIDAS QES Digital Signing Platform to meet ETSI (European Telecommunications Standards Institute) standards for qualified electronic signatures.

**Scope**: This policy covers all aspects of QES certificate issuance, digital signature creation, validation, and long-term preservation in accordance with EU regulations.

**Regulatory Framework**:
- eIDAS Regulation (EU) No 910/2014
- ETSI EN 319 series standards
- ISO/IEC 19790 (FIPS 140-2)
- Common Criteria (ISO/IEC 15408)

---

## 2. ETSI Standards Compliance Matrix

### 2.1 ETSI EN 319 401 - General Policy Requirements

| Requirement | Standard Reference | Implementation | Status |
|-------------|-------------------|----------------|---------|
| Certificate Policy Framework | EN 319 401-1 | PKI policies defined in Vault | ✅ Implemented |
| Signature Policy Framework | EN 319 401-2 | Signature policies per format | ✅ Implemented |
| Time-stamping Policy | EN 319 401-3 | TSA integration required | 🔄 In Progress |
| Validation Service Policy | EN 319 401-4 | Validation service planned | 📋 Planned |

### 2.2 ETSI EN 319 411 - Certificate Policies and Certification Practice Statements

| Requirement | Standard Reference | Implementation | Status |
|-------------|-------------------|----------------|---------|
| QES Certificate Profile | EN 319 411-1 | X.509 v3 with QES extensions | ✅ Implemented |
| Certificate Lifecycle | EN 319 411-2 | Vault PKI engine | ✅ Implemented |
| Key Management Requirements | EN 319 411-3 | HSM integration | ✅ Implemented |
| Certificate Revocation | EN 319 411-4 | CRL and OCSP support | 🔄 In Progress |

### 2.3 ETSI EN 319 421 - Policy and Security Requirements for Trust Service Providers

| Requirement | Standard Reference | Implementation | Status |
|-------------|-------------------|----------------|---------|
| Physical and Environmental Security | EN 319 421-1 | HSM requirements | ✅ Implemented |
| Personnel Security | EN 319 421-2 | Access control policies | ✅ Implemented |
| Asset Management | EN 319 421-3 | Key lifecycle management | ✅ Implemented |
| Access Control | EN 319 421-4 | RBAC implementation | ✅ Implemented |
| Cryptographic Controls | EN 319 421-5 | FIPS 140-2 Level 3+ | ✅ Implemented |
| Operations Security | EN 319 421-6 | Security monitoring | ✅ Implemented |
| Incident Management | EN 319 421-7 | Incident response plan | ✅ Implemented |
| Business Continuity | EN 319 421-8 | Disaster recovery | 📋 Planned |

### 2.4 ETSI TS 119 312 - Cryptographic Suites

| Algorithm | Standard Reference | Implementation | Status |
|-----------|-------------------|----------------|---------|
| RSA-2048 with SHA-256 | TS 119 312 | Supported | ✅ Implemented |
| RSA-4096 with SHA-256 | TS 119 312 | Supported | ✅ Implemented |
| ECDSA P-256 with SHA-256 | TS 119 312 | Supported | ✅ Implemented |
| ECDSA P-384 with SHA-384 | TS 119 312 | Supported | ✅ Implemented |
| ECDSA P-521 with SHA-512 | TS 119 312 | Supported | ✅ Implemented |

---

## 3. Digital Signature Format Compliance

### 3.1 XAdES (XML Advanced Electronic Signatures)

#### XAdES-B (Baseline)
- **Standard**: ETSI EN 319 132-1
- **Implementation**: XML signature with qualifying properties
- **Required Elements**:
  - SignedProperties
  - SigningTime
  - SigningCertificate
  - DataObjectFormat
  - CommitmentTypeIndication (where applicable)

#### XAdES-T (Timestamp)
- **Standard**: ETSI EN 319 132-1
- **Implementation**: XAdES-B + RFC 3161 timestamp
- **Required Elements**:
  - All XAdES-B elements
  - SignatureTimeStamp
  - TSA certificate validation

#### XAdES-LT (Long Term)
- **Standard**: ETSI EN 319 132-1
- **Implementation**: XAdES-T + validation data
- **Required Elements**:
  - All XAdES-T elements
  - CertificateValues
  - RevocationValues
  - CRL/OCSP responses

#### XAdES-LTA (Long Term Archival)
- **Standard**: ETSI EN 319 132-1
- **Implementation**: XAdES-LT + archival timestamp
- **Required Elements**:
  - All XAdES-LT elements
  - ArchiveTimeStamp
  - Complete validation chain

### 3.2 PAdES (PDF Advanced Electronic Signatures)

#### PAdES-B (Baseline)
- **Standard**: ETSI EN 319 142-1
- **Implementation**: PDF signature dictionary
- **Required Elements**:
  - Signature dictionary
  - Certificate reference
  - Signing time
  - Document integrity protection

#### PAdES-T (Timestamp)
- **Standard**: ETSI EN 319 142-1
- **Implementation**: PAdES-B + document timestamp
- **Required Elements**:
  - All PAdES-B elements
  - Document Security Store (DSS)
  - RFC 3161 timestamp

#### PAdES-LT (Long Term)
- **Standard**: ETSI EN 319 142-1
- **Implementation**: PAdES-T + validation information
- **Required Elements**:
  - All PAdES-T elements
  - Certificate values in DSS
  - Revocation information in DSS

#### PAdES-LTA (Long Term Archival)
- **Standard**: ETSI EN 319 142-1
- **Implementation**: PAdES-LT + archival timestamp
- **Required Elements**:
  - All PAdES-LT elements
  - Document timestamp covering DSS
  - Complete validation chain

### 3.3 CAdES (CMS Advanced Electronic Signatures)

#### CAdES-B (Baseline)
- **Standard**: ETSI EN 319 122-1
- **Implementation**: CMS SignedData structure
- **Required Elements**:
  - SignedData structure
  - SignedAttributes
  - Signing certificate reference

#### CAdES-T, CAdES-LT, CAdES-LTA
- **Standards**: ETSI EN 319 122-1
- **Implementation**: Similar progression as XAdES
- **Status**: 📋 Future implementation

---

## 4. Certificate Profiles

### 4.1 QES Certificate Profile (Natural Person)

```
Certificate:
    Version: 3 (0x2)
    Serial Number: [Unique per CA]
    Signature Algorithm: sha256WithRSAEncryption
    Issuer: [Qualified CA DN]
    Validity:
        Not Before: [Issue Date]
        Not After: [Max 3 years for QES]
    Subject: 
        CN=[Person Name]
        SERIALNUMBER=[eIDAS PersonIdentifier]
        C=[Country Code]
    Subject Public Key Info:
        Public Key Algorithm: rsaEncryption
        RSA Public Key: (2048/4096 bit)
    X509v3 extensions:
        X509v3 Key Usage: critical
            Digital Signature, Non Repudiation
        X509v3 Certificate Policies: critical
            Policy: [QES Policy OID]
            CPS: [Certification Practice Statement URL]
        X509v3 QC Statements: critical
            QC Compliance
            QC SSCD (Secure Signature Creation Device)
            QC Type: Electronic Signature
        X509v3 Subject Alternative Name:
            [eIDAS attributes per country]
        X509v3 Authority Key Identifier:
            [CA Key Identifier]
        X509v3 Subject Key Identifier:
            [Certificate Key Identifier]
        X509v3 CRL Distribution Points:
            [CRL URLs]
        Authority Information Access:
            CA Issuers: [CA Certificate URL]
            OCSP: [OCSP Responder URL]
```

### 4.2 QES Certificate Profile (Legal Person)

```
Certificate:
    [Similar structure with following differences]
    Subject:
        CN=[Organization Name]
        O=[Organization Name]
        SERIALNUMBER=[eIDAS LegalPersonIdentifier]
        C=[Country Code]
    X509v3 QC Statements: critical
        QC Compliance
        QC SSCD
        QC Type: Electronic Seal
```

---

## 5. Cryptographic Requirements

### 5.1 Key Generation
- **Algorithms**: RSA (2048/4096 bit), ECDSA (P-256/P-384/P-521)
- **Entropy**: FIPS 140-2 Level 3+ random number generation
- **Key Storage**: Hardware Security Module (HSM)
- **Key Backup**: Secure key escrow procedures

### 5.2 Signature Creation
- **Hash Algorithms**: SHA-256, SHA-384, SHA-512
- **Signature Algorithms**: 
  - RSA-PKCS#1 v1.5 with SHA-256/384/512
  - RSA-PSS with SHA-256/384/512
  - ECDSA with SHA-256/384/512
- **Key Protection**: HSM-based signing only

### 5.3 Certificate Validation
- **Path Validation**: RFC 5280 compliant
- **Revocation Checking**: CRL and OCSP support
- **Trust Anchors**: EU Trusted List integration
- **Validation Time**: Support for validation at specific times

---

## 6. Time-Stamping Requirements

### 6.1 TSA (Time-Stamping Authority)
- **Standard**: RFC 3161
- **Implementation**: External TSA integration
- **Requirements**:
  - Qualified time-stamp service
  - UTC time synchronization
  - Hash algorithm support (SHA-256/384/512)
  - TSA certificate validation

### 6.2 Time-Stamp Token Structure
```
TimeStampToken ::= ContentInfo
    contentType: id-pkcs9-timestamping
    content: TSAResp
        status: granted
        timeStampToken: TimeStampData
            version: 1
            policy: [TSA Policy OID]
            messageImprint: 
                hashAlgorithm: sha256/384/512
                hashedMessage: [Document Hash]
            serialNumber: [Unique per TSA]
            genTime: [UTC Time]
            accuracy: [Time accuracy]
            tsa: [TSA GeneralName]
```

---

## 7. Audit and Logging Requirements

### 7.1 Security Events Logging
- **Certificate Lifecycle Events**:
  - Certificate requests
  - Certificate issuance
  - Certificate revocation
  - Certificate renewal
- **Signature Events**:
  - Signature creation requests
  - Signature creation success/failure
  - Signature validation requests
  - Signature validation results
- **Administrative Events**:
  - Policy changes
  - Configuration changes
  - User access events
  - System maintenance

### 7.2 Log Format and Retention
- **Format**: Structured JSON with ETSI-compliant fields
- **Integrity**: Cryptographically protected logs
- **Retention**: Minimum 10 years for QES events
- **Access Control**: Restricted access with audit trails

### 7.3 Evidence Generation
- **Signature Creation Evidence**: 
  - Complete audit trail
  - Environmental information
  - User authentication proof
  - Device/location information (where available)
- **Evidence Format**: ETSI EN 319 401 compliant
- **Evidence Storage**: Immutable storage with integrity protection

---

## 8. Validation Service Requirements

### 8.1 Signature Validation Service (SVS)
- **Standard**: ETSI EN 319 442
- **Functionality**:
  - Multi-format signature validation
  - Validation policy enforcement
  - Validation report generation
  - Historical validation support

### 8.2 Validation Policies
- **Basic Validation**: Certificate path and revocation
- **Long-term Validation**: Including expired certificates
- **Archival Validation**: Full chain validation
- **Custom Policies**: Client-specific validation rules

### 8.3 Validation Reports
- **Format**: ETSI EN 319 102-1 compliant
- **Content**:
  - Validation time and policy
  - Certificate chain analysis
  - Revocation status
  - Cryptographic verification
  - Overall validation result

---

## 9. Long-Term Preservation

### 9.1 Signature Preservation Requirements
- **Format Migration**: Support for format updates
- **Algorithm Migration**: Crypto-agility support
- **Evidence Preservation**: Complete audit chains
- **Accessibility**: Long-term format readability

### 9.2 Preservation Procedures
- **Regular Validation**: Periodic signature checking
- **Timestamp Renewal**: Before timestamp expiry
- **Evidence Updates**: Maintaining validation chains
- **Format Updates**: Migration to newer standards

---

## 10. Compliance Testing

### 10.1 Conformance Testing
- **Test Suites**: ETSI conformance test packages
- **Validation Tools**: EU DSS validation service
- **Test Scenarios**:
  - Signature creation workflows
  - Validation scenarios
  - Error handling
  - Edge cases

### 10.2 Interoperability Testing
- **Cross-Platform**: Multiple signature viewers
- **Cross-Country**: Different eIDAS providers
- **Cross-Format**: XAdES, PAdES, CAdES
- **Cross-Time**: Historical validation

### 10.3 Security Testing
- **Penetration Testing**: External security assessment
- **Vulnerability Scanning**: Regular automated scans
- **Code Review**: Security-focused code analysis
- **Compliance Audit**: Third-party ETSI compliance review

---

## 11. Certification and Assessment

### 11.1 Required Certifications
- **Common Criteria**: EAL 4+ for security components
- **FIPS 140-2**: Level 3+ for cryptographic modules
- **eIDAS Compliance**: National body assessment
- **ISO 27001**: Information security management

### 11.2 Assessment Schedule
- **Initial Assessment**: Before production deployment
- **Annual Review**: Compliance policy updates
- **Triennial Audit**: Full security and compliance audit
- **Continuous Monitoring**: Automated compliance checking

---

## 12. Non-Compliance Handling

### 12.1 Incident Classification
- **Critical**: Security breach or compliance violation
- **High**: Partial compliance failure
- **Medium**: Process deviation
- **Low**: Documentation updates needed

### 12.2 Response Procedures
1. **Immediate Assessment**: Impact and scope analysis
2. **Containment**: Limit exposure and damage
3. **Investigation**: Root cause analysis
4. **Remediation**: Fix underlying issues
5. **Documentation**: Update policies and procedures
6. **Reporting**: Notify relevant authorities if required

---

## 13. Policy Maintenance

### 13.1 Review Schedule
- **Quarterly**: Technical standard updates
- **Semi-Annual**: Regulatory changes
- **Annual**: Complete policy review
- **Ad-hoc**: Emergency updates

### 13.2 Change Management
- **Impact Assessment**: Effect on compliance status
- **Approval Process**: Technical and legal review
- **Implementation**: Controlled rollout
- **Verification**: Compliance validation
- **Documentation**: Update all related documents

---

## 14. Conclusion

This ETSI compliance policy ensures that the eIDAS QES Digital Signing Platform meets all relevant European standards for qualified electronic signatures. Regular review and updates of this policy are essential to maintain compliance as standards evolve.

**Key Success Factors**:
1. Comprehensive implementation of ETSI standards
2. Regular compliance monitoring and testing
3. Continuous improvement based on assessments
4. Stakeholder engagement and training
5. Proactive standard updates adoption

---

**Document History**:
- v1.0 (Dec 2024): Initial policy establishment
- Next Review: March 2025

**Related Documents**:
- STRIDE Threat Model
- Security Architecture Design
- Certificate Practice Statement
- Incident Response Procedures