# ETSI Compliance Test Cases - eIDAS QES Platform

## Document Information

**Document Title**: ETSI Compliance Test Cases  
**Document Version**: 1.0  
**Date**: December 2024  
**Classification**: Internal  
**Owner**: QA Team  
**Approved by**: Technical Lead  

---

## 1. Test Overview

This document defines comprehensive test cases to validate ETSI compliance for the eIDAS QES Digital Signing Platform. Test cases cover signature creation, validation, and long-term preservation scenarios.

**Test Scope**:
- XAdES-B/T/LT/LTA signature creation and validation
- PAdES-B/T/LT/LTA signature creation and validation  
- Certificate lifecycle and validation
- Time-stamping functionality
- Long-term preservation
- Interoperability testing

**Test Environment**:
- Development: Internal testing
- Staging: Pre-production validation
- Production: Live monitoring tests

---

## 2. XAdES Test Cases

### 2.1 XAdES-B (Baseline) Tests

#### TC-XADES-B-001: Basic XAdES-B Signature Creation
**Objective**: Verify basic XAdES-B signature creation  
**Preconditions**: Valid QES certificate, XML document  
**Test Steps**:
1. Load XML document for signing
2. Initialize XAdES-B signature creation
3. Add SignedProperties element
4. Add SigningTime property
5. Add SigningCertificate property
6. Create signature value
7. Validate signature structure

**Expected Result**: Valid XAdES-B signature with all required elements  
**Validation Criteria**:
- ✅ Signature verifies cryptographically
- ✅ SignedProperties present and valid
- ✅ SigningTime within acceptable range
- ✅ SigningCertificate matches signing key
- ✅ No validation errors

#### TC-XADES-B-002: DataObjectFormat Property
**Objective**: Verify DataObjectFormat property inclusion  
**Test Steps**:
1. Create XAdES-B signature with DataObjectFormat
2. Specify MIME type and encoding
3. Validate property structure

**Expected Result**: DataObjectFormat correctly included and validates

#### TC-XADES-B-003: CommitmentTypeIndication Property
**Objective**: Verify CommitmentTypeIndication for approval signatures  
**Test Steps**:
1. Create XAdES-B signature with commitment type
2. Set commitment type to "http://uri.etsi.org/01903/v1.2.2#ProofOfApproval"
3. Validate commitment indication

**Expected Result**: CommitmentTypeIndication correctly set and validates

### 2.2 XAdES-T (Timestamp) Tests

#### TC-XADES-T-001: Timestamp Addition to XAdES-B
**Objective**: Verify XAdES-T creation by adding timestamp to XAdES-B  
**Preconditions**: Valid XAdES-B signature, TSA available  
**Test Steps**:
1. Create valid XAdES-B signature
2. Calculate hash of signature value
3. Request RFC 3161 timestamp from TSA
4. Add SignatureTimeStamp to UnsignedProperties
5. Validate complete XAdES-T signature

**Expected Result**: Valid XAdES-T with embedded timestamp  
**Validation Criteria**:
- ✅ Original XAdES-B validation passes
- ✅ RFC 3161 timestamp is valid
- ✅ Timestamp covers signature value
- ✅ TSA certificate validates
- ✅ Timestamp time is reasonable

#### TC-XADES-T-002: Multiple Timestamp Support
**Objective**: Verify support for multiple timestamps  
**Test Steps**:
1. Create XAdES-T signature
2. Add additional timestamp from different TSA
3. Validate both timestamps

**Expected Result**: All timestamps validate independently

#### TC-XADES-T-003: Timestamp Validation at Different Times
**Objective**: Verify timestamp validation across time periods  
**Test Steps**:
1. Create XAdES-T signature
2. Validate immediately after creation
3. Validate after 24 hours
4. Validate after 30 days

**Expected Result**: Timestamp remains valid across all time periods

### 2.3 XAdES-LT (Long Term) Tests

#### TC-XADES-LT-001: Certificate Values Addition
**Objective**: Verify addition of certificate chain to XAdES-T  
**Preconditions**: Valid XAdES-T signature  
**Test Steps**:
1. Take valid XAdES-T signature
2. Collect complete certificate chain
3. Add CertificateValues to UnsignedProperties
4. Validate certificate chain completeness

**Expected Result**: Complete certificate chain embedded in signature

#### TC-XADES-LT-002: Revocation Values Addition
**Objective**: Verify addition of revocation information  
**Test Steps**:
1. Take XAdES-T with CertificateValues
2. Collect CRL responses for all certificates
3. Collect OCSP responses where available
4. Add RevocationValues to UnsignedProperties
5. Validate revocation information

**Expected Result**: Current revocation status embedded in signature

#### TC-XADES-LT-003: Long-term Validation
**Objective**: Verify LT signature validates with embedded data  
**Test Steps**:
1. Create complete XAdES-LT signature
2. Validate using only embedded certificates and revocation data
3. Verify no external lookups required

**Expected Result**: Signature validates without external dependencies

### 2.4 XAdES-LTA (Long Term Archival) Tests

#### TC-XADES-LTA-001: Archive Timestamp Addition
**Objective**: Verify archival timestamp addition to XAdES-LT  
**Preconditions**: Valid XAdES-LT signature  
**Test Steps**:
1. Take complete XAdES-LT signature
2. Calculate hash covering signature and validation data
3. Request archival timestamp from TSA
4. Add ArchiveTimeStamp to UnsignedProperties
5. Validate complete XAdES-LTA

**Expected Result**: XAdES-LTA with protective archival timestamp

#### TC-XADES-LTA-002: Multiple Archive Timestamps
**Objective**: Verify support for timestamp renewal  
**Test Steps**:
1. Create XAdES-LTA signature
2. After time period, add additional ArchiveTimeStamp
3. Validate both archival timestamps

**Expected Result**: Multiple archival timestamps validate correctly

#### TC-XADES-LTA-003: Long-term Preservation Validation
**Objective**: Verify signature survives algorithm deprecation  
**Test Steps**:
1. Create XAdES-LTA with SHA-1 (simulated legacy)
2. Add new ArchiveTimeStamp with SHA-256
3. Validate signature after SHA-1 deprecation

**Expected Result**: Signature remains valid with newer timestamp

---

## 3. PAdES Test Cases

### 3.1 PAdES-B (Baseline) Tests

#### TC-PADES-B-001: Basic PDF Signature Creation
**Objective**: Verify basic PAdES-B signature creation  
**Preconditions**: Valid QES certificate, PDF document  
**Test Steps**:
1. Load PDF document for signing
2. Create signature dictionary
3. Add certificate reference
4. Set signing time
5. Apply signature to PDF
6. Validate PDF signature

**Expected Result**: Valid PAdES-B signature in PDF  
**Validation Criteria**:
- ✅ PDF signature dictionary complete
- ✅ Signature covers document content
- ✅ Certificate properly referenced
- ✅ Signing time reasonable
- ✅ PDF structure maintains integrity

#### TC-PADES-B-002: Incremental Update Preservation
**Objective**: Verify PDF incremental updates preserve original content  
**Test Steps**:
1. Sign PDF with PAdES-B
2. Verify original PDF content unchanged
3. Validate signature covers original content only

**Expected Result**: Original PDF content preserved and protected

#### TC-PADES-B-003: Multiple Signature Support
**Objective**: Verify multiple signatures in single PDF  
**Test Steps**:
1. Create initial PAdES-B signature
2. Add second PAdES-B signature
3. Validate both signatures independently

**Expected Result**: Both signatures validate correctly

### 3.2 PAdES-T (Timestamp) Tests

#### TC-PADES-T-001: Document Timestamp Addition
**Objective**: Verify document timestamp addition to PAdES-B  
**Test Steps**:
1. Create PAdES-B signature
2. Add Document Security Store (DSS)
3. Request document timestamp
4. Embed timestamp in DSS
5. Validate PAdES-T structure

**Expected Result**: Valid PAdES-T with document timestamp

#### TC-PADES-T-002: DSS Dictionary Structure
**Objective**: Verify proper DSS dictionary creation  
**Test Steps**:
1. Create PAdES-T signature
2. Validate DSS dictionary structure
3. Verify certificate storage in DSS
4. Verify timestamp storage in DSS

**Expected Result**: DSS dictionary properly structured and populated

### 3.3 PAdES-LT (Long Term) Tests

#### TC-PADES-LT-001: Validation Information in DSS
**Objective**: Verify complete validation information in DSS  
**Test Steps**:
1. Create PAdES-T signature
2. Add certificate chain to DSS
3. Add CRL/OCSP responses to DSS
4. Validate complete validation chain

**Expected Result**: All validation information available in DSS

#### TC-PADES-LT-002: Self-contained Validation
**Objective**: Verify signature validates without external resources  
**Test Steps**:
1. Create complete PAdES-LT
2. Validate in isolated environment
3. Verify no external certificate/CRL lookups

**Expected Result**: Signature validates independently

### 3.4 PAdES-LTA (Long Term Archival) Tests

#### TC-PADES-LTA-001: Document Timestamp over DSS
**Objective**: Verify archival timestamp covers DSS  
**Test Steps**:
1. Create complete PAdES-LT
2. Add document timestamp covering DSS
3. Validate timestamp protects validation data

**Expected Result**: Archival timestamp protects all validation information

---

## 4. Certificate Lifecycle Tests

### 4.1 Certificate Issuance Tests

#### TC-CERT-001: QES Certificate Profile Validation
**Objective**: Verify QES certificate contains required extensions  
**Test Steps**:
1. Request QES certificate from CA
2. Validate certificate profile
3. Check required extensions present
4. Verify QC statements compliance

**Expected Result**: Certificate meets ETSI EN 319 411 requirements  
**Validation Criteria**:
- ✅ Key Usage: Digital Signature, Non-repudiation
- ✅ Certificate Policies with QES OID
- ✅ QC Statements with SSCD indication
- ✅ Subject information properly formatted
- ✅ Validity period within limits

#### TC-CERT-002: Certificate Chain Validation
**Objective**: Verify complete certificate chain validates  
**Test Steps**:
1. Obtain end-entity certificate
2. Obtain intermediate CA certificates
3. Obtain root CA certificate
4. Validate complete chain to trust anchor

**Expected Result**: Certificate chain validates successfully

#### TC-CERT-003: Certificate Policy Validation
**Objective**: Verify certificate policy compliance  
**Test Steps**:
1. Extract certificate policies from certificate
2. Validate policy OIDs are correct
3. Verify policy qualifiers if present
4. Check CPS references

**Expected Result**: Certificate policies comply with requirements

### 4.2 Certificate Revocation Tests

#### TC-CERT-REV-001: CRL Generation and Validation
**Objective**: Verify CRL generation and structure  
**Test Steps**:
1. Revoke test certificate
2. Generate new CRL
3. Validate CRL structure and signatures
4. Verify revoked certificate appears in CRL

**Expected Result**: CRL properly generated with revoked certificate

#### TC-CERT-REV-002: OCSP Response Validation
**Objective**: Verify OCSP responder functionality  
**Test Steps**:
1. Query OCSP for valid certificate
2. Query OCSP for revoked certificate
3. Validate OCSP response signatures
4. Verify response timeliness

**Expected Result**: OCSP responses accurate and properly signed

---

## 5. Time-stamping Tests

### 5.1 TSA Integration Tests

#### TC-TSA-001: RFC 3161 Timestamp Request
**Objective**: Verify proper RFC 3161 timestamp requests  
**Test Steps**:
1. Create timestamp request for document hash
2. Send request to TSA
3. Validate timestamp response structure
4. Verify timestamp token

**Expected Result**: Valid RFC 3161 timestamp token received

#### TC-TSA-002: Timestamp Token Validation
**Objective**: Verify timestamp token validation  
**Test Steps**:
1. Obtain timestamp token
2. Validate TSA certificate
3. Verify timestamp signature
4. Check timestamp accuracy

**Expected Result**: Timestamp token validates correctly

#### TC-TSA-003: Multiple TSA Support
**Objective**: Verify support for multiple TSA providers  
**Test Steps**:
1. Configure multiple TSA endpoints
2. Request timestamps from different TSAs
3. Validate all timestamp tokens

**Expected Result**: All TSA providers function correctly

---

## 6. Long-term Preservation Tests

### 6.1 Algorithm Migration Tests

#### TC-LTP-001: Hash Algorithm Migration
**Objective**: Verify signature survives hash algorithm deprecation  
**Test Steps**:
1. Create signature with SHA-256
2. Simulate SHA-256 deprecation
3. Add new timestamp with SHA-384
4. Validate signature with new algorithm

**Expected Result**: Signature remains valid after algorithm update

#### TC-LTP-002: Signature Algorithm Migration
**Objective**: Verify handling of deprecated signature algorithms  
**Test Steps**:
1. Create signature with RSA-PKCS#1
2. Add timestamp before algorithm deprecation
3. Validate using historical algorithm support

**Expected Result**: Signature validates with historical context

### 6.2 Format Migration Tests

#### TC-LTP-003: Signature Format Updates
**Objective**: Verify handling of format specification updates  
**Test Steps**:
1. Create signature with current format
2. Update to newer format specification
3. Validate backward compatibility

**Expected Result**: Signatures remain valid across format versions

---

## 7. Interoperability Tests

### 7.1 Cross-Platform Tests

#### TC-INTEROP-001: Adobe Reader Validation
**Objective**: Verify PAdES signatures validate in Adobe Reader  
**Test Steps**:
1. Create PAdES-LTA signature
2. Open in Adobe Reader
3. Verify signature shows as valid
4. Check all signature properties visible

**Expected Result**: Signature validates and displays correctly

#### TC-INTEROP-002: EU DSS Validation
**Objective**: Verify signatures validate with EU DSS library  
**Test Steps**:
1. Create XAdES/PAdES signatures
2. Validate using EU DSS validation service
3. Verify validation reports

**Expected Result**: EU DSS confirms signature validity

#### TC-INTEROP-003: Cross-Country Validation
**Objective**: Verify signatures from different countries validate  
**Test Steps**:
1. Create signatures with different country providers
2. Cross-validate signatures
3. Verify trust lists work correctly

**Expected Result**: Cross-border signature validation works

---

## 8. Error Handling Tests

### 8.1 Invalid Certificate Tests

#### TC-ERROR-001: Expired Certificate Handling
**Objective**: Verify proper handling of expired certificates  
**Test Steps**:
1. Attempt signature with expired certificate
2. Verify appropriate error message
3. Ensure signature creation fails gracefully

**Expected Result**: Clear error message, no signature created

#### TC-ERROR-002: Revoked Certificate Handling
**Objective**: Verify handling of revoked certificates  
**Test Steps**:
1. Attempt signature with revoked certificate
2. Verify revocation check occurs
3. Ensure signature creation fails

**Expected Result**: Revocation detected, signature creation blocked

### 8.2 Timestamp Error Tests

#### TC-ERROR-003: TSA Unavailable Handling
**Objective**: Verify handling when TSA is unavailable  
**Test Steps**:
1. Configure unavailable TSA
2. Attempt timestamp signature creation
3. Verify appropriate fallback or error

**Expected Result**: Graceful handling of TSA unavailability

#### TC-ERROR-004: Invalid Timestamp Response
**Objective**: Verify handling of malformed timestamp responses  
**Test Steps**:
1. Simulate invalid timestamp response
2. Verify response validation
3. Ensure signature creation fails appropriately

**Expected Result**: Invalid timestamps rejected, clear error message

---

## 9. Performance Tests

### 9.1 Signature Creation Performance

#### TC-PERF-001: XAdES-LTA Creation Time
**Objective**: Measure XAdES-LTA signature creation time  
**Test Steps**:
1. Create 100 XAdES-LTA signatures
2. Measure average creation time
3. Verify performance within SLA

**Expected Result**: Average creation time < 5 seconds  
**Performance Target**: 
- XAdES-B: < 1 second
- XAdES-T: < 3 seconds  
- XAdES-LT: < 4 seconds
- XAdES-LTA: < 5 seconds

#### TC-PERF-002: PAdES-LTA Creation Time
**Objective**: Measure PAdES-LTA signature creation time  
**Test Steps**:
1. Create 100 PAdES-LTA signatures
2. Measure average creation time
3. Compare with XAdES performance

**Expected Result**: Performance comparable to XAdES

### 9.2 Validation Performance

#### TC-PERF-003: Signature Validation Time
**Objective**: Measure signature validation performance  
**Test Steps**:
1. Validate 1000 existing signatures
2. Measure average validation time
3. Verify performance acceptable

**Expected Result**: Average validation time < 2 seconds

---

## 10. Security Tests

### 10.1 Signature Tampering Tests

#### TC-SEC-001: Document Modification Detection
**Objective**: Verify signature detects document changes  
**Test Steps**:
1. Create valid signature
2. Modify signed document
3. Validate signature
4. Verify validation fails

**Expected Result**: Document modification detected and reported

#### TC-SEC-002: Signature Modification Detection
**Objective**: Verify signature detects signature tampering  
**Test Steps**:
1. Create valid signature
2. Modify signature data
3. Validate signature
4. Verify validation fails

**Expected Result**: Signature tampering detected

### 10.2 Certificate Security Tests

#### TC-SEC-003: Certificate Chain Attack
**Objective**: Verify resistance to certificate substitution  
**Test Steps**:
1. Create signature with valid certificate
2. Substitute different certificate in validation
3. Verify validation fails

**Expected Result**: Certificate substitution detected

---

## 11. Compliance Validation Tests

### 11.1 ETSI Conformance Tests

#### TC-CONF-001: XAdES Conformance Suite
**Objective**: Execute ETSI XAdES conformance tests  
**Test Steps**:
1. Download ETSI XAdES test suite
2. Execute all test cases
3. Verify platform passes all tests

**Expected Result**: 100% pass rate on conformance tests

#### TC-CONF-002: PAdES Conformance Suite
**Objective**: Execute ETSI PAdES conformance tests  
**Test Steps**:
1. Download ETSI PAdES test suite
2. Execute all test cases
3. Analyze any failures

**Expected Result**: 95%+ pass rate on conformance tests

---

## 12. Test Automation

### 12.1 Automated Test Execution
- **Framework**: pytest with custom ETSI validation plugins
- **Schedule**: Daily regression testing
- **Reporting**: Automated test reports with compliance metrics
- **Integration**: CI/CD pipeline integration

### 12.2 Test Data Management
- **Test Certificates**: Dedicated test CA infrastructure
- **Test Documents**: Representative document samples
- **Test Vectors**: ETSI-provided test vectors
- **Environment Isolation**: Separate test/prod environments

---

## 13. Test Reporting

### 13.1 Test Results Format
```json
{
  "test_suite": "ETSI_XAdES_Compliance",
  "execution_date": "2024-12-01T10:00:00Z",
  "total_tests": 156,
  "passed": 154,
  "failed": 2,
  "skipped": 0,
  "pass_rate": "98.7%",
  "execution_time": "45.6s",
  "failures": [
    {
      "test_id": "TC-XADES-LT-003",
      "error": "Timestamp validation timeout",
      "severity": "medium"
    }
  ]
}
```

### 13.2 Compliance Dashboard
- **Real-time Metrics**: Test pass rates and trends
- **Compliance Status**: Overall ETSI compliance percentage
- **Alert System**: Notifications for compliance violations
- **Historical Tracking**: Compliance metrics over time

---

**Document History**:
- v1.0 (Dec 2024): Initial test case specification
- Next Review: March 2025

**Related Documents**:
- ETSI Compliance Policy
- Test Automation Framework
- Conformance Test Results