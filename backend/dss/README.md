# EU DSS Integration for eIDAS-Compliant Signatures

Comprehensive implementation of EU DSS (Digital Signature Service) compatible functionality for creating and validating eIDAS-compliant digital signatures.

## Features

### 📋 Supported Signature Formats

#### XAdES (XML Advanced Electronic Signatures)
- **XAdES-BASELINE-B**: Basic signature with signing certificate
- **XAdES-BASELINE-T**: Basic signature + trusted timestamp
- **XAdES-BASELINE-LT**: Timestamp signature + validation info (CRL/OCSP)
- **XAdES-BASELINE-LTA**: LT signature + archival timestamp

#### PAdES (PDF Advanced Electronic Signatures)
- **PAdES-BASELINE-B**: Basic PDF signature
- **PAdES-BASELINE-T**: PDF signature + trusted timestamp
- **PAdES-BASELINE-LT**: Timestamp signature + validation info
- **PAdES-BASELINE-LTA**: LT signature + archival timestamp

#### CAdES (CMS Advanced Electronic Signatures)
- **CAdES-BASELINE-B**: Basic CMS signature
- **CAdES-BASELINE-T**: CMS signature + trusted timestamp
- **CAdES-BASELINE-LT**: Timestamp signature + validation info
- **CAdES-BASELINE-LTA**: LT signature + archival timestamp

### 🔐 Supported Algorithms

#### Digest Algorithms
- SHA-1 (deprecated, for legacy support)
- SHA-256 (recommended)
- SHA-384
- SHA-512

#### Signature Algorithms
- RSA-SHA256 (recommended)
- RSA-SHA384
- RSA-SHA512
- ECDSA-SHA256
- ECDSA-SHA384
- ECDSA-SHA512

## API Endpoints

### Core Signature Operations

#### Create eIDAS Signature
```bash
POST /api/v1/eu-dss/create-signature
Content-Type: application/json

{
    "document_content": "SGVsbG8gV29ybGQ=",  # base64-encoded
    "document_name": "contract.pdf",
    "document_mime_type": "application/pdf",
    "signature_level": "PAdES-BASELINE-T",
    "digest_algorithm": "SHA256",
    "signature_algorithm": "RSA_SHA256",
    "timestamp_service_url": "http://timestamp.digicert.com",
    "signer_reason": "Contract approval",
    "signer_location": "Stockholm, Sweden"
}
```

**Response:**
```json
{
    "success": true,
    "signed_document": "JVBERi0xLjQK...",  // base64-encoded signed document
    "signature_level": "PAdES-BASELINE-T",
    "signature_algorithm": "RSA_SHA256",
    "digest_algorithm": "SHA256",
    "signature_id": "sig_123_1701234567",
    "timestamp": "2024-12-01T12:00:00Z",
    "certificate_info": {
        "subject": "CN=John Doe, O=Example Corp",
        "issuer": "CN=QES Platform Demo CA",
        "serial_number": "123456789",
        "not_before": "2024-01-01T00:00:00Z",
        "not_after": "2025-01-01T00:00:00Z",
        "key_usage": ["digital_signature", "key_encipherment"],
        "extended_key_usage": ["clientAuth", "emailProtection"]
    },
    "validation_info": {
        "signature_level_achieved": "PAdES-BASELINE-T",
        "timestamp_included": true,
        "certificate_values_included": true,
        "revocation_values_included": true,
        "signing_time": "2024-12-01T12:00:00Z"
    }
}
```

#### Validate eIDAS Signature
```bash
POST /api/v1/eu-dss/validate-signature
Content-Type: application/json

{
    "signed_document": "JVBERi0xLjQK...",  # base64-encoded signed document
    "document_name": "signed_contract.pdf",
    "original_document": "SGVsbG8gV29ybGQ=",  # optional, base64-encoded
    "validation_policy": "EIDAS_COMPLIANT",
    "check_certificate_validity": true,
    "check_revocation_status": true,
    "check_timestamp_validity": true,
    "check_signature_integrity": true
}
```

**Response:**
```json
{
    "success": true,
    "is_valid": true,
    "signature_level": "PAdES-BASELINE-T",
    "signature_format": "PAdES",
    "validation_time": "2024-12-01T12:05:00Z",
    "certificate_validation": {
        "valid": true,
        "certificate_chain_valid": true,
        "certificate_not_expired": true,
        "trusted_chain": true
    },
    "signature_validation": {
        "signature_intact": true,
        "signature_algorithm_valid": true,
        "digest_algorithm_valid": true,
        "signed_data_intact": true
    },
    "timestamp_validation": {
        "timestamp_present": true,
        "timestamp_valid": true,
        "timestamp_algorithm_valid": true,
        "timestamp_within_validity": true
    },
    "revocation_validation": {
        "revocation_checked": true,
        "certificate_not_revoked": true,
        "ocsp_response_valid": true,
        "crl_valid": true
    },
    "certificate_chain": [
        {
            "subject": "CN=John Doe, O=Example Corp",
            "issuer": "CN=QES Platform Demo CA",
            "serial_number": "123456789",
            "valid": true,
            "not_before": "2024-01-01T00:00:00Z",
            "not_after": "2025-01-01T00:00:00Z"
        }
    ],
    "errors": [],
    "warnings": []
}
```

#### Upload and Sign (Convenience Endpoint)
```bash
POST /api/v1/eu-dss/upload-and-sign
Content-Type: multipart/form-data

file: [contract.pdf]
signature_level: XAdES-BASELINE-LTA
digest_algorithm: SHA256
signature_algorithm: RSA_SHA256
timestamp_service_url: http://timestamp.digicert.com
signer_reason: Document approval
```

#### Get Supported Signature Levels
```bash
GET /api/v1/eu-dss/signature-levels
```

**Response:**
```json
{
    "signature_levels": [
        "XAdES-BASELINE-B", "XAdES-BASELINE-T", "XAdES-BASELINE-LT", "XAdES-BASELINE-LTA",
        "PAdES-BASELINE-B", "PAdES-BASELINE-T", "PAdES-BASELINE-LT", "PAdES-BASELINE-LTA",
        "CAdES-BASELINE-B", "CAdES-BASELINE-T", "CAdES-BASELINE-LT", "CAdES-BASELINE-LTA"
    ],
    "digest_algorithms": ["SHA1", "SHA256", "SHA384", "SHA512"],
    "signature_algorithms": [
        "RSA_SHA256", "RSA_SHA384", "RSA_SHA512",
        "ECDSA_SHA256", "ECDSA_SHA384", "ECDSA_SHA512"
    ],
    "descriptions": {
        "XAdES-BASELINE-B": "Basic XAdES signature",
        "XAdES-BASELINE-T": "XAdES with timestamp",
        "XAdES-BASELINE-LT": "XAdES with long-term validation info",
        "XAdES-BASELINE-LTA": "XAdES with archival timestamp",
        "PAdES-BASELINE-B": "Basic PAdES signature",
        "PAdES-BASELINE-T": "PAdES with timestamp",
        "PAdES-BASELINE-LT": "PAdES with long-term validation info",
        "PAdES-BASELINE-LTA": "PAdES with archival timestamp"
    }
}
```

## XAdES Implementation Details

### XML Signature Structure
```xml
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" 
              xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
    <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="">
            <ds:Transforms>
                <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            </ds:Transforms>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <ds:DigestValue>...</ds:DigestValue>
        </ds:Reference>
        <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#SignedProperties-id">
            <ds:Transforms>
                <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            </ds:Transforms>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <ds:DigestValue>...</ds:DigestValue>
        </ds:Reference>
    </ds:SignedInfo>
    
    <ds:SignatureValue>...</ds:SignatureValue>
    
    <ds:KeyInfo>
        <ds:X509Data>
            <ds:X509Certificate>...</ds:X509Certificate>
        </ds:X509Data>
    </ds:KeyInfo>
    
    <ds:Object>
        <xades:QualifyingProperties Target="#Signature-id">
            <xades:SignedProperties Id="SignedProperties-id">
                <xades:SignedSignatureProperties>
                    <xades:SigningTime>2024-12-01T12:00:00Z</xades:SigningTime>
                    <xades:SigningCertificate>
                        <xades:Cert>
                            <xades:CertDigest>
                                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                <ds:DigestValue>...</ds:DigestValue>
                            </xades:CertDigest>
                            <xades:IssuerSerial>
                                <ds:X509IssuerName>...</ds:X509IssuerName>
                                <ds:X509SerialNumber>...</ds:X509SerialNumber>
                            </xades:IssuerSerial>
                        </xades:Cert>
                    </xades:SigningCertificate>
                </xades:SignedSignatureProperties>
            </xades:SignedProperties>
            
            <!-- For T, LT, LTA levels -->
            <xades:UnsignedProperties>
                <xades:UnsignedSignatureProperties>
                    <!-- XAdES-T: Signature Timestamp -->
                    <xades:SignatureTimeStamp Id="SignatureTimeStamp-id">
                        <xades:EncapsulatedTimeStamp>...</xades:EncapsulatedTimeStamp>
                    </xades:SignatureTimeStamp>
                    
                    <!-- XAdES-LT: Certificate and Revocation Values -->
                    <xades:CertificateValues Id="CertificateValues-id">
                        <!-- Certificate chain -->
                    </xades:CertificateValues>
                    <xades:RevocationValues Id="RevocationValues-id">
                        <xades:CRLValues>
                            <!-- CRL responses -->
                        </xades:CRLValues>
                        <xades:OCSPValues>
                            <!-- OCSP responses -->
                        </xades:OCSPValues>
                    </xades:RevocationValues>
                    
                    <!-- XAdES-LTA: Archive Timestamp -->
                    <xades:ArchiveTimeStamp Id="ArchiveTimeStamp-id">
                        <xades:EncapsulatedTimeStamp>...</xades:EncapsulatedTimeStamp>
                    </xades:ArchiveTimeStamp>
                </xades:UnsignedSignatureProperties>
            </xades:UnsignedProperties>
        </xades:QualifyingProperties>
    </ds:Object>
</ds:Signature>
```

## PAdES Implementation Details

### PDF Signature Dictionary
```
/Type /Sig
/Filter /Adobe.PPKLite
/SubFilter /ETSI.CAdES.detached
/ByteRange [0 1234 5678 9012]
/Contents <hexadecimal signature data>
/Reason (Contract approval)
/Location (Stockholm, Sweden)
/M (D:20241201120000+00'00')
/ContactInfo (john.doe@example.com)
```

### Document Security Store (DSS) for LT/LTA
For PAdES-LT and PAdES-LTA levels, validation information is stored in a Document Security Store (DSS):

```
/Names <<
    /DSS <<
        /Certs [cert1 cert2 ...]
        /CRLs [crl1 crl2 ...]
        /OCSPs [ocsp1 ocsp2 ...]
        /VRI <<
            /SignatureHash <<
                /Cert [cert_refs...]
                /CRL [crl_refs...]
                /OCSP [ocsp_refs...]
            >>
        >>
    >>
>>
```

## Integration with Signing Engine

The EU DSS service integrates seamlessly with the existing signing engine:

```python
# In signing_engine.py
def _embed_timestamp(self, signed_document: bytes, timestamp_token: TimestampToken, job: SigningJob) -> bytes:
    """Embed timestamp token in signature using EU DSS."""
    from .eu_dss_service import EUDSSService
    
    dss_service = EUDSSService(self.config)
    
    if job.target_format.value.startswith("XAdES"):
        return self._embed_xades_timestamp(signed_document, timestamp_token, job, dss_service)
    elif job.target_format.value.startswith("PAdES"):
        return self._embed_pades_timestamp(signed_document, timestamp_token, job, dss_service)
    elif job.target_format.value.startswith("CAdES"):
        return self._embed_cades_timestamp(signed_document, timestamp_token, job, dss_service)
```

## Dependencies

### Python Libraries
```bash
# XML processing
lxml==4.9.3
xmlsec==1.3.13
xmlschema==2.5.0

# PDF processing  
PyPDF2==3.0.1

# Cryptography
pyOpenSSL==23.3.0
cryptography==41.0.7
```

### System Dependencies
```bash
# For xmlsec
sudo apt-get install libxml2-dev libxmlsec1-dev libxmlsec1-openssl

# For PDF processing
sudo apt-get install poppler-utils
```

## Configuration

### Environment Variables
```bash
# TSA Configuration
DSS_TSA_URL=http://timestamp.digicert.com
DSS_TSA_TIMEOUT=30
DSS_TSA_VERIFY_SSL=true

# Certificate Validation
DSS_VALIDATE_CERTIFICATES=true
DSS_CHECK_REVOCATION=true
DSS_TRUST_STORE_PATH=/etc/ssl/certs

# Signature Policies
DSS_DEFAULT_SIGNATURE_POLICY=EIDAS_COMPLIANT
DSS_ALLOW_WEAK_ALGORITHMS=false

# XML Canonicalization
DSS_XML_C14N_METHOD=http://www.w3.org/2001/10/xml-exc-c14n#
```

### DSS Service Configuration
```python
dss_config = {
    "tsa_url": "http://timestamp.digicert.com",
    "tsa_timeout": 30,
    "verify_ssl": True,
    "certificate_validation": {
        "validate_chain": True,
        "check_revocation": True,
        "trust_store_path": "/etc/ssl/certs"
    },
    "signature_policies": {
        "default": "EIDAS_COMPLIANT",
        "allow_weak_algorithms": False
    }
}

dss_service = EUDSSService(dss_config)
```

## Compliance and Standards

### eIDAS Regulation Compliance
- **Article 24**: Requirements for qualified electronic signatures
- **Article 25**: Effects of qualified electronic signatures
- **Article 26**: Requirements for qualified electronic seals
- **Annex I**: Requirements for qualified certificates for electronic signatures

### Technical Standards
- **ETSI EN 319 122-1**: XAdES digital signatures (Part 1: Building blocks and XAdES baseline signatures)
- **ETSI EN 319 122-2**: XAdES digital signatures (Part 2: Extended XAdES signatures)
- **ETSI EN 319 142-1**: PAdES digital signatures (Part 1: Building blocks and PAdES baseline signatures)
- **ETSI EN 319 142-2**: PAdES digital signatures (Part 2: Additional PAdES signatures profiles)
- **ETSI EN 319 132-1**: CAdES digital signatures (Part 1: Building blocks and CAdES baseline signatures)
- **ETSI EN 319 132-2**: CAdES digital signatures (Part 2: Extended CAdES signatures)

### XML Standards
- **XML Signature Syntax and Processing (W3C)**: Core XML signature specification
- **XML-Signature XPath Filter 2.0 (W3C)**: XPath-based transformations
- **Exclusive XML Canonicalization (W3C)**: Canonical XML for signatures

## Production Considerations

### Security
- Use HSM for private key operations
- Implement proper certificate validation
- Validate timestamp tokens against trusted TSAs
- Implement CRL/OCSP checking for real-time revocation

### Performance
- Cache certificate chains and validation responses
- Implement async processing for large documents
- Use streaming for large PDF files
- Optimize XML canonicalization

### Monitoring
- Log all signature operations
- Monitor TSA response times
- Track signature validation success rates
- Alert on certificate expiration

### Scalability
- Implement signature queue processing
- Use distributed certificate caches
- Load balance TSA requests
- Implement signature job status tracking

## Testing

### Unit Tests
```bash
pytest backend/tests/test_eu_dss_service.py -v
pytest backend/tests/test_eu_dss_api.py -v
```

### Integration Tests
```bash
pytest backend/tests/test_dss_integration.py -v
```

### Performance Tests
```bash
pytest backend/tests/test_dss_performance.py -v
```

## Troubleshooting

### Common Issues

#### XMLSec Initialization Fails
```
Error: Failed to initialize xmlsec
Solution: Install libxmlsec1-dev and ensure proper library paths
```

#### PDF Signature Embedding Fails
```
Error: Could not embed signature in PDF
Solution: Ensure PDF is not encrypted and has write permissions
```

#### Timestamp Request Fails
```
Error: TSA request failed with status 500
Solution: Check TSA URL and network connectivity
```

#### Certificate Validation Fails
```
Error: Certificate chain validation failed
Solution: Check trust store configuration and certificate chain completeness
```

### Debug Mode
```python
# Enable detailed logging
import logging
logging.getLogger('eu_dss_service').setLevel(logging.DEBUG)
logging.getLogger('xmlsec').setLevel(logging.DEBUG)

# Test DSS service
dss_service = EUDSSService({"debug": True})
```