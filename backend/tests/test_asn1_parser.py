"""
Test Suite for Advanced ASN.1 Parser

Comprehensive tests for RFC 3161 timestamp token parsing,
including edge cases and malformed input handling.
"""

import pytest
import hashlib
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from core.asn1_parser import ASN1Parser, TSAInfo, CertificateInfo, SignatureInfo
from core.tsa_client import TSAClient


class TestASN1Parser:
    """Test suite for ASN.1Parser class"""
    
    def setup_method(self):
        """Setup test environment"""
        self.parser = ASN1Parser()
    
    def test_hash_oid_mapping(self):
        """Test hash algorithm OID mappings"""
        
        # Test known OIDs
        assert self.parser.hash_oid_map["2.16.840.1.101.3.4.2.1"] == "SHA-256"
        assert self.parser.hash_oid_map["1.3.14.3.2.26"] == "SHA-1"
        assert self.parser.hash_oid_map["2.16.840.1.101.3.4.2.3"] == "SHA-512"
        
        # Test OID count
        assert len(self.parser.hash_oid_map) >= 9  # Should have multiple algorithms
    
    def test_signature_oid_mapping(self):
        """Test signature algorithm OID mappings"""
        
        # Test known OIDs
        assert self.parser.signature_oid_map["1.2.840.113549.1.1.11"] == "RSA-SHA256"
        assert self.parser.signature_oid_map["1.2.840.10045.4.3.2"] == "ECDSA-SHA256"
        
        # Test OID count
        assert len(self.parser.signature_oid_map) >= 8  # Should have multiple algorithms
    
    def test_tsa_policy_mapping(self):
        """Test TSA policy OID mappings"""
        
        # Test known TSA policies
        assert "DigiCert" in self.parser.tsa_policy_map["1.3.6.1.4.1.4146.1.1"]
        assert "VeriSign" in self.parser.tsa_policy_map["1.3.6.1.4.1.601.10.3.1"]
        
        # Test policy count
        assert len(self.parser.tsa_policy_map) >= 3
    
    def test_message_imprint_verification_success(self):
        """Test successful message imprint verification"""
        
        # Create test data
        original_data = b"Hello, World!"
        hash_digest = hashlib.sha256(original_data).digest()
        
        # Create mock TSTInfo
        tst_info = TSAInfo(
            version=1,
            policy_id="1.2.3.4",
            message_imprint=hash_digest,
            hash_algorithm="SHA-256",
            serial_number="12345",
            gen_time=datetime.now(timezone.utc),
            accuracy=None,
            ordering=False,
            nonce=None,
            tsa_name="Test TSA",
            extensions=None
        )
        
        # Test verification
        result = self.parser.verify_message_imprint(tst_info, original_data)
        assert result is True
    
    def test_message_imprint_verification_failure(self):
        """Test failed message imprint verification"""
        
        # Create test data
        original_data = b"Hello, World!"
        wrong_data = b"Goodbye, World!"
        hash_digest = hashlib.sha256(wrong_data).digest()
        
        # Create mock TSTInfo with wrong hash
        tst_info = TSAInfo(
            version=1,
            policy_id="1.2.3.4",
            message_imprint=hash_digest,
            hash_algorithm="SHA-256",
            serial_number="12345",
            gen_time=datetime.now(timezone.utc),
            accuracy=None,
            ordering=False,
            nonce=None,
            tsa_name="Test TSA",
            extensions=None
        )
        
        # Test verification
        result = self.parser.verify_message_imprint(tst_info, original_data)
        assert result is False
    
    def test_message_imprint_unsupported_algorithm(self):
        """Test message imprint verification with unsupported algorithm"""
        
        original_data = b"Hello, World!"
        hash_digest = b"fake_hash"
        
        # Create mock TSTInfo with unsupported algorithm
        tst_info = TSAInfo(
            version=1,
            policy_id="1.2.3.4",
            message_imprint=hash_digest,
            hash_algorithm="UNSUPPORTED-HASH",
            serial_number="12345",
            gen_time=datetime.now(timezone.utc),
            accuracy=None,
            ordering=False,
            nonce=None,
            tsa_name="Test TSA",
            extensions=None
        )
        
        # Test verification
        result = self.parser.verify_message_imprint(tst_info, original_data)
        assert result is False
    
    def test_parse_generalized_time_with_z(self):
        """Test parsing GeneralizedTime with Z suffix"""
        
        # Mock ASN.1 GeneralizedTime
        mock_time = Mock()
        mock_time.__str__ = Mock(return_value="20241201120000Z")
        
        result = self.parser._parse_generalized_time(mock_time)
        
        assert isinstance(result, datetime)
        assert result.year == 2024
        assert result.month == 12
        assert result.day == 1
        assert result.hour == 12
        assert result.tzinfo == timezone.utc
    
    def test_parse_generalized_time_without_z(self):
        """Test parsing GeneralizedTime without Z suffix"""
        
        mock_time = Mock()
        mock_time.__str__ = Mock(return_value="20241201120000")
        
        result = self.parser._parse_generalized_time(mock_time)
        
        assert isinstance(result, datetime)
        assert result.year == 2024
        assert result.tzinfo == timezone.utc
    
    def test_parse_generalized_time_invalid(self):
        """Test parsing invalid GeneralizedTime"""
        
        mock_time = Mock()
        mock_time.__str__ = Mock(return_value="invalid_time")
        
        # Should fallback to current time
        result = self.parser._parse_generalized_time(mock_time)
        
        assert isinstance(result, datetime)
        assert result.tzinfo == timezone.utc
    
    def test_parse_accuracy_complete(self):
        """Test parsing accuracy with all fields"""
        
        mock_accuracy = Mock()
        mock_accuracy.hasValue = Mock(side_effect=lambda field: field in ['seconds', 'millis', 'micros'])
        mock_accuracy.getComponentByName = Mock(side_effect=lambda field: {
            'seconds': 1,
            'millis': 500,
            'micros': 250
        }[field])
        
        result = self.parser._parse_accuracy(mock_accuracy)
        
        assert result == {'seconds': 1, 'millis': 500, 'micros': 250}
    
    def test_parse_accuracy_partial(self):
        """Test parsing accuracy with only some fields"""
        
        mock_accuracy = Mock()
        mock_accuracy.hasValue = Mock(side_effect=lambda field: field == 'seconds')
        mock_accuracy.getComponentByName = Mock(return_value=5)
        
        result = self.parser._parse_accuracy(mock_accuracy)
        
        assert result == {'seconds': 5}
    
    def test_certificate_matches_signer_by_issuer_serial(self):
        """Test certificate matching by issuer and serial number"""
        
        # Create mock certificate
        cert = CertificateInfo(
            subject="CN=Test User",
            issuer="CN=Test CA, O=Test Org",
            serial_number="123456789",
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc),
            public_key_algorithm="RSA",
            signature_algorithm="SHA256withRSA",
            key_usage=["digital_signature"],
            extended_key_usage=["timeStamping"],
            raw_certificate=b"fake_cert_data"
        )
        
        # Create matching signer ID
        signer_id = {
            "type": "issuer_and_serial",
            "issuer": "CN=Test CA, O=Test Org",
            "serial_number": "123456789"
        }
        
        result = self.parser._certificate_matches_signer(cert, signer_id)
        assert result is True
    
    def test_certificate_matches_signer_no_match(self):
        """Test certificate not matching signer"""
        
        cert = CertificateInfo(
            subject="CN=Test User",
            issuer="CN=Test CA, O=Test Org",
            serial_number="123456789",
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc),
            public_key_algorithm="RSA",
            signature_algorithm="SHA256withRSA",
            key_usage=["digital_signature"],
            extended_key_usage=["timeStamping"],
            raw_certificate=b"fake_cert_data"
        )
        
        # Create non-matching signer ID
        signer_id = {
            "type": "issuer_and_serial",
            "issuer": "CN=Different CA",
            "serial_number": "987654321"
        }
        
        result = self.parser._certificate_matches_signer(cert, signer_id)
        assert result is False
    
    def test_parse_invalid_token_data(self):
        """Test parsing completely invalid token data"""
        
        invalid_data = b"This is not ASN.1 data"
        
        with pytest.raises(ValueError, match="Timestamp token parsing failed"):
            self.parser.parse_timestamp_token(invalid_data)
    
    @patch('core.asn1_parser.decoder.decode')
    def test_parse_token_with_decoder_error(self, mock_decode):
        """Test token parsing when ASN.1 decoder fails"""
        
        # Make decoder raise an exception
        mock_decode.side_effect = Exception("ASN.1 decode error")
        
        token_data = b"fake_token_data"
        
        with pytest.raises(ValueError, match="Timestamp token parsing failed"):
            self.parser.parse_timestamp_token(token_data)


class TestTSAClientWithAdvancedParsing:
    """Test TSA client integration with advanced ASN.1 parsing"""
    
    def setup_method(self):
        """Setup test environment"""
        self.tsa_client = TSAClient("http://test-tsa.example.com")
    
    @patch('core.tsa_client.ASN1Parser')
    def test_extract_timestamp_info_success(self, mock_parser_class):
        """Test successful timestamp info extraction"""
        
        # Mock parser and its methods
        mock_parser = Mock()
        mock_parser_class.return_value = mock_parser
        
        # Mock TSTInfo
        mock_tst_info = TSAInfo(
            version=1,
            policy_id="1.2.3.4.5",
            message_imprint=b"test_hash",
            hash_algorithm="SHA-256",
            serial_number="TEST123456",
            gen_time=datetime(2024, 12, 1, 12, 0, 0, tzinfo=timezone.utc),
            accuracy={"seconds": 1},
            ordering=False,
            nonce=42,
            tsa_name="Test TSA Authority",
            extensions=[]
        )
        
        # Mock certificate
        mock_cert = CertificateInfo(
            subject="CN=TSA Certificate",
            issuer="CN=TSA CA",
            serial_number="CERT123",
            not_before=datetime.now(timezone.utc),
            not_after=datetime.now(timezone.utc),
            public_key_algorithm="RSA",
            signature_algorithm="SHA256withRSA",
            key_usage=["digital_signature"],
            extended_key_usage=["timeStamping"],
            raw_certificate=b"cert_data"
        )
        
        # Setup mock parser response
        mock_parser.parse_timestamp_token.return_value = {
            "tst_info": mock_tst_info,
            "certificates": [mock_cert],
            "signature_info": []
        }
        
        # Mock time stamp token
        mock_token = Mock()
        
        # Mock original request
        from core.tsa_client import TSARequest
        original_request = TSARequest(
            message_imprint=b"test_hash",
            hash_algorithm="SHA-256"
        )
        
        # Test extraction
        result = self.tsa_client._extract_timestamp_info(mock_token, original_request)
        
        # Verify results
        assert result["parsed_successfully"] is True
        assert result["timestamp"] == mock_tst_info.gen_time
        assert result["serial_number"] == "TEST123456"
        assert result["policy_id"] == "1.2.3.4.5"
        assert result["hash_algorithm"] == "SHA-256"
        assert result["tsa_name"] == "Test TSA Authority"
        assert result["accuracy"] == {"seconds": 1}
        assert result["nonce"] == 42
        assert result["certificate"] == b"cert_data"
    
    @patch('core.tsa_client.ASN1Parser')
    def test_extract_timestamp_info_fallback(self, mock_parser_class):
        """Test timestamp info extraction fallback on parsing error"""
        
        # Make parser raise exception
        mock_parser = Mock()
        mock_parser_class.return_value = mock_parser
        mock_parser.parse_timestamp_token.side_effect = Exception("Parsing failed")
        
        mock_token = Mock()
        from core.tsa_client import TSARequest
        original_request = TSARequest(
            message_imprint=b"test_hash",
            hash_algorithm="SHA-256"
        )
        
        # Test extraction
        result = self.tsa_client._extract_timestamp_info(mock_token, original_request)
        
        # Verify fallback behavior
        assert result["parsed_successfully"] is False
        assert "error" in result
        assert isinstance(result["timestamp"], datetime)
        assert result["serial_number"] is not None
    
    @patch('core.tsa_client.ASN1Parser')
    async def test_verify_timestamp_token_comprehensive(self, mock_parser_class):
        """Test comprehensive timestamp token verification"""
        
        # Setup mock parser
        mock_parser = Mock()
        mock_parser_class.return_value = mock_parser
        
        # Mock parsed token structure
        mock_tst_info = TSAInfo(
            version=1,
            policy_id="1.2.3.4.5",
            message_imprint=hashlib.sha256(b"test_data").digest(),
            hash_algorithm="SHA-256",
            serial_number="TEST123456",
            gen_time=datetime.now(timezone.utc),
            accuracy=None,
            ordering=False,
            nonce=None,
            tsa_name="Test TSA",
            extensions=None
        )
        
        mock_parser.parse_timestamp_token.return_value = {
            "tst_info": mock_tst_info,
            "certificates": [],
            "signature_info": [],
            "signed_data": {}
        }
        
        # Mock verification methods
        mock_parser.verify_message_imprint.return_value = True
        mock_parser.verify_timestamp_signature.return_value = {
            "signature_valid": True,
            "certificate_valid": True,
            "timestamp_valid": True,
            "errors": []
        }
        
        # Test verification
        result = await self.tsa_client.verify_timestamp_token(
            b"fake_token_data",
            b"test_data",
            "SHA-256"
        )
        
        # Verify comprehensive results
        assert result["valid"] is True
        assert result["message_imprint_valid"] is True
        assert result["signature_valid"] is True
        assert result["certificate_valid"] is True
        assert result["chain_valid"] is True
        assert result["timestamp_within_validity"] is True
        assert len(result["errors"]) == 0
        assert "parsing_details" in result
    
    def test_get_timestamp_info_with_advanced_parsing(self):
        """Test getting timestamp info with advanced parsing"""
        
        with patch('core.tsa_client.ASN1Parser') as mock_parser_class:
            # Setup mock parser
            mock_parser = Mock()
            mock_parser_class.return_value = mock_parser
            
            # Mock comprehensive token info
            mock_tst_info = TSAInfo(
                version=1,
                policy_id="1.2.3.4.5",
                message_imprint=b"test_hash",
                hash_algorithm="SHA-256",
                serial_number="TEST123456",
                gen_time=datetime(2024, 12, 1, 12, 0, 0, tzinfo=timezone.utc),
                accuracy={"seconds": 1, "millis": 500},
                ordering=True,
                nonce=12345,
                tsa_name="Test TSA Authority",
                extensions=[{"oid": "1.2.3", "critical": False}]
            )
            
            mock_cert = CertificateInfo(
                subject="CN=TSA Cert",
                issuer="CN=TSA CA",
                serial_number="CERT123",
                not_before=datetime.now(timezone.utc),
                not_after=datetime.now(timezone.utc),
                public_key_algorithm="RSA",
                signature_algorithm="SHA256withRSA",
                key_usage=["digital_signature", "key_cert_sign"],
                extended_key_usage=["timeStamping", "codeSigning"],
                raw_certificate=b"cert_data"
            )
            
            mock_sig_info = SignatureInfo(
                digest_algorithm="SHA-256",
                signature_algorithm="RSA-SHA256",
                signature_value=b"signature_data",
                signer_certificate=mock_cert,
                signed_attributes={"attr1": b"value1"},
                unsigned_attributes={"attr2": b"value2"}
            )
            
            mock_parser.parse_timestamp_token.return_value = {
                "tst_info": mock_tst_info,
                "certificates": [mock_cert],
                "signature_info": [mock_sig_info],
                "content_info": {"content_type": "1.2.840.113549.1.7.2"},
                "signed_data": {
                    "is_tst_info": True,
                    "version": 3,
                    "digest_algorithms": [{"algorithm": "SHA-256"}],
                    "encap_content_type": "1.2.840.113549.1.9.16.1.4"
                }
            }
            
            # Test getting info
            result = self.tsa_client.get_timestamp_info(b"fake_token_data")
            
            # Verify comprehensive info
            assert result["parsed_successfully"] is True
            assert result["timestamp"] == mock_tst_info.gen_time
            assert result["serial_number"] == "TEST123456"
            assert result["policy_id"] == "1.2.3.4.5"
            assert result["hash_algorithm"] == "SHA-256"
            assert result["tsa_info"]["accuracy"] == {"seconds": 1, "millis": 500}
            assert result["tsa_info"]["ordering"] is True
            assert result["tsa_info"]["nonce"] == 12345
            assert len(result["certificates"]) == 1
            assert len(result["signatures"]) == 1
            assert result["summary"]["total_certificates"] == 1
            assert result["summary"]["has_nonce"] is True
            assert result["summary"]["has_extensions"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])