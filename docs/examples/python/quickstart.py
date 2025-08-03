#!/usr/bin/env python3
"""
QES Platform Python SDK Quick Start Example

This example demonstrates how to:
1. Authenticate with the QES Platform API
2. Authenticate a user with a QES provider (Freja eID)
3. Sign a PDF document with qualified electronic signature
4. Verify the created signature

Prerequisites:
- QES Platform account and API credentials
- Freja eID test account (or other supported provider)
- Python 3.8+ with requests library

Install dependencies:
    pip install requests cryptography

Usage:
    python quickstart.py
"""

import os
import json
import time
import base64
from typing import Dict, Any, Optional
import requests
from pathlib import Path


class QESPlatformClient:
    """Simple QES Platform API client for demonstration purposes."""
    
    def __init__(self, api_url: str, api_key: str, tenant_id: str):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.tenant_id = tenant_id
        self.session = requests.Session()
        
        # Set default headers
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'X-Tenant-ID': tenant_id,
            'Content-Type': 'application/json',
            'User-Agent': 'QES-Platform-Python-Example/1.0'
        })
    
    def health_check(self) -> Dict[str, Any]:
        """Check API connectivity and health."""
        response = self.session.get(f'{self.api_url}/health')
        response.raise_for_status()
        return response.json()
    
    def list_providers(self) -> Dict[str, Any]:
        """List available QES providers."""
        response = self.session.get(f'{self.api_url}/providers')
        response.raise_for_status()
        return response.json()
    
    def authenticate_user(self, provider: str, user_identifier: str, 
                         redirect_uri: str, **kwargs) -> Dict[str, Any]:
        """Initiate user authentication with QES provider."""
        payload = {
            'provider': provider,
            'user_identifier': user_identifier,
            'auth_method': 'oauth2',
            'redirect_uri': redirect_uri,
            **kwargs
        }
        
        response = self.session.post(f'{self.api_url}/auth/login', json=payload)
        response.raise_for_status()
        return response.json()
    
    def handle_auth_callback(self, provider: str, session_id: str, 
                           callback_params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle authentication callback from QES provider."""
        payload = {
            'provider': provider,
            'session_id': session_id,
            'callback_params': callback_params
        }
        
        response = self.session.post(f'{self.api_url}/auth/callback', json=payload)
        response.raise_for_status()
        return response.json()
    
    def list_certificates(self) -> Dict[str, Any]:
        """List available certificates for signing."""
        response = self.session.get(f'{self.api_url}/certificates')
        response.raise_for_status()
        return response.json()
    
    def sign_document(self, document_path: str, document_name: str,
                     signature_format: str, certificate_id: Optional[str] = None,
                     **kwargs) -> Dict[str, Any]:
        """Sign a document with qualified electronic signature."""
        
        # Prepare multipart form data
        files = {
            'document': (document_name, open(document_path, 'rb'), 'application/pdf')
        }
        
        data = {
            'document_name': document_name,
            'signature_format': signature_format,
            **kwargs
        }
        
        if certificate_id:
            data['certificate_id'] = certificate_id
        
        # Remove Content-Type header for multipart requests
        headers = self.session.headers.copy()
        headers.pop('Content-Type', None)
        
        response = self.session.post(
            f'{self.api_url}/sign',
            files=files,
            data=data,
            headers=headers
        )
        response.raise_for_status()
        return response.json()
    
    def verify_signature(self, signed_document_path: str, 
                        verification_level: str = 'qualified') -> Dict[str, Any]:
        """Verify a digitally signed document."""
        
        files = {
            'signed_document': (
                'signed_document.pdf',
                open(signed_document_path, 'rb'),
                'application/pdf'
            )
        }
        
        data = {
            'verification_level': verification_level
        }
        
        # Remove Content-Type header for multipart requests
        headers = self.session.headers.copy()
        headers.pop('Content-Type', None)
        
        response = self.session.post(
            f'{self.api_url}/verify',
            files=files,
            data=data,
            headers=headers
        )
        response.raise_for_status()
        return response.json()
    
    def get_usage_stats(self, period: str = 'day') -> Dict[str, Any]:
        """Get tenant usage statistics."""
        response = self.session.get(f'{self.api_url}/tenant/usage?period={period}')
        response.raise_for_status()
        return response.json()


def create_sample_pdf() -> str:
    """Create a simple PDF document for testing."""
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter
        
        filename = 'sample_document.pdf'
        c = canvas.Canvas(filename, pagesize=letter)
        
        # Add content to PDF
        c.drawString(100, 750, "QES Platform Test Document")
        c.drawString(100, 700, "This is a sample document for digital signature testing.")
        c.drawString(100, 650, f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(100, 600, "Content: Lorem ipsum dolor sit amet, consectetur adipiscing elit.")
        
        c.save()
        return filename
        
    except ImportError:
        # Fallback: create a minimal PDF manually
        print("ReportLab not available, creating minimal PDF...")
        
        minimal_pdf = b"""%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj

4 0 obj
<<
/Length 55
>>
stream
BT
/F1 12 Tf
100 700 Td
(QES Platform Test Document) Tj
ET
endstream
endobj

xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000206 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
312
%%EOF"""
        
        filename = 'sample_document.pdf'
        with open(filename, 'wb') as f:
            f.write(minimal_pdf)
        return filename


def demonstrate_workflow():
    """Demonstrate complete QES Platform workflow."""
    
    # Load configuration from environment variables
    api_url = os.getenv('QES_API_URL', 'http://localhost:8000/api/v1')
    api_key = os.getenv('QES_API_KEY', 'dev-api-key')
    tenant_id = os.getenv('QES_TENANT_ID', 'dev-tenant')
    
    if not all([api_url, api_key, tenant_id]):
        print("❌ Missing required environment variables:")
        print("   QES_API_URL, QES_API_KEY, QES_TENANT_ID")
        print("\nSet them like this:")
        print("   export QES_API_URL='https://your-tenant.qes-platform.com/api/v1'")
        print("   export QES_API_KEY='your-api-key'")
        print("   export QES_TENANT_ID='your-tenant-id'")
        return
    
    print("🚀 QES Platform Python SDK Quick Start")
    print("=" * 50)
    
    # Initialize client
    client = QESPlatformClient(api_url, api_key, tenant_id)
    
    try:
        # 1. Health Check
        print("\n1️⃣  Checking API connectivity...")
        health = client.health_check()
        print(f"   ✅ API Status: {health.get('status', 'unknown')}")
        print(f"   📅 Timestamp: {health.get('timestamp', 'unknown')}")
        
        # 2. List Available Providers
        print("\n2️⃣  Listing available QES providers...")
        providers = client.list_providers()
        print(f"   📋 Found {len(providers.get('providers', []))} providers:")
        for provider in providers.get('providers', []):
            status = "🟢" if provider.get('is_available') else "🔴"
            print(f"      {status} {provider.get('name')} ({provider.get('country_code')})")
        
        # 3. Create Sample Document
        print("\n3️⃣  Creating sample document...")
        sample_pdf = create_sample_pdf()
        print(f"   📄 Created: {sample_pdf}")
        
        # 4. User Authentication (Demo Mode)
        print("\n4️⃣  Initiating user authentication...")
        
        # In demo mode, we'll simulate the authentication flow
        if 'localhost' in api_url or 'dev' in tenant_id:
            print("   🧪 Demo Mode: Simulating authentication...")
            auth_result = {
                'auth_url': 'https://demo.frejaeid.com/auth?state=demo123',
                'session_id': 'demo_session_123',
                'state': 'demo123'
            }
            print(f"   🔗 Auth URL: {auth_result['auth_url']}")
            
            # Simulate callback
            print("   ⏳ Simulating user authentication...")
            time.sleep(2)
            
            callback_result = {
                'status': 'authenticated',
                'access_token': 'demo_access_token_123',
                'user_info': {
                    'user_id': 'demo_user_123',
                    'given_name': 'John',
                    'family_name': 'Doe',
                    'email': 'john.doe@example.com',
                    'country_code': 'SE'
                }
            }
            print(f"   ✅ User authenticated: {callback_result['user_info']['given_name']} {callback_result['user_info']['family_name']}")
            
        else:
            # Real authentication flow
            auth_result = client.authenticate_user(
                provider='freja-se',
                user_identifier='user@example.com',
                redirect_uri='https://your-app.com/callback'
            )
            print(f"   🔗 Please visit: {auth_result.get('auth_url')}")
            print("   ⏳ Waiting for authentication...")
            
            # In a real application, you would handle the callback
            # For this demo, we'll wait for user input
            input("   👆 Press Enter after completing authentication...")
        
        # 5. List Available Certificates
        print("\n5️⃣  Listing available certificates...")
        try:
            certificates = client.list_certificates()
            cert_list = certificates.get('certificates', [])
            
            if cert_list:
                print(f"   📜 Found {len(cert_list)} certificates:")
                for cert in cert_list[:3]:  # Show first 3
                    print(f"      🔐 {cert.get('subject_dn', 'Unknown')}")
                    print(f"         Valid: {cert.get('valid_from')} → {cert.get('valid_to')}")
                
                certificate_id = cert_list[0].get('certificate_id')
            else:
                print("   ⚠️  No certificates found, using demo certificate")
                certificate_id = 'demo_cert_123'
                
        except Exception as e:
            print(f"   ⚠️  Certificate listing failed: {e}")
            certificate_id = 'demo_cert_123'
        
        # 6. Sign Document
        print("\n6️⃣  Signing document...")
        signature_result = client.sign_document(
            document_path=sample_pdf,
            document_name='sample_contract.pdf',
            signature_format='PAdES-LTA',
            certificate_id=certificate_id
        )
        
        print(f"   ✅ Signature created successfully!")
        print(f"   🆔 Signature ID: {signature_result.get('signature_id')}")
        print(f"   📝 Format: {signature_result.get('signature_format')}")
        print(f"   ⏰ Timestamp: {signature_result.get('timestamp')}")
        
        # Save signed document
        if 'signed_document' in signature_result:
            signed_doc_data = base64.b64decode(signature_result['signed_document'])
            signed_filename = 'signed_document.pdf'
            with open(signed_filename, 'wb') as f:
                f.write(signed_doc_data)
            print(f"   💾 Saved signed document: {signed_filename}")
        
        # 7. Verify Signature
        if 'signed_document' in signature_result:
            print("\n7️⃣  Verifying signature...")
            verification_result = client.verify_signature(signed_filename)
            
            is_valid = verification_result.get('is_valid', False)
            status_icon = "✅" if is_valid else "❌"
            print(f"   {status_icon} Signature Valid: {is_valid}")
            print(f"   🔍 Verification Level: {verification_result.get('verification_level')}")
            
            validation_details = verification_result.get('validation_details', {})
            print(f"   📋 Certificate Valid: {validation_details.get('certificate_valid')}")
            print(f"   🔒 Signature Intact: {validation_details.get('signature_intact')}")
            print(f"   ⏱️  Timestamp Valid: {validation_details.get('timestamp_valid')}")
        
        # 8. Usage Statistics
        print("\n8️⃣  Checking usage statistics...")
        try:
            usage_stats = client.get_usage_stats()
            print(f"   📊 Signatures Created Today: {usage_stats.get('signatures_created', 0)}")
            print(f"   ✔️  Signatures Verified Today: {usage_stats.get('signatures_verified', 0)}")
            print(f"   📈 API Requests Today: {usage_stats.get('api_requests', 0)}")
        except Exception as e:
            print(f"   ⚠️  Usage stats unavailable: {e}")
        
        print("\n🎉 QES Platform workflow completed successfully!")
        print("\n📚 Next Steps:")
        print("   • Explore the full API documentation")
        print("   • Integrate with your application")
        print("   • Test with different signature formats")
        print("   • Set up webhook notifications")
        
    except requests.exceptions.RequestException as e:
        print(f"\n❌ API Error: {e}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_data = e.response.json()
                print(f"   Error Details: {error_data.get('message', 'Unknown error')}")
            except:
                print(f"   HTTP Status: {e.response.status_code}")
        
    except Exception as e:
        print(f"\n❌ Unexpected Error: {e}")
        
    finally:
        # Cleanup
        for file in ['sample_document.pdf', 'signed_document.pdf']:
            if os.path.exists(file):
                os.remove(file)
                print(f"   🧹 Cleaned up: {file}")


if __name__ == '__main__':
    print("QES Platform Python SDK - Quick Start Example")
    print("=" * 50)
    print()
    print("This example demonstrates the complete QES workflow:")
    print("• API connectivity check")
    print("• Provider listing")
    print("• User authentication")
    print("• Document signing")
    print("• Signature verification")
    print()
    
    # Check for environment setup
    missing_vars = []
    for var in ['QES_API_URL', 'QES_API_KEY', 'QES_TENANT_ID']:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print("⚠️  Missing environment variables for production use:")
        for var in missing_vars:
            print(f"   • {var}")
        print("\nRunning in demo mode with local development server...")
        print("For production, set the above environment variables.")
        print()
    
    input("Press Enter to start the demonstration...")
    demonstrate_workflow()