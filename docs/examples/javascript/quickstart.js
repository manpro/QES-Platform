#!/usr/bin/env node

/**
 * QES Platform JavaScript SDK Quick Start Example
 * 
 * This example demonstrates how to:
 * 1. Authenticate with the QES Platform API
 * 2. Authenticate a user with a QES provider
 * 3. Sign a document with qualified electronic signature
 * 4. Verify the created signature
 * 
 * Prerequisites:
 * - QES Platform account and API credentials
 * - Node.js 16+ with npm
 * - Supported QES provider account
 * 
 * Install dependencies:
 *   npm install axios form-data fs-extra
 * 
 * Usage:
 *   node quickstart.js
 */

const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs-extra');
const path = require('path');

/**
 * Simple QES Platform API client for demonstration purposes
 */
class QESPlatformClient {
  constructor(apiUrl, apiKey, tenantId) {
    this.apiUrl = apiUrl.replace(/\/$/, '');
    this.apiKey = apiKey;
    this.tenantId = tenantId;
    
    // Configure axios defaults
    this.client = axios.create({
      baseURL: this.apiUrl,
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'X-Tenant-ID': tenantId,
        'Content-Type': 'application/json',
        'User-Agent': 'QES-Platform-JS-Example/1.0'
      },
      timeout: 30000 // 30 second timeout
    });
    
    // Add response interceptor for error handling
    this.client.interceptors.response.use(
      response => response,
      error => {
        if (error.response) {
          // Server responded with error status
          const errorMessage = error.response.data?.message || error.message;
          throw new Error(`API Error (${error.response.status}): ${errorMessage}`);
        } else if (error.request) {
          // Request made but no response
          throw new Error('Network Error: No response from server');
        } else {
          // Something else happened
          throw new Error(`Request Error: ${error.message}`);
        }
      }
    );
  }

  /**
   * Check API connectivity and health
   */
  async healthCheck() {
    const response = await this.client.get('/health');
    return response.data;
  }

  /**
   * List available QES providers
   */
  async listProviders() {
    const response = await this.client.get('/providers');
    return response.data;
  }

  /**
   * Initiate user authentication with QES provider
   */
  async authenticateUser(provider, userIdentifier, redirectUri, options = {}) {
    const payload = {
      provider,
      user_identifier: userIdentifier,
      auth_method: 'oauth2',
      redirect_uri: redirectUri,
      ...options
    };
    
    const response = await this.client.post('/auth/login', payload);
    return response.data;
  }

  /**
   * Handle authentication callback from QES provider
   */
  async handleAuthCallback(provider, sessionId, callbackParams) {
    const payload = {
      provider,
      session_id: sessionId,
      callback_params: callbackParams
    };
    
    const response = await this.client.post('/auth/callback', payload);
    return response.data;
  }

  /**
   * List available certificates for signing
   */
  async listCertificates() {
    const response = await this.client.get('/certificates');
    return response.data;
  }

  /**
   * Sign a document with qualified electronic signature
   */
  async signDocument(documentPath, documentName, signatureFormat, certificateId = null, options = {}) {
    const formData = new FormData();
    
    // Add document file
    const documentStream = fs.createReadStream(documentPath);
    formData.append('document', documentStream, {
      filename: documentName,
      contentType: 'application/pdf'
    });
    
    // Add form fields
    formData.append('document_name', documentName);
    formData.append('signature_format', signatureFormat);
    
    if (certificateId) {
      formData.append('certificate_id', certificateId);
    }
    
    // Add additional options
    Object.entries(options).forEach(([key, value]) => {
      formData.append(key, value);
    });
    
    const response = await this.client.post('/sign', formData, {
      headers: {
        ...formData.getHeaders(),
        // Remove default Content-Type to let axios set it with boundary
        'Content-Type': undefined
      }
    });
    
    return response.data;
  }

  /**
   * Verify a digitally signed document
   */
  async verifySignature(signedDocumentPath, verificationLevel = 'qualified') {
    const formData = new FormData();
    
    // Add signed document file
    const documentStream = fs.createReadStream(signedDocumentPath);
    formData.append('signed_document', documentStream, {
      filename: 'signed_document.pdf',
      contentType: 'application/pdf'
    });
    
    formData.append('verification_level', verificationLevel);
    
    const response = await this.client.post('/verify', formData, {
      headers: {
        ...formData.getHeaders(),
        'Content-Type': undefined
      }
    });
    
    return response.data;
  }

  /**
   * Get tenant usage statistics
   */
  async getUsageStats(period = 'day') {
    const response = await this.client.get(`/tenant/usage?period=${period}`);
    return response.data;
  }
}

/**
 * Create a simple PDF document for testing
 */
async function createSamplePdf() {
  const pdfContent = `%PDF-1.4
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
/Resources <<
/Font <<
/F1 <<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
>>
>>
>>
>>
endobj

4 0 obj
<<
/Length 120
>>
stream
BT
/F1 12 Tf
100 700 Td
(QES Platform Test Document) Tj
0 -20 Td
(Generated: ${new Date().toISOString()}) Tj
0 -20 Td
(This is a sample document for digital signature testing.) Tj
ET
endstream
endobj

xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000300 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
470
%%EOF`;

  const filename = 'sample_document.pdf';
  await fs.writeFile(filename, pdfContent);
  return filename;
}

/**
 * Demonstrate complete QES Platform workflow
 */
async function demonstrateWorkflow() {
  // Load configuration from environment variables
  const apiUrl = process.env.QES_API_URL || 'http://localhost:8000/api/v1';
  const apiKey = process.env.QES_API_KEY || 'dev-api-key';
  const tenantId = process.env.QES_TENANT_ID || 'dev-tenant';
  
  if (!apiUrl || !apiKey || !tenantId) {
    console.log('❌ Missing required environment variables:');
    console.log('   QES_API_URL, QES_API_KEY, QES_TENANT_ID');
    console.log('\nSet them like this:');
    console.log('   export QES_API_URL="https://your-tenant.qes-platform.com/api/v1"');
    console.log('   export QES_API_KEY="your-api-key"');
    console.log('   export QES_TENANT_ID="your-tenant-id"');
    return;
  }

  console.log('🚀 QES Platform JavaScript SDK Quick Start');
  console.log('='.repeat(50));

  // Initialize client
  const client = new QESPlatformClient(apiUrl, apiKey, tenantId);

  try {
    // 1. Health Check
    console.log('\n1️⃣  Checking API connectivity...');
    const health = await client.healthCheck();
    console.log(`   ✅ API Status: ${health.status || 'unknown'}`);
    console.log(`   📅 Timestamp: ${health.timestamp || 'unknown'}`);

    // 2. List Available Providers
    console.log('\n2️⃣  Listing available QES providers...');
    const providers = await client.listProviders();
    const providerList = providers.providers || [];
    console.log(`   📋 Found ${providerList.length} providers:`);
    
    providerList.forEach(provider => {
      const status = provider.is_available ? '🟢' : '🔴';
      console.log(`      ${status} ${provider.name} (${provider.country_code})`);
    });

    // 3. Create Sample Document
    console.log('\n3️⃣  Creating sample document...');
    const samplePdf = await createSamplePdf();
    console.log(`   📄 Created: ${samplePdf}`);

    // 4. User Authentication (Demo Mode)
    console.log('\n4️⃣  Initiating user authentication...');
    
    let authResult, callbackResult;
    
    if (apiUrl.includes('localhost') || tenantId.includes('dev')) {
      console.log('   🧪 Demo Mode: Simulating authentication...');
      authResult = {
        auth_url: 'https://demo.frejaeid.com/auth?state=demo123',
        session_id: 'demo_session_123',
        state: 'demo123'
      };
      console.log(`   🔗 Auth URL: ${authResult.auth_url}`);
      
      // Simulate callback
      console.log('   ⏳ Simulating user authentication...');
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      callbackResult = {
        status: 'authenticated',
        access_token: 'demo_access_token_123',
        user_info: {
          user_id: 'demo_user_123',
          given_name: 'John',
          family_name: 'Doe',
          email: 'john.doe@example.com',
          country_code: 'SE'
        }
      };
      console.log(`   ✅ User authenticated: ${callbackResult.user_info.given_name} ${callbackResult.user_info.family_name}`);
      
    } else {
      // Real authentication flow
      authResult = await client.authenticateUser(
        'freja-se',
        'user@example.com',
        'https://your-app.com/callback'
      );
      console.log(`   🔗 Please visit: ${authResult.auth_url}`);
      console.log('   ⏳ Waiting for authentication...');
      
      // In a real application, you would handle the callback
      console.log('   👆 Complete authentication in your browser and press Enter...');
      await new Promise(resolve => {
        process.stdin.once('data', resolve);
      });
    }

    // 5. List Available Certificates
    console.log('\n5️⃣  Listing available certificates...');
    let certificateId;
    
    try {
      const certificates = await client.listCertificates();
      const certList = certificates.certificates || [];
      
      if (certList.length > 0) {
        console.log(`   📜 Found ${certList.length} certificates:`);
        certList.slice(0, 3).forEach(cert => {
          console.log(`      🔐 ${cert.subject_dn || 'Unknown'}`);
          console.log(`         Valid: ${cert.valid_from} → ${cert.valid_to}`);
        });
        
        certificateId = certList[0].certificate_id;
      } else {
        console.log('   ⚠️  No certificates found, using demo certificate');
        certificateId = 'demo_cert_123';
      }
      
    } catch (error) {
      console.log(`   ⚠️  Certificate listing failed: ${error.message}`);
      certificateId = 'demo_cert_123';
    }

    // 6. Sign Document
    console.log('\n6️⃣  Signing document...');
    const signatureResult = await client.signDocument(
      samplePdf,
      'sample_contract.pdf',
      'PAdES-LTA',
      certificateId
    );
    
    console.log('   ✅ Signature created successfully!');
    console.log(`   🆔 Signature ID: ${signatureResult.signature_id}`);
    console.log(`   📝 Format: ${signatureResult.signature_format}`);
    console.log(`   ⏰ Timestamp: ${signatureResult.timestamp}`);
    
    // Save signed document
    let signedFilename;
    if (signatureResult.signed_document) {
      const signedDocData = Buffer.from(signatureResult.signed_document, 'base64');
      signedFilename = 'signed_document.pdf';
      await fs.writeFile(signedFilename, signedDocData);
      console.log(`   💾 Saved signed document: ${signedFilename}`);
    }

    // 7. Verify Signature
    if (signedFilename) {
      console.log('\n7️⃣  Verifying signature...');
      const verificationResult = await client.verifySignature(signedFilename);
      
      const isValid = verificationResult.is_valid || false;
      const statusIcon = isValid ? '✅' : '❌';
      console.log(`   ${statusIcon} Signature Valid: ${isValid}`);
      console.log(`   🔍 Verification Level: ${verificationResult.verification_level}`);
      
      const validationDetails = verificationResult.validation_details || {};
      console.log(`   📋 Certificate Valid: ${validationDetails.certificate_valid}`);
      console.log(`   🔒 Signature Intact: ${validationDetails.signature_intact}`);
      console.log(`   ⏱️  Timestamp Valid: ${validationDetails.timestamp_valid}`);
    }

    // 8. Usage Statistics
    console.log('\n8️⃣  Checking usage statistics...');
    try {
      const usageStats = await client.getUsageStats();
      console.log(`   📊 Signatures Created Today: ${usageStats.signatures_created || 0}`);
      console.log(`   ✔️  Signatures Verified Today: ${usageStats.signatures_verified || 0}`);
      console.log(`   📈 API Requests Today: ${usageStats.api_requests || 0}`);
    } catch (error) {
      console.log(`   ⚠️  Usage stats unavailable: ${error.message}`);
    }

    console.log('\n🎉 QES Platform workflow completed successfully!');
    console.log('\n📚 Next Steps:');
    console.log('   • Explore the full API documentation');
    console.log('   • Integrate with your application');
    console.log('   • Test with different signature formats');
    console.log('   • Set up webhook notifications');

  } catch (error) {
    console.log(`\n❌ Error: ${error.message}`);
    
    if (error.stack) {
      console.log('\n🔍 Stack Trace:');
      console.log(error.stack);
    }
    
  } finally {
    // Cleanup
    const filesToCleanup = ['sample_document.pdf', 'signed_document.pdf'];
    
    for (const file of filesToCleanup) {
      try {
        if (await fs.pathExists(file)) {
          await fs.remove(file);
          console.log(`   🧹 Cleaned up: ${file}`);
        }
      } catch (error) {
        console.log(`   ⚠️  Failed to cleanup ${file}: ${error.message}`);
      }
    }
  }
}

/**
 * Check for required dependencies
 */
async function checkDependencies() {
  const requiredPackages = ['axios', 'form-data', 'fs-extra'];
  const missingPackages = [];
  
  for (const pkg of requiredPackages) {
    try {
      require.resolve(pkg);
    } catch (error) {
      missingPackages.push(pkg);
    }
  }
  
  if (missingPackages.length > 0) {
    console.log('❌ Missing required dependencies:');
    missingPackages.forEach(pkg => console.log(`   • ${pkg}`));
    console.log('\nInstall them with:');
    console.log(`   npm install ${missingPackages.join(' ')}`);
    process.exit(1);
  }
}

/**
 * Main function
 */
async function main() {
  console.log('QES Platform JavaScript SDK - Quick Start Example');
  console.log('='.repeat(50));
  console.log();
  console.log('This example demonstrates the complete QES workflow:');
  console.log('• API connectivity check');
  console.log('• Provider listing');
  console.log('• User authentication');
  console.log('• Document signing');
  console.log('• Signature verification');
  console.log();
  
  // Check dependencies
  await checkDependencies();
  
  // Check for environment setup
  const missingVars = [];
  const envVars = ['QES_API_URL', 'QES_API_KEY', 'QES_TENANT_ID'];
  
  for (const varName of envVars) {
    if (!process.env[varName]) {
      missingVars.push(varName);
    }
  }
  
  if (missingVars.length > 0) {
    console.log('⚠️  Missing environment variables for production use:');
    missingVars.forEach(varName => console.log(`   • ${varName}`));
    console.log('\nRunning in demo mode with local development server...');
    console.log('For production, set the above environment variables.');
    console.log();
  }
  
  console.log('Press Enter to start the demonstration...');
  await new Promise(resolve => {
    process.stdin.once('data', resolve);
  });
  
  await demonstrateWorkflow();
}

// Run the demonstration if this file is executed directly
if (require.main === module) {
  main().catch(error => {
    console.error('Fatal error:', error.message);
    process.exit(1);
  });
}

module.exports = {
  QESPlatformClient,
  demonstrateWorkflow,
  createSamplePdf
};