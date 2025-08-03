import React, { useState, useCallback } from 'react';
import { QESPlatformProvider, useQESPlatform } from './hooks/useQESPlatform';
import AuthenticationFlow from './components/AuthenticationFlow';
import DocumentUploader from './components/DocumentUploader';
import SignatureViewer from './components/SignatureViewer';
import ProviderSelector from './components/ProviderSelector';
import './App.css';

/**
 * QES Platform React Demo Application
 * 
 * This application demonstrates how to integrate the QES Platform
 * into a React frontend application, including:
 * 
 * - User authentication with QES providers
 * - Document upload and signing
 * - Signature verification
 * - Real-time status updates
 */

function QESPlatformDemo() {
  const {
    isAuthenticated,
    user,
    providers,
    certificates,
    loading,
    error,
    authenticate,
    signDocument,
    verifySignature,
    clearError
  } = useQESPlatform();

  const [selectedProvider, setSelectedProvider] = useState(null);
  const [signedDocuments, setSignedDocuments] = useState([]);
  const [activeTab, setActiveTab] = useState('authenticate');

  const handleAuthentication = useCallback(async (providerInfo, userIdentifier) => {
    try {
      const result = await authenticate(providerInfo.provider_id, userIdentifier);
      console.log('Authentication initiated:', result);
      setActiveTab('sign');
    } catch (err) {
      console.error('Authentication failed:', err);
    }
  }, [authenticate]);

  const handleDocumentSign = useCallback(async (file, signatureFormat) => {
    try {
      const result = await signDocument(file, signatureFormat);
      setSignedDocuments(prev => [...prev, result]);
      setActiveTab('verify');
    } catch (err) {
      console.error('Signature failed:', err);
    }
  }, [signDocument]);

  const handleSignatureVerification = useCallback(async (signatureId) => {
    try {
      const result = await verifySignature(signatureId);
      console.log('Verification result:', result);
    } catch (err) {
      console.error('Verification failed:', err);
    }
  }, [verifySignature]);

  return (
    <div className="qes-demo-app">
      <header className="app-header">
        <div className="container">
          <h1>🔐 QES Platform Demo</h1>
          <p>Qualified Electronic Signatures made simple</p>
          
          {isAuthenticated && user && (
            <div className="user-info">
              <span>👋 Welcome, {user.given_name} {user.family_name}</span>
              <span className="country-badge">{user.country_code}</span>
            </div>
          )}
        </div>
      </header>

      <main className="app-main">
        <div className="container">
          {error && (
            <div className="error-banner">
              <span>⚠️ {error}</span>
              <button onClick={clearError} className="error-close">✕</button>
            </div>
          )}

          {loading && (
            <div className="loading-banner">
              <span>⏳ Processing...</span>
            </div>
          )}

          <div className="demo-tabs">
            <button 
              className={`tab ${activeTab === 'authenticate' ? 'active' : ''}`}
              onClick={() => setActiveTab('authenticate')}
            >
              1. Authenticate
            </button>
            <button 
              className={`tab ${activeTab === 'sign' ? 'active' : ''}`}
              onClick={() => setActiveTab('sign')}
              disabled={!isAuthenticated}
            >
              2. Sign Document
            </button>
            <button 
              className={`tab ${activeTab === 'verify' ? 'active' : ''}`}
              onClick={() => setActiveTab('verify')}
              disabled={signedDocuments.length === 0}
            >
              3. Verify Signature
            </button>
          </div>

          <div className="demo-content">
            {activeTab === 'authenticate' && (
              <div className="auth-section">
                <h2>🔑 User Authentication</h2>
                <p>Select a QES provider and authenticate to get started:</p>
                
                <ProviderSelector
                  providers={providers}
                  selectedProvider={selectedProvider}
                  onProviderSelect={setSelectedProvider}
                />

                {selectedProvider && (
                  <AuthenticationFlow
                    provider={selectedProvider}
                    onAuthenticate={handleAuthentication}
                    isAuthenticated={isAuthenticated}
                  />
                )}
              </div>
            )}

            {activeTab === 'sign' && (
              <div className="sign-section">
                <h2>✍️ Document Signing</h2>
                <p>Upload a document and create a qualified electronic signature:</p>
                
                <DocumentUploader
                  onDocumentSign={handleDocumentSign}
                  certificates={certificates}
                />

                {signedDocuments.length > 0 && (
                  <div className="signed-documents">
                    <h3>📋 Recent Signatures</h3>
                    {signedDocuments.map((doc, index) => (
                      <div key={index} className="signed-document-item">
                        <span>📄 {doc.document_name}</span>
                        <span className="signature-format">{doc.signature_format}</span>
                        <span className="signature-time">{new Date(doc.timestamp).toLocaleString()}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'verify' && (
              <div className="verify-section">
                <h2>🔍 Signature Verification</h2>
                <p>Verify the authenticity and integrity of signed documents:</p>
                
                <SignatureViewer
                  signedDocuments={signedDocuments}
                  onVerifySignature={handleSignatureVerification}
                />
              </div>
            )}
          </div>
        </div>
      </main>

      <footer className="app-footer">
        <div className="container">
          <p>
            Powered by <a href="https://qes-platform.com" target="_blank" rel="noopener noreferrer">QES Platform</a>
            • Built with React • eIDAS Compliant
          </p>
          
          <div className="footer-links">
            <a href="https://docs.qes-platform.com" target="_blank" rel="noopener noreferrer">
              📚 Documentation
            </a>
            <a href="https://github.com/qes-platform/examples" target="_blank" rel="noopener noreferrer">
              🔧 GitHub
            </a>
            <a href="https://support.qes-platform.com" target="_blank" rel="noopener noreferrer">
              💬 Support
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}

/**
 * Main App Component with QES Platform Provider
 */
function App() {
  const config = {
    apiUrl: process.env.REACT_APP_QES_API_URL || 'http://localhost:8000/api/v1',
    apiKey: process.env.REACT_APP_QES_API_KEY || 'dev-api-key',
    tenantId: process.env.REACT_APP_QES_TENANT_ID || 'dev-tenant'
  };

  return (
    <QESPlatformProvider config={config}>
      <QESPlatformDemo />
    </QESPlatformProvider>
  );
}

export default App;