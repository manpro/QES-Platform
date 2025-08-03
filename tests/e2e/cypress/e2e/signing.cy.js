/**
 * Digital Signing End-to-End Tests
 * 
 * Tests document signing workflows including:
 * - Document upload and validation
 * - Signature creation with different formats
 * - Provider-specific signing flows
 * - Batch signing operations
 */

describe('Digital Signing', () => {
  const apiUrl = Cypress.env('apiUrl');
  const testUsers = Cypress.env('testUsers');
  
  beforeEach(() => {
    // Login before each test
    cy.login(testUsers.user.email, testUsers.user.password);
    cy.visit('/sign');
  });

  describe('Document Upload', () => {
    it('should upload PDF document successfully', () => {
      const fileName = 'test-document.pdf';
      
      cy.get('[data-cy=document-upload]').should('be.visible');
      cy.get('[data-cy=upload-area]').should('contain', 'Drop files here or click to browse');
      
      // Upload test PDF
      cy.fixture(fileName, 'base64').then(fileContent => {
        cy.get('[data-cy=file-input]').selectFile({
          contents: Cypress.Buffer.from(fileContent, 'base64'),
          fileName: fileName,
          mimeType: 'application/pdf'
        }, { force: true });
      });
      
      // Should show upload progress
      cy.get('[data-cy=upload-progress]').should('be.visible');
      
      // Should complete upload
      cy.get('[data-cy=upload-success]', { timeout: 10000 })
        .should('be.visible')
        .and('contain', fileName);
      
      // Should display document preview
      cy.get('[data-cy=document-preview]').should('be.visible');
      cy.get('[data-cy=document-info]')
        .should('contain', fileName)
        .and('contain', 'PDF');
    });

    it('should validate file types', () => {
      const invalidFile = 'invalid-file.txt';
      
      cy.fixture(invalidFile).then(fileContent => {
        cy.get('[data-cy=file-input]').selectFile({
          contents: fileContent,
          fileName: invalidFile,
          mimeType: 'text/plain'
        }, { force: true });
      });
      
      // Should show validation error
      cy.get('[data-cy=upload-error]')
        .should('be.visible')
        .and('contain', 'Invalid file type');
      
      cy.get('[data-cy=supported-formats]')
        .should('be.visible')
        .and('contain', 'PDF, XML');
    });

    it('should validate file size limits', () => {
      // Mock large file
      cy.intercept('POST', `${apiUrl}/sign`, {
        statusCode: 413,
        body: { error: 'File too large' }
      }).as('fileTooLarge');
      
      const largeFile = 'large-document.pdf';
      cy.fixture(largeFile, 'base64').then(fileContent => {
        cy.get('[data-cy=file-input]').selectFile({
          contents: Cypress.Buffer.from(fileContent, 'base64'),
          fileName: largeFile,
          mimeType: 'application/pdf'
        }, { force: true });
      });
      
      cy.wait('@fileTooLarge');
      
      cy.get('[data-cy=upload-error]')
        .should('be.visible')
        .and('contain', 'File size exceeds limit');
    });
  });

  describe('Signature Configuration', () => {
    beforeEach(() => {
      // Upload test document first
      cy.uploadTestDocument('test-document.pdf');
    });

    it('should configure signature format', () => {
      cy.get('[data-cy=signature-format]').should('be.visible');
      
      // Test different formats
      const formats = ['PAdES-B', 'PAdES-T', 'PAdES-LTA', 'XAdES-B', 'XAdES-T', 'XAdES-LTA'];
      
      formats.forEach(format => {
        cy.get('[data-cy=format-selector]').select(format);
        cy.get('[data-cy=format-description]')
          .should('be.visible')
          .and('contain', format);
      });
    });

    it('should select certificate', () => {
      cy.get('[data-cy=certificate-selection]').should('be.visible');
      
      // Should load available certificates
      cy.get('[data-cy=certificate-list]').should('be.visible');
      cy.get('[data-cy=certificate-item]').should('have.length.at.least', 1);
      
      // Select certificate
      cy.get('[data-cy=certificate-item]').first().click();
      
      // Should show certificate details
      cy.get('[data-cy=certificate-details]')
        .should('be.visible')
        .and('contain', 'Valid until');
    });

    it('should configure advanced options', () => {
      cy.get('[data-cy=advanced-options]').click();
      
      // Timestamp configuration
      cy.get('[data-cy=timestamp-enabled]').check();
      cy.get('[data-cy=timestamp-url]')
        .should('be.visible')
        .and('have.value', 'http://timestamp.digicert.com');
      
      // Signature policy
      cy.get('[data-cy=signature-policy]').select('ETSI-TS-119-442');
      
      // Visual signature (for PDF)
      cy.get('[data-cy=visual-signature]').check();
      cy.get('[data-cy=signature-position]').should('be.visible');
    });
  });

  describe('Signing Process', () => {
    beforeEach(() => {
      cy.uploadTestDocument('test-document.pdf');
      cy.selectCertificate();
    });

    it('should sign document with PAdES-LTA format', { tags: ['@signing'] }, () => {
      cy.get('[data-cy=format-selector]').select('PAdES-LTA');
      cy.get('[data-cy=sign-button]').click();
      
      // Should show signing progress
      cy.get('[data-cy=signing-progress]').should('be.visible');
      cy.get('[data-cy=progress-status]').should('contain', 'Preparing signature');
      
      // Should complete signing
      cy.get('[data-cy=signing-success]', { timeout: 30000 })
        .should('be.visible')
        .and('contain', 'Document signed successfully');
      
      // Should display signature details
      cy.get('[data-cy=signature-info]')
        .should('be.visible')
        .and('contain', 'PAdES-LTA');
      
      // Should allow download
      cy.get('[data-cy=download-signed]').should('be.visible').and('not.be.disabled');
    });

    it('should handle provider-specific signing', { tags: ['@provider'] }, () => {
      const provider = 'freja-se';
      
      // Select provider-specific certificate
      cy.get(`[data-cy=certificate-${provider}]`).click();
      cy.get('[data-cy=sign-button]').click();
      
      if (Cypress.env('testProviders')[provider].mockMode) {
        // Mock provider authentication
        cy.mockProviderSigning(provider);
        
        // Should complete signing
        cy.get('[data-cy=signing-success]', { timeout: 30000 })
          .should('be.visible');
      } else {
        // Should redirect to provider
        cy.url().should('include', provider);
      }
    });

    it('should validate signing prerequisites', () => {
      // Try to sign without certificate
      cy.get('[data-cy=certificate-item]').should('be.visible');
      cy.get('[data-cy=sign-button]').click();
      
      cy.get('[data-cy=validation-error]')
        .should('be.visible')
        .and('contain', 'Please select a certificate');
      
      // Select certificate but invalid format
      cy.selectCertificate();
      cy.get('[data-cy=format-selector]').select('');
      cy.get('[data-cy=sign-button]').click();
      
      cy.get('[data-cy=validation-error]')
        .should('be.visible')
        .and('contain', 'Please select signature format');
    });

    it('should handle signing errors gracefully', () => {
      cy.intercept('POST', `${apiUrl}/sign`, {
        statusCode: 500,
        body: { error: 'Signing service unavailable' }
      }).as('signingError');
      
      cy.get('[data-cy=sign-button]').click();
      cy.wait('@signingError');
      
      cy.get('[data-cy=signing-error]')
        .should('be.visible')
        .and('contain', 'Signing failed');
      
      // Should allow retry
      cy.get('[data-cy=retry-button]').should('be.visible');
    });
  });

  describe('Batch Signing', () => {
    it('should upload multiple documents', { tags: ['@batch'] }, () => {
      cy.visit('/sign/batch');
      
      const files = ['doc1.pdf', 'doc2.pdf', 'doc3.xml'];
      
      files.forEach(fileName => {
        cy.fixture(fileName, 'base64').then(fileContent => {
          cy.get('[data-cy=batch-file-input]').selectFile({
            contents: Cypress.Buffer.from(fileContent, 'base64'),
            fileName: fileName,
            mimeType: fileName.endsWith('.pdf') ? 'application/pdf' : 'application/xml'
          }, { action: 'drag-drop', force: true });
        });
      });
      
      // Should show all uploaded files
      cy.get('[data-cy=batch-file-list]').should('be.visible');
      cy.get('[data-cy=batch-file-item]').should('have.length', files.length);
    });

    it('should configure batch signing options', { tags: ['@batch'] }, () => {
      cy.visit('/sign/batch');
      cy.uploadMultipleTestDocuments(['doc1.pdf', 'doc2.pdf']);
      
      // Select format for all
      cy.get('[data-cy=batch-format-all]').select('PAdES-T');
      
      // Should apply to all documents
      cy.get('[data-cy=document-format]').each($el => {
        cy.wrap($el).should('contain', 'PAdES-T');
      });
      
      // Select certificate for all
      cy.get('[data-cy=batch-certificate-all]').click();
      cy.selectCertificate();
      
      // Should apply to all documents
      cy.get('[data-cy=document-certificate]').each($el => {
        cy.wrap($el).should('not.be.empty');
      });
    });

    it('should execute batch signing', { tags: ['@batch'] }, () => {
      cy.visit('/sign/batch');
      cy.uploadMultipleTestDocuments(['doc1.pdf', 'doc2.pdf']);
      cy.configureBatchSigning();
      
      cy.get('[data-cy=batch-sign-button]').click();
      
      // Should show batch progress
      cy.get('[data-cy=batch-progress]').should('be.visible');
      cy.get('[data-cy=progress-bar]').should('be.visible');
      
      // Should complete batch signing
      cy.get('[data-cy=batch-success]', { timeout: 60000 })
        .should('be.visible')
        .and('contain', 'Batch signing completed');
      
      // Should show results summary
      cy.get('[data-cy=batch-summary]')
        .should('be.visible')
        .and('contain', '2 documents signed successfully');
      
      // Should allow download all
      cy.get('[data-cy=download-all-signed]').should('be.visible');
    });
  });

  describe('Signature Management', () => {
    it('should view signature history', () => {
      cy.visit('/signatures');
      
      cy.get('[data-cy=signature-list]').should('be.visible');
      cy.get('[data-cy=signature-item]').should('have.length.at.least', 1);
      
      // Should display signature details
      cy.get('[data-cy=signature-item]').first().within(() => {
        cy.get('[data-cy=document-name]').should('be.visible');
        cy.get('[data-cy=signature-format]').should('be.visible');
        cy.get('[data-cy=signature-date]').should('be.visible');
        cy.get('[data-cy=signature-status]').should('be.visible');
      });
    });

    it('should filter signatures', () => {
      cy.visit('/signatures');
      
      // Filter by format
      cy.get('[data-cy=format-filter]').select('PAdES-LTA');
      cy.get('[data-cy=signature-item]').each($item => {
        cy.wrap($item).find('[data-cy=signature-format]')
          .should('contain', 'PAdES-LTA');
      });
      
      // Filter by date range
      cy.get('[data-cy=date-from]').type('2023-01-01');
      cy.get('[data-cy=date-to]').type('2023-12-31');
      cy.get('[data-cy=apply-filter]').click();
      
      // Should update results
      cy.get('[data-cy=filter-results]').should('be.visible');
    });

    it('should download signed documents', () => {
      cy.visit('/signatures');
      
      cy.get('[data-cy=signature-item]').first().within(() => {
        cy.get('[data-cy=download-signed]').click();
      });
      
      // Should trigger download
      cy.readFile('cypress/downloads', { timeout: 10000 }).should('exist');
    });
  });
});