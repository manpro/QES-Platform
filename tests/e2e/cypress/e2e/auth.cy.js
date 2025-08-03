/**
 * Authentication End-to-End Tests
 * 
 * Tests user authentication flows including:
 * - Login/logout
 * - Provider-specific authentication
 * - Session management
 * - Multi-tenant access
 */

describe('Authentication', () => {
  const apiUrl = Cypress.env('apiUrl');
  const testUsers = Cypress.env('testUsers');
  
  beforeEach(() => {
    // Clear any existing sessions
    cy.clearCookies();
    cy.clearLocalStorage();
    
    // Visit login page
    cy.visit('/login');
  });

  describe('Basic Authentication', () => {
    it('should display login form', () => {
      cy.get('[data-cy=login-form]').should('be.visible');
      cy.get('[data-cy=email-input]').should('be.visible');
      cy.get('[data-cy=password-input]').should('be.visible');
      cy.get('[data-cy=login-button]').should('be.visible');
    });

    it('should show validation errors for empty fields', () => {
      cy.get('[data-cy=login-button]').click();
      
      cy.get('[data-cy=email-error]')
        .should('be.visible')
        .and('contain', 'Email is required');
      
      cy.get('[data-cy=password-error]')
        .should('be.visible')
        .and('contain', 'Password is required');
    });

    it('should login with valid credentials', () => {
      const { email, password } = testUsers.user;
      
      cy.get('[data-cy=email-input]').type(email);
      cy.get('[data-cy=password-input]').type(password);
      cy.get('[data-cy=login-button]').click();
      
      // Should redirect to dashboard
      cy.url().should('include', '/dashboard');
      
      // Should display user info
      cy.get('[data-cy=user-menu]').should('contain', email);
    });

    it('should show error for invalid credentials', () => {
      cy.get('[data-cy=email-input]').type('invalid@example.com');
      cy.get('[data-cy=password-input]').type('wrongpassword');
      cy.get('[data-cy=login-button]').click();
      
      cy.get('[data-cy=login-error]')
        .should('be.visible')
        .and('contain', 'Invalid email or password');
    });

    it('should logout successfully', () => {
      // Login first
      cy.login(testUsers.user.email, testUsers.user.password);
      
      // Logout
      cy.get('[data-cy=user-menu]').click();
      cy.get('[data-cy=logout-button]').click();
      
      // Should redirect to login
      cy.url().should('include', '/login');
      
      // Should not have user data in local storage
      cy.window().its('localStorage.token').should('not.exist');
    });
  });

  describe('Provider Authentication', () => {
    const providers = ['freja-se', 'dtrust-de'];
    
    providers.forEach(provider => {
      it(`should initiate ${provider} authentication`, { tags: ['@provider'] }, () => {
        cy.get(`[data-cy=provider-${provider}]`).click();
        
        // Should redirect to provider auth URL
        cy.url().should('include', provider);
        
        // In mock mode, simulate successful auth
        if (Cypress.env('testProviders')[provider].mockMode) {
          cy.mockProviderAuth(provider);
          
          // Should redirect back with auth code
          cy.url().should('include', '/auth/callback');
          
          // Should complete authentication
          cy.url().should('include', '/dashboard');
        }
      });
    });
  });

  describe('Multi-tenant Authentication', () => {
    it('should authenticate for specific tenant', { tags: ['@multitenant'] }, () => {
      const tenant = Cypress.env('testTenant');
      
      // Visit tenant-specific login
      cy.visit(`/${tenant.subdomain}/login`);
      
      cy.get('[data-cy=tenant-info]')
        .should('be.visible')
        .and('contain', tenant.name);
      
      // Login with tenant context
      cy.get('[data-cy=email-input]').type(testUsers.user.email);
      cy.get('[data-cy=password-input]').type(testUsers.user.password);
      cy.get('[data-cy=login-button]').click();
      
      // Should be in tenant context
      cy.url().should('include', `/${tenant.subdomain}/dashboard`);
      
      // Should display tenant-specific data
      cy.get('[data-cy=tenant-selector]').should('contain', tenant.name);
    });
  });

  describe('Session Management', () => {
    it('should maintain session across page reloads', () => {
      cy.login(testUsers.user.email, testUsers.user.password);
      
      // Reload page
      cy.reload();
      
      // Should still be authenticated
      cy.url().should('include', '/dashboard');
      cy.get('[data-cy=user-menu]').should('be.visible');
    });

    it('should handle expired tokens', () => {
      cy.login(testUsers.user.email, testUsers.user.password);
      
      // Mock expired token
      cy.window().then(win => {
        win.localStorage.setItem('token', 'expired-token');
      });
      
      // Make authenticated request
      cy.visit('/dashboard');
      
      // Should redirect to login
      cy.url().should('include', '/login');
      
      // Should show session expired message
      cy.get('[data-cy=session-expired]')
        .should('be.visible')
        .and('contain', 'Your session has expired');
    });

    it('should refresh tokens automatically', () => {
      cy.login(testUsers.user.email, testUsers.user.password);
      
      // Intercept token refresh
      cy.intercept('POST', `${apiUrl}/auth/refresh`, {
        statusCode: 200,
        body: {
          access_token: 'new-token',
          refresh_token: 'new-refresh-token',
          expires_in: 3600
        }
      }).as('refreshToken');
      
      // Trigger token refresh (mock near-expiry)
      cy.window().then(win => {
        const expiredTime = Date.now() - 1000; // 1 second ago
        win.localStorage.setItem('tokenExpiry', expiredTime.toString());
      });
      
      // Navigate to trigger token check
      cy.visit('/certificates');
      
      // Should refresh token
      cy.wait('@refreshToken');
      
      // Should continue to work
      cy.url().should('include', '/certificates');
    });
  });

  describe('Security Features', () => {
    it('should implement rate limiting', { tags: ['@security'] }, () => {
      const attempts = 6; // Exceed rate limit
      
      for (let i = 0; i < attempts; i++) {
        cy.get('[data-cy=email-input]').clear().type('test@example.com');
        cy.get('[data-cy=password-input]').clear().type('wrongpassword');
        cy.get('[data-cy=login-button]').click();
        
        if (i < 5) {
          cy.get('[data-cy=login-error]').should('contain', 'Invalid');
        }
      }
      
      // Should show rate limit error
      cy.get('[data-cy=rate-limit-error]')
        .should('be.visible')
        .and('contain', 'Too many login attempts');
    });

    it('should validate CSRF tokens', { tags: ['@security'] }, () => {
      // Mock CSRF token validation
      cy.intercept('POST', `${apiUrl}/auth/login`, {
        statusCode: 403,
        body: { error: 'Invalid CSRF token' }
      }).as('csrfError');
      
      cy.get('[data-cy=email-input]').type(testUsers.user.email);
      cy.get('[data-cy=password-input]').type(testUsers.user.password);
      cy.get('[data-cy=login-button]').click();
      
      cy.wait('@csrfError');
      
      cy.get('[data-cy=security-error]')
        .should('be.visible')
        .and('contain', 'Security validation failed');
    });
  });
});