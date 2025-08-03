const { defineConfig } = require('cypress');

module.exports = defineConfig({
  e2e: {
    baseUrl: 'http://localhost:3000',
    supportFile: 'cypress/support/e2e.js',
    specPattern: 'cypress/e2e/**/*.cy.{js,jsx,ts,tsx}',
    fixturesFolder: 'cypress/fixtures',
    screenshotsFolder: 'cypress/screenshots',
    videosFolder: 'cypress/videos',
    downloadsFolder: 'cypress/downloads',
    
    // Test configuration
    viewportWidth: 1280,
    viewportHeight: 720,
    video: true,
    screenshotOnRunFailure: true,
    
    // Timeouts
    defaultCommandTimeout: 10000,
    requestTimeout: 15000,
    responseTimeout: 15000,
    pageLoadTimeout: 30000,
    
    // Retry configuration
    retries: {
      runMode: 2,
      openMode: 0
    },
    
    env: {
      // API configuration
      apiUrl: 'http://localhost:8000',
      apiVersion: 'v1',
      
      // Test users
      testUsers: {
        admin: {
          email: 'admin@example.com',
          password: 'admin123'
        },
        user: {
          email: 'user@example.com', 
          password: 'user123'
        }
      },
      
      // Test data
      testTenant: {
        name: 'E2E Test Tenant',
        subdomain: 'e2e-test'
      },
      
      // Provider configuration
      testProviders: {
        'freja-se': {
          enabled: true,
          mockMode: true
        },
        'dtrust-de': {
          enabled: true,
          mockMode: true
        }
      },
      
      // Feature flags
      features: {
        multiTenant: true,
        rateLimit: true,
        auditLogging: true
      }
    },
    
    setupNodeEvents(on, config) {
      // Grep plugin for test filtering
      require('@cypress/grep/src/plugin')(config);
      
      // Custom tasks
      on('task', {
        // Database tasks
        clearDatabase() {
          // Clear test database
          return null;
        },
        
        seedDatabase(data) {
          // Seed test data
          return null;
        },
        
        // API tasks
        createTestTenant(tenantData) {
          // Create tenant via API
          return null;
        },
        
        uploadTestDocument(filePath) {
          // Upload document for testing
          return null;
        },
        
        // Log tasks
        log(message) {
          console.log(message);
          return null;
        }
      });
      
      // File preprocessing
      on('file:preprocessor', (file) => {
        // Add any custom file preprocessing here
        return file;
      });
      
      // Browser launch options
      on('before:browser:launch', (browser = {}, launchOptions) => {
        if (browser.name === 'chrome') {
          launchOptions.args.push('--disable-dev-shm-usage');
          launchOptions.args.push('--no-sandbox');
        }
        return launchOptions;
      });
      
      return config;
    }
  },
  
  component: {
    devServer: {
      framework: 'create-react-app',
      bundler: 'webpack'
    }
  }
});