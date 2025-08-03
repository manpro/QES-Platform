package com.qesplatform.sdk;

import com.qesplatform.sdk.auth.AuthManager;
import com.qesplatform.sdk.certificates.CertificateManager;
import com.qesplatform.sdk.config.QESClientConfig;
import com.qesplatform.sdk.exceptions.QESAuthenticationException;
import com.qesplatform.sdk.exceptions.QESConnectionException;
import com.qesplatform.sdk.exceptions.QESException;
import com.qesplatform.sdk.http.HttpClient;
import com.qesplatform.sdk.models.ApiInfo;
import com.qesplatform.sdk.models.HealthStatus;
import com.qesplatform.sdk.providers.ProviderManager;
import com.qesplatform.sdk.signatures.SignatureManager;
import com.qesplatform.sdk.tenants.TenantManager;
import com.qesplatform.sdk.verification.VerificationManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.util.concurrent.CompletableFuture;

/**
 * Main client for the QES Platform API.
 * 
 * <p>This client provides access to all QES Platform services including
 * authentication, signing, verification, and certificate management.</p>
 * 
 * <p>Example usage:</p>
 * <pre>{@code
 * QESClient client = QESClient.builder()
 *     .apiUrl("https://api.qes-platform.com/v1")
 *     .apiKey("your-api-key")
 *     .tenantId("your-tenant-id")
 *     .build();
 * 
 * // Authenticate user
 * LoginRequest request = LoginRequest.builder()
 *     .provider("freja-se")
 *     .userIdentifier("user@example.com")
 *     .authMethod("oauth2")
 *     .build();
 * 
 * LoginResponse response = client.auth().login(request);
 * }</pre>
 * 
 * @author QES Platform Team
 * @version 1.0.0
 * @since 1.0.0
 */
public class QESClient implements Closeable {
    
    private static final Logger logger = LoggerFactory.getLogger(QESClient.class);
    
    private final QESClientConfig config;
    private final HttpClient httpClient;
    
    // Service managers
    private final AuthManager authManager;
    private final CertificateManager certificateManager;
    private final SignatureManager signatureManager;
    private final VerificationManager verificationManager;
    private final ProviderManager providerManager;
    private final TenantManager tenantManager;
    
    /**
     * Create a new QES Platform client.
     * 
     * @param config Client configuration
     * @throws IllegalArgumentException if configuration is invalid
     */
    public QESClient(QESClientConfig config) {
        this.config = validateConfig(config);
        this.httpClient = new HttpClient(config);
        
        // Initialize service managers
        this.authManager = new AuthManager(httpClient);
        this.certificateManager = new CertificateManager(httpClient);
        this.signatureManager = new SignatureManager(httpClient);
        this.verificationManager = new VerificationManager(httpClient);
        this.providerManager = new ProviderManager(httpClient);
        this.tenantManager = new TenantManager(httpClient);
        
        logger.info("Initialized QES Platform client for {}", config.getApiUrl());
    }
    
    /**
     * Create a new builder for QES client configuration.
     * 
     * @return New builder instance
     */
    public static QESClientConfig.Builder builder() {
        return QESClientConfig.builder();
    }
    
    /**
     * Get authentication manager.
     * 
     * @return Authentication manager instance
     */
    public AuthManager auth() {
        return authManager;
    }
    
    /**
     * Get certificate manager.
     * 
     * @return Certificate manager instance
     */
    public CertificateManager certificates() {
        return certificateManager;
    }
    
    /**
     * Get signature manager.
     * 
     * @return Signature manager instance
     */
    public SignatureManager signatures() {
        return signatureManager;
    }
    
    /**
     * Get verification manager.
     * 
     * @return Verification manager instance
     */
    public VerificationManager verification() {
        return verificationManager;
    }
    
    /**
     * Get provider manager.
     * 
     * @return Provider manager instance
     */
    public ProviderManager providers() {
        return providerManager;
    }
    
    /**
     * Get tenant manager.
     * 
     * @return Tenant manager instance
     */
    public TenantManager tenants() {
        return tenantManager;
    }
    
    /**
     * Update the API key.
     * 
     * @param apiKey New API key
     * @throws IllegalArgumentException if API key is null or empty
     */
    public void setApiKey(String apiKey) {
        if (apiKey == null || apiKey.trim().isEmpty()) {
            throw new IllegalArgumentException("API key cannot be null or empty");
        }
        
        httpClient.setApiKey(apiKey);
        logger.info("API key updated");
    }
    
    /**
     * Update the tenant ID.
     * 
     * @param tenantId New tenant ID
     * @throws IllegalArgumentException if tenant ID is null or empty
     */
    public void setTenantId(String tenantId) {
        if (tenantId == null || tenantId.trim().isEmpty()) {
            throw new IllegalArgumentException("Tenant ID cannot be null or empty");
        }
        
        httpClient.setTenantId(tenantId);
        logger.info("Tenant ID updated: {}", tenantId);
    }
    
    /**
     * Check API health status.
     * 
     * @return Health status information
     * @throws QESConnectionException if health check fails
     */
    public HealthStatus healthCheck() throws QESException {
        try {
            return httpClient.get("/health", HealthStatus.class);
        } catch (Exception e) {
            logger.error("Health check failed", e);
            throw new QESConnectionException("Health check failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Check API health status asynchronously.
     * 
     * @return CompletableFuture with health status information
     */
    public CompletableFuture<HealthStatus> healthCheckAsync() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return healthCheck();
            } catch (QESException e) {
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * Get API information and version.
     * 
     * @return API information
     */
    public ApiInfo getApiInfo() {
        try {
            return httpClient.get("/info", ApiInfo.class);
        } catch (Exception e) {
            logger.warn("Could not get API info: {}", e.getMessage());
            return ApiInfo.builder()
                .version("unknown")
                .build();
        }
    }
    
    /**
     * Get API information asynchronously.
     * 
     * @return CompletableFuture with API information
     */
    public CompletableFuture<ApiInfo> getApiInfoAsync() {
        return CompletableFuture.supplyAsync(this::getApiInfo);
    }
    
    /**
     * Get client configuration.
     * 
     * @return Client configuration (defensive copy)
     */
    public QESClientConfig getConfig() {
        return QESClientConfig.builder()
            .apiUrl(config.getApiUrl())
            .apiKey(config.getApiKey())
            .tenantId(config.getTenantId())
            .timeout(config.getTimeout())
            .retryCount(config.getRetryCount())
            .userAgent(config.getUserAgent())
            .build();
    }
    
    /**
     * Close the client and release resources.
     */
    @Override
    public void close() {
        try {
            httpClient.close();
            logger.info("QES Platform client closed");
        } catch (Exception e) {
            logger.warn("Error closing QES Platform client", e);
        }
    }
    
    /**
     * Validate client configuration.
     * 
     * @param config Configuration to validate
     * @return Validated configuration
     * @throws IllegalArgumentException if configuration is invalid
     */
    private QESClientConfig validateConfig(QESClientConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("Configuration cannot be null");
        }
        
        if (config.getApiUrl() == null || config.getApiUrl().trim().isEmpty()) {
            throw new IllegalArgumentException("API URL cannot be null or empty");
        }
        
        try {
            new java.net.URL(config.getApiUrl());
        } catch (java.net.MalformedURLException e) {
            throw new IllegalArgumentException("Invalid API URL format: " + config.getApiUrl(), e);
        }
        
        if (config.getTimeout() <= 0) {
            throw new IllegalArgumentException("Timeout must be positive");
        }
        
        if (config.getRetryCount() < 0) {
            throw new IllegalArgumentException("Retry count cannot be negative");
        }
        
        return config;
    }
    
    @Override
    public String toString() {
        return String.format("QESClient{apiUrl='%s', tenantId='%s'}", 
            config.getApiUrl(), 
            config.getTenantId());
    }
}