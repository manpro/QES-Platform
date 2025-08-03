// Package qes provides a Go SDK for the QES Platform API
package qes

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
)

const (
	// Version is the SDK version
	Version = "1.0.0"
	// APIVersion is the supported API version
	APIVersion = "v1"
	// DefaultTimeout is the default request timeout
	DefaultTimeout = 30 * time.Second
	// DefaultRetryCount is the default number of retries
	DefaultRetryCount = 3
)

// Client represents the QES Platform API client
//
// Example usage:
//
//	client := qes.NewClient(&qes.Config{
//		APIUrl:   "https://api.qes-platform.com/v1",
//		APIKey:   "your-api-key",
//		TenantID: "your-tenant-id",
//	})
//
//	// Authenticate user
//	authReq := &qes.LoginRequest{
//		Provider:       "freja-se",
//		UserIdentifier: "user@example.com",
//		AuthMethod:     "oauth2",
//	}
//
//	authResp, err := client.Auth.Login(context.Background(), authReq)
//	if err != nil {
//		log.Fatal(err)
//	}
type Client struct {
	config     *Config
	httpClient *resty.Client

	// Service managers
	Auth         *AuthManager
	Certificates *CertificateManager
	Signatures   *SignatureManager
	Verification *VerificationManager
	Providers    *ProviderManager
	Tenants      *TenantManager
}

// Config holds the client configuration
type Config struct {
	// APIUrl is the base URL for the QES Platform API
	APIUrl string

	// APIKey for authentication (optional, can be set later)
	APIKey string

	// TenantID for multi-tenant environments (optional)
	TenantID string

	// Timeout for HTTP requests
	Timeout time.Duration

	// RetryCount for failed requests
	RetryCount int

	// UserAgent string for requests
	UserAgent string

	// HTTPClient allows using a custom HTTP client
	HTTPClient *http.Client

	// Debug enables debug logging
	Debug bool
}

// NewClient creates a new QES Platform client
func NewClient(config *Config) *Client {
	if config == nil {
		config = &Config{}
	}

	// Set defaults
	if config.Timeout == 0 {
		config.Timeout = DefaultTimeout
	}
	if config.RetryCount == 0 {
		config.RetryCount = DefaultRetryCount
	}
	if config.UserAgent == "" {
		config.UserAgent = fmt.Sprintf("qes-platform-go-sdk/%s", Version)
	}

	// Validate config
	if err := validateConfig(config); err != nil {
		panic(fmt.Sprintf("invalid config: %v", err))
	}

	// Create HTTP client
	httpClient := resty.New()
	if config.HTTPClient != nil {
		httpClient.SetHTTPClient(config.HTTPClient)
	}

	// Configure HTTP client
	httpClient.
		SetTimeout(config.Timeout).
		SetRetryCount(config.RetryCount).
		SetRetryWaitTime(1 * time.Second).
		SetRetryMaxWaitTime(10 * time.Second).
		SetBaseURL(config.APIUrl).
		SetHeader("User-Agent", config.UserAgent).
		SetHeader("Accept", "application/json").
		SetHeader("Content-Type", "application/json")

	// Set authentication headers
	if config.APIKey != "" {
		httpClient.SetAuthToken(config.APIKey)
	}
	if config.TenantID != "" {
		httpClient.SetHeader("X-Tenant-ID", config.TenantID)
	}

	// Enable debug if requested
	if config.Debug {
		httpClient.SetDebug(true)
	}

	// Setup request/response middleware
	setupMiddleware(httpClient)

	client := &Client{
		config:     config,
		httpClient: httpClient,
	}

	// Initialize service managers
	client.Auth = NewAuthManager(client)
	client.Certificates = NewCertificateManager(client)
	client.Signatures = NewSignatureManager(client)
	client.Verification = NewVerificationManager(client)
	client.Providers = NewProviderManager(client)
	client.Tenants = NewTenantManager(client)

	return client
}

// SetAPIKey updates the API key
func (c *Client) SetAPIKey(apiKey string) {
	c.config.APIKey = apiKey
	c.httpClient.SetAuthToken(apiKey)
}

// SetTenantID updates the tenant ID
func (c *Client) SetTenantID(tenantID string) {
	c.config.TenantID = tenantID
	c.httpClient.SetHeader("X-Tenant-ID", tenantID)
}

// HealthCheck performs a health check against the API
func (c *Client) HealthCheck(ctx context.Context) (*HealthStatus, error) {
	var health HealthStatus
	resp, err := c.httpClient.R().
		SetContext(ctx).
		SetResult(&health).
		Get("/health")

	if err != nil {
		return nil, &ConnectionError{Message: fmt.Sprintf("health check failed: %v", err)}
	}

	if resp.IsError() {
		return nil, handleErrorResponse(resp)
	}

	return &health, nil
}

// GetAPIInfo retrieves API information
func (c *Client) GetAPIInfo(ctx context.Context) (*APIInfo, error) {
	var info APIInfo
	resp, err := c.httpClient.R().
		SetContext(ctx).
		SetResult(&info).
		Get("/info")

	if err != nil {
		// Return basic info if request fails
		return &APIInfo{
			Version: "unknown",
			Status:  "unknown",
		}, nil
	}

	if resp.IsError() {
		return &APIInfo{
			Version: "unknown",
			Status:  "error",
		}, nil
	}

	return &info, nil
}

// GetConfig returns a copy of the client configuration
func (c *Client) GetConfig() Config {
	return *c.config
}

// validateConfig validates the client configuration
func validateConfig(config *Config) error {
	if config.APIUrl == "" {
		return fmt.Errorf("API URL is required")
	}

	if config.Timeout < 0 {
		return fmt.Errorf("timeout cannot be negative")
	}

	if config.RetryCount < 0 {
		return fmt.Errorf("retry count cannot be negative")
	}

	return nil
}

// setupMiddleware configures request/response middleware
func setupMiddleware(client *resty.Client) {
	// Request middleware - add request ID
	client.OnBeforeRequest(func(c *resty.Client, req *resty.Request) error {
		if req.Header.Get("X-Request-ID") == "" {
			req.SetHeader("X-Request-ID", generateRequestID())
		}
		return nil
	})

	// Response middleware - handle common errors
	client.OnAfterResponse(func(c *resty.Client, resp *resty.Response) error {
		if resp.IsError() {
			return handleErrorResponse(resp)
		}
		return nil
	})

	// Error conditions for retry
	client.AddRetryCondition(func(r *resty.Response, err error) bool {
		return r.StatusCode() >= 500 || r.StatusCode() == 429
	})
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	return fmt.Sprintf("req_%d_%s", time.Now().Unix(), uuid.New().String()[:8])
}

// handleErrorResponse converts HTTP error responses to appropriate error types
func handleErrorResponse(resp *resty.Response) error {
	statusCode := resp.StatusCode()
	
	var errorMsg string
	if body := resp.Body(); len(body) > 0 {
		// Try to parse error response
		var errorResp struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if err := resp.Unmarshal(&errorResp); err == nil {
			errorMsg = errorResp.Message
			if errorMsg == "" {
				errorMsg = errorResp.Error
			}
		}
	}
	
	if errorMsg == "" {
		errorMsg = resp.Status()
	}

	switch statusCode {
	case 401:
		return &AuthenticationError{Message: errorMsg}
	case 429:
		retryAfter := resp.Header().Get("Retry-After")
		return &RateLimitError{
			Message:    errorMsg,
			RetryAfter: retryAfter,
		}
	case 400, 422:
		return &ValidationError{Message: errorMsg}
	case 404:
		return &NotFoundError{Message: errorMsg}
	case 500, 502, 503, 504:
		return &ConnectionError{Message: errorMsg}
	default:
		return &APIError{
			Message:    errorMsg,
			StatusCode: statusCode,
		}
	}
}