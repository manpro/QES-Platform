/**
 * Main QES Platform client
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import FormData from 'form-data';

import { VERSION } from './index';
import { 
  QESClientConfig, 
  QESResponse, 
  QESError 
} from './types';
import { 
  QESException, 
  QESAuthenticationException, 
  QESConnectionException,
  QESRateLimitException 
} from './errors';
import {
  AuthManager,
  CertificateManager,
  SignatureManager,
  VerificationManager,
  ProviderManager,
  TenantManager
} from './managers';

/**
 * Main client for the QES Platform API
 * 
 * Provides access to all QES Platform services including
 * authentication, signing, verification, and certificate management.
 * 
 * @example
 * ```typescript
 * const client = new QESClient({
 *   apiUrl: 'https://api.qes-platform.com/v1',
 *   apiKey: 'your-api-key',
 *   tenantId: 'your-tenant-id'
 * });
 * 
 * const result = await client.auth.login({
 *   provider: 'freja-se',
 *   userIdentifier: 'user@example.com'
 * });
 * ```
 */
export class QESClient {
  private httpClient: AxiosInstance;
  
  /** Authentication manager */
  public readonly auth: AuthManager;
  
  /** Certificate manager */
  public readonly certificates: CertificateManager;
  
  /** Signature manager */
  public readonly signatures: SignatureManager;
  
  /** Verification manager */
  public readonly verification: VerificationManager;
  
  /** Provider manager */
  public readonly providers: ProviderManager;
  
  /** Tenant manager */
  public readonly tenants: TenantManager;

  /**
   * Create a new QES Platform client
   * 
   * @param config - Client configuration
   */
  constructor(private config: QESClientConfig) {
    // Validate configuration
    this.validateConfig(config);
    
    // Setup HTTP client
    this.httpClient = axios.create({
      baseURL: config.apiUrl.replace(/\/$/, ''),
      timeout: config.timeout || 30000,
      headers: {
        'User-Agent': config.userAgent || `qes-platform-js-sdk/${VERSION}`,
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        ...config.extraHeaders
      }
    });
    
    // Set authentication headers
    if (config.apiKey) {
      this.httpClient.defaults.headers.common['Authorization'] = `Bearer ${config.apiKey}`;
    }
    
    if (config.tenantId) {
      this.httpClient.defaults.headers.common['X-Tenant-ID'] = config.tenantId;
    }
    
    // Setup request/response interceptors
    this.setupInterceptors();
    
    // Initialize service managers
    this.auth = new AuthManager(this);
    this.certificates = new CertificateManager(this);
    this.signatures = new SignatureManager(this);
    this.verification = new VerificationManager(this);
    this.providers = new ProviderManager(this);
    this.tenants = new TenantManager(this);
  }

  /**
   * Update API key
   */
  setApiKey(apiKey: string): void {
    this.config.apiKey = apiKey;
    this.httpClient.defaults.headers.common['Authorization'] = `Bearer ${apiKey}`;
  }

  /**
   * Update tenant ID
   */
  setTenantId(tenantId: string): void {
    this.config.tenantId = tenantId;
    this.httpClient.defaults.headers.common['X-Tenant-ID'] = tenantId;
  }

  /**
   * Make HTTP request
   * 
   * @param config - Axios request configuration
   * @returns Promise with response data
   */
  async request<T = any>(config: AxiosRequestConfig): Promise<QESResponse<T>> {
    try {
      const response: AxiosResponse<QESResponse<T>> = await this.httpClient.request(config);
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * GET request
   */
  async get<T = any>(url: string, config?: AxiosRequestConfig): Promise<QESResponse<T>> {
    return this.request<T>({ method: 'GET', url, ...config });
  }

  /**
   * POST request
   */
  async post<T = any>(
    url: string, 
    data?: any, 
    config?: AxiosRequestConfig
  ): Promise<QESResponse<T>> {
    return this.request<T>({ method: 'POST', url, data, ...config });
  }

  /**
   * PUT request
   */
  async put<T = any>(
    url: string, 
    data?: any, 
    config?: AxiosRequestConfig
  ): Promise<QESResponse<T>> {
    return this.request<T>({ method: 'PUT', url, data, ...config });
  }

  /**
   * DELETE request
   */
  async delete<T = any>(url: string, config?: AxiosRequestConfig): Promise<QESResponse<T>> {
    return this.request<T>({ method: 'DELETE', url, ...config });
  }

  /**
   * Upload file with form data
   */
  async uploadFile<T = any>(
    url: string,
    file: Buffer | Blob | File,
    filename: string,
    additionalData?: Record<string, any>
  ): Promise<QESResponse<T>> {
    const formData = new FormData();
    formData.append('document', file, filename);
    
    if (additionalData) {
      Object.entries(additionalData).forEach(([key, value]) => {
        formData.append(key, String(value));
      });
    }

    return this.request<T>({
      method: 'POST',
      url,
      data: formData,
      headers: {
        'Content-Type': 'multipart/form-data',
        ...formData.getHeaders?.()
      }
    });
  }

  /**
   * Check API health
   */
  async healthCheck(): Promise<{ status: string; timestamp: string }> {
    try {
      const response = await this.get<{ status: string; timestamp: string }>('/health');
      return response.data || response as any;
    } catch (error) {
      throw new QESConnectionException('Health check failed');
    }
  }

  /**
   * Get API information
   */
  async getApiInfo(): Promise<{ version: string; features: string[] }> {
    try {
      const response = await this.get<{ version: string; features: string[] }>('/info');
      return response.data || response as any;
    } catch (error) {
      return {
        version: 'unknown',
        features: []
      };
    }
  }

  /**
   * Validate client configuration
   */
  private validateConfig(config: QESClientConfig): void {
    if (!config.apiUrl) {
      throw new Error('API URL is required');
    }

    try {
      new URL(config.apiUrl);
    } catch {
      throw new Error('Invalid API URL format');
    }

    if (config.timeout && config.timeout < 1000) {
      throw new Error('Timeout must be at least 1000ms');
    }
  }

  /**
   * Setup request/response interceptors
   */
  private setupInterceptors(): void {
    // Request interceptor
    this.httpClient.interceptors.request.use(
      (config) => {
        // Add request ID for tracing
        config.headers = {
          ...config.headers,
          'X-Request-ID': this.generateRequestId()
        };
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor
    this.httpClient.interceptors.response.use(
      (response) => response,
      (error) => {
        return Promise.reject(this.handleError(error));
      }
    );
  }

  /**
   * Handle HTTP errors and convert to QES exceptions
   */
  private handleError(error: any): QESException {
    if (error.response) {
      const { status, data } = error.response;
      const message = data?.message || data?.error || error.message;

      switch (status) {
        case 401:
          return new QESAuthenticationException(message);
        case 429:
          const retryAfter = error.response.headers['retry-after'];
          return new QESRateLimitException(message, retryAfter);
        case 400:
        case 404:
        case 422:
          return new QESException(message, status);
        case 500:
        case 502:
        case 503:
        case 504:
          return new QESConnectionException(`Server error: ${message}`);
        default:
          return new QESException(message, status);
      }
    } else if (error.request) {
      return new QESConnectionException('Network error: No response received');
    } else {
      return new QESException(error.message);
    }
  }

  /**
   * Generate unique request ID
   */
  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}