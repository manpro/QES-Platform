"""
QES Platform Python SDK Client

Main client class for interacting with the QES Platform API.
"""

import logging
from typing import Optional, Dict, Any, Union
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ._version import __version__, API_VERSION
from .auth import AuthManager
from .certificates import CertificateManager
from .signatures import SignatureManager
from .verification import VerificationManager
from .providers import ProviderManager
from .tenants import TenantManager
from .exceptions import QESConnectionException, QESAuthenticationException
from .models import QESError


logger = logging.getLogger(__name__)


class QESClient:
    """
    Main client for the QES Platform API.
    
    This client provides access to all QES Platform services including
    authentication, signing, verification, and certificate management.
    
    Attributes:
        auth: Authentication manager
        certificates: Certificate manager
        signatures: Signature manager  
        verification: Verification manager
        providers: Provider manager
        tenants: Tenant manager
    
    Example:
        >>> client = QESClient(
        ...     api_url="https://api.qes-platform.com/v1",
        ...     api_key="your-api-key",
        ...     tenant_id="your-tenant-id"
        ... )
        >>> 
        >>> # Authenticate user
        >>> result = client.auth.login(
        ...     provider="freja-se",
        ...     user_identifier="user@example.com"
        ... )
    """
    
    def __init__(
        self,
        api_url: str,
        api_key: Optional[str] = None,
        tenant_id: Optional[str] = None,
        timeout: int = 30,
        verify_ssl: bool = True,
        retry_total: int = 3,
        retry_backoff_factor: float = 0.3,
        user_agent: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize QES Platform client.
        
        Args:
            api_url: Base URL for QES Platform API
            api_key: API key for authentication (can be set later)
            tenant_id: Tenant ID for multi-tenant environments
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
            retry_total: Total number of retries
            retry_backoff_factor: Backoff factor for retries
            user_agent: Custom user agent string
            extra_headers: Additional headers to send with requests
            
        Raises:
            ValueError: If api_url is invalid
        """
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.tenant_id = tenant_id
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        # Setup session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=retry_total,
            backoff_factor=retry_backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Setup default headers
        default_user_agent = f"qes-platform-python-sdk/{__version__}"
        self.session.headers.update({
            "User-Agent": user_agent or default_user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        
        if extra_headers:
            self.session.headers.update(extra_headers)
            
        # Set API key and tenant headers if provided
        if self.api_key:
            self.session.headers["Authorization"] = f"Bearer {self.api_key}"
        if self.tenant_id:
            self.session.headers["X-Tenant-ID"] = self.tenant_id
            
        # Initialize service managers
        self.auth = AuthManager(self)
        self.certificates = CertificateManager(self)
        self.signatures = SignatureManager(self)
        self.verification = VerificationManager(self)
        self.providers = ProviderManager(self)
        self.tenants = TenantManager(self)
        
        logger.info(f"Initialized QES Platform client for {self.api_url}")
    
    def set_api_key(self, api_key: str) -> None:
        """
        Set or update the API key.
        
        Args:
            api_key: New API key
        """
        self.api_key = api_key
        self.session.headers["Authorization"] = f"Bearer {api_key}"
        logger.info("API key updated")
    
    def set_tenant_id(self, tenant_id: str) -> None:
        """
        Set or update the tenant ID.
        
        Args:
            tenant_id: New tenant ID
        """
        self.tenant_id = tenant_id
        self.session.headers["X-Tenant-ID"] = tenant_id
        logger.info(f"Tenant ID updated: {tenant_id}")
    
    def request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        **kwargs
    ) -> requests.Response:
        """
        Make a request to the QES Platform API.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (without base URL)
            params: Query parameters
            data: Request body data
            files: Files to upload
            headers: Additional headers
            timeout: Request timeout (overrides default)
            **kwargs: Additional arguments for requests
            
        Returns:
            Response object
            
        Raises:
            QESConnectionException: If connection fails
            QESAuthenticationException: If authentication fails
        """
        url = urljoin(self.api_url + '/', endpoint.lstrip('/'))
        request_timeout = timeout or self.timeout
        
        # Prepare request arguments
        request_kwargs = {
            'verify': self.verify_ssl,
            'timeout': request_timeout,
            **kwargs
        }
        
        if params:
            request_kwargs['params'] = params
        if data and not files:
            request_kwargs['json'] = data
        elif data and files:
            request_kwargs['data'] = data
        if files:
            request_kwargs['files'] = files
        if headers:
            request_kwargs['headers'] = {**self.session.headers, **headers}
        
        try:
            logger.debug(f"Making {method} request to {url}")
            response = self.session.request(method, url, **request_kwargs)
            
            # Handle rate limiting
            if response.status_code == 429:
                retry_after = response.headers.get('Retry-After')
                logger.warning(f"Rate limited. Retry after: {retry_after}")
                
            # Handle authentication errors
            if response.status_code == 401:
                logger.error("Authentication failed")
                raise QESAuthenticationException("Invalid API key or expired token")
                
            # Log response details
            logger.debug(f"Response: {response.status_code} - {response.reason}")
            
            return response
            
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error: {e}")
            raise QESConnectionException(f"Failed to connect to QES Platform: {e}")
        except requests.exceptions.Timeout as e:
            logger.error(f"Request timeout: {e}")
            raise QESConnectionException(f"Request timeout: {e}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {e}")
            raise QESConnectionException(f"Request failed: {e}")
    
    def get(self, endpoint: str, **kwargs) -> requests.Response:
        """Make a GET request."""
        return self.request('GET', endpoint, **kwargs)
    
    def post(self, endpoint: str, **kwargs) -> requests.Response:
        """Make a POST request."""
        return self.request('POST', endpoint, **kwargs)
    
    def put(self, endpoint: str, **kwargs) -> requests.Response:
        """Make a PUT request."""
        return self.request('PUT', endpoint, **kwargs)
    
    def delete(self, endpoint: str, **kwargs) -> requests.Response:
        """Make a DELETE request."""
        return self.request('DELETE', endpoint, **kwargs)
    
    def health_check(self) -> Dict[str, Any]:
        """
        Check API health status.
        
        Returns:
            Health status information
            
        Raises:
            QESConnectionException: If health check fails
        """
        try:
            response = self.get('/health')
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            raise QESConnectionException(f"Health check failed: {e}")
    
    def get_api_info(self) -> Dict[str, Any]:
        """
        Get API information and version.
        
        Returns:
            API information
        """
        try:
            response = self.get('/info')
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.warning(f"Could not get API info: {e}")
            return {
                "api_version": API_VERSION,
                "sdk_version": __version__,
                "status": "unknown"
            }
    
    def close(self) -> None:
        """Close the client session."""
        self.session.close()
        logger.info("QES Platform client session closed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
    
    def __repr__(self) -> str:
        """String representation of the client."""
        return f"QESClient(api_url='{self.api_url}', tenant_id='{self.tenant_id}')"