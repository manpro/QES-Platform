"""
OAuth2 Client for Freja eID

Handles OAuth2 authentication flow with Freja eID services
including token management and SCIM user lookup.
"""

import asyncio
import json
import base64
import hashlib
from typing import Dict, Any, Optional
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode, parse_qs, urlparse
import httpx
import jwt


class OAuth2Error(Exception):
    """OAuth2-related errors"""
    def __init__(self, message: str, error_code: Optional[str] = None):
        super().__init__(message)
        self.error_code = error_code


class FrejaOAuth2Client:
    """
    OAuth2 client for Freja eID services.
    
    Implements the OAuth2 Authorization Code flow with PKCE
    for secure authentication and token management.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.client_id = config["client_id"]
        self.client_secret = config["client_secret"]
        self.redirect_uri = config["redirect_uri"]
        
        # OAuth2 endpoints
        self.base_url = config.get("base_url", "https://services.test.frejaeid.com")
        self.auth_endpoint = f"{self.base_url}/oauth2/authorize"
        self.token_endpoint = f"{self.base_url}/oauth2/token"
        self.userinfo_endpoint = f"{self.base_url}/oauth2/userinfo"
        self.scim_endpoint = f"{self.base_url}/scim/v2"
        
        # Configuration
        self.scope = config.get("scope", "openid profile email frejaeid")
        self.timeout = config.get("timeout", 30)
        
        # Token storage (in production use Redis/database)
        self._access_tokens: Dict[str, Dict[str, Any]] = {}
        self._refresh_tokens: Dict[str, str] = {}
    
    def generate_authorization_url(self, state: Optional[str] = None,
                                 code_challenge: Optional[str] = None) -> str:
        """
        Generate OAuth2 authorization URL.
        
        Args:
            state: Optional state parameter for CSRF protection
            code_challenge: PKCE code challenge
            
        Returns:
            Authorization URL for user redirect
        """
        
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "state": state or self._generate_state(),
            "code_challenge_method": "S256",
            "code_challenge": code_challenge or self._generate_code_challenge()
        }
        
        return f"{self.auth_endpoint}?{urlencode(params)}"
    
    async def exchange_code_for_tokens(self, authorization_code: str,
                                     code_verifier: str,
                                     state: Optional[str] = None) -> Dict[str, Any]:
        """
        Exchange authorization code for access and refresh tokens.
        
        Args:
            authorization_code: Authorization code from callback
            code_verifier: PKCE code verifier
            state: State parameter for verification
            
        Returns:
            Token response with access_token, refresh_token, etc.
        """
        
        token_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code_verifier": code_verifier
        }
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.token_endpoint,
                    data=token_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                
                if response.status_code != 200:
                    error_data = response.json() if response.content else {}
                    raise OAuth2Error(
                        f"Token exchange failed: {error_data.get('error_description', response.text)}",
                        error_code=error_data.get('error', 'TOKEN_EXCHANGE_FAILED')
                    )
                
                tokens = response.json()
                
                # Store tokens
                access_token = tokens["access_token"]
                self._access_tokens[access_token] = {
                    "token": access_token,
                    "expires_at": datetime.now(timezone.utc) + timedelta(seconds=tokens.get("expires_in", 3600)),
                    "scope": tokens.get("scope", self.scope),
                    "token_type": tokens.get("token_type", "Bearer")
                }
                
                if "refresh_token" in tokens:
                    self._refresh_tokens[access_token] = tokens["refresh_token"]
                
                return tokens
                
        except httpx.RequestError as e:
            raise OAuth2Error(f"Network error during token exchange: {str(e)}")
    
    async def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh access token using refresh token.
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            New token response
        """
        
        refresh_data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.token_endpoint,
                    data=refresh_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                
                if response.status_code != 200:
                    error_data = response.json() if response.content else {}
                    raise OAuth2Error(
                        f"Token refresh failed: {error_data.get('error_description', response.text)}",
                        error_code=error_data.get('error', 'TOKEN_REFRESH_FAILED')
                    )
                
                tokens = response.json()
                
                # Update stored tokens
                access_token = tokens["access_token"]
                self._access_tokens[access_token] = {
                    "token": access_token,
                    "expires_at": datetime.now(timezone.utc) + timedelta(seconds=tokens.get("expires_in", 3600)),
                    "scope": tokens.get("scope", self.scope),
                    "token_type": tokens.get("token_type", "Bearer")
                }
                
                return tokens
                
        except httpx.RequestError as e:
            raise OAuth2Error(f"Network error during token refresh: {str(e)}")
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information using access token.
        
        Args:
            access_token: Valid access token
            
        Returns:
            User information from userinfo endpoint
        """
        
        if not self._is_token_valid(access_token):
            raise OAuth2Error("Access token is invalid or expired", error_code="TOKEN_INVALID")
        
        try:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(self.userinfo_endpoint, headers=headers)
                
                if response.status_code != 200:
                    raise OAuth2Error(
                        f"Failed to get user info: {response.text}",
                        error_code="USERINFO_FAILED"
                    )
                
                return response.json()
                
        except httpx.RequestError as e:
            raise OAuth2Error(f"Network error getting user info: {str(e)}")
    
    async def scim_lookup_user(self, access_token: str,
                             personal_number: Optional[str] = None,
                             email: Optional[str] = None) -> Dict[str, Any]:
        """
        Lookup user via SCIM API.
        
        Args:
            access_token: Valid access token
            personal_number: Swedish personal number
            email: Email address
            
        Returns:
            SCIM user object
        """
        
        if not self._is_token_valid(access_token):
            raise OAuth2Error("Access token is invalid or expired", error_code="TOKEN_INVALID")
        
        if not personal_number and not email:
            raise OAuth2Error("Either personal_number or email must be provided")
        
        try:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/scim+json"
            }
            
            # Build SCIM filter
            if personal_number:
                filter_query = f'personalNumber eq "{personal_number}"'
            else:
                filter_query = f'emails.value eq "{email}"'
            
            params = {
                "filter": filter_query,
                "attributes": "id,userName,name,emails,personalNumber,phoneNumbers"
            }
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.scim_endpoint}/Users",
                    headers=headers,
                    params=params
                )
                
                if response.status_code != 200:
                    raise OAuth2Error(
                        f"SCIM lookup failed: {response.text}",
                        error_code="SCIM_LOOKUP_FAILED"
                    )
                
                scim_response = response.json()
                
                # Return first matching user
                users = scim_response.get("Resources", [])
                if users:
                    return users[0]
                else:
                    raise OAuth2Error(
                        "User not found in SCIM directory",
                        error_code="SCIM_USER_NOT_FOUND"
                    )
                
        except httpx.RequestError as e:
            raise OAuth2Error(f"Network error during SCIM lookup: {str(e)}")
    
    def _is_token_valid(self, access_token: str) -> bool:
        """Check if access token is valid and not expired."""
        token_info = self._access_tokens.get(access_token)
        if not token_info:
            return False
        
        return datetime.now(timezone.utc) < token_info["expires_at"]
    
    def _generate_state(self) -> str:
        """Generate random state parameter."""
        import secrets
        return secrets.token_urlsafe(32)
    
    def _generate_code_challenge(self) -> str:
        """Generate PKCE code challenge."""
        import secrets
        code_verifier = secrets.token_urlsafe(32)
        
        # Store code_verifier for later use (in production use secure storage)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode().rstrip('=')
        
        return challenge
    
    def parse_callback_url(self, callback_url: str) -> Dict[str, Any]:
        """
        Parse OAuth2 callback URL and extract parameters.
        
        Args:
            callback_url: Full callback URL with parameters
            
        Returns:
            Dictionary with code, state, error, etc.
        """
        
        parsed = urlparse(callback_url)
        params = parse_qs(parsed.query)
        
        result = {}
        for key, values in params.items():
            if values:
                result[key] = values[0]  # Take first value
        
        return result
    
    def validate_state(self, received_state: str, expected_state: str) -> bool:
        """Validate state parameter to prevent CSRF attacks."""
        return received_state == expected_state
    
    async def revoke_token(self, token: str, token_type: str = "access_token") -> bool:
        """
        Revoke access or refresh token.
        
        Args:
            token: Token to revoke
            token_type: "access_token" or "refresh_token"
            
        Returns:
            True if revocation was successful
        """
        
        revoke_data = {
            "token": token,
            "token_type_hint": token_type,
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        
        try:
            revoke_endpoint = f"{self.base_url}/oauth2/revoke"
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    revoke_endpoint,
                    data=revoke_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                
                # Clean up local storage
                if token in self._access_tokens:
                    del self._access_tokens[token]
                if token in self._refresh_tokens:
                    del self._refresh_tokens[token]
                
                return response.status_code == 200
                
        except httpx.RequestError:
            return False