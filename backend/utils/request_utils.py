"""
Request utility functions for extracting client information
"""

from typing import Optional
from fastapi import Request


def get_client_ip(request: Request) -> str:
    """
    Extract real client IP from request, considering proxy headers
    
    Args:
        request: FastAPI Request object
        
    Returns:
        Client IP address as string
    """
    # Check for proxy headers in order of preference
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # X-Forwarded-For can contain multiple IPs, take the first (original client)
        client_ip = forwarded_for.split(",")[0].strip()
        return client_ip
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    cf_connecting_ip = request.headers.get("CF-Connecting-IP")  # Cloudflare
    if cf_connecting_ip:
        return cf_connecting_ip.strip()
    
    x_forwarded = request.headers.get("X-Forwarded")
    if x_forwarded:
        return x_forwarded.strip()
    
    # Fallback to direct connection IP
    if request.client:
        return request.client.host
    
    return "unknown"


def get_user_agent(request: Request) -> str:
    """
    Extract User-Agent from request headers
    
    Args:
        request: FastAPI Request object
        
    Returns:
        User-Agent string
    """
    user_agent = request.headers.get("User-Agent", "unknown")
    return user_agent


def get_request_info(request: Request) -> dict:
    """
    Extract comprehensive request information for logging/audit
    
    Args:
        request: FastAPI Request object
        
    Returns:
        Dictionary with request information
    """
    return {
        "client_ip": get_client_ip(request),
        "user_agent": get_user_agent(request),
        "method": request.method,
        "url": str(request.url),
        "headers": {
            "accept": request.headers.get("Accept"),
            "accept_language": request.headers.get("Accept-Language"),
            "accept_encoding": request.headers.get("Accept-Encoding"),
            "referer": request.headers.get("Referer"),
            "origin": request.headers.get("Origin"),
        },
        "query_params": dict(request.query_params) if request.query_params else None
    }


def is_secure_request(request: Request) -> bool:
    """
    Check if request is made over HTTPS
    
    Args:
        request: FastAPI Request object
        
    Returns:
        True if request is secure (HTTPS)
    """
    # Check direct HTTPS
    if request.url.scheme == "https":
        return True
    
    # Check proxy headers for forwarded HTTPS
    forwarded_proto = request.headers.get("X-Forwarded-Proto")
    if forwarded_proto and forwarded_proto.lower() == "https":
        return True
    
    forwarded_ssl = request.headers.get("X-Forwarded-SSL")
    if forwarded_ssl and forwarded_ssl.lower() == "on":
        return True
    
    return False


def get_country_from_ip(ip: str) -> Optional[str]:
    """
    Extract country code from IP address (placeholder for GeoIP integration)
    
    Args:
        ip: IP address string
        
    Returns:
        Country code (ISO 3166-1 alpha-2) or None
    """
    # TODO: Integrate with GeoIP service like MaxMind or similar
    # For now, return None as placeholder
    return None


def detect_bot_user_agent(user_agent: str) -> bool:
    """
    Detect if User-Agent appears to be from a bot/crawler
    
    Args:
        user_agent: User-Agent string
        
    Returns:
        True if appears to be bot traffic
    """
    bot_indicators = [
        "bot", "crawler", "spider", "scraper", "scanner",
        "curl", "wget", "python", "java", "go-http-client",
        "postman", "insomnia", "httpie"
    ]
    
    user_agent_lower = user_agent.lower()
    return any(indicator in user_agent_lower for indicator in bot_indicators)