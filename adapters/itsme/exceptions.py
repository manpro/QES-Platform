"""
itsme-specific exceptions
"""


class ItsmeException(Exception):
    """Base exception for itsme operations"""
    
    def __init__(self, message: str, error_code: str = None, correlation_id: str = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.correlation_id = correlation_id


class ItsmeAuthenticationException(ItsmeException):
    """Raised when itsme authentication fails"""
    
    def __init__(self, message: str, error: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.error = error


class ItsmeSigningException(ItsmeException):
    """Raised when itsme signing operation fails"""
    
    def __init__(self, message: str, signature_id: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.signature_id = signature_id


class ItsmeAPIException(ItsmeException):
    """Raised when itsme API calls fail"""
    
    def __init__(self, message: str, status_code: int = None, response_body: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.status_code = status_code
        self.response_body = response_body


class ItsmeConfigurationException(ItsmeException):
    """Raised when itsme configuration is invalid"""
    
    def __init__(self, message: str, parameter: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.parameter = parameter


class ItsmeTokenException(ItsmeException):
    """Raised when itsme token operations fail"""
    
    def __init__(self, message: str, token_type: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.token_type = token_type