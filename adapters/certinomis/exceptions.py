"""
Certinomis-specific exceptions
"""


class CertinomisException(Exception):
    """Base exception for Certinomis operations"""
    
    def __init__(self, message: str, error_code: str = None, request_id: str = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.request_id = request_id


class CertinomisAuthenticationException(CertinomisException):
    """Raised when Certinomis authentication fails"""
    
    def __init__(self, message: str, error: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.error = error


class CertinomisSigningException(CertinomisException):
    """Raised when Certinomis signing operation fails"""
    
    def __init__(self, message: str, signature_id: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.signature_id = signature_id


class CertinomisAPIException(CertinomisException):
    """Raised when Certinomis API calls fail"""
    
    def __init__(self, message: str, status_code: int = None, response_body: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.status_code = status_code
        self.response_body = response_body


class CertinomisConfigurationException(CertinomisException):
    """Raised when Certinomis configuration is invalid"""
    
    def __init__(self, message: str, parameter: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.parameter = parameter


class CertinomisTokenException(CertinomisException):
    """Raised when Certinomis token operations fail"""
    
    def __init__(self, message: str, token_type: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.token_type = token_type


class CertinomisCertificateException(CertinomisException):
    """Raised when Certinomis certificate operations fail"""
    
    def __init__(self, message: str, certificate_id: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.certificate_id = certificate_id


class CertinomisValidationException(CertinomisException):
    """Raised when Certinomis validation fails"""
    
    def __init__(self, message: str, validation_type: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.validation_type = validation_type