"""
Camerfirma-specific exceptions
"""


class CamerfirmaException(Exception):
    """Base exception for Camerfirma operations"""
    
    def __init__(self, message: str, error_code: str = None, request_id: str = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.request_id = request_id


class CamerfirmaAuthenticationException(CamerfirmaException):
    """Raised when Camerfirma authentication fails"""
    
    def __init__(self, message: str, error: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.error = error


class CamerfirmaSigningException(CamerfirmaException):
    """Raised when Camerfirma signing operation fails"""
    
    def __init__(self, message: str, signature_id: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.signature_id = signature_id


class CamerfirmaAPIException(CamerfirmaException):
    """Raised when Camerfirma API calls fail"""
    
    def __init__(self, message: str, status_code: int = None, response_body: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.status_code = status_code
        self.response_body = response_body


class CamerfirmaConfigurationException(CamerfirmaException):
    """Raised when Camerfirma configuration is invalid"""
    
    def __init__(self, message: str, parameter: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.parameter = parameter


class CamerfirmaTokenException(CamerfirmaException):
    """Raised when Camerfirma token operations fail"""
    
    def __init__(self, message: str, token_type: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.token_type = token_type


class CamerfirmaCertificateException(CamerfirmaException):
    """Raised when Camerfirma certificate operations fail"""
    
    def __init__(self, message: str, certificate_id: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.certificate_id = certificate_id


class CamerfirmaValidationException(CamerfirmaException):
    """Raised when Camerfirma validation fails"""
    
    def __init__(self, message: str, validation_type: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.validation_type = validation_type


class CamerfirmaDNIException(CamerfirmaException):
    """Raised when DNI/NIE validation fails"""
    
    def __init__(self, message: str, dni: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.dni = dni


class CamerfirmaMobileSignatureException(CamerfirmaException):
    """Raised when mobile signature operations fail"""
    
    def __init__(self, message: str, mobile_number: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.mobile_number = mobile_number