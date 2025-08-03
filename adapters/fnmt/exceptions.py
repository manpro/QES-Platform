"""
FNMT QES Exceptions

Custom exceptions for FNMT-related operations.
"""


class FNMTException(Exception):
    """Base FNMT exception"""
    def __init__(self, message: str, error_code: str = None):
        super().__init__(message)
        self.error_code = error_code


class FNMTAuthenticationException(FNMTException):
    """FNMT authentication failed"""
    def __init__(self, message: str, error: str = None, error_description: str = None):
        super().__init__(message)
        self.error = error
        self.error_description = error_description


class FNMTSigningException(FNMTException):
    """FNMT signing operation failed"""
    def __init__(self, message: str, signature_id: str = None):
        super().__init__(message)
        self.signature_id = signature_id


class FNMTAPIException(FNMTException):
    """FNMT API error"""
    def __init__(self, message: str, status_code: int = None, response_data: dict = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_data = response_data


class FNMTConfigurationException(FNMTException):
    """FNMT configuration error"""
    pass


class FNMTTokenException(FNMTException):
    """FNMT token error"""
    def __init__(self, message: str, token_type: str = None):
        super().__init__(message)
        self.token_type = token_type


class FNMTCertificateException(FNMTException):
    """FNMT certificate error"""
    def __init__(self, message: str, certificate_id: str = None):
        super().__init__(message)
        self.certificate_id = certificate_id


class FNMTValidationException(FNMTException):
    """FNMT validation error"""
    pass


class FNMTDNIException(FNMTException):
    """FNMT DNI/NIF validation error"""
    def __init__(self, message: str, dni_nif: str = None):
        super().__init__(message)
        self.dni_nif = dni_nif