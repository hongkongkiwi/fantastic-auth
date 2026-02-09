"""
Error classes for Vault Auth SDK.
"""

from typing import Optional, Dict, Any


class VaultAuthError(Exception):
    """Base error for Vault Auth SDK."""
    
    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details or {}
        self.request_id = request_id

    def __str__(self) -> str:
        parts = [self.message]
        if self.error_code:
            parts.append(f"(code: {self.error_code})")
        if self.request_id:
            parts.append(f"[request_id: {self.request_id}]")
        return " ".join(parts)


class AuthenticationError(VaultAuthError):
    """Raised when authentication fails (401)."""
    
    def __init__(
        self,
        message: str = "Authentication failed",
        **kwargs
    ):
        super().__init__(message, status_code=401, **kwargs)


class AuthorizationError(VaultAuthError):
    """Raised when user lacks permission (403)."""
    
    def __init__(
        self,
        message: str = "Not authorized",
        **kwargs
    ):
        super().__init__(message, status_code=403, **kwargs)


class NotFoundError(VaultAuthError):
    """Raised when resource is not found (404)."""
    
    def __init__(
        self,
        message: str = "Resource not found",
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        **kwargs
    ):
        if resource_type and resource_id:
            message = f"{resource_type} '{resource_id}' not found"
        super().__init__(message, status_code=404, **kwargs)
        self.resource_type = resource_type
        self.resource_id = resource_id


class RateLimitError(VaultAuthError):
    """Raised when rate limit is exceeded (429)."""
    
    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        **kwargs
    ):
        super().__init__(message, status_code=429, **kwargs)
        self.retry_after = retry_after


class ServerError(VaultAuthError):
    """Raised when server returns 5xx error."""
    
    def __init__(
        self,
        message: str = "Internal server error",
        status_code: int = 500,
        **kwargs
    ):
        super().__init__(message, status_code=status_code, **kwargs)


class ValidationError(VaultAuthError):
    """Raised when request validation fails (400)."""
    
    def __init__(
        self,
        message: str = "Validation failed",
        field_errors: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        super().__init__(message, status_code=400, **kwargs)
        self.field_errors = field_errors or {}


class TokenExpiredError(AuthenticationError):
    """Raised when JWT token is expired."""
    
    def __init__(self, message: str = "Token has expired", **kwargs):
        super().__init__(message, **kwargs)


class InvalidTokenError(AuthenticationError):
    """Raised when JWT token is invalid."""
    
    def __init__(self, message: str = "Invalid token", **kwargs):
        super().__init__(message, **kwargs)


class ConfigurationError(VaultAuthError):
    """Raised when SDK is misconfigured."""
    
    def __init__(self, message: str = "Configuration error", **kwargs):
        super().__init__(message, status_code=None, **kwargs)
