"""
Vault Auth Python SDK

Official Python SDK for Vault authentication and user management.
"""

from .client import VaultAuth
from .types import User, Organization, Session, JWKS
from .errors import (
    VaultAuthError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)
from .decorators import require_auth

__version__ = "1.0.0"
__all__ = [
    "VaultAuth",
    "User",
    "Organization",
    "Session",
    "JWKS",
    "VaultAuthError",
    "AuthenticationError",
    "AuthorizationError",
    "NotFoundError",
    "RateLimitError",
    "ServerError",
    "ValidationError",
    "require_auth",
]
