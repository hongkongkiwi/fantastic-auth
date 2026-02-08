"""
Decorators for protecting routes.
"""

import functools
from typing import Optional, Callable, Any, List

from .client import VaultAuth
from .errors import AuthenticationError, AuthorizationError


def require_auth(
    client: Optional[VaultAuth] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    roles: Optional[List[str]] = None,
    require_org: bool = False,
):
    """
    Decorator to require authentication for a route.
    
    Args:
        client: VaultAuth client instance (optional)
        api_key: Vault API key (used if client not provided)
        base_url: Vault base URL (used if client not provided)
        roles: Required organization roles (optional)
        require_org: Whether organization membership is required
        
    Usage:
        @require_auth(api_key="vault_m2m_...")
        def protected_route(request):
            user = request.vault_user
            return f"Hello {user.email}"
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Get request object (first arg for Flask/Django/FastAPI)
            request = args[0] if args else None
            
            # Resolve client
            auth_client = client
            if auth_client is None:
                if api_key is None:
                    raise ConfigurationError("Either client or api_key must be provided")
                auth_client = VaultAuth(api_key=api_key, base_url=base_url or "https://api.vault.dev")
            
            # Extract token from request
            token = _extract_token(request)
            if not token:
                raise AuthenticationError("No authentication token provided")
            
            # Verify token and get user
            try:
                user = auth_client.verify_token(token)
            except Exception as e:
                raise AuthenticationError(f"Invalid token: {str(e)}")
            
            # Check organization requirements
            if require_org:
                token_payload = auth_client.decode_token(token)
                if not token_payload.org_id:
                    raise AuthorizationError("Organization membership required")
                
                if roles and token_payload.org_role not in roles:
                    raise AuthorizationError(f"Required role: {', '.join(roles)}")
            
            # Attach user to request
            if request:
                request.vault_user = user
                request.vault_token_payload = auth_client.decode_token(token)
            
            # Also pass user as keyword argument if function accepts it
            if 'vault_user' in func.__code__.co_varnames:
                kwargs['vault_user'] = user
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def _extract_token(request: Any) -> Optional[str]:
    """Extract Bearer token from request."""
    if request is None:
        return None
    
    # Try different request types
    
    # Flask/Werkzeug
    if hasattr(request, 'headers'):
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:]
    
    # Django HttpRequest
    if hasattr(request, 'META'):
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:]
    
    # FastAPI/Starlette
    if hasattr(request, 'headers') and hasattr(request.headers, 'get'):
        auth_header = request.headers.get('authorization', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:]
    
    return None


class ConfigurationError(Exception):
    """Configuration error for decorators."""
    pass
