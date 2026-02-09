"""
Django middleware for Vault Auth.
"""

from typing import Optional, List, Callable, Any
from functools import wraps

from django.http import JsonResponse
from django.conf import settings

from ..client import VaultAuth
from ..errors import VaultAuthError, AuthenticationError


class VaultAuthMiddleware:
    """Django middleware for Vault authentication."""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self._client: Optional[VaultAuth] = None
        
        # Get settings
        self.api_key = getattr(settings, 'VAULT_API_KEY', None)
        self.base_url = getattr(settings, 'VAULT_BASE_URL', 'https://api.vault.dev')
        self.excluded_paths = getattr(settings, 'VAULT_EXCLUDED_PATHS', ['/health', '/admin/'])
    
    @property
    def client(self) -> VaultAuth:
        if self._client is None:
            if not self.api_key:
                raise ValueError("VAULT_API_KEY setting is required")
            self._client = VaultAuth(
                api_key=self.api_key,
                base_url=self.base_url,
            )
        return self._client
    
    def __call__(self, request):
        """Process request."""
        # Skip excluded paths
        if any(request.path.startswith(path) for path in self.excluded_paths):
            return self.get_response(request)
        
        # Extract token
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth_header.startswith('Bearer '):
            request.vault_user = None
            request.vault_token = None
            return self.get_response(request)
        
        token = auth_header[7:]
        
        try:
            user = self.client.verify_token(token)
            request.vault_user = user
            request.vault_token = token
            request.vault_token_payload = self.client.decode_token(token)
        except VaultAuthError:
            request.vault_user = None
            request.vault_token = None
            request.vault_token_payload = None
        
        return self.get_response(request)
    
    def process_exception(self, request, exception):
        """Process exceptions."""
        if isinstance(exception, VaultAuthError):
            return JsonResponse({
                "error": exception.message,
                "code": exception.error_code,
            }, status=exception.status_code or 500)
        return None


def require_auth(
    roles: Optional[List[str]] = None,
    require_org: bool = False,
    error_message: str = "Authentication required",
):
    """
    Decorator to require authentication for a view.
    
    Usage:
        @require_auth()
        def my_view(request):
            return JsonResponse({"email": request.vault_user.email})
            
        @require_auth(roles=['admin', 'owner'])
        def admin_view(request):
            return JsonResponse({"message": "Admin only"})
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not hasattr(request, 'vault_user') or request.vault_user is None:
                return JsonResponse({"error": error_message}, status=401)
            
            if require_org:
                payload = getattr(request, 'vault_token_payload', None)
                if not payload or not payload.org_id:
                    return JsonResponse(
                        {"error": "Organization membership required"},
                        status=403
                    )
                
                if roles and payload.org_role not in roles:
                    return JsonResponse(
                        {"error": f"Required role: {', '.join(roles)}"},
                        status=403
                    )
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def require_org_member(org_id_param: str = "org_id"):
    """
    Decorator to require user to be a member of the organization.
    
    Usage:
        @require_auth()
        @require_org_member()
        def org_detail(request, org_id):
            return JsonResponse({"org_id": org_id})
    """
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not hasattr(request, 'vault_user') or request.vault_user is None:
                return JsonResponse({"error": "Authentication required"}, status=401)
            
            org_id = kwargs.get(org_id_param)
            payload = getattr(request, 'vault_token_payload', None)
            
            if not payload or payload.org_id != org_id:
                return JsonResponse(
                    {"error": "Not a member of this organization"},
                    status=403
                )
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


# Django REST Framework integration (optional)
try:
    from rest_framework import authentication, exceptions
    
    class VaultAuthentication(authentication.BaseAuthentication):
        """DRF authentication class for Vault."""
        
        def authenticate(self, request):
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            if not auth_header.startswith('Bearer '):
                return None
            
            token = auth_header[7:]
            
            # Get client from settings
            api_key = getattr(settings, 'VAULT_API_KEY', None)
            base_url = getattr(settings, 'VAULT_BASE_URL', 'https://api.vault.dev')
            
            if not api_key:
                raise exceptions.AuthenticationFailed('VAULT_API_KEY not configured')
            
            client = VaultAuth(api_key=api_key, base_url=base_url)
            
            try:
                user = client.verify_token(token)
                return (user, token)
            except VaultAuthError as e:
                raise exceptions.AuthenticationFailed(str(e))
    
except ImportError:
    pass  # DRF not installed
