"""
Flask middleware for Vault Auth.
"""

from functools import wraps
from typing import Optional, Callable, List, Any

from flask import request, g, jsonify

from ..client import VaultAuth
from ..errors import VaultAuthError, AuthenticationError, AuthorizationError


class VaultAuthMiddleware:
    """Flask middleware for Vault authentication."""
    
    def __init__(
        self,
        app=None,
        api_key: Optional[str] = None,
        base_url: str = "https://api.vault.dev",
        excluded_paths: Optional[List[str]] = None,
    ):
        self.api_key = api_key
        self.base_url = base_url
        self.excluded_paths = excluded_paths or ["/health", "/metrics"]
        self._client: Optional[VaultAuth] = None
        
        if app:
            self.init_app(app)
    
    @property
    def client(self) -> VaultAuth:
        if self._client is None:
            if not self.api_key:
                raise ValueError("API key is required")
            self._client = VaultAuth(
                api_key=self.api_key,
                base_url=self.base_url,
            )
        return self._client
    
    def init_app(self, app):
        """Initialize with Flask app."""
        app.before_request(self._before_request)
        app.errorhandler(VaultAuthError)(self._handle_error)
        
        # Store client in app extensions
        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['vault_auth'] = self
    
    def _before_request(self):
        """Process before each request."""
        # Skip excluded paths
        if any(request.path.startswith(path) for path in self.excluded_paths):
            return None
        
        # Extract token
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            g.vault_user = None
            g.vault_token = None
            return None
        
        token = auth_header[7:]
        
        try:
            user = self.client.verify_token(token)
            g.vault_user = user
            g.vault_token = token
            g.vault_token_payload = self.client.decode_token(token)
        except VaultAuthError:
            g.vault_user = None
            g.vault_token = None
            g.vault_token_payload = None
    
    def _handle_error(self, error: VaultAuthError):
        """Handle VaultAuthError exceptions."""
        response = jsonify({
            "error": error.message,
            "code": error.error_code,
        })
        response.status_code = error.status_code or 500
        return response


def require_auth(
    roles: Optional[List[str]] = None,
    require_org: bool = False,
    error_message: str = "Authentication required",
):
    """
    Decorator to require authentication for a route.
    
    Args:
        roles: Required organization roles
        require_org: Whether organization membership is required
        error_message: Error message when not authenticated
        
    Usage:
        @app.route('/protected')
        @require_auth()
        def protected():
            return f"Hello {g.vault_user.email}"
            
        @app.route('/admin-only')
        @require_auth(roles=['admin', 'owner'])
        def admin_only():
            return "Admin area"
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'vault_user') or g.vault_user is None:
                return jsonify({"error": error_message}), 401
            
            if require_org:
                payload = getattr(g, 'vault_token_payload', None)
                if not payload or not payload.org_id:
                    return jsonify({"error": "Organization membership required"}), 403
                
                if roles and payload.org_role not in roles:
                    return jsonify({"error": f"Required role: {', '.join(roles)}"}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_org_member(org_id_param: str = "org_id"):
    """
    Decorator to require user to be a member of the organization.
    
    Usage:
        @app.route('/orgs/<org_id>/settings')
        @require_auth()
        @require_org_member()
        def org_settings(org_id):
            return f"Settings for org {org_id}"
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'vault_user') or g.vault_user is None:
                return jsonify({"error": "Authentication required"}), 401
            
            org_id = kwargs.get(org_id_param)
            payload = getattr(g, 'vault_token_payload', None)
            
            if not payload or payload.org_id != org_id:
                return jsonify({"error": "Not a member of this organization"}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def get_current_user() -> Optional[Any]:
    """Get current authenticated user from Flask g."""
    return getattr(g, 'vault_user', None)


def get_current_token_payload() -> Optional[Any]:
    """Get current token payload from Flask g."""
    return getattr(g, 'vault_token_payload', None)
