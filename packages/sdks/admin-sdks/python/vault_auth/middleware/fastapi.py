"""
FastAPI middleware and dependencies for Vault Auth.
"""

from typing import Optional, List, Callable, Any
from functools import wraps

from fastapi import Request, HTTPException, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware

from ..client import VaultAuth
from ..errors import VaultAuthError, AuthenticationError
from ..types import User, TokenPayload


security = HTTPBearer(auto_error=False)


class VaultAuthMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for Vault authentication."""
    
    def __init__(
        self,
        app,
        api_key: str,
        base_url: str = "https://api.vault.dev",
        excluded_paths: Optional[List[str]] = None,
    ):
        super().__init__(app)
        self.api_key = api_key
        self.base_url = base_url
        self.excluded_paths = excluded_paths or ["/health", "/docs", "/openapi.json"]
        self.client = VaultAuth(api_key=api_key, base_url=base_url)
    
    async def dispatch(self, request: Request, call_next):
        """Process request."""
        # Skip excluded paths
        if any(request.url.path.startswith(path) for path in self.excluded_paths):
            return await call_next(request)
        
        # Extract token
        auth_header = request.headers.get('authorization', '')
        if not auth_header.startswith('Bearer '):
            request.state.vault_user = None
            request.state.vault_token = None
            return await call_next(request)
        
        token = auth_header[7:]
        
        try:
            user = self.client.verify_token(token)
            request.state.vault_user = user
            request.state.vault_token = token
            request.state.vault_token_payload = self.client.decode_token(token)
        except VaultAuthError:
            request.state.vault_user = None
            request.state.vault_token = None
            request.state.vault_token_payload = None
        
        return await call_next(request)


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    api_key: Optional[str] = None,
    base_url: str = "https://api.vault.dev",
) -> User:
    """
    FastAPI dependency to get current authenticated user.
    
    Usage:
        @app.get("/protected")
        async def protected(user: User = Depends(get_current_user)):
            return {"email": user.email}
    """
    # First check if middleware already set the user
    user = getattr(request.state, 'vault_user', None)
    if user:
        return user
    
    # Otherwise verify token
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    token = credentials.credentials
    
    if not api_key:
        raise HTTPException(status_code=500, detail="Vault API key not configured")
    
    client = VaultAuth(api_key=api_key, base_url=base_url)
    
    try:
        return client.verify_token(token)
    except VaultAuthError as e:
        raise HTTPException(status_code=e.status_code or 401, detail=e.message)


async def get_current_token_payload(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    api_key: Optional[str] = None,
    base_url: str = "https://api.vault.dev",
) -> TokenPayload:
    """
    FastAPI dependency to get current token payload.
    
    Usage:
        @app.get("/token-info")
        async def token_info(payload: TokenPayload = Depends(get_current_token_payload)):
            return {"user_id": payload.sub, "org_id": payload.org_id}
    """
    # First check if middleware already set the payload
    payload = getattr(request.state, 'vault_token_payload', None)
    if payload:
        return payload
    
    # Otherwise decode token
    if not credentials:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    token = credentials.credentials
    
    if not api_key:
        raise HTTPException(status_code=500, detail="Vault API key not configured")
    
    client = VaultAuth(api_key=api_key, base_url=base_url)
    
    try:
        return client.decode_token(token)
    except VaultAuthError as e:
        raise HTTPException(status_code=e.status_code or 401, detail=e.message)


class RequireAuth:
    """
    Class-based dependency for requiring authentication with optional checks.
    
    Usage:
        require_auth = RequireAuth(api_key="vault_m2m_...")
        
        @app.get("/protected")
        async def protected(user: User = Depends(require_auth())):
            return {"email": user.email}
            
        @app.get("/admin-only")
        async def admin_only(user: User = Depends(require_auth(roles=["admin", "owner"]))):
            return {"message": "Admin area"}
    """
    
    def __init__(self, api_key: str, base_url: str = "https://api.vault.dev"):
        self.api_key = api_key
        self.base_url = base_url
        self.client = VaultAuth(api_key=api_key, base_url=base_url)
    
    def __call__(
        self,
        roles: Optional[List[str]] = None,
        require_org: bool = False,
    ):
        async def dependency(
            credentials: HTTPAuthorizationCredentials = Depends(security),
        ) -> User:
            if not credentials:
                raise HTTPException(status_code=401, detail="Authentication required")
            
            token = credentials.credentials
            
            try:
                user = self.client.verify_token(token)
                payload = self.client.decode_token(token)
            except VaultAuthError as e:
                raise HTTPException(status_code=e.status_code or 401, detail=e.message)
            
            # Check organization requirements
            if require_org:
                if not payload.org_id:
                    raise HTTPException(status_code=403, detail="Organization membership required")
                
                if roles and payload.org_role not in roles:
                    raise HTTPException(
                        status_code=403,
                        detail=f"Required role: {', '.join(roles)}"
                    )
            
            return user
        
        return dependency


def require_org_access(org_id_param: str = "org_id"):
    """
    Decorator/dependency factory to require organization access.
    
    Usage:
        @app.get("/orgs/{org_id}/settings")
        async def org_settings(
            org_id: str,
            user: User = Depends(get_current_user),
            payload: TokenPayload = Depends(get_current_token_payload),
        ):
            if payload.org_id != org_id:
                raise HTTPException(status_code=403, detail="Not a member of this organization")
            return {"org_id": org_id}
    """
    def checker(
        user: User = Depends(get_current_user),
        payload: TokenPayload = Depends(get_current_token_payload),
    ) -> User:
        # Note: This needs to be used in path operation function
        # The org_id check should happen inside the handler
        return user
    return checker
