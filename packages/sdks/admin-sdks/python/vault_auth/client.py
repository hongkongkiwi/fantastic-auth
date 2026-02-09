"""
Main Vault Auth client implementation.
"""

import base64
import hashlib
import json
import time
import logging
from typing import Optional, Dict, Any, List, Callable
from urllib.parse import urljoin

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

from .types import (
    User,
    Organization,
    OrganizationMembership,
    Session,
    JWKS,
    TokenPayload,
    PaginatedResponse,
)
from .errors import (
    VaultAuthError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
    TokenExpiredError,
    InvalidTokenError,
)

logger = logging.getLogger(__name__)


class HTTPClient:
    """Internal HTTP client with retry logic."""
    
    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        request_id: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.request_id = request_id
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "vault-auth-python/1.0.0",
        })
        if request_id:
            self._session.headers["X-Request-ID"] = request_id

    def _make_request(
        self,
        method: str,
        path: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Make HTTP request with retry logic."""
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        
        last_error = None
        for attempt in range(self.max_retries):
            try:
                response = self._session.request(
                    method,
                    url,
                    timeout=self.timeout,
                    **kwargs
                )
                return self._handle_response(response)
            except requests.exceptions.Timeout:
                last_error = ServerError("Request timeout")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (2 ** attempt))
            except requests.exceptions.ConnectionError as e:
                last_error = ServerError(f"Connection error: {str(e)}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (2 ** attempt))
            except VaultAuthError:
                raise
            except Exception as e:
                last_error = VaultAuthError(f"Request failed: {str(e)}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (2 ** attempt))
        
        raise last_error or ServerError("Request failed after retries")

    def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """Handle HTTP response and raise appropriate errors."""
        request_id = response.headers.get("X-Request-ID")
        
        if response.status_code == 200 or response.status_code == 201:
            return response.json() if response.content else {}
        
        if response.status_code == 204:
            return {}
        
        try:
            error_data = response.json()
        except:
            error_data = {}
        
        message = error_data.get("message", "Unknown error")
        error_code = error_data.get("code")
        details = error_data.get("details", {})
        
        if response.status_code == 400:
            raise ValidationError(
                message=message,
                error_code=error_code,
                details=details,
                request_id=request_id,
                field_errors=details.get("fields"),
            )
        elif response.status_code == 401:
            raise AuthenticationError(
                message=message,
                error_code=error_code,
                details=details,
                request_id=request_id,
            )
        elif response.status_code == 403:
            raise AuthorizationError(
                message=message,
                error_code=error_code,
                details=details,
                request_id=request_id,
            )
        elif response.status_code == 404:
            raise NotFoundError(
                message=message,
                error_code=error_code,
                details=details,
                request_id=request_id,
            )
        elif response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 60))
            raise RateLimitError(
                message=message,
                error_code=error_code,
                details=details,
                request_id=request_id,
                retry_after=retry_after,
            )
        elif response.status_code >= 500:
            raise ServerError(
                message=message,
                status_code=response.status_code,
                error_code=error_code,
                details=details,
                request_id=request_id,
            )
        else:
            raise VaultAuthError(
                message=message,
                status_code=response.status_code,
                error_code=error_code,
                details=details,
                request_id=request_id,
            )

    def get(self, path: str, **kwargs) -> Dict[str, Any]:
        return self._make_request("GET", path, **kwargs)

    def post(self, path: str, **kwargs) -> Dict[str, Any]:
        return self._make_request("POST", path, **kwargs)

    def put(self, path: str, **kwargs) -> Dict[str, Any]:
        return self._make_request("PUT", path, **kwargs)

    def patch(self, path: str, **kwargs) -> Dict[str, Any]:
        return self._make_request("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs) -> Dict[str, Any]:
        return self._make_request("DELETE", path, **kwargs)


class UsersAPI:
    """Users API endpoints."""
    
    def __init__(self, client: HTTPClient):
        self._client = client

    def get(self, user_id: str) -> User:
        """Get user by ID."""
        response = self._client.get(f"/api/v1/users/{user_id}")
        return User.from_dict(response["data"])

    def get_by_email(self, email: str) -> User:
        """Get user by email address."""
        response = self._client.get(f"/api/v1/users/email/{email}")
        return User.from_dict(response["data"])

    def list(
        self,
        page: int = 1,
        per_page: int = 20,
        status: Optional[str] = None,
        organization_id: Optional[str] = None,
    ) -> PaginatedResponse:
        """List users with optional filtering."""
        params = {"page": page, "per_page": per_page}
        if status:
            params["status"] = status
        if organization_id:
            params["organization_id"] = organization_id
        
        response = self._client.get("/api/v1/users", params=params)
        data = response["data"]
        users = [User.from_dict(u) for u in data.get("users", [])]
        return PaginatedResponse(
            data=users,
            total=data.get("total", 0),
            page=data.get("page", page),
            per_page=data.get("per_page", per_page),
            has_more=data.get("has_more", False),
        )

    def create(
        self,
        email: str,
        password: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        email_verified: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> User:
        """Create a new user."""
        payload = {
            "email": email,
            "password": password,
            "email_verified": email_verified,
        }
        if first_name:
            payload["first_name"] = first_name
        if last_name:
            payload["last_name"] = last_name
        if metadata:
            payload["metadata"] = metadata
        
        response = self._client.post("/api/v1/users", json=payload)
        return User.from_dict(response["data"])

    def update(
        self,
        user_id: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        email: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> User:
        """Update user information."""
        payload = {}
        if first_name is not None:
            payload["first_name"] = first_name
        if last_name is not None:
            payload["last_name"] = last_name
        if email is not None:
            payload["email"] = email
        if metadata is not None:
            payload["metadata"] = metadata
        
        response = self._client.patch(f"/api/v1/users/{user_id}", json=payload)
        return User.from_dict(response["data"])

    def delete(self, user_id: str) -> None:
        """Delete a user."""
        self._client.delete(f"/api/v1/users/{user_id}")

    def update_password(self, user_id: str, password: str) -> None:
        """Update user password."""
        self._client.patch(
            f"/api/v1/users/{user_id}/password",
            json={"password": password}
        )

    def get_organizations(self, user_id: str) -> List[OrganizationMembership]:
        """Get organizations a user belongs to."""
        response = self._client.get(f"/api/v1/users/{user_id}/organizations")
        memberships = response["data"].get("memberships", [])
        return [OrganizationMembership.from_dict(m) for m in memberships]

    def get_sessions(self, user_id: str) -> List[Session]:
        """Get user's active sessions."""
        response = self._client.get(f"/api/v1/users/{user_id}/sessions")
        sessions = response["data"].get("sessions", [])
        return [Session.from_dict(s) for s in sessions]


class OrganizationsAPI:
    """Organizations API endpoints."""
    
    def __init__(self, client: HTTPClient):
        self._client = client

    def get(self, org_id: str) -> Organization:
        """Get organization by ID."""
        response = self._client.get(f"/api/v1/organizations/{org_id}")
        return Organization.from_dict(response["data"])

    def get_by_slug(self, slug: str) -> Organization:
        """Get organization by slug."""
        response = self._client.get(f"/api/v1/organizations/slug/{slug}")
        return Organization.from_dict(response["data"])

    def list(
        self,
        page: int = 1,
        per_page: int = 20,
    ) -> PaginatedResponse:
        """List organizations."""
        params = {"page": page, "per_page": per_page}
        response = self._client.get("/api/v1/organizations", params=params)
        data = response["data"]
        orgs = [Organization.from_dict(o) for o in data.get("organizations", [])]
        return PaginatedResponse(
            data=orgs,
            total=data.get("total", 0),
            page=data.get("page", page),
            per_page=data.get("per_page", per_page),
            has_more=data.get("has_more", False),
        )

    def create(
        self,
        name: str,
        slug: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Organization:
        """Create a new organization."""
        payload = {"name": name}
        if slug:
            payload["slug"] = slug
        if metadata:
            payload["metadata"] = metadata
        
        response = self._client.post("/api/v1/organizations", json=payload)
        return Organization.from_dict(response["data"])

    def update(
        self,
        org_id: str,
        name: Optional[str] = None,
        slug: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Organization:
        """Update organization information."""
        payload = {}
        if name is not None:
            payload["name"] = name
        if slug is not None:
            payload["slug"] = slug
        if metadata is not None:
            payload["metadata"] = metadata
        
        response = self._client.patch(f"/api/v1/organizations/{org_id}", json=payload)
        return Organization.from_dict(response["data"])

    def delete(self, org_id: str) -> None:
        """Delete an organization."""
        self._client.delete(f"/api/v1/organizations/{org_id}")

    def get_members(self, org_id: str) -> List[OrganizationMembership]:
        """Get organization members."""
        response = self._client.get(f"/api/v1/organizations/{org_id}/members")
        members = response["data"].get("members", [])
        return [OrganizationMembership.from_dict(m) for m in members]

    def add_member(
        self,
        org_id: str,
        user_id: str,
        role: str = "member",
    ) -> OrganizationMembership:
        """Add a member to organization."""
        payload = {"user_id": user_id, "role": role}
        response = self._client.post(
            f"/api/v1/organizations/{org_id}/members",
            json=payload
        )
        return OrganizationMembership.from_dict(response["data"])

    def remove_member(self, org_id: str, user_id: str) -> None:
        """Remove a member from organization."""
        self._client.delete(f"/api/v1/organizations/{org_id}/members/{user_id}")

    def update_member_role(self, org_id: str, user_id: str, role: str) -> OrganizationMembership:
        """Update member's role in organization."""
        payload = {"role": role}
        response = self._client.patch(
            f"/api/v1/organizations/{org_id}/members/{user_id}",
            json=payload
        )
        return OrganizationMembership.from_dict(response["data"])


class SessionsAPI:
    """Sessions API endpoints."""
    
    def __init__(self, client: HTTPClient):
        self._client = client

    def get(self, session_id: str) -> Session:
        """Get session by ID."""
        response = self._client.get(f"/api/v1/sessions/{session_id}")
        return Session.from_dict(response["data"])

    def revoke(self, session_id: str) -> None:
        """Revoke a session."""
        self._client.post(f"/api/v1/sessions/{session_id}/revoke")

    def revoke_all_user_sessions(self, user_id: str) -> None:
        """Revoke all sessions for a user."""
        self._client.post(f"/api/v1/users/{user_id}/sessions/revoke-all")


class VaultAuth:
    """Main Vault Auth client."""
    
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.vault.dev",
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        request_id: Optional[str] = None,
        jwks_cache_ttl: int = 3600,
    ):
        """
        Initialize Vault Auth client.
        
        Args:
            api_key: Vault API key (vault_m2m_...)
            base_url: Vault API base URL
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries on 5xx errors
            retry_delay: Base delay between retries in seconds
            request_id: Request ID for tracing
            jwks_cache_ttl: JWKS cache time-to-live in seconds
        """
        if not api_key:
            raise ValueError("API key is required")
        if not api_key.startswith("vault_m2m_"):
            raise ValueError("API key must start with 'vault_m2m_'")
        
        self._http = HTTPClient(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
            max_retries=max_retries,
            retry_delay=retry_delay,
            request_id=request_id,
        )
        self._jwks_cache_ttl = jwks_cache_ttl
        self._jwks: Optional[JWKS] = None
        self._jwks_fetched_at: float = 0
        
        # API sub-clients
        self._users: Optional[UsersAPI] = None
        self._organizations: Optional[OrganizationsAPI] = None
        self._sessions: Optional[SessionsAPI] = None

    @property
    def users(self) -> UsersAPI:
        """Users API."""
        if self._users is None:
            self._users = UsersAPI(self._http)
        return self._users

    @property
    def organizations(self) -> OrganizationsAPI:
        """Organizations API."""
        if self._organizations is None:
            self._organizations = OrganizationsAPI(self._http)
        return self._organizations

    @property
    def sessions(self) -> SessionsAPI:
        """Sessions API."""
        if self._sessions is None:
            self._sessions = SessionsAPI(self._http)
        return self._sessions

    def _get_jwks(self) -> JWKS:
        """Get JWKS, fetching if necessary."""
        now = time.time()
        if self._jwks is None or (now - self._jwks_fetched_at) > self._jwks_cache_ttl:
            response = self._http.get("/.well-known/jwks.json")
            self._jwks = JWKS.from_dict(response)
            self._jwks_fetched_at = now
        return self._jwks

    def verify_token(self, token: str) -> User:
        """
        Verify a JWT token and return the associated user.
        
        Args:
            token: JWT token string
            
        Returns:
            User: Authenticated user
            
        Raises:
            TokenExpiredError: If token is expired
            InvalidTokenError: If token is invalid
            AuthenticationError: If verification fails
        """
        try:
            # Parse token header to get key ID
            parts = token.split(".")
            if len(parts) != 3:
                raise InvalidTokenError("Invalid token format")
            
            # Decode header
            header_json = base64.urlsafe_b64decode(parts[0] + "==")
            header = json.loads(header_json)
            kid = header.get("kid")
            
            if not kid:
                raise InvalidTokenError("Token missing key ID")
            
            # Get JWKS and find matching key
            jwks = self._get_jwks()
            key_data = None
            for key in jwks.keys:
                if key.kid == kid:
                    key_data = key
                    break
            
            if not key_data:
                # Refresh JWKS cache and try again
                self._jwks = None
                jwks = self._get_jwks()
                for key in jwks.keys:
                    if key.kid == kid:
                        key_data = key
                        break
                
                if not key_data:
                    raise InvalidTokenError("Signing key not found")
            
            # Decode payload to check expiration
            payload_json = base64.urlsafe_b64decode(parts[1] + "==")
            payload = json.loads(payload_json)
            
            exp = payload.get("exp")
            if exp and exp < time.time():
                raise TokenExpiredError()
            
            # Verify signature (simplified - in production use proper JWT library)
            # This makes a call to Vault to verify the token
            response = self._http.post(
                "/api/v1/auth/verify",
                json={"token": token}
            )
            
            return User.from_dict(response["data"])
            
        except json.JSONDecodeError as e:
            raise InvalidTokenError(f"Failed to decode token: {str(e)}")
        except (TokenExpiredError, InvalidTokenError):
            raise
        except VaultAuthError:
            raise
        except Exception as e:
            raise InvalidTokenError(f"Token verification failed: {str(e)}")

    def decode_token(self, token: str) -> TokenPayload:
        """
        Decode a JWT token without verification.
        
        Args:
            token: JWT token string
            
        Returns:
            TokenPayload: Decoded token payload
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise InvalidTokenError("Invalid token format")
            
            payload_json = base64.urlsafe_b64decode(parts[1] + "==")
            payload = json.loads(payload_json)
            
            return TokenPayload(
                sub=payload["sub"],
                exp=payload["exp"],
                iat=payload["iat"],
                iss=payload["iss"],
                aud=payload["aud"],
                jti=payload["jti"],
                email=payload.get("email"),
                email_verified=payload.get("email_verified"),
                org_id=payload.get("org_id"),
                org_role=payload.get("org_role"),
            )
        except Exception as e:
            raise InvalidTokenError(f"Failed to decode token: {str(e)}")

    def get_jwks(self) -> JWKS:
        """Get JWKS (JSON Web Key Set)."""
        return self._get_jwks()

    def health_check(self) -> Dict[str, Any]:
        """Check Vault API health status."""
        return self._http.get("/health")
