"""
Type definitions for Vault Auth SDK.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class UserStatus(str, Enum):
    """User status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"


class OrganizationRole(str, Enum):
    """Organization role enumeration."""
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"


@dataclass
class User:
    """Represents a Vault user."""
    id: str
    email: str
    email_verified: bool
    status: UserStatus
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    avatar_url: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_login_at: Optional[datetime] = None

    @property
    def full_name(self) -> str:
        """Get user's full name."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.first_name or self.last_name or self.email

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "User":
        """Create User from API response dict."""
        return cls(
            id=data["id"],
            email=data["email"],
            email_verified=data.get("email_verified", False),
            status=UserStatus(data.get("status", "active")),
            first_name=data.get("first_name"),
            last_name=data.get("last_name"),
            avatar_url=data.get("avatar_url"),
            metadata=data.get("metadata", {}),
            created_at=_parse_datetime(data.get("created_at")),
            updated_at=_parse_datetime(data.get("updated_at")),
            last_login_at=_parse_datetime(data.get("last_login_at")),
        )


@dataclass
class Organization:
    """Represents a Vault organization."""
    id: str
    name: str
    slug: str
    status: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Organization":
        """Create Organization from API response dict."""
        return cls(
            id=data["id"],
            name=data["name"],
            slug=data["slug"],
            status=data.get("status", "active"),
            metadata=data.get("metadata", {}),
            created_at=_parse_datetime(data.get("created_at")),
            updated_at=_parse_datetime(data.get("updated_at")),
        )


@dataclass
class OrganizationMembership:
    """Represents a user's membership in an organization."""
    id: str
    user_id: str
    organization_id: str
    role: OrganizationRole
    joined_at: Optional[datetime] = None
    organization: Optional[Organization] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OrganizationMembership":
        """Create OrganizationMembership from API response dict."""
        org_data = data.get("organization")
        return cls(
            id=data["id"],
            user_id=data["user_id"],
            organization_id=data["organization_id"],
            role=OrganizationRole(data.get("role", "member")),
            joined_at=_parse_datetime(data.get("joined_at")),
            organization=Organization.from_dict(org_data) if org_data else None,
        )


@dataclass
class Session:
    """Represents a user session."""
    id: str
    user_id: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None

    @property
    def is_active(self) -> bool:
        """Check if session is active."""
        if self.revoked_at:
            return False
        if self.expires_at and self.expires_at < datetime.utcnow():
            return False
        return True

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Session":
        """Create Session from API response dict."""
        return cls(
            id=data["id"],
            user_id=data["user_id"],
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent"),
            created_at=_parse_datetime(data.get("created_at")),
            expires_at=_parse_datetime(data.get("expires_at")),
            last_used_at=_parse_datetime(data.get("last_used_at")),
            revoked_at=_parse_datetime(data.get("revoked_at")),
        )


@dataclass
class JWKSKey:
    """Represents a JWK (JSON Web Key)."""
    kty: str
    kid: str
    use: Optional[str] = None
    alg: Optional[str] = None
    n: Optional[str] = None  # RSA modulus
    e: Optional[str] = None  # RSA exponent
    x: Optional[str] = None  # EC x coordinate
    y: Optional[str] = None  # EC y coordinate
    crv: Optional[str] = None  # EC curve


@dataclass
class JWKS:
    """Represents a JWKS (JSON Web Key Set)."""
    keys: List[JWKSKey]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JWKS":
        """Create JWKS from API response dict."""
        keys = [JWKSKey(**key_data) for key_data in data.get("keys", [])]
        return cls(keys=keys)


@dataclass
class TokenPayload:
    """Represents decoded JWT token payload."""
    sub: str  # User ID
    exp: int  # Expiration timestamp
    iat: int  # Issued at timestamp
    iss: str  # Issuer
    aud: str  # Audience
    jti: str  # JWT ID
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    org_id: Optional[str] = None
    org_role: Optional[str] = None

    @property
    def user_id(self) -> str:
        """Get user ID from subject claim."""
        return self.sub


@dataclass
class PaginatedResponse:
    """Generic paginated response wrapper."""
    data: List[Any]
    total: int
    page: int
    per_page: int
    has_more: bool


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse ISO datetime string to datetime object."""
    if not value:
        return None
    try:
        # Handle ISO format with Z
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
