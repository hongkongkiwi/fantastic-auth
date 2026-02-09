"""
Tests for VaultAuth client.
"""

import json
import base64
import pytest
import responses
from datetime import datetime, timezone

from vault_auth import VaultAuth
from vault_auth.errors import (
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)


BASE_URL = "https://api.vault.dev"
API_KEY = "vault_m2m_test_key_12345"


@pytest.fixture
def client():
    return VaultAuth(
        api_key=API_KEY,
        base_url=BASE_URL,
        max_retries=1,
    )


@responses.activate
def test_verify_token_success(client):
    """Test successful token verification."""
    responses.add(
        responses.POST,
        f"{BASE_URL}/api/v1/auth/verify",
        json={
            "data": {
                "id": "user_123",
                "email": "test@example.com",
                "email_verified": True,
                "status": "active",
                "first_name": "Test",
                "last_name": "User",
            }
        },
        status=200,
    )
    
    # Create a dummy JWT
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "kid": "key1"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "user_123", "exp": 9999999999}).encode()).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(b"signature").decode().rstrip("=")
    token = f"{header}.{payload}.{signature}"
    
    user = client.verify_token(token)
    
    assert user.id == "user_123"
    assert user.email == "test@example.com"
    assert user.first_name == "Test"
    assert user.last_name == "User"


@responses.activate
def test_get_user(client):
    """Test getting user by ID."""
    responses.add(
        responses.GET,
        f"{BASE_URL}/api/v1/users/user_123",
        json={
            "data": {
                "id": "user_123",
                "email": "test@example.com",
                "email_verified": True,
                "status": "active",
            }
        },
        status=200,
    )
    
    user = client.users.get("user_123")
    
    assert user.id == "user_123"
    assert user.email == "test@example.com"


@responses.activate
def test_create_user(client):
    """Test creating a user."""
    responses.add(
        responses.POST,
        f"{BASE_URL}/api/v1/users",
        json={
            "data": {
                "id": "user_new",
                "email": "new@example.com",
                "email_verified": False,
                "status": "pending_verification",
                "first_name": "New",
                "last_name": "User",
            }
        },
        status=201,
    )
    
    user = client.users.create(
        email="new@example.com",
        password="secure_password",
        first_name="New",
        last_name="User",
    )
    
    assert user.id == "user_new"
    assert user.email == "new@example.com"
    assert user.full_name == "New User"


@responses.activate
def test_list_users(client):
    """Test listing users."""
    responses.add(
        responses.GET,
        f"{BASE_URL}/api/v1/users",
        json={
            "data": {
                "users": [
                    {"id": "user_1", "email": "user1@example.com", "status": "active"},
                    {"id": "user_2", "email": "user2@example.com", "status": "active"},
                ],
                "total": 2,
                "page": 1,
                "per_page": 20,
                "has_more": False,
            }
        },
        status=200,
    )
    
    result = client.users.list()
    
    assert len(result.data) == 2
    assert result.total == 2
    assert result.data[0].email == "user1@example.com"


@responses.activate
def test_update_user(client):
    """Test updating a user."""
    responses.add(
        responses.PATCH,
        f"{BASE_URL}/api/v1/users/user_123",
        json={
            "data": {
                "id": "user_123",
                "email": "test@example.com",
                "first_name": "Updated",
                "last_name": "Name",
            }
        },
        status=200,
    )
    
    user = client.users.update(
        user_id="user_123",
        first_name="Updated",
        last_name="Name",
    )
    
    assert user.first_name == "Updated"
    assert user.last_name == "Name"


@responses.activate
def test_delete_user(client):
    """Test deleting a user."""
    responses.add(
        responses.DELETE,
        f"{BASE_URL}/api/v1/users/user_123",
        status=204,
    )
    
    client.users.delete("user_123")
    
    assert len(responses.calls) == 1


@responses.activate
def test_get_organization(client):
    """Test getting organization by ID."""
    responses.add(
        responses.GET,
        f"{BASE_URL}/api/v1/organizations/org_123",
        json={
            "data": {
                "id": "org_123",
                "name": "Test Org",
                "slug": "test-org",
                "status": "active",
            }
        },
        status=200,
    )
    
    org = client.organizations.get("org_123")
    
    assert org.id == "org_123"
    assert org.name == "Test Org"
    assert org.slug == "test-org"


@responses.activate
def test_create_organization(client):
    """Test creating an organization."""
    responses.add(
        responses.POST,
        f"{BASE_URL}/api/v1/organizations",
        json={
            "data": {
                "id": "org_new",
                "name": "New Org",
                "slug": "new-org",
                "status": "active",
            }
        },
        status=201,
    )
    
    org = client.organizations.create(name="New Org", slug="new-org")
    
    assert org.id == "org_new"
    assert org.name == "New Org"


@responses.activate
def test_get_organization_members(client):
    """Test getting organization members."""
    responses.add(
        responses.GET,
        f"{BASE_URL}/api/v1/organizations/org_123/members",
        json={
            "data": {
                "members": [
                    {
                        "id": "mem_1",
                        "user_id": "user_1",
                        "organization_id": "org_123",
                        "role": "owner",
                    },
                    {
                        "id": "mem_2",
                        "user_id": "user_2",
                        "organization_id": "org_123",
                        "role": "member",
                    },
                ]
            }
        },
        status=200,
    )
    
    members = client.organizations.get_members("org_123")
    
    assert len(members) == 2
    assert members[0].role.value == "owner"
    assert members[1].role.value == "member"


@responses.activate
def test_not_found_error(client):
    """Test handling 404 errors."""
    responses.add(
        responses.GET,
        f"{BASE_URL}/api/v1/users/notfound",
        json={"message": "User not found", "code": "not_found"},
        status=404,
    )
    
    with pytest.raises(NotFoundError) as exc_info:
        client.users.get("notfound")
    
    assert exc_info.value.status_code == 404
    assert "not found" in exc_info.value.message.lower()


@responses.activate
def test_rate_limit_error(client):
    """Test handling rate limit errors."""
    responses.add(
        responses.GET,
        f"{BASE_URL}/api/v1/users",
        json={"message": "Rate limit exceeded"},
        status=429,
        headers={"Retry-After": "60"},
    )
    
    with pytest.raises(RateLimitError) as exc_info:
        client.users.list()
    
    assert exc_info.value.status_code == 429
    assert exc_info.value.retry_after == 60


@responses.activate
def test_server_error_with_retry(client):
    """Test retry logic on server error."""
    # First request fails
    responses.add(
        responses.GET,
        f"{BASE_URL}/api/v1/users/user_123",
        json={"message": "Internal server error"},
        status=500,
    )
    # Second request succeeds
    responses.add(
        responses.GET,
        f"{BASE_URL}/api/v1/users/user_123",
        json={
            "data": {
                "id": "user_123",
                "email": "test@example.com",
                "status": "active",
            }
        },
        status=200,
    )
    
    # Client with retries
    retry_client = VaultAuth(
        api_key=API_KEY,
        base_url=BASE_URL,
        max_retries=2,
        retry_delay=0.01,
    )
    
    user = retry_client.users.get("user_123")
    
    assert user.id == "user_123"
    assert len(responses.calls) == 2


def test_invalid_api_key_format():
    """Test that invalid API key format raises error."""
    with pytest.raises(ValueError, match="vault_m2m_"):
        VaultAuth(api_key="invalid_key")


def test_missing_api_key():
    """Test that missing API key raises error."""
    with pytest.raises(ValueError, match="API key is required"):
        VaultAuth(api_key="")
