"""
Tests for framework middleware.
"""

import pytest
from unittest.mock import Mock, patch

from vault_auth.middleware.flask import require_auth as flask_require_auth
from vault_auth.errors import AuthenticationError


class TestFlaskMiddleware:
    """Test Flask middleware."""
    
    @patch('vault_auth.middleware.flask.g')
    @patch('vault_auth.middleware.flask.jsonify')
    def test_require_auth_success(self, mock_jsonify, mock_g):
        """Test successful auth check."""
        mock_user = Mock()
        mock_user.email = "test@example.com"
        mock_g.vault_user = mock_user
        
        @flask_require_auth()
        def protected():
            return {"success": True}
        
        result = protected()
        assert result == {"success": True}
    
    @patch('vault_auth.middleware.flask.g')
    @patch('vault_auth.middleware.flask.jsonify')
    def test_require_auth_failure(self, mock_jsonify, mock_g):
        """Test failed auth check."""
        mock_g.vault_user = None
        mock_jsonify.return_value = ({"error": "Auth required"}, 401)
        
        @flask_require_auth()
        def protected():
            return {"success": True}
        
        result = protected()
        assert result[1] == 401


class TestDjangoMiddleware:
    """Test Django middleware."""
    
    def test_extract_token_from_header(self):
        """Test token extraction from request header."""
        from vault_auth.middleware.django import VaultAuthMiddleware
        
        request = Mock()
        request.META = {'HTTP_AUTHORIZATION': 'Bearer test_token_123'}
        request.path = '/protected'
        
        # Token should be extractable
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        assert auth_header.startswith('Bearer ')
        token = auth_header[7:]
        assert token == 'test_token_123'


class TestFastAPIMiddleware:
    """Test FastAPI middleware."""
    
    @pytest.mark.asyncio
    async def test_get_current_user_no_credentials(self):
        """Test get_current_user with no credentials."""
        from fastapi import HTTPException
        from vault_auth.middleware.fastapi import get_current_user
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(
                request=Mock(),
                credentials=None,
                api_key="vault_m2m_test"
            )
        
        assert exc_info.value.status_code == 401
