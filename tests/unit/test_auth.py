"""
Unit tests for backend/auth.py — Bearer token validation.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from backend.auth import verify_token


@pytest.mark.asyncio
async def test_verify_token_missing():
    """Test that missing token raises 401 with 'Missing Bearer token'."""
    with pytest.raises(HTTPException) as exc_info:
        await verify_token(None)
    
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Missing Bearer token"


@pytest.mark.asyncio
async def test_verify_token_invalid():
    """Test that invalid token raises 401 with 'Invalid or expired token'."""
    fake_credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="invalid.token.here"
    )
    
    with pytest.raises(HTTPException) as exc_info:
        await verify_token(fake_credentials)
    
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid or expired token"


@pytest.mark.asyncio
async def test_verify_token_malformed():
    """Test that malformed token raises 401 with 'Invalid or expired token'."""
    fake_credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="not-a-jwt"
    )
    
    with pytest.raises(HTTPException) as exc_info:
        await verify_token(fake_credentials)
    
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid or expired token"


@pytest.mark.asyncio
async def test_verify_token_valid(monkeypatch):
    """Test that valid token returns decoded payload."""
    # Mock jwt.decode to return a fixed payload
    from jose import jwt
    
    fake_payload = {"sub": "user123", "exp": 9999999999}
    
    def mock_decode(token, key, algorithms):
        if token == "valid.token.here":
            return fake_payload
        raise Exception("Unexpected token")
    
    monkeypatch.setattr(jwt, "decode", mock_decode)
    
    fake_credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="valid.token.here"
    )
    
    result = await verify_token(fake_credentials)
    assert result == fake_payload
