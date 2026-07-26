"""
CortexSOC — Bearer Token Authentication
JWT validation using python-jose with HS256 algorithm.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt

from backend.config import settings

# HTTPBearer dependency — extracts Bearer token from Authorization header
security = HTTPBearer(auto_error=False)


async def verify_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)]
) -> dict:
    """
    FastAPI dependency that validates Bearer JWT tokens.
    
    Validates tokens using HS256 algorithm with SECRET_KEY from config.settings.
    
    Args:
        credentials: HTTPBearer credentials extracted from Authorization header
    
    Returns:
        dict: Decoded JWT payload
    
    Raises:
        HTTPException: 401 with appropriate detail message for missing/invalid tokens
    """
    # Missing token case
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    
    # Validate and decode token
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=["HS256"],
        )
        return payload
    except JWTError:
        # Invalid, expired, or malformed token
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
