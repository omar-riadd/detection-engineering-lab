"""
api/core/auth.py
Optional API key authentication dependency for write operations.
If the API_KEY environment variable is not configured, authentication is bypassed
to preserve zero-config local development and testing workflows.
"""
import os
from typing import Optional
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: Optional[str] = Security(API_KEY_HEADER)) -> Optional[str]:
    """
    FastAPI security dependency.
    If API_KEY is set in environment, enforces that the incoming X-API-Key header matches.
    If API_KEY is not set, permits requests unconditionally.
    """
    configured_key = os.getenv("API_KEY")
    if not configured_key:
        return None  # Passthrough: Auth is disabled in dev / local mode

    if not api_key or api_key.strip() != configured_key.strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Invalid or missing API key in X-API-Key header",
        )

    return api_key
