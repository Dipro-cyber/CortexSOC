"""
CortexSOC — Request Size Check Middleware
Enforces 1 MB maximum request body size (Requirement 20.1).
"""
from __future__ import annotations

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


class SizeCheckMiddleware(BaseHTTPMiddleware):
    """
    HTTP middleware that reads the Content-Length header and rejects requests
    with bodies exceeding the configured maximum size (default 1 MB).
    
    Returns HTTP 400 with a structured error body if the limit is exceeded.
    """

    def __init__(self, app, max_body_size: int = 1_000_000):
        super().__init__(app)
        self.max_body_size = max_body_size

    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Check Content-Length header before processing the request.
        If the body size exceeds max_body_size, return HTTP 400 immediately.
        """
        content_length = request.headers.get("content-length")
        
        if content_length is not None:
            try:
                content_length_int = int(content_length)
                if content_length_int > self.max_body_size:
                    return JSONResponse(
                        status_code=400,
                        content={"detail": "Request body exceeds 1 MB limit"},
                    )
            except ValueError:
                # Invalid Content-Length header — let FastAPI handle the malformed request
                pass

        # Content-Length is within limit or not present; proceed with request
        response = await call_next(request)
        return response
