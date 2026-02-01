"""
Authentication middleware for API key validation.
"""

from fastapi import Request, HTTPException, Security
from fastapi.security import APIKeyHeader
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from ..config import get_settings

# API Key header scheme
api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)


async def verify_api_key(api_key: str = Security(api_key_header)) -> str:
    """
    Verify the API key from request header.
    
    Args:
        api_key: API key from x-api-key header
        
    Returns:
        The validated API key
        
    Raises:
        HTTPException: 401 if API key is missing or invalid
    """
    settings = get_settings()
    
    if api_key is None:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Please provide 'x-api-key' header.",
        )
    
    if api_key != settings.api_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key.",
        )
    
    return api_key


class APIKeyMiddleware(BaseHTTPMiddleware):
    """
    Middleware for API key authentication.
    Validates x-api-key header for all protected routes.
    """
    
    # Paths that don't require authentication
    PUBLIC_PATHS = ["/", "/health", "/docs", "/redoc", "/openapi.json"]
    
    async def dispatch(self, request: Request, call_next):
        """Process request and validate API key."""
        
        # Skip authentication for public paths
        if request.url.path in self.PUBLIC_PATHS:
            return await call_next(request)
        
        # Get API key from header
        api_key = request.headers.get("x-api-key")
        settings = get_settings()
        
        # Validate API key
        if api_key is None:
            return JSONResponse(
                status_code=401,
                content={
                    "status": "error",
                    "detail": "Missing API key. Please provide 'x-api-key' header.",
                }
            )
        
        if api_key != settings.api_key:
            return JSONResponse(
                status_code=401,
                content={
                    "status": "error",
                    "detail": "Invalid API key.",
                }
            )
        
        # Proceed with request
        return await call_next(request)
