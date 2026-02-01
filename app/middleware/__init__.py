"""
Middleware components for the Honeypot API.
"""

from .auth import verify_api_key, APIKeyMiddleware

__all__ = ["verify_api_key", "APIKeyMiddleware"]
