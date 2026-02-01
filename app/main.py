"""
Main FastAPI application entry point for the Agentic Honeypot API.
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .routers import honeypot_router
from .middleware.auth import APIKeyMiddleware

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown events."""
    logger.info("Starting Agentic Honeypot API...")
    yield
    logger.info("Shutting down Agentic Honeypot API...")


# Create FastAPI application
app = FastAPI(
    title="Agentic Honeypot API",
    description="""
    An AI-powered agentic honeypot API that detects scam messages, 
    handles multi-turn conversations, extracts scam intelligence, 
    and reports results to the evaluation endpoint.
    
    ## Features
    - 🔐 API Key Authentication
    - 🕵️ Scam Pattern Detection
    - 🤖 AI-Powered Agent Responses
    - 📊 Intelligence Extraction
    - 📤 Automatic Callback Reporting
    
    ## Authentication
    All endpoints (except health check) require `x-api-key` header.
    """,
    version="1.0.0",
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(honeypot_router, prefix="/api/v1")


@app.get("/", tags=["Health"])
async def root():
    """Root endpoint - API information."""
    return {
        "name": "Agentic Honeypot API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "honeypot-api",
    }


# For backward compatibility - also expose honeypot at root level
app.include_router(honeypot_router, prefix="")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
