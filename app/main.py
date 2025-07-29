"""Enhanced Main FastAPI application with comprehensive security."""
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import (
    APP_TITLE, APP_DESCRIPTION, APP_VERSION,
    CORS_ORIGINS, CORS_CREDENTIALS, CORS_METHODS, CORS_HEADERS,
    LOG_LEVEL
)
from app.dependencies import initialize_app
from app.background_tasks import periodic_token_cleanup
from app.core.error_handling import setup_error_handlers
from app.api import auth, users, trading, admin

# Configure enhanced logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management."""
    logger.info("Starting up application...")
    
    try:
        # Initialize everything in one go
        storage = await initialize_app()
        
        # Start background tasks
        token_cleanup_task = asyncio.create_task(periodic_token_cleanup(storage))
        app.state.token_cleanup_task = token_cleanup_task
        app.state.storage = storage
        
        logger.info("Application initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize application: {e}")
        raise

    yield

    # Shutdown
    logger.info("Shutting down application...")
    
    # Cancel background tasks and close storage
    tasks = []
    if hasattr(app.state, 'token_cleanup_task'):
        app.state.token_cleanup_task.cancel()
        tasks.append(app.state.token_cleanup_task)
    
    if tasks:
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
    
    # Close storage
    if hasattr(app.state, 'storage'):
        await app.state.storage.close()
        logger.info("Application shutdown complete")


# Create enhanced FastAPI app with OAuth2 security
app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION,
    lifespan=lifespan,
    openapi_tags=[
        {"name": "Authentication", "description": "Enhanced user authentication with MFA support"},
        {"name": "Users", "description": "User management with hierarchical RBAC"},
        {"name": "Trading", "description": "Trading operations with granular permissions"},
        {"name": "Admin", "description": "Administrative endpoints with audit logging"}
    ]
)

# Setup comprehensive error handlers
setup_error_handlers(app)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=CORS_CREDENTIALS,
    allow_methods=CORS_METHODS,
    allow_headers=CORS_HEADERS,
)

# Include routers with enhanced security (prefixes defined in individual routers)
app.include_router(auth.router)
app.include_router(users.router)  
app.include_router(trading.router)
app.include_router(admin.router)


@app.get("/")
async def root():
    """Enhanced root endpoint with security features overview."""
    return {
        "message": "Enhanced Trading Terminal RBAC API with Advanced Security",
        "version": APP_VERSION,
        "docs": "/docs",
        "health": "/admin/health",
        "security_features": [
            "Hierarchical Role-Based Access Control (RBAC)",
            "Multi-Factor Authentication (MFA) for admin roles",
            "Argon2id password hashing with breach detection",
            "Comprehensive error handling and audit logging",
            "Rate limiting and account lockout protection",
            "Casbin-based policy enforcement with inheritance",
            "Password strength validation and policy enforcement",
            "Secure JWT token management with refresh capability"
        ],
        "compliance": [
            "NIST 800-63B password guidelines",
            "OWASP authentication best practices",
            "Industry-standard role hierarchy patterns",
            "Comprehensive audit and security logging"
        ]
    } 