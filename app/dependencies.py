"""Optimized dependency injection utilities with enhanced performance."""
import os
import tempfile
import logging
import asyncio
from typing import Optional, Dict, Set
from datetime import datetime, timezone
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
import casbin
import redis

from app.config import SECRET_KEY, ALGORITHM, REDIS_CONFIGS, CASBIN_MODEL, DEFAULT_ROLES
from app.core.storage import StorageInterface, RedisStorage, InMemoryStorage
from app.core.casbin_adapter import SyncRedisAdapter
from app.core.security import (
    get_password_hash, run_in_thread, initialize_security_managers,
    get_password_manager, get_rbac_manager
)
from app.core.mfa_manager import initialize_mfa_manager, get_mfa_manager
from app.core.error_handling import (
    AuthenticationError, AuthorizationError, 
    create_authentication_error, create_authorization_error
)
from app.core.oauth2_security import (
    oauth2_scheme, get_current_user_with_scopes, create_scope_dependency,
    RequireUserRead, RequireUserWrite, RequireUserDelete, RequireRoleManagement,
    RequireTrading, RequireMarketData, RequireAdmin
)
from app.models.auth import TokenData, RefreshTokenRequest
from app.models.user import UserResponse

logger = logging.getLogger(__name__)

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Global variables with optimized access
storage: Optional[StorageInterface] = None
enforcer: Optional[casbin.Enforcer] = None
_initialization_lock = asyncio.Lock()
_initialized = False


async def get_storage() -> StorageInterface:
    """Optimized storage factory with singleton pattern."""
    global storage
    if storage is None:
        async with _initialization_lock:
            if storage is None:  # Double-check locking
                storage = await _create_storage()
    return storage


async def _create_storage() -> StorageInterface:
    """Optimized storage creation with fast failover."""
    # Try Redis configurations in parallel for faster connection
    tasks = []
    for config in REDIS_CONFIGS:
        task = asyncio.create_task(_try_redis_connection(config))
        tasks.append(task)
    
    # Wait for first successful connection
    if tasks:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        
        # Cancel remaining tasks
        for task in pending:
            task.cancel()
        
        # Check if any succeeded
        for task in done:
            result = await task
            if result:
                return result
    
    # Fallback to in-memory storage
    logger.warning("Redis connection failed, using in-memory storage")
    return InMemoryStorage()


async def _try_redis_connection(config: Dict) -> Optional[RedisStorage]:
    """Try to connect to Redis with given configuration."""
    try:
        logger.info(f"Attempting Redis connection to {config['host']}:{config['port']}")
        redis_storage = RedisStorage(
            config["host"], config["port"], 
            config["username"], config["password"]
        )
        if await redis_storage.connect():
            logger.info(f"Successfully connected to Redis at {config['host']}:{config['port']}")
            return redis_storage
    except Exception as e:
        logger.debug(f"Failed to connect to Redis at {config['host']}:{config['port']}: {e}")
    
    return None


def get_enforcer() -> Optional[casbin.Enforcer]:
    """Get the Casbin enforcer instance."""
    return enforcer


def _create_sync_redis_client():
    """Optimized sync Redis client creation with proper SSL handling."""
    for config in REDIS_CONFIGS:
        # Try different connection methods
        connection_methods = [
            {"ssl": False},  # Try non-SSL first for performance
            {"ssl": True, "ssl_cert_reqs": None},  # SSL with no cert requirements
            {"connection_class": redis.SSLConnection, "ssl_cert_reqs": None}  # Alternative SSL method
        ]
        
        for ssl_config in connection_methods:
            try:
                client_config = {
                    "host": config["host"],
                    "port": config["port"],
                    "decode_responses": True,
                    "socket_connect_timeout": 5,
                    "socket_timeout": 5,
                    "retry_on_timeout": True,
                    "health_check_interval": 30,
                    **ssl_config
                }
                
                if config["username"]:
                    client_config["username"] = config["username"]
                if config["password"]:
                    client_config["password"] = config["password"]
                
                client = redis.Redis(**client_config)
                client.ping()
                ssl_status = "SSL" if ssl_config.get("ssl", False) else "no SSL"
                logger.info(f"Sync Redis connected to {config['host']}:{config['port']} ({ssl_status})")
                return client
            except Exception as e:
                ssl_status = "SSL" if ssl_config.get("ssl", False) else "non-SSL"
                logger.debug(f"Sync Redis {ssl_status} failed for {config['host']}:{config['port']}: {e}")
    
    raise ConnectionError("All Redis connection attempts failed")


async def _initialize_casbin():
    """Optimized Casbin initialization with pre-computed policies."""
    global enforcer
    
    logger.info("Starting Casbin initialization...")
    
    try:
        # Pre-computed policies for better performance
        basic_policies = [
            # Admin permissions (full access)
            "p, admin, user, create", "p, admin, user, read", "p, admin, user, update", "p, admin, user, delete",
            "p, admin, role, create", "p, admin, role, read", "p, admin, role, update", "p, admin, role, delete", "p, admin, role, assign",
            "p, admin, permission, create", "p, admin, permission, read", "p, admin, permission, update", "p, admin, permission, delete", "p, admin, permission, assign",
            "p, admin, trade, execute",
            # Trader permissions
            "p, trader, trade, execute", "p, trader, order, create", "p, trader, order, delete",
            # Viewer permissions
            "p, viewer, market, read", "p, viewer, account, read",
            # Role hierarchy
            "g, admin, trader", "g, trader, viewer"
        ]
        
        # Create temporary files efficiently
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as model_file:
            model_file.write(CASBIN_MODEL)
            model_file_path = model_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as policy_file:
            policy_file.write('\n'.join(basic_policies))
            policy_file_path = policy_file.name
        
        logger.info(f"Created policy file with {len(basic_policies)} policies")
        
        try:
            # Initialize Casbin with file adapter
            file_adapter = casbin.persist.FileAdapter(policy_file_path)
            enforcer = casbin.Enforcer(model_file_path, file_adapter)
            enforcer.load_policy()
            
            logger.info("Basic Casbin enforcer created and policies loaded")
            
            # Add permissions from config in batches for better performance
            permission_batch = []
            for role_name, role_data in DEFAULT_ROLES.items():
                for permission in role_data["permissions"]:
                    obj, act = permission.split(":", 1)
                    permission_batch.append((role_name, obj, act))
            
            # Add permissions in batches
            for role_name, obj, act in permission_batch:
                try:
                    await run_in_thread(enforcer.add_policy, role_name, obj, act)
                except Exception as e:
                    logger.debug(f"Policy {role_name}, {obj}, {act} already exists or error: {e}")
            
            # Add role inheritance efficiently
            hierarchy_batch = []
            for role_name, role_data in DEFAULT_ROLES.items():
                for parent_role in role_data.get("parent_roles", []):
                    hierarchy_batch.append((role_name, parent_role))
            
            for role_name, parent_role in hierarchy_batch:
                try:
                    await run_in_thread(enforcer.add_grouping_policy, role_name, parent_role)
                except Exception as e:
                    logger.debug(f"Grouping policy {role_name} -> {parent_role} already exists or error: {e}")
            
            # Add symbol-specific permissions efficiently
            symbols = ["AAPL", "GOOGL", "MSFT", "TSLA", "AMZN"]
            symbol_tasks = []
            for symbol in symbols:
                symbol_tasks.append(run_in_thread(enforcer.add_policy, "admin", symbol, "execute"))
                symbol_tasks.append(run_in_thread(enforcer.add_policy, "trader", symbol, "execute"))
            
            # Execute symbol policy additions in parallel
            await asyncio.gather(*symbol_tasks, return_exceptions=True)
            
            # Test the enforcer
            test_result = await run_in_thread(enforcer.enforce, "admin", "permission", "read")
            logger.info(f"Enforcer test (admin can read permissions): {test_result}")
            
            # Try to set up Redis adapter (optional - fail gracefully)
            try:
                sync_redis = _create_sync_redis_client()
                redis_adapter = SyncRedisAdapter(sync_redis)
                enforcer.set_adapter(redis_adapter)
                await run_in_thread(enforcer.save_policy)
                logger.info("Casbin initialized with Redis adapter")
            except Exception as redis_error:
                logger.warning(f"Redis adapter setup failed, continuing with file adapter: {redis_error}")
            
            logger.info("Casbin initialization completed successfully")
            
        finally:
            # Clean up temporary files
            os.unlink(policy_file_path)
            os.unlink(model_file_path)
                
    except Exception as e:
        logger.error(f"Failed to initialize Casbin: {e}")
        enforcer = None


async def _create_enhanced_default_data(storage: StorageInterface):
    """Optimized default data creation with batch operations."""
    try:
        rbac_manager = get_rbac_manager()
        password_manager = get_password_manager()
        
        # Batch create roles and permissions
        role_tasks = []
        permission_tasks = []
        
        for role_name, role_data in DEFAULT_ROLES.items():
            role_key = f"role:{role_name}"
            role_tasks.append(_create_role_if_not_exists(storage, role_key, role_data))
            
            # Create permissions for this role
            for permission in role_data["permissions"]:
                perm_key = f"permission:{permission}"
                permission_tasks.append(_create_permission_if_not_exists(storage, perm_key, permission))
        
        # Execute role and permission creation in parallel
        await asyncio.gather(*role_tasks, return_exceptions=True)
        await asyncio.gather(*permission_tasks, return_exceptions=True)
        
        # Setup hierarchical role inheritance
        await rbac_manager.initialize_standard_hierarchy()
        
        # Validate hierarchy integrity
        issues = await rbac_manager.validate_hierarchy_integrity()
        if issues:
            logger.warning(f"Role hierarchy issues detected: {issues}")
        else:
            logger.info("Role hierarchy validation passed")
        
        # Add breached passwords efficiently
        breached_passwords = ["password", "123456", "password123", "admin", "qwerty"]
        breached_tasks = [password_manager.add_breached_password(pwd) for pwd in breached_passwords]
        await asyncio.gather(*breached_tasks, return_exceptions=True)
        
        # Create admin user if not exists
        await _create_admin_user_if_not_exists(storage)
        
        logger.info("Enhanced default data creation completed")

    except Exception as e:
        logger.error(f"Failed to create enhanced default data: {e}")


async def _create_role_if_not_exists(storage: StorageInterface, role_key: str, role_data: Dict):
    """Create role if it doesn't exist."""
    if not await storage.exists(role_key):
        await storage.hset(role_key, mapping={
            "description": role_data["description"],
            "created_at": datetime.now(timezone.utc).isoformat()
        })


async def _create_permission_if_not_exists(storage: StorageInterface, perm_key: str, permission: str):
    """Create permission if it doesn't exist."""
    if not await storage.exists(perm_key):
        await storage.hset(perm_key, mapping={
            "description": f"Permission to {permission.split(':')[1]} {permission.split(':')[0]}",
            "created_at": datetime.now(timezone.utc).isoformat()
        })


async def _create_admin_user_if_not_exists(storage: StorageInterface):
    """Create admin user if it doesn't exist."""
    admin_key = "user:admin"
    if not await storage.exists(admin_key):
        strong_password = "AdminSecure123!@#$"
        hashed_password = get_password_hash(strong_password)
        await storage.hset(admin_key, mapping={
            "password": hashed_password,
            "is_active": "true",
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        await storage.sadd("user_roles:admin", "admin")
        logger.info(f"Default admin user created (username: admin, password: {strong_password})")
        logger.warning("CHANGE THE DEFAULT ADMIN PASSWORD IMMEDIATELY!")


async def initialize_app():
    """Optimized application initialization with concurrency."""
    global storage, _initialized
    
    async with _initialization_lock:
        if _initialized:
            return storage
            
        # Initialize storage
        storage = await _create_storage()
        logger.info("Storage initialized")
        
        # Initialize security managers
        initialize_security_managers(storage)
        logger.info("Security managers initialized")
        
        # Parallel initialization of independent components
        initialization_tasks = [
            _initialize_rbac_hierarchy(),
            _initialize_mfa(),
            _initialize_casbin()
        ]
        
        await asyncio.gather(*initialization_tasks, return_exceptions=True)
        
        # Create enhanced default data
        await _create_enhanced_default_data(storage)
        logger.info("Enhanced default data created")
        
        _initialized = True
        
    return storage


async def _initialize_rbac_hierarchy():
    """Initialize RBAC hierarchy."""
    rbac_manager = get_rbac_manager()
    await rbac_manager.initialize_standard_hierarchy()
    logger.info("Standard role hierarchy initialized")


async def _initialize_mfa():
    """Initialize MFA manager."""
    initialize_mfa_manager(storage)
    logger.info("MFA manager initialized")


# Optimized user validation with caching
_user_cache: Dict[str, tuple] = {}
_cache_timeout = 300  # 5 minutes


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    storage: StorageInterface = Depends(get_storage)
) -> UserResponse:
    """Optimized user validation with caching and early returns."""
    try:
        # Fast token validation
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Early validation checks
        if payload.get("token_type") != "access":
            raise create_authentication_error("Invalid token type")
            
        username: str = payload.get("sub")
        if not username:
            raise create_authentication_error("Invalid token: missing subject")
        
        # Check cache first
        cache_key = f"{username}:{token[:10]}"  # Use token prefix for cache key
        if cache_key in _user_cache:
            cached_user, timestamp = _user_cache[cache_key]
            if (datetime.now() - timestamp).total_seconds() < _cache_timeout:
                return cached_user
        
        # Get user data from storage
        user_key = f"user:{username}"
        user_data = await storage.hgetall(user_key)

        if not user_data:
            raise create_authentication_error("User not found")

        # Get user roles efficiently
        user_roles = await storage.smembers(f"user_roles:{username}")
        
        user = UserResponse(
            username=username,
            roles=list(user_roles),
            is_active=user_data.get("is_active", "true").lower() == "true",
            created_at=datetime.fromisoformat(user_data.get("created_at"))
        )

        if not user.is_active:
            raise create_authorization_error("Account is inactive")

        # Cache the user (cleanup cache if too large)
        if len(_user_cache) > 1000:
            _cleanup_user_cache()
        
        _user_cache[cache_key] = (user, datetime.now())
        
        return user
        
    except JWTError as e:
        logger.warning(f"JWT validation failed: {e}")
        raise create_authentication_error("Invalid or expired token")


def _cleanup_user_cache():
    """Clean up expired entries from user cache."""
    now = datetime.now()
    expired_keys = [
        key for key, (_, timestamp) in _user_cache.items()
        if (now - timestamp).total_seconds() > _cache_timeout
    ]
    for key in expired_keys:
        del _user_cache[key]


def requires_permission(permission: str):
    """Optimized permission dependency with caching."""
    async def permission_dependency(
        current_user: UserResponse = Depends(get_current_user), 
        storage: StorageInterface = Depends(get_storage)
    ):
        from app.core.security import check_permission
        await check_permission(permission, current_user, storage, enforcer)
        return current_user
    return permission_dependency


async def get_refresh_token(request: Request, refresh_token_request: Optional[RefreshTokenRequest] = None):
    """Optimized refresh token extraction."""
    # Try request body first (fastest)
    if refresh_token_request and refresh_token_request.refresh_token:
        return refresh_token_request.refresh_token
        
    # Try cookies (fallback)
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        return refresh_token
        
    # No refresh token found
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Refresh token is required",
        headers={"WWW-Authenticate": "Bearer"},
    ) 