"""Enhanced Security utilities for authentication and authorization."""
import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Set
from fastapi import HTTPException, status, Request
from jose import JWTError, jwt

from app.config import SECRET_KEY, ALGORITHM
from app.core.storage import StorageInterface
from app.core.password_manager import PasswordManager, PasswordPolicyError
from app.core.rbac_manager import RBACManager
from app.core.error_handling import (
    AuthenticationError, AuthorizationError, RateLimitError,
    create_authentication_error, create_authorization_error, create_rate_limit_error
)
from app.models.auth import TokenData
from app.models.user import UserResponse

logger = logging.getLogger(__name__)

# Global instances
password_manager: Optional[PasswordManager] = None
rbac_manager: Optional[RBACManager] = None


def initialize_security_managers(storage: StorageInterface):
    """Initialize security managers with storage."""
    global password_manager, rbac_manager
    password_manager = PasswordManager(storage)
    rbac_manager = RBACManager(storage)
    logger.info("Security managers initialized")


def get_password_manager() -> PasswordManager:
    """Get password manager instance."""
    if password_manager is None:
        raise RuntimeError("Password manager not initialized")
    return password_manager


def get_rbac_manager() -> RBACManager:
    """Get RBAC manager instance."""
    if rbac_manager is None:
        raise RuntimeError("RBAC manager not initialized")
    return rbac_manager


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return get_password_manager().verify_password(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generate password hash."""
    return get_password_manager().hash_password(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token with permissions as scopes."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({
        "exp": expire,
        "scopes": data.get("permissions", []),
        "token_type": "access"
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(username: str, token_id: Optional[str] = None, 
                        expires_delta: Optional[timedelta] = None) -> tuple[str, str]:
    """Create refresh token with unique ID for revocation capability."""
    token_id = token_id or str(uuid.uuid4())
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(days=7))
    to_encode = {
        "sub": username,
        "exp": expire,
        "jti": token_id,
        "token_type": "refresh"
    }
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token, token_id


async def authenticate_user(username: str, password: str, storage: StorageInterface, 
                           request: Optional[Request] = None) -> Optional[UserResponse]:
    """Enhanced user authentication with rate limiting and security checks."""
    pm = get_password_manager()
    
    # Check for account lockout
    if await pm.is_account_locked(username):
        if request:
            from app.core.error_handling import ErrorLogger
            ErrorLogger.log_security_event(
                "ACCOUNT_LOCKED_ATTEMPT", 
                {"username": username}, 
                request
            )
        raise create_rate_limit_error("Account temporarily locked due to multiple failed attempts")
    
    user_key = f"user:{username}"
    user_data = await storage.hgetall(user_key)

    if not user_data:
        # Record failed attempt for non-existent user to prevent enumeration
        await pm.record_failed_attempt(username)
        return None
    
    # Check if account is active
    if user_data.get("is_active", "true").lower() != "true":
        if request:
            from app.core.error_handling import ErrorLogger
            ErrorLogger.log_security_event(
                "INACTIVE_ACCOUNT_LOGIN_ATTEMPT", 
                {"username": username}, 
                request
            )
        raise create_authentication_error("Account is inactive")
    
    # Verify password
    stored_password = user_data.get("password", "")
    if not verify_password(password, stored_password):
        await pm.record_failed_attempt(username)
        return None
    
    # Check if password needs rehashing
    if pm.needs_rehash(stored_password):
        new_hash = get_password_hash(password)
        await storage.hset(user_key, {"password": new_hash})
        logger.info(f"Password rehashed for user: {username}")
    
    # Clear failed attempts on successful login
    await pm.clear_failed_attempts(username)
    
    return UserResponse(
        username=username,
        roles=list(await storage.smembers(f"user_roles:{username}")),
        is_active=True,
        created_at=datetime.fromisoformat(user_data.get("created_at"))
    )


async def get_user_permissions(storage: StorageInterface, username: str, enforcer) -> Set[str]:
    """Get all permissions for a user including hierarchical inheritance."""
    try:
        # Use the enhanced RBAC manager for permission calculation
        rbac = get_rbac_manager()
        return await rbac.get_effective_permissions(username)
    except Exception as e:
        logger.warning(f"Error getting permissions for user {username}: {e}")
        
        # Fallback to basic permission lookup
        roles_key = f"user_roles:{username}"
        user_roles = await storage.smembers(roles_key)
        permissions = set()
        
        for role in user_roles:
            role_perms_key = f"role_permissions:{role}"
            role_permissions = await storage.smembers(role_perms_key)
            permissions.update(role_permissions)
        
        return permissions


async def validate_refresh_token(token: str, storage: StorageInterface) -> Optional[tuple[str, str]]:
    """Validate a refresh token and return the associated username and token ID."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Validate token structure
        if (payload.get("token_type") != "refresh" or 
            not payload.get("sub") or 
            not payload.get("jti")):
            return None
            
        username = payload["sub"]
        token_id = payload["jti"]
        exp = payload.get("exp")
        
        # Check expiration
        if exp and datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
            await revoke_refresh_token(storage, username, token_id)
            return None
            
        # Validate token exists and is active
        token_key = f"refresh_token:{token_id}"
        token_data = await storage.hgetall(token_key)
        
        if (not token_data or 
            token_data.get("username") != username or
            not await storage.sismember(f"user_refresh_tokens:{username}", token_id)):
            return None
            
        return username, token_id
    except JWTError:
        return None


async def store_refresh_token(storage: StorageInterface, username: str, token_id: str, expires_delta: timedelta):
    """Store refresh token in storage for validation and revocation."""
    await storage.sadd(f"user_refresh_tokens:{username}", token_id)
    
    expiry_timestamp = int((datetime.now(timezone.utc) + expires_delta).timestamp())
    await storage.hset(f"refresh_token:{token_id}", mapping={
        "username": username,
        "expires_at": str(expiry_timestamp),
        "created_at": datetime.now(timezone.utc).isoformat()
    })


async def revoke_refresh_token(storage: StorageInterface, username: str, token_id: str):
    """Revoke a refresh token."""
    await storage.srem(f"user_refresh_tokens:{username}", token_id)
    await storage.delete(f"refresh_token:{token_id}")


async def revoke_all_user_refresh_tokens(storage: StorageInterface, username: str):
    """Revoke all refresh tokens for a user with enhanced error handling."""
    try:
        user_tokens_key = f"user_refresh_tokens:{username}"
        token_ids = await storage.smembers(user_tokens_key)
        
        if not token_ids:
            logger.debug(f"No refresh tokens found for user: {username}")
            return
        
        # Delete all token data with error handling for each token
        for token_id in token_ids:
            try:
                await storage.delete(f"refresh_token:{token_id}")
            except Exception as e:
                logger.warning(f"Failed to delete refresh token {token_id} for user {username}: {e}")
        
        # Clear the active tokens set
        try:
            await storage.delete(user_tokens_key)
            logger.debug(f"Successfully revoked {len(token_ids)} refresh tokens for user: {username}")
        except Exception as e:
            logger.warning(f"Failed to clear user tokens set for {username}: {e}")
            
    except Exception as e:
        logger.error(f"Error revoking refresh tokens for user {username}: {e}")
        # Don't re-raise to prevent 500 errors in password change
        return


async def run_in_thread(func, *args):
    """Helper to run synchronous functions in thread pool."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, func, *args)


async def check_permission(required_permission: str, user: UserResponse, storage: StorageInterface, enforcer):
    """Enhanced permission check using hierarchical RBAC and Casbin."""
    if ":" not in required_permission:
        raise AuthorizationError("Invalid permission format")
    
    obj, act = required_permission.split(":", 1)
    
    try:
        # Get all user roles including inherited ones
        rbac = get_rbac_manager()
        user_roles = await storage.smembers(f"user_roles:{user.username}")
        
        # Check permissions for user roles and inherited roles
        for role in user_roles:
            # Get all inherited roles for this role
            inherited_roles = await rbac.get_all_inherited_roles(role)
            
            # Check permission for each inherited role
            for inherited_role in inherited_roles:
                try:
                    if await run_in_thread(enforcer.enforce, inherited_role, obj, act):
                        logger.debug(f"Permission granted: {user.username} -> {inherited_role} -> {required_permission}")
                        return  # Permission granted
                except Exception as e:
                    logger.warning(f"Casbin enforce error for {inherited_role}, {obj}, {act}: {e}")
        
        # No permission found
        logger.warning(f"Permission denied: {user.username} attempted {required_permission}")
        raise create_authorization_error("Insufficient permissions for this action")
        
    except Exception as e:
        logger.error(f"Permission check failed for {user.username}: {e}")
        raise create_authorization_error("Permission check failed")


async def check_object_permission(user: UserResponse, resource: str, action: str, 
                                 object_id: Optional[str] = None, enforcer=None) -> bool:
    """Object-level permission check via Casbin for ABAC scenarios."""
    from app.dependencies import get_storage
    
    storage = await get_storage()
    user_roles = await storage.smembers(f"user_roles:{user.username}")
    
    for role in user_roles:
        try:
            # Check basic permission
            if await run_in_thread(enforcer.enforce, role, resource, action):
                # For object-level checks
                if object_id:
                    if await run_in_thread(enforcer.enforce, user.username, object_id, action):
                        return True
                else:
                    return True
        except Exception as e:
            logger.warning(f"Object permission check error: {e}")
    
    return False 