"""OAuth2 Security Implementation with Scopes for FastAPI."""
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from fastapi.security.utils import get_authorization_scheme_param
from pydantic import ValidationError
from jose import JWTError, jwt
from typing import Optional, List

from app.config import SECRET_KEY, ALGORITHM
from app.core.storage import StorageInterface
from app.core.error_handling import create_authentication_error, create_authorization_error
from app.models.auth import TokenData
from app.models.user import UserResponse


class OAuth2PasswordBearerWithScopes(OAuth2PasswordBearer):
    """Enhanced OAuth2 password bearer with scope support."""
    
    def __init__(self, tokenUrl: str, scopes: dict = None):
        super().__init__(tokenUrl=tokenUrl, auto_error=False)
        self.scopes = scopes or {}


# OAuth2 scheme with scopes
oauth2_scheme = OAuth2PasswordBearerWithScopes(
    tokenUrl="auth/login",
    scopes={
        # Market data permissions
        "market:read": "Read market data",
        "market:read:level1": "Read level 1 market data", 
        "market:read:level2": "Read level 2 market data",
        
        # Account permissions
        "account:read": "Read account information",
        "account:update": "Update account information",
        
        # Trading permissions
        "trade:execute": "Execute trades",
        "trade:cancel": "Cancel trades",
        "trade:modify": "Modify trades",
        "order:create": "Create orders",
        "order:read": "Read orders",
        "order:update": "Update orders",
        "order:delete": "Delete orders",
        
        # User management permissions
        "user:create": "Create users",
        "user:read": "Read user information",
        "user:update": "Update users", 
        "user:delete": "Delete users",
        
        # Role management permissions
        "role:create": "Create roles",
        "role:read": "Read roles",
        "role:update": "Update roles",
        "role:delete": "Delete roles",
        "role:assign": "Assign roles",
        
        # Permission management
        "permission:create": "Create permissions",
        "permission:read": "Read permissions",
        "permission:update": "Update permissions",
        "permission:delete": "Delete permissions",
        "permission:assign": "Assign permissions",
        
        # Administrative permissions
        "admin:health": "Access health endpoints",
        "admin:logs": "Access system logs",
        "admin:config": "Manage configuration"
    }
)


async def get_current_user_with_scopes(
    security_scopes: SecurityScopes,
    token: str = None,
    storage: StorageInterface = None
) -> UserResponse:
    """
    Get current user and validate required scopes.
    This is the main dependency for OAuth2 with scopes.
    """
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{" ".join(security_scopes.scopes)}"'
    else:
        authenticate_value = "Bearer"

    if not token:
        raise create_authentication_error("Not authenticated")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Verify token type
        if payload.get("token_type") != "access":
            raise create_authentication_error("Invalid token type")
            
        username: str = payload.get("sub")
        if username is None:
            raise create_authentication_error("Invalid token: missing subject")
            
        # Get token scopes/permissions
        token_scopes = payload.get("scopes", payload.get("permissions", []))
        
        token_data = TokenData(
            username=username,
            permissions=token_scopes
        )
        
    except JWTError:
        raise create_authentication_error("Could not validate credentials")

    # Get user from storage
    user_key = f"user:{token_data.username}"
    user_data = await storage.hgetall(user_key)

    if not user_data:
        raise create_authentication_error("User not found")

    user = UserResponse(
        username=token_data.username,
        roles=list(await storage.smembers(f"user_roles:{token_data.username}")),
        is_active=user_data.get("is_active", "true").lower() == "true",
        created_at=user_data.get("created_at")
    )

    if not user.is_active:
        raise create_authorization_error("Inactive user")

    # Validate required scopes
    if security_scopes.scopes:
        for scope in security_scopes.scopes:
            if scope not in token_scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Not enough permissions",
                    headers={"WWW-Authenticate": authenticate_value},
                )

    return user


def create_scope_dependency(required_scopes: List[str]):
    """
    Create a FastAPI Security dependency for specific scopes.
    
    Usage:
    @app.get("/protected", dependencies=[Security(create_scope_dependency(["user:read"]))])
    """
    async def scope_dependency(
        token: str = Depends(oauth2_scheme)
    ) -> UserResponse:
        from app.dependencies import get_storage
        storage = await get_storage()
        
        # Create SecurityScopes with our required scopes
        security_scopes = SecurityScopes(scopes=required_scopes)
        
        return await get_current_user_with_scopes(security_scopes, token, storage)
    
    return scope_dependency


# Common scope dependencies for reuse
RequireUserRead = create_scope_dependency(["user:read"])
RequireUserWrite = create_scope_dependency(["user:create", "user:update"])
RequireUserDelete = create_scope_dependency(["user:delete"])
RequireRoleManagement = create_scope_dependency(["role:assign"])
RequireTrading = create_scope_dependency(["trade:execute"])
RequireMarketData = create_scope_dependency(["market:read"])
RequireAdmin = create_scope_dependency(["admin:health"])


def get_oauth2_scopes() -> dict:
    """Get all available OAuth2 scopes."""
    return oauth2_scheme.scopes 