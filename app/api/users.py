"""User management API routes with OAuth2 Security."""
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Security, HTTPException
from typing import List

from app.core.storage import StorageInterface
from app.core.security import get_password_hash, get_user_permissions, get_rbac_manager
from app.core.oauth2_security import (
    RequireUserRead, RequireUserWrite, RequireUserDelete, RequireRoleManagement
)
from app.dependencies import get_storage, get_current_user, get_enforcer
from app.models.user import UserCreate, UserResponse, RoleCreate, PermissionCreate, AssignRole, AssignPermission

router = APIRouter(prefix="/users", tags=["Users"])
logger = logging.getLogger(__name__)


@router.post("/", response_model=UserResponse)
async def create_user(
    user: UserCreate,
    current_user: UserResponse = Security(RequireUserWrite),
    storage: StorageInterface = Depends(get_storage)
):
    """Create user with security validation."""
    user_key = f"user:{user.username}"
    if await storage.exists(user_key):
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = get_password_hash(user.password)
    created_at = datetime.now(timezone.utc).isoformat()
    await storage.hset(user_key, mapping={
        "password": hashed_password,
        "is_active": "true",
        "created_at": created_at
    })

    logger.info(f"User created: {user.username}")

    return UserResponse(
        username=user.username,
        roles=[],
        is_active=True,
        created_at=datetime.fromisoformat(created_at)
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: UserResponse = Security(RequireUserRead)
):
    """Get current user information."""
    return current_user


@router.get("/me/permissions")
async def get_my_permissions(
    current_user: UserResponse = Depends(get_current_user),
    storage: StorageInterface = Depends(get_storage)
):
    """Get user permissions through RBAC system."""
    try:
        rbac_manager = get_rbac_manager()
        permissions = await rbac_manager.get_effective_permissions(current_user.username)
        
        return {
            "permissions": sorted(list(permissions)),
            "roles": current_user.roles
        }
    except Exception as e:
        logger.error(f"Error getting permissions for {current_user.username}: {e}")
        return {
            "permissions": [],
            "roles": current_user.roles,
            "error": "Could not retrieve permissions"
        }


@router.get("/me/role-hierarchy")
async def get_my_role_hierarchy(
    current_user: UserResponse = Depends(get_current_user),
    storage: StorageInterface = Depends(get_storage)
):
    """Get user's role hierarchy and inheritance chain."""
    try:
        rbac_manager = get_rbac_manager()
        role_inheritance = await rbac_manager.get_user_roles_with_inheritance(current_user.username)
        
        return {
            "assigned_roles": current_user.roles,
            "role_inheritance": {role: list(inherited) for role, inherited in role_inheritance.items()},
            "hierarchy_tree": await rbac_manager.get_role_hierarchy_tree()
        }
    except Exception as e:
        logger.error(f"Error getting role hierarchy for {current_user.username}: {e}")
        return {"error": "Could not retrieve role hierarchy"}


@router.get("/{username}/permissions")
async def get_user_permissions(
    username: str,
    current_user: UserResponse = Security(RequireUserRead),
    storage: StorageInterface = Depends(get_storage)
):
    """Get specific user permissions (admin access required)."""
    try:
        # Verify user exists
        user_key = f"user:{username}"
        if not await storage.exists(user_key):
            raise HTTPException(status_code=404, detail="User not found")
        
        # Get user roles
        user_roles = await storage.smembers(f"user_roles:{username}")
        
        # Get effective permissions through RBAC
        rbac_manager = get_rbac_manager()
        permissions = await rbac_manager.get_effective_permissions(username)
        
        return {
            "username": username,
            "permissions": sorted(list(permissions)),
            "roles": list(user_roles)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting permissions for user {username}: {e}")
        raise HTTPException(status_code=500, detail="Could not retrieve user permissions")


@router.get("/{username}/role-hierarchy")
async def get_user_role_hierarchy(
    username: str,
    current_user: UserResponse = Security(RequireUserRead),
    storage: StorageInterface = Depends(get_storage)
):
    """Get specific user's role hierarchy (admin access required)."""
    try:
        # Verify user exists
        user_key = f"user:{username}"
        if not await storage.exists(user_key):
            raise HTTPException(status_code=404, detail="User not found")
        
        # Get user roles
        user_roles = await storage.smembers(f"user_roles:{username}")
        
        # Get role hierarchy
        rbac_manager = get_rbac_manager()
        role_inheritance = await rbac_manager.get_user_roles_with_inheritance(username)
        
        return {
            "username": username,
            "assigned_roles": list(user_roles),
            "role_inheritance": {role: list(inherited) for role, inherited in role_inheritance.items()},
            "hierarchy_tree": await rbac_manager.get_role_hierarchy_tree()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting role hierarchy for user {username}: {e}")
        raise HTTPException(status_code=500, detail="Could not retrieve user role hierarchy")


@router.post("/roles")
async def create_role(
    role: RoleCreate,
    current_user: UserResponse = Security(RequireRoleManagement),
    storage: StorageInterface = Depends(get_storage)
):
    """Create role with validation."""
    role_key = f"role:{role.name}"
    if await storage.exists(role_key):
        raise HTTPException(status_code=400, detail="Role already exists")

    created_at = datetime.now(timezone.utc).isoformat()
    await storage.hset(role_key, mapping={
        "description": role.description,
        "created_at": created_at
    })

    return {"message": f"Role '{role.name}' created successfully"}


@router.post("/permissions")
async def create_permission(
    permission: PermissionCreate,
    current_user: UserResponse = Security(RequireRoleManagement),
    storage: StorageInterface = Depends(get_storage)
):
    """Create permission with validation."""
    permission_key = f"permission:{permission.name}"
    if await storage.exists(permission_key):
        raise HTTPException(status_code=400, detail="Permission already exists")

    created_at = datetime.now(timezone.utc).isoformat()
    await storage.hset(permission_key, mapping={
        "description": permission.description,
        "created_at": created_at
    })

    logger.info(f"Permission created: {permission.name}")
    return {"message": f"Permission '{permission.name}' created successfully"}


@router.post("/assign-role")
async def assign_role(
    assignment: AssignRole,
    current_user: UserResponse = Security(RequireRoleManagement),
    storage: StorageInterface = Depends(get_storage)
):
    """Assign role to user with hierarchy validation."""
    user_key = f"user:{assignment.username}"
    if not await storage.exists(user_key):
        raise HTTPException(status_code=404, detail="User not found")

    # Validate role compatibility
    rbac_manager = get_rbac_manager()
    existing_roles = await storage.smembers(f"user_roles:{assignment.username}")
    new_roles = existing_roles.union({assignment.role_name})
    
    try:
        await rbac_manager._validate_role_compatibility(new_roles)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    await storage.sadd(f"user_roles:{assignment.username}", assignment.role_name)
    
    # Update Casbin
    enforcer = get_enforcer()
    if enforcer:
        enforcer.add_grouping_policy(assignment.username, assignment.role_name)

    return {"message": f"Role '{assignment.role_name}' assigned to '{assignment.username}'"}


@router.delete("/{username}")
async def delete_user(
    username: str,
    current_user: UserResponse = Security(RequireUserDelete),
    storage: StorageInterface = Depends(get_storage)
):
    """Delete user and cleanup associated data."""
    user_key = f"user:{username}"
    if not await storage.exists(user_key):
        raise HTTPException(status_code=404, detail="User not found")

    # Delete user data
    await storage.delete(user_key)
    
    # Delete user roles
    await storage.delete(f"user_roles:{username}")
    
    # Delete refresh tokens
    from app.core.security import revoke_all_user_refresh_tokens
    await revoke_all_user_refresh_tokens(storage, username)

    return {"message": f"User '{username}' deleted successfully"} 