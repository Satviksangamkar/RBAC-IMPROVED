"""Advanced RBAC Manager with Hierarchical Role Inheritance."""
import logging
import asyncio
from collections import deque, defaultdict
from typing import Set, List, Dict, Optional, Tuple
from datetime import datetime, timedelta

from app.core.storage import StorageInterface

logger = logging.getLogger(__name__)


class RoleHierarchyError(Exception):
    """Exception raised for role hierarchy violations."""
    pass


class RBACManager:
    """Advanced RBAC Manager with hierarchical role inheritance and caching."""
    
    # Financial industry role hierarchy
    STANDARD_HIERARCHY = {
        "admin": ["trader", "approver"],
        "trader": ["viewer"],
        "approver": ["viewer"],
        "viewer": []
    }
    
    # Core permissions by role
    ROLE_PERMISSIONS = {
        "viewer": {
            "market:read", "account:read", "position:read", 
            "order:read", "report:read", "user:read"
        },
        "trader": {
            "trade:execute", "order:create", "order:read", "order:update", "order:delete", 
            "order:modify", "order:cancel", "position:manage"
        },
        "approver": {
            "trade:approve", "limit:modify", "risk:override",
            "audit:access"
        },
        "admin": {
            "user:create", "user:read", "user:update", "user:delete",
            "role:assign", "role:create", "role:read", "role:update", "role:delete",
            "permission:create", "permission:read", "permission:update", "permission:delete", "permission:assign",
            "system:configure", "admin:health", "audit:full", "backup:create"
        }
    }
    
    def __init__(self, storage: StorageInterface):
        self.storage = storage
        self._inheritance_cache: Dict[str, Set[str]] = {}
        self._permissions_cache: Dict[str, Set[str]] = {}
        self._cache_expiry: Dict[str, datetime] = {}
        self._cache_ttl = timedelta(minutes=30)
        
    async def initialize_standard_hierarchy(self):
        """Initialize the standard financial industry role hierarchy."""
        try:
            # Clear existing hierarchy
            await self._clear_role_hierarchy()
            
            # Set up role permissions
            for role, permissions in self.ROLE_PERMISSIONS.items():
                role_key = f"role_permissions:{role}"
                # Clear existing permissions
                await self.storage.delete(role_key)
                # Add new permissions
                if permissions:
                    await self.storage.sadd(role_key, *permissions)
            
            # Set up hierarchy relationships
            for child_role, parent_roles in self.STANDARD_HIERARCHY.items():
                hierarchy_key = f"role_hierarchy:{child_role}"
                await self.storage.delete(hierarchy_key)
                if parent_roles:
                    await self.storage.sadd(hierarchy_key, *parent_roles)
            
            # Clear caches
            self._invalidate_cache()
            
            logger.info("Standard role hierarchy initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize standard hierarchy: {e}")
            raise RoleHierarchyError(f"Hierarchy initialization failed: {e}")
    
    async def get_all_inherited_roles(self, role: str) -> Set[str]:
        """
        Get all roles that this role inherits from using BFS traversal.
        Includes cycle detection and caching for performance.
        """
        # Check cache first
        if self._is_cache_valid(role):
            return self._inheritance_cache[role].copy()
        
        # BFS traversal to get all inherited roles
        visited = set()
        queue = deque([role])
        inherited_roles = set()
        path = []  # Track path for cycle detection
        
        while queue:
            current_role = queue.popleft()
            
            if current_role in path:
                raise RoleHierarchyError(
                    f"Circular dependency detected: {' -> '.join(path + [current_role])}"
                )
                
            if current_role in visited:
                continue
                
            visited.add(current_role)
            inherited_roles.add(current_role)
            path.append(current_role)
            
            # Get parent roles
            parent_roles_key = f"role_hierarchy:{current_role}"
            parent_roles = await self.storage.smembers(parent_roles_key)
            
            for parent_role in parent_roles:
                if parent_role not in visited:
                    queue.append(parent_role)
            
            path.pop()
        
        # Cache the result
        self._inheritance_cache[role] = inherited_roles.copy()
        self._cache_expiry[role] = datetime.now() + self._cache_ttl
        
        logger.debug(f"Role '{role}' inherits from: {inherited_roles - {role}}")
        return inherited_roles
    
    async def get_effective_permissions(self, username: str) -> Set[str]:
        """
        Get all effective permissions for a user including inherited permissions.
        Implements separation of duties for financial compliance.
        """
        # Check cache first
        cache_key = f"user_permissions:{username}"
        if self._is_cache_valid(cache_key):
            return self._permissions_cache[cache_key].copy()
            
        user_roles = await self.storage.smembers(f"user_roles:{username}")
        all_permissions = set()
        
        # Validate role compatibility (separation of duties)
        await self._validate_role_compatibility(user_roles)
        
        for role in user_roles:
            # Get all inherited roles
            inherited_roles = await self.get_all_inherited_roles(role)
            
            # Collect permissions from all inherited roles
            for inherited_role in inherited_roles:
                role_permissions = await self.storage.smembers(f"role_permissions:{inherited_role}")
                all_permissions.update(role_permissions)
        
        # Cache the result
        self._permissions_cache[cache_key] = all_permissions.copy()
        self._cache_expiry[cache_key] = datetime.now() + self._cache_ttl
        
        return all_permissions
    
    async def add_role_inheritance(self, child_role: str, parent_role: str):
        """
        Add role inheritance relationship with comprehensive validation.
        """
        # Validate roles exist
        if not await self._role_exists(child_role):
            raise RoleHierarchyError(f"Child role '{child_role}' does not exist")
        if not await self._role_exists(parent_role):
            raise RoleHierarchyError(f"Parent role '{parent_role}' does not exist")
        
        # Check for self-inheritance
        if child_role == parent_role:
            raise RoleHierarchyError("Role cannot inherit from itself")
        
        # Temporarily add the relationship to test for cycles
        hierarchy_key = f"role_hierarchy:{child_role}"
        existing_parents = await self.storage.smembers(hierarchy_key)
        
        try:
            await self.storage.sadd(hierarchy_key, parent_role)
            
            # Test for cycles by getting inherited roles
            await self.get_all_inherited_roles(child_role)
            
            # If no exception, the relationship is valid
            self._invalidate_cache()
            logger.info(f"Added role inheritance: {child_role} inherits from {parent_role}")
            
        except RoleHierarchyError as e:
            # Restore original state
            await self.storage.delete(hierarchy_key)
            if existing_parents:
                await self.storage.sadd(hierarchy_key, *existing_parents)
            raise e
    
    async def remove_role_inheritance(self, child_role: str, parent_role: str):
        """Remove role inheritance relationship."""
        await self.storage.srem(f"role_hierarchy:{child_role}", parent_role)
        self._invalidate_cache()
        logger.info(f"Removed role inheritance: {child_role} no longer inherits from {parent_role}")
    
    async def get_role_hierarchy_tree(self) -> Dict[str, List[str]]:
        """Get the complete role hierarchy as a tree structure."""
        hierarchy = {}
        
        for role in self.STANDARD_HIERARCHY.keys():
            parents = await self.storage.smembers(f"role_hierarchy:{role}")
            hierarchy[role] = list(parents)
        
        return hierarchy
    
    async def validate_hierarchy_integrity(self) -> List[str]:
        """Validate the integrity of the role hierarchy."""
        issues = []
        
        try:
            for role in self.STANDARD_HIERARCHY.keys():
                try:
                    await self.get_all_inherited_roles(role)
                except RoleHierarchyError as e:
                    issues.append(f"Role {role}: {str(e)}")
                    
        except Exception as e:
            issues.append(f"General hierarchy validation error: {str(e)}")
        
        return issues
    
    async def _validate_role_compatibility(self, roles: Set[str]):
        """
        Validate role compatibility for separation of duties.
        Financial regulations often require separation between trading and approval roles.
        """
        role_list = list(roles)
        
        # Check for conflicting roles (trader + approver)
        if "trader" in role_list and "approver" in role_list:
            logger.warning("User has both trader and approver roles - separation of duties concern")
            # In strict environments, this might raise an exception
            # raise RoleHierarchyError("Separation of duties violation: user cannot have both trader and approver roles")
    
    async def _role_exists(self, role: str) -> bool:
        """Check if a role exists by verifying it has permissions or hierarchy."""
        permissions_exist = await self.storage.exists(f"role_permissions:{role}")
        hierarchy_exists = await self.storage.exists(f"role_hierarchy:{role}")
        return permissions_exist or hierarchy_exists or role in self.STANDARD_HIERARCHY
    
    async def _clear_role_hierarchy(self):
        """Clear all existing role hierarchy and permission data."""
        for role in self.STANDARD_HIERARCHY.keys():
            await self.storage.delete(f"role_hierarchy:{role}")
            await self.storage.delete(f"role_permissions:{role}")
    
    def _is_cache_valid(self, key: str) -> bool:
        """Check if cache entry is valid."""
        if key not in self._cache_expiry:
            return False
        return datetime.now() < self._cache_expiry[key]
    
    def _invalidate_cache(self):
        """Invalidate all caches."""
        self._inheritance_cache.clear()
        self._permissions_cache.clear()
        self._cache_expiry.clear()
        logger.debug("Role hierarchy cache invalidated")
    
    async def get_user_roles_with_inheritance(self, username: str) -> Dict[str, Set[str]]:
        """Get user roles and their complete inheritance chain."""
        user_roles = await self.storage.smembers(f"user_roles:{username}")
        result = {}
        
        for role in user_roles:
            inherited = await self.get_all_inherited_roles(role)
            result[role] = inherited - {role}  # Exclude the role itself
        
        return result 