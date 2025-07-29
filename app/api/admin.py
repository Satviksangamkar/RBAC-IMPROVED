"""Admin API routes with OAuth2 Security."""
import asyncio
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Security

from app.core.storage import StorageInterface
from app.core.oauth2_security import RequireAdmin
from app.dependencies import get_storage, get_enforcer
from app.models.user import UserResponse

router = APIRouter(prefix="/admin", tags=["Admin"])
logger = logging.getLogger(__name__)


@router.get("/debug-casbin")
async def debug_casbin_enforcer():
    """Debug endpoint to check Casbin enforcer state."""
    try:
        enforcer = get_enforcer()
        
        if enforcer is None:
            return {"error": "Enforcer not initialized"}
        
        # Get policies and test basic functionality
        policies = enforcer.get_policy()
        grouping = enforcer.get_grouping_policy()
        
        # Test key permissions
        tests = [
            ("admin", "permission", "read"),
            ("admin", "trade", "execute"), 
            ("trader", "trade", "execute"),
            ("viewer", "market", "read")
        ]
        
        test_results = {}
        for role, obj, act in tests:
            test_results[f"{role}+{obj}:{act}"] = enforcer.enforce(role, obj, act)
        
        return {
            "enforcer_exists": True,
            "policies": policies,
            "grouping_policies": grouping,
            "test_results": test_results
        }
        
    except Exception as e:
        return {"error": str(e), "enforcer_exists": False}


@router.get("/casbin-policies")
async def get_casbin_policies(
    current_user: UserResponse = Security(RequireAdmin),
    storage: StorageInterface = Depends(get_storage)
):
    """Get all Casbin policies for auditing."""
    enforcer = get_enforcer()
    try:
        loop = asyncio.get_event_loop()
        policies = await loop.run_in_executor(None, enforcer.get_policy)
        grouping_policies = await loop.run_in_executor(None, enforcer.get_grouping_policy)
        
        return {
            "policies": policies,
            "role_inheritance": grouping_policies
        }
    except Exception as e:
        logger.error(f"Error getting Casbin policies: {e}")
        return {"error": str(e)}


@router.get("/health")
async def health_check(
    storage: StorageInterface = Depends(get_storage)
):
    """Health check endpoint."""
    storage_ok = await storage.ping()
    enforcer = get_enforcer()
    casbin_ok = enforcer is not None
    
    return {
        "api": "running",
        "storage": "ok" if storage_ok else "unavailable",
        "casbin": "ok" if casbin_ok else "unavailable", 
        "timestamp": datetime.now(timezone.utc).isoformat()
    } 