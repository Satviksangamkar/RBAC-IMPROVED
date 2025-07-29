"""Background tasks for application maintenance."""
import asyncio
import logging
from datetime import datetime, timezone

from app.config import TOKEN_CLEANUP_INTERVAL
from app.core.storage import StorageInterface
from app.core.security import revoke_refresh_token

logger = logging.getLogger(__name__)


async def periodic_token_cleanup(storage: StorageInterface):
    """Run token cleanup periodically."""
    while True:
        try:
            await asyncio.sleep(TOKEN_CLEANUP_INTERVAL)
            logger.info("Running scheduled refresh token cleanup")
            await cleanup_expired_tokens(storage)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in token cleanup task: {e}")
            await asyncio.sleep(60)  # Wait a bit before retrying


async def cleanup_expired_tokens(storage: StorageInterface):
    """Clean up expired refresh tokens."""
    try:
        # Get all refresh token keys
        all_token_keys = await storage.keys("refresh_token:*")
        current_time = datetime.now(timezone.utc).timestamp()
        
        for token_key in all_token_keys:
            token_data = await storage.hgetall(token_key)
            if not token_data:
                continue
                
            # Check if token has expired
            expires_at = token_data.get("expires_at")
            if expires_at and float(expires_at) < current_time:
                # Extract token ID from key
                token_id = token_key.split(":")[1]
                username = token_data.get("username")
                
                if username:
                    # Revoke expired token
                    await revoke_refresh_token(storage, username, token_id)
                    logger.info(f"Cleaned up expired token for user {username}")
    except Exception as e:
        logger.error(f"Error cleaning up expired tokens: {e}") 