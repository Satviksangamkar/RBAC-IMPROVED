"""Multi-Factor Authentication Manager."""
import base64
import logging
import secrets
from typing import List, Optional, Tuple
from datetime import datetime, timedelta

try:
    import pyotp
    import qrcode
    from io import BytesIO
    MFA_AVAILABLE = True
except ImportError:
    MFA_AVAILABLE = False

from app.core.storage import StorageInterface

logger = logging.getLogger(__name__)


class MFAError(Exception):
    """Exception for MFA-related errors."""
    pass


class MFAManager:
    """Multi-Factor Authentication manager with TOTP support."""
    
    def __init__(self, storage: StorageInterface, app_name: str = "Trading Terminal RBAC"):
        if not MFA_AVAILABLE:
            raise RuntimeError("MFA dependencies not available. Install pyotp and qrcode packages.")
        
        self.storage = storage
        self.app_name = app_name
        self.backup_codes_count = 10
        
    async def setup_totp(self, username: str) -> Tuple[str, str, List[str]]:
        """
        Setup TOTP for a user.
        Returns: (secret, qr_code_url, backup_codes)
        """
        # Generate secret
        secret = pyotp.random_base32()
        
        # Create TOTP instance
        totp = pyotp.TOTP(secret)
        
        # Generate QR code URL
        qr_code_url = totp.provisioning_uri(
            name=username,
            issuer_name=self.app_name
        )
        
        # Generate backup codes
        backup_codes = [secrets.token_hex(4).upper() for _ in range(self.backup_codes_count)]
        
        # Store MFA data
        mfa_data = {
            "secret": secret,
            "enabled": "false",  # Not enabled until verified
            "backup_codes": ",".join(backup_codes),
            "setup_time": datetime.utcnow().isoformat()
        }
        
        await self.storage.hset(f"mfa:{username}", mfa_data)
        
        logger.info(f"TOTP setup initiated for user: {username}")
        return secret, qr_code_url, backup_codes
    
    async def verify_setup(self, username: str, code: str) -> bool:
        """
        Verify TOTP setup with provided code and enable MFA.
        """
        mfa_data = await self.storage.hgetall(f"mfa:{username}")
        
        if not mfa_data or not mfa_data.get("secret"):
            raise MFAError("MFA not set up for this user")
        
        secret = mfa_data["secret"]
        totp = pyotp.TOTP(secret)
        
        if totp.verify(code, valid_window=2):  # Allow 2 time windows for clock drift
            # Enable MFA
            await self.storage.hset(f"mfa:{username}", {"enabled": "true"})
            logger.info(f"MFA enabled for user: {username}")
            return True
        
        return False
    
    async def verify_code(self, username: str, code: str) -> bool:
        """
        Verify TOTP code or backup code.
        """
        mfa_data = await self.storage.hgetall(f"mfa:{username}")
        
        if not mfa_data or mfa_data.get("enabled") != "true":
            raise MFAError("MFA not enabled for this user")
        
        # Check if it's a backup code first
        if await self._verify_backup_code(username, code, mfa_data):
            return True
        
        # Check TOTP code
        secret = mfa_data["secret"]
        totp = pyotp.TOTP(secret)
        
        # Use valid_window=1 for stricter verification during actual auth
        return totp.verify(code, valid_window=1)
    
    async def _verify_backup_code(self, username: str, code: str, mfa_data: dict) -> bool:
        """
        Verify and consume backup code.
        """
        backup_codes_str = mfa_data.get("backup_codes", "")
        if not backup_codes_str:
            return False
        
        backup_codes = backup_codes_str.split(",")
        code_upper = code.upper()
        
        if code_upper in backup_codes:
            # Remove used backup code
            backup_codes.remove(code_upper)
            await self.storage.hset(
                f"mfa:{username}", 
                {"backup_codes": ",".join(backup_codes)}
            )
            
            logger.warning(f"Backup code used for user: {username}. Remaining codes: {len(backup_codes)}")
            return True
        
        return False
    
    async def is_mfa_enabled(self, username: str) -> bool:
        """
        Check if MFA is enabled for a user.
        """
        mfa_data = await self.storage.hgetall(f"mfa:{username}")
        return mfa_data.get("enabled") == "true"
    
    async def disable_mfa(self, username: str):
        """
        Disable MFA for a user.
        """
        await self.storage.delete(f"mfa:{username}")
        logger.info(f"MFA disabled for user: {username}")
    
    async def regenerate_backup_codes(self, username: str) -> List[str]:
        """
        Regenerate backup codes for a user.
        """
        mfa_data = await self.storage.hgetall(f"mfa:{username}")
        
        if not mfa_data or mfa_data.get("enabled") != "true":
            raise MFAError("MFA not enabled for this user")
        
        # Generate new backup codes
        backup_codes = [secrets.token_hex(4).upper() for _ in range(self.backup_codes_count)]
        
        await self.storage.hset(
            f"mfa:{username}", 
            {"backup_codes": ",".join(backup_codes)}
        )
        
        logger.info(f"Backup codes regenerated for user: {username}")
        return backup_codes
    
    async def get_backup_codes_count(self, username: str) -> int:
        """
        Get remaining backup codes count.
        """
        mfa_data = await self.storage.hgetall(f"mfa:{username}")
        
        if not mfa_data:
            return 0
        
        backup_codes_str = mfa_data.get("backup_codes", "")
        if not backup_codes_str:
            return 0
        
        return len(backup_codes_str.split(","))
    
    async def is_mfa_required_for_role(self, roles: List[str]) -> bool:
        """
        Check if MFA is required for any of the user's roles.
        Currently requires MFA for admin roles.
        """
        admin_roles = {"admin", "super_admin", "system_admin"}
        return bool(set(roles) & admin_roles)
    
    def generate_qr_code_image(self, qr_code_url: str) -> bytes:
        """
        Generate QR code image as bytes.
        """
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_code_url)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        img_buffer = BytesIO()
        img.save(img_buffer, format='PNG')
        return img_buffer.getvalue()


# Global MFA manager instance
mfa_manager: Optional[MFAManager] = None


def initialize_mfa_manager(storage: StorageInterface, app_name: str = "Trading Terminal RBAC"):
    """Initialize MFA manager with storage."""
    global mfa_manager
    if MFA_AVAILABLE:
        mfa_manager = MFAManager(storage, app_name)
        logger.info("MFA manager initialized")
    else:
        logger.warning("MFA dependencies not available. MFA features disabled.")


def get_mfa_manager() -> Optional[MFAManager]:
    """Get MFA manager instance."""
    return mfa_manager 