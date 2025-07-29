"""Advanced Password Management with Strong Security Policies."""
import re
import logging
import hashlib
from typing import List, Set, Optional
from datetime import datetime, timedelta

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, HashingError
    ARGON2_AVAILABLE = True
except ImportError:
    from passlib.context import CryptContext
    ARGON2_AVAILABLE = False

from app.core.storage import StorageInterface

logger = logging.getLogger(__name__)


class PasswordPolicyError(Exception):
    """Exception raised for password policy violations."""
    pass


class PasswordManager:
    """Advanced password manager with strong security policies."""
    
    def __init__(self, storage: StorageInterface):
        self.storage = storage
        
        if ARGON2_AVAILABLE:
            # Use Argon2id with high security parameters
            self.ph = PasswordHasher(
                time_cost=3,      # Number of iterations
                memory_cost=65536,  # Memory usage in KiB (64 MB)
                parallelism=1,    # Number of parallel threads
                hash_len=32,      # Hash output length
                salt_len=16       # Salt length
            )
            logger.info("Using Argon2id for password hashing")
        else:
            # Fallback to bcrypt with high rounds
            self.pwd_context = CryptContext(
                schemes=["bcrypt"], 
                deprecated="auto", 
                bcrypt__rounds=14
            )
            logger.warning("Argon2id not available, using bcrypt with 14 rounds")
        
        # Common weak passwords (sample - in production use HaveIBeenPwned API)
        self.common_passwords = {
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "1234567890", "abc123",
            "password1", "123456789", "welcome123", "admin123",
            "root", "toor", "pass", "test", "guest", "user"
        }
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password using Argon2id or bcrypt fallback.
        """
        try:
            if ARGON2_AVAILABLE:
                return self.ph.hash(password)
            else:
                return self.pwd_context.hash(password)
        except Exception as e:
            logger.error(f"Password hashing failed: {e}")
            raise PasswordPolicyError("Password hashing failed")
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.
        """
        try:
            if ARGON2_AVAILABLE:
                self.ph.verify(hashed_password, password)
                return True
            else:
                return self.pwd_context.verify(password, hashed_password)
        except (VerifyMismatchError, ValueError):
            return False
        except Exception as e:
            logger.error(f"Password verification failed: {e}")
            return False
    
    def needs_rehash(self, hashed_password: str) -> bool:
        """
        Check if password hash needs to be updated.
        """
        try:
            if ARGON2_AVAILABLE:
                return self.ph.check_needs_rehash(hashed_password)
            else:
                return self.pwd_context.needs_update(hashed_password)
        except Exception:
            return True  # If in doubt, rehash
    
    async def validate_password_policy(self, password: str, username: Optional[str] = None) -> List[str]:
        """
        Validate password against comprehensive security policy.
        Returns list of policy violations.
        """
        violations = []
        
        # Length requirement (minimum 12 characters)
        if len(password) < 12:
            violations.append("Password must be at least 12 characters long")
        
        # Maximum length check (prevent DoS)
        if len(password) > 128:
            violations.append("Password must not exceed 128 characters")
        
        # Complexity requirements
        if not re.search(r'[a-z]', password):
            violations.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'[A-Z]', password):
            violations.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'\d', password):
            violations.append("Password must contain at least one digit")
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?`~]', password):
            violations.append("Password must contain at least one special character")
        
        # Check against common passwords
        if password.lower() in self.common_passwords:
            violations.append("Password is too common and easily guessable")
        
        # Check if password contains username (if provided)
        if username and username.lower() in password.lower():
            violations.append("Password must not contain username")
        
        # Check for repeated characters (more than 3 consecutive)
        if re.search(r'(.)\1{3,}', password):
            violations.append("Password must not contain more than 3 consecutive identical characters")
        
        # Check for keyboard patterns (basic check)
        keyboard_patterns = [
            "qwerty", "asdf", "zxcv", "1234", "abcd",
            "qwertyuiop", "asdfghjkl", "zxcvbnm"
        ]
        password_lower = password.lower()
        for pattern in keyboard_patterns:
            if pattern in password_lower or pattern[::-1] in password_lower:
                violations.append("Password must not contain keyboard patterns")
                break
        
        # Check against previously breached passwords (simulate)
        if await self._check_breached_password(password):
            violations.append("Password has been found in known data breaches")
        
        return violations
    
    async def _check_breached_password(self, password: str) -> bool:
        """
        Check if password appears in breach databases.
        In production, integrate with HaveIBeenPwned API.
        """
        # Simple hash-based check against stored breached passwords
        password_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        
        # Check if hash exists in our breach database
        breach_key = f"breached_passwords:{password_hash[:5]}"
        breached_hashes = await self.storage.smembers(breach_key)
        
        return password_hash in breached_hashes
    
    async def add_breached_password(self, password: str):
        """
        Add a password to the breach database (for testing/admin purposes).
        """
        password_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        breach_key = f"breached_passwords:{password_hash[:5]}"
        await self.storage.sadd(breach_key, password_hash)
    
    async def record_failed_attempt(self, identifier: str):
        """
        Record a failed password attempt for rate limiting.
        """
        key = f"failed_attempts:{identifier}"
        current_count = await self.storage.get(key)
        
        if current_count:
            await self.storage.set(key, str(int(current_count) + 1))
        else:
            await self.storage.set(key, "1")
            # Set expiry for 15 minutes
            # Note: This is a simplified implementation
            # In production, use Redis EXPIRE command
    
    async def get_failed_attempts(self, identifier: str) -> int:
        """
        Get the number of failed attempts for an identifier.
        """
        count = await self.storage.get(f"failed_attempts:{identifier}")
        return int(count) if count else 0
    
    async def clear_failed_attempts(self, identifier: str):
        """
        Clear failed attempts for an identifier.
        """
        await self.storage.delete(f"failed_attempts:{identifier}")
    
    async def is_account_locked(self, identifier: str, max_attempts: int = 5) -> bool:
        """
        Check if account is locked due to too many failed attempts.
        """
        failed_count = await self.get_failed_attempts(identifier)
        return failed_count >= max_attempts
    
    def calculate_password_strength(self, password: str) -> dict:
        """
        Calculate password strength score and provide feedback.
        """
        score = 0
        feedback = []
        
        # Length scoring
        if len(password) >= 12:
            score += 25
        elif len(password) >= 8:
            score += 15
            feedback.append("Consider using a longer password (12+ characters)")
        else:
            feedback.append("Password is too short")
        
        # Character variety scoring
        if re.search(r'[a-z]', password):
            score += 15
        else:
            feedback.append("Add lowercase letters")
        
        if re.search(r'[A-Z]', password):
            score += 15
        else:
            feedback.append("Add uppercase letters")
        
        if re.search(r'\d', password):
            score += 15
        else:
            feedback.append("Add numbers")
        
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?`~]', password):
            score += 20
        else:
            feedback.append("Add special characters")
        
        # Uniqueness scoring
        unique_chars = len(set(password))
        if unique_chars >= len(password) * 0.7:
            score += 10
        else:
            feedback.append("Avoid repetitive characters")
        
        # Determine strength level
        if score >= 85:
            strength = "Very Strong"
        elif score >= 70:
            strength = "Strong"
        elif score >= 50:
            strength = "Medium"
        elif score >= 30:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        return {
            "score": score,
            "strength": strength,
            "feedback": feedback
        } 