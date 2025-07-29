"""Authentication-related Pydantic models."""
from typing import List, Optional
from pydantic import BaseModel, Field, validator


class Token(BaseModel):
    """JWT token response model."""
    access_token: str
    refresh_token: str
    token_type: str
    access_token_expires_in: int
    refresh_token_expires_in: int


class TokenData(BaseModel):
    """Token payload data model."""
    username: str
    roles: List[str] = []
    permissions: List[str] = []


class RefreshTokenRequest(BaseModel):
    """Refresh token request model."""
    refresh_token: str


class PasswordChange(BaseModel):
    """Password change request model with enhanced validation."""
    current_password: str
    new_password: str = Field(..., min_length=12, max_length=128)
    
    @validator('new_password')
    def validate_new_password_complexity(cls, v):
        """Enhanced password complexity validation."""
        import re
        
        errors = []
        
        if len(v) < 12:
            errors.append("Password must be at least 12 characters long")
        
        if not re.search(r'[a-z]', v):
            errors.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'[A-Z]', v):
            errors.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'\d', v):
            errors.append("Password must contain at least one digit")
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?`~]', v):
            errors.append("Password must contain at least one special character")
        
        if errors:
            raise ValueError(". ".join(errors))
        
        return v


class MFASetupRequest(BaseModel):
    """MFA setup request model."""
    method: str = Field(..., pattern=r"^(totp|sms)$")


class MFASetupResponse(BaseModel):
    """MFA setup response model."""
    secret: str
    qr_code_url: str
    backup_codes: List[str]


class MFAVerifyRequest(BaseModel):
    """MFA verification request model."""
    code: str = Field(..., min_length=6, max_length=8, pattern=r"^\d+$")


class LoginWithMFARequest(BaseModel):
    """Login request with MFA support."""
    username: str
    password: str
    mfa_code: Optional[str] = Field(None, min_length=6, max_length=8, pattern=r"^\d+$") 