"""Enhanced User-related Pydantic models with strong validation."""
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field, validator


class UserCreate(BaseModel):
    """User creation request model with enhanced password validation."""
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(..., min_length=12, max_length=128)
    
    @validator('password')
    def validate_password_complexity(cls, v):
        """Basic client-side password complexity validation."""
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


class PasswordStrengthResponse(BaseModel):
    """Password strength assessment response."""
    score: int = Field(..., ge=0, le=100)
    strength: str
    feedback: List[str]


class UserResponse(BaseModel):
    """User response model."""
    username: str
    roles: List[str] = []
    is_active: bool
    created_at: datetime


class RoleCreate(BaseModel):
    """Role creation request model."""
    name: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    description: str = Field(default="", max_length=255)
    parent_roles: List[str] = Field(default=[], description="Roles to inherit permissions from")


class PermissionCreate(BaseModel):
    """Permission creation request model."""
    name: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9:_-]+$")
    description: str = Field(default="", max_length=255)


class AssignRole(BaseModel):
    """Role assignment request model."""
    username: str
    role_name: str


class AssignPermission(BaseModel):
    """Permission assignment request model."""
    role_name: str
    permission_name: str 