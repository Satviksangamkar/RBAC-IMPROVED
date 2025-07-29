"""Application configuration settings."""
import os
from typing import List, Dict, Any
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Security settings
SECRET_KEY = os.getenv("SECRET_KEY", "your-strong-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Password hashing settings
BCRYPT_ROUNDS = 12

# Redis configurations
REDIS_CONFIGS = [
    {
        "host": os.getenv("REDIS_HOST", "localhost"),
        "port": int(os.getenv("REDIS_PORT", 6379)),
        "username": os.getenv("REDIS_USERNAME", "") or None,
        "password": os.getenv("REDIS_PASSWORD", "") or None,
    }
]

# Casbin model configuration
CASBIN_MODEL = '''
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
'''

# Default role configurations
DEFAULT_ROLES: Dict[str, Dict[str, Any]] = {
    "viewer": {
        "description": "Can view market data and account information",
        "permissions": ["market:read", "account:read"]
    },
    "trader": {
        "description": "Can execute trades and manage orders",
        "permissions": ["trade:execute", "order:create", "order:delete"],
        "parent_roles": ["viewer"]
    },
    "admin": {
        "description": "Full system access",
        "permissions": [
            "user:create", "user:read", "user:update", "user:delete",
            "role:create", "role:read", "role:update", "role:delete", "role:assign",
            "permission:create", "permission:read", "permission:update", "permission:delete", "permission:assign"
        ],
        "parent_roles": ["trader"]
    }
}

# CORS settings
CORS_ORIGINS = ["*"]
CORS_CREDENTIALS = True
CORS_METHODS = ["*"]
CORS_HEADERS = ["*"]

# Application metadata
APP_TITLE = "Trading Terminal RBAC API with Casbin"
APP_DESCRIPTION = "Role-Based Access Control for Trading Platform using Casbin"
APP_VERSION = "2.0.0"

# Logging configuration
LOG_LEVEL = "INFO"

# Background task settings
TOKEN_CLEANUP_INTERVAL = 3600  # 1 hour in seconds 