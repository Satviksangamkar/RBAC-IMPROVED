"""
Optimized Security Middleware for Trading Terminal RBAC System
Provides efficient security checks, rate limiting, and threat detection.
"""

import logging
import time
import hashlib
import json
from typing import Dict, Set, Optional, List, Tuple
from datetime import datetime, timedelta
from fastapi import Request, Response, HTTPException, status
from fastapi.security.utils import get_authorization_scheme_param
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import asyncio
from collections import defaultdict, deque

from app.core.storage import StorageInterface
from app.core.security import get_rbac_manager, get_password_manager
from app.core.error_handling import create_authentication_error, create_authorization_error
from app.config import SECRET_KEY, ALGORITHM
from jose import jwt, JWTError

logger = logging.getLogger(__name__)


class SecurityConfig:
    """Optimized security configuration constants."""
    
    # Rate limiting thresholds
    MAX_REQUESTS_PER_MINUTE = 60
    MAX_AUTH_ATTEMPTS_PER_HOUR = 10
    MAX_LOGIN_ATTEMPTS_PER_IP = 5
    
    # Security headers - precomputed for performance
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
    }
    
    # Protected endpoints requiring enhanced security - use set for O(1) lookup
    HIGH_SECURITY_ENDPOINTS = {
        "/auth/login", "/auth/refresh-token", "/users/", "/users/assign-role",
        "/trading/execute", "/admin/casbin-policies", "/auth/change-password"
    }
    
    # Public endpoints that don't require authentication - use set for O(1) lookup
    PUBLIC_ENDPOINTS = {
        "/", "/docs", "/openapi.json", "/admin/health", "/admin/debug-casbin",
        "/auth/password/check-strength"
    }


class OptimizedThreatDetector:
    """Optimized threat detection with caching and efficient algorithms."""
    
    def __init__(self, storage: StorageInterface):
        self.storage = storage
        # In-memory cache for performance
        self._ip_cache = {}
        self._pattern_cache = defaultdict(deque)
        self._malicious_ips = set()
        self._cache_timeout = 300  # 5 minutes
        
    async def detect_suspicious_activity(self, request: Request, user_id: Optional[str] = None) -> Dict[str, any]:
        """Optimized suspicious activity detection."""
        threats = []
        risk_score = 0
        
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")
        
        # Quick checks first (lowest cost)
        if self._is_known_malicious_ip(client_ip):
            threats.append("Known malicious IP address")
            risk_score += 50
        
        if self._detect_bot_behavior_fast(user_agent, request):
            threats.append("Bot-like behavior detected")
            risk_score += 25
        
        # More expensive checks only if needed
        if risk_score < 50:
            if await self._detect_unusual_patterns_optimized(client_ip, request.url.path):
                threats.append("Unusual request patterns detected")
                risk_score += 30
        
        return {
            "threats": threats,
            "risk_score": risk_score,
            "client_ip": client_ip,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _get_client_ip(self, request: Request) -> str:
        """Optimized client IP extraction."""
        # Check headers in order of preference
        for header in ["X-Forwarded-For", "X-Real-IP", "X-Client-IP"]:
            if header in request.headers:
                ip = request.headers[header].split(',')[0].strip()
                if ip:
                    return ip
        return request.client.host if request.client else "unknown"
    
    def _is_known_malicious_ip(self, client_ip: str) -> bool:
        """Fast malicious IP check using cached set."""
        return client_ip in self._malicious_ips
    
    def _detect_bot_behavior_fast(self, user_agent: str, request: Request) -> bool:
        """Fast bot detection using simple heuristics."""
        if not user_agent:
            return True
        
        # Common bot indicators
        bot_indicators = ["bot", "crawler", "spider", "scraper", "wget", "curl"]
        user_agent_lower = user_agent.lower()
        
        return any(indicator in user_agent_lower for indicator in bot_indicators)
    
    async def _detect_unusual_patterns_optimized(self, client_ip: str, path: str) -> bool:
        """Optimized pattern detection with sliding window."""
        current_time = time.time()
        
        # Clean old entries (sliding window)
        if client_ip in self._pattern_cache:
            # Remove entries older than 1 hour
            cutoff = current_time - 3600
            while (self._pattern_cache[client_ip] and 
                   self._pattern_cache[client_ip][0] < cutoff):
                self._pattern_cache[client_ip].popleft()
        
        # Add current request
        self._pattern_cache[client_ip].append(current_time)
        
        # Check for unusual patterns (more than 100 requests per hour)
        return len(self._pattern_cache[client_ip]) > 100


class OptimizedRateLimiter:
    """Memory-efficient rate limiter with sliding window."""
    
    def __init__(self):
        self._requests = defaultdict(deque)
        self._auth_attempts = defaultdict(deque)
        self._login_attempts = defaultdict(deque)
    
    def _clean_old_entries(self, container: deque, window_seconds: int):
        """Remove entries outside the time window."""
        cutoff = time.time() - window_seconds
        while container and container[0] < cutoff:
            container.popleft()
    
    async def check_rate_limit(self, client_ip: str, endpoint: str) -> Tuple[bool, str]:
        """Optimized rate limiting check."""
        current_time = time.time()
        
        # General rate limiting (60 requests per minute)
        self._clean_old_entries(self._requests[client_ip], 60)
        if len(self._requests[client_ip]) >= SecurityConfig.MAX_REQUESTS_PER_MINUTE:
            return False, "Rate limit exceeded: too many requests"
        
        self._requests[client_ip].append(current_time)
        
        # Authentication endpoint limiting
        if "/auth/" in endpoint:
            self._clean_old_entries(self._auth_attempts[client_ip], 3600)  # 1 hour
            if len(self._auth_attempts[client_ip]) >= SecurityConfig.MAX_AUTH_ATTEMPTS_PER_HOUR:
                return False, "Rate limit exceeded: too many auth attempts"
            
            self._auth_attempts[client_ip].append(current_time)
        
        # Login specific limiting
        if "/auth/login" in endpoint:
            self._clean_old_entries(self._login_attempts[client_ip], 300)  # 5 minutes
            if len(self._login_attempts[client_ip]) >= SecurityConfig.MAX_LOGIN_ATTEMPTS_PER_IP:
                return False, "Rate limit exceeded: too many login attempts"
            
            self._login_attempts[client_ip].append(current_time)
        
        return True, ""


class OptimizedSecurityMiddleware(BaseHTTPMiddleware):
    """Optimized security middleware with efficient processing."""
    
    def __init__(self, app, storage: StorageInterface):
        super().__init__(app)
        self.storage = storage
        self.threat_detector = OptimizedThreatDetector(storage)
        self.rate_limiter = OptimizedRateLimiter()
        self._request_count = 0
    
    async def dispatch(self, request: Request, call_next):
        """Optimized request processing with early returns."""
        start_time = time.time()
        client_ip = self.threat_detector._get_client_ip(request)
        
        try:
            # Skip security checks for public endpoints (performance optimization)
            if self._is_public_endpoint(request.url.path):
                response = await call_next(request)
                self._add_security_headers(response)
                return response
            
            # Rate limiting check
            rate_ok, rate_message = await self.rate_limiter.check_rate_limit(client_ip, request.url.path)
            if not rate_ok:
                return self._create_rate_limit_response(rate_message)
            
            # High-security endpoint checks
            if self._is_high_security_endpoint(request.url.path):
                security_result = await self._perform_enhanced_security_check(request, client_ip)
                if security_result:
                    return security_result
            
            # Process request
            response = await call_next(request)
            
            # Add security headers
            self._add_security_headers(response)
            
            # Log security metrics (async, non-blocking)
            asyncio.create_task(self._log_security_metrics(request, response, client_ip, start_time))
            
            return response
            
        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal security error"}
            )
    
    def _is_public_endpoint(self, path: str) -> bool:
        """Fast public endpoint check."""
        return path in SecurityConfig.PUBLIC_ENDPOINTS or path.startswith("/docs")
    
    def _is_high_security_endpoint(self, path: str) -> bool:
        """Fast high-security endpoint check."""
        return any(secure_path in path for secure_path in SecurityConfig.HIGH_SECURITY_ENDPOINTS)
    
    async def _perform_enhanced_security_check(self, request: Request, client_ip: str) -> Optional[Response]:
        """Enhanced security checks for sensitive endpoints."""
        # Token validation for protected endpoints
        auth_header = request.headers.get("authorization")
        if auth_header:
            try:
                scheme, token = get_authorization_scheme_param(auth_header)
                if scheme.lower() == "bearer" and token:
                    # Quick token format validation
                    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                    if payload.get("token_type") != "access":
                        return self._create_auth_error_response("Invalid token type")
            except JWTError:
                return self._create_auth_error_response("Invalid token")
        
        # Threat detection (only for very sensitive operations)
        if "/admin/" in request.url.path or "/trading/" in request.url.path:
            threat_result = await self.threat_detector.detect_suspicious_activity(request)
            if threat_result["risk_score"] > 70:
                logger.warning(f"High-risk activity detected: {threat_result}")
                return self._create_security_response("Suspicious activity detected")
        
        return None
    
    def _add_security_headers(self, response: Response):
        """Efficiently add security headers."""
        for header, value in SecurityConfig.SECURITY_HEADERS.items():
            response.headers[header] = value
    
    def _create_rate_limit_response(self, message: str) -> JSONResponse:
        """Create standardized rate limit response."""
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": message},
            headers=SecurityConfig.SECURITY_HEADERS
        )
    
    def _create_auth_error_response(self, message: str) -> JSONResponse:
        """Create standardized auth error response."""
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": message},
            headers=SecurityConfig.SECURITY_HEADERS
        )
    
    def _create_security_response(self, message: str) -> JSONResponse:
        """Create standardized security error response."""
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": message},
            headers=SecurityConfig.SECURITY_HEADERS
        )
    
    async def _log_security_metrics(self, request: Request, response: Response, client_ip: str, start_time: float):
        """Asynchronous security metrics logging."""
        try:
            processing_time = time.time() - start_time
            
            # Only log significant events to reduce overhead
            if (response.status_code >= 400 or 
                processing_time > 1.0 or 
                self._request_count % 100 == 0):
                
                logger.info(f"Security: {client_ip} {request.method} {request.url.path} "
                          f"{response.status_code} {processing_time:.3f}s")
            
            self._request_count += 1
            
        except Exception as e:
            logger.debug(f"Metrics logging error: {e}")


class OptimizedAuthenticationValidator:
    """Optimized authentication validation with caching."""
    
    def __init__(self, storage: StorageInterface):
        self.storage = storage
        self._token_cache = {}
        self._cache_timeout = 300  # 5 minutes
    
    async def validate_token_fast(self, token: str) -> Optional[dict]:
        """Fast token validation with caching."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
        
        # Check cache first
        if token_hash in self._token_cache:
            cached_data, timestamp = self._token_cache[token_hash]
            if time.time() - timestamp < self._cache_timeout:
                return cached_data
        
        # Validate token
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            
            # Cache valid token data
            self._token_cache[token_hash] = (payload, time.time())
            
            # Clean old cache entries periodically
            if len(self._token_cache) > 1000:
                self._clean_token_cache()
            
            return payload
            
        except JWTError:
        return None
    
    def _clean_token_cache(self):
        """Clean expired entries from token cache."""
        current_time = time.time()
        expired_keys = [
            key for key, (_, timestamp) in self._token_cache.items()
            if current_time - timestamp > self._cache_timeout
        ]
        for key in expired_keys:
            del self._token_cache[key] 