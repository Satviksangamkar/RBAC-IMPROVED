"""Comprehensive Error Handling and Exception Management."""
import logging
import traceback
import uuid
from datetime import datetime
from typing import Dict, Any, Optional
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import ValidationError

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Exception for security-related errors."""
    pass


class AuthenticationError(Exception):
    """Exception for authentication failures."""
    pass


class AuthorizationError(Exception):
    """Exception for authorization failures."""
    pass


class ResourceNotFoundError(Exception):
    """Exception for missing resources."""
    pass


class RateLimitError(Exception):
    """Exception for rate limiting violations."""
    pass


class ServiceUnavailableError(Exception):
    """Exception for service unavailability."""
    pass


class ErrorResponse:
    """Standardized error response format."""
    
    def __init__(self, 
                 error_code: str,
                 message: str,
                 details: Optional[str] = None,
                 request_id: Optional[str] = None,
                 timestamp: Optional[datetime] = None):
        self.error_code = error_code
        self.message = message
        self.details = details
        self.request_id = request_id or str(uuid.uuid4())
        self.timestamp = timestamp or datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON response."""
        response = {
            "error": {
                "code": self.error_code,
                "message": self.message,
                "request_id": self.request_id,
                "timestamp": self.timestamp.isoformat() + "Z"
            }
        }
        if self.details:
            response["error"]["details"] = self.details
        return response


class ErrorLogger:
    """Centralized error logging with security considerations."""
    
    @staticmethod
    def log_error(error: Exception, request: Request, user_id: Optional[str] = None):
        """Log error with context while maintaining security."""
        error_id = str(uuid.uuid4())
        
        # Create sanitized context
        context = {
            "error_id": error_id,
            "error_type": type(error).__name__,
            "error_message": str(error),
            "method": request.method,
            "url": str(request.url),
            "user_agent": request.headers.get("user-agent", "Unknown"),
            "ip_address": request.client.host if request.client else "Unknown",
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        if user_id:
            context["user_id"] = user_id
        
        # Log the full stack trace internally
        logger.error(
            f"Error {error_id}: {context}",
            exc_info=True,
            extra={"error_context": context}
        )
        
        return error_id
    
    @staticmethod
    def log_security_event(event_type: str, details: Dict[str, Any], request: Request):
        """Log security-related events."""
        event_id = str(uuid.uuid4())
        
        security_context = {
            "event_id": event_id,
            "event_type": event_type,
            "details": details,
            "method": request.method,
            "url": str(request.url),
            "user_agent": request.headers.get("user-agent", "Unknown"),
            "ip_address": request.client.host if request.client else "Unknown",
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        logger.warning(
            f"Security Event {event_id}: {event_type}",
            extra={"security_context": security_context}
        )
        
        return event_id


def setup_error_handlers(app: FastAPI):
    """Setup comprehensive error handlers for the FastAPI application."""
    
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Handle HTTP exceptions with consistent formatting."""
        error_id = ErrorLogger.log_error(exc, request)
        
        # Map HTTP status codes to error codes
        error_code_map = {
            400: "BAD_REQUEST",
            401: "UNAUTHORIZED", 
            403: "FORBIDDEN",
            404: "NOT_FOUND",
            405: "METHOD_NOT_ALLOWED",
            409: "CONFLICT",
            422: "VALIDATION_ERROR",
            429: "RATE_LIMITED",
            500: "INTERNAL_ERROR",
            502: "BAD_GATEWAY",
            503: "SERVICE_UNAVAILABLE",
            504: "GATEWAY_TIMEOUT"
        }
        
        error_code = error_code_map.get(exc.status_code, "HTTP_ERROR")
        
        error_response = ErrorResponse(
            error_code=error_code,
            message=exc.detail,
            request_id=error_id
        )
        
        return JSONResponse(
            status_code=exc.status_code,
            content=error_response.to_dict()
        )
    
    @app.exception_handler(StarletteHTTPException)
    async def starlette_exception_handler(request: Request, exc: StarletteHTTPException):
        """Handle Starlette HTTP exceptions."""
        error_id = ErrorLogger.log_error(exc, request)
        
        error_response = ErrorResponse(
            error_code="HTTP_ERROR",
            message="An error occurred processing your request",
            request_id=error_id
        )
        
        return JSONResponse(
            status_code=exc.status_code,
            content=error_response.to_dict()
        )
    
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        """Handle Pydantic validation errors."""
        error_id = ErrorLogger.log_error(exc, request)
        
        # Create user-friendly validation error messages
        error_details = []
        for error in exc.errors():
            field = " -> ".join(str(loc) for loc in error["loc"])
            message = error["msg"]
            error_details.append(f"{field}: {message}")
        
        error_response = ErrorResponse(
            error_code="VALIDATION_ERROR",
            message="Request validation failed",
            details="; ".join(error_details),
            request_id=error_id
        )
        
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=error_response.to_dict()
        )
    
    @app.exception_handler(AuthenticationError)
    async def authentication_exception_handler(request: Request, exc: AuthenticationError):
        """Handle authentication errors."""
        error_id = ErrorLogger.log_security_event(
            "AUTHENTICATION_FAILURE",
            {"reason": str(exc)},
            request
        )
        
        error_response = ErrorResponse(
            error_code="AUTHENTICATION_FAILED",
            message="Authentication failed",
            request_id=error_id
        )
        
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=error_response.to_dict(),
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    @app.exception_handler(AuthorizationError)
    async def authorization_exception_handler(request: Request, exc: AuthorizationError):
        """Handle authorization errors."""
        error_id = ErrorLogger.log_security_event(
            "AUTHORIZATION_FAILURE",
            {"reason": str(exc)},
            request
        )
        
        error_response = ErrorResponse(
            error_code="INSUFFICIENT_PERMISSIONS",
            message="Insufficient permissions to access this resource",
            request_id=error_id
        )
        
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=error_response.to_dict()
        )
    
    @app.exception_handler(ResourceNotFoundError)
    async def resource_not_found_exception_handler(request: Request, exc: ResourceNotFoundError):
        """Handle resource not found errors."""
        error_id = ErrorLogger.log_error(exc, request)
        
        error_response = ErrorResponse(
            error_code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found",
            request_id=error_id
        )
        
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=error_response.to_dict()
        )
    
    @app.exception_handler(RateLimitError)
    async def rate_limit_exception_handler(request: Request, exc: RateLimitError):
        """Handle rate limiting errors."""
        error_id = ErrorLogger.log_security_event(
            "RATE_LIMIT_EXCEEDED",
            {"reason": str(exc)},
            request
        )
        
        error_response = ErrorResponse(
            error_code="RATE_LIMITED",
            message="Rate limit exceeded. Please try again later",
            request_id=error_id
        )
        
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content=error_response.to_dict(),
            headers={"Retry-After": "60"}
        )
    
    @app.exception_handler(ServiceUnavailableError)
    async def service_unavailable_exception_handler(request: Request, exc: ServiceUnavailableError):
        """Handle service unavailable errors."""
        error_id = ErrorLogger.log_error(exc, request)
        
        error_response = ErrorResponse(
            error_code="SERVICE_UNAVAILABLE",
            message="Service temporarily unavailable. Please try again later",
            request_id=error_id
        )
        
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=error_response.to_dict(),
            headers={"Retry-After": "300"}
        )
    
    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        """Handle all other unhandled exceptions."""
        error_id = ErrorLogger.log_error(exc, request)
        
        # Never expose internal errors to clients
        error_response = ErrorResponse(
            error_code="INTERNAL_ERROR",
            message="An internal error occurred. Please try again later",
            request_id=error_id
        )
        
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_response.to_dict()
        )


def create_http_exception(status_code: int, message: str, details: Optional[str] = None) -> HTTPException:
    """Create standardized HTTP exception."""
    return HTTPException(
        status_code=status_code,
        detail=message
    )


def validate_and_raise(condition: bool, status_code: int, message: str):
    """Validate condition and raise HTTPException if false."""
    if not condition:
        raise create_http_exception(status_code, message)


# Common error factory functions
def create_authentication_error(message: str = "Authentication failed") -> AuthenticationError:
    """Create authentication error."""
    return AuthenticationError(message)


def create_authorization_error(message: str = "Insufficient permissions") -> AuthorizationError:
    """Create authorization error."""
    return AuthorizationError(message)


def create_resource_not_found_error(resource: str) -> ResourceNotFoundError:
    """Create resource not found error."""
    return ResourceNotFoundError(f"{resource} not found")


def create_rate_limit_error(message: str = "Rate limit exceeded") -> RateLimitError:
    """Create rate limit error."""
    return RateLimitError(message)


def create_service_unavailable_error(service: str) -> ServiceUnavailableError:
    """Create service unavailable error."""
    return ServiceUnavailableError(f"{service} is currently unavailable") 