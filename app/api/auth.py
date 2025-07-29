"""Enhanced Authentication API routes with MFA support."""
import logging
from datetime import timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse, Response, StreamingResponse
from io import BytesIO

from app.config import ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS
from app.core.storage import StorageInterface
from app.core.security import (
    authenticate_user, get_user_permissions, create_access_token, 
    create_refresh_token, store_refresh_token, validate_refresh_token,
    revoke_refresh_token, revoke_all_user_refresh_tokens, 
    verify_password, get_password_hash, get_password_manager
)
from app.core.mfa_manager import get_mfa_manager, MFAError
from app.core.error_handling import (
    create_authentication_error, create_authorization_error,
    AuthenticationError, AuthorizationError
)
from app.dependencies import get_storage, get_current_user, get_refresh_token, get_enforcer
from app.models.auth import (
    Token, RefreshTokenRequest, PasswordChange, 
    MFASetupRequest, MFASetupResponse, MFAVerifyRequest, LoginWithMFARequest
)
from app.models.user import UserResponse, PasswordStrengthResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _create_token_response(access_token: str, refresh_token: str, 
                          access_expires: timedelta, refresh_expires: timedelta) -> JSONResponse:
    """Create standardized token response with cookies."""
    token_data = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "access_token_expires_in": int(access_expires.total_seconds()),
        "refresh_token_expires_in": int(refresh_expires.total_seconds())
    }
    
    response = JSONResponse(content=token_data)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,  # Set to False for localhost testing
        samesite="lax",
        max_age=int(refresh_expires.total_seconds()),
        path="/refresh-token"  # Fixed path to match optimized endpoints
    )
    return response


async def _create_tokens_for_user(username: str, storage: StorageInterface):
    """Create access and refresh tokens for a user."""
    # Get user permissions
    enforcer = get_enforcer()
    permissions = await get_user_permissions(storage, username, enforcer)
    
    # Create tokens
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": username,
            "permissions": list(permissions)
        },
        expires_delta=access_token_expires
    )
    
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token, token_id = create_refresh_token(
        username=username,
        expires_delta=refresh_token_expires
    )
    
    # Store refresh token
    await store_refresh_token(
        storage=storage,
        username=username,
        token_id=token_id,
        expires_delta=refresh_token_expires
    )
    
    return access_token, refresh_token, access_token_expires, refresh_token_expires


@router.post("/login", response_model=Token)
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    storage: StorageInterface = Depends(get_storage)
):
    """Enhanced login with username and password, supporting MFA."""
    try:
        user = await authenticate_user(form_data.username, form_data.password, storage, request)
        if not user:
            raise create_authentication_error("Incorrect username or password")

        # Check if MFA is required for this user's roles
        mfa_manager = get_mfa_manager()
        if mfa_manager and await mfa_manager.is_mfa_required_for_role(user.roles):
            # Check if MFA is enabled for user
            if await mfa_manager.is_mfa_enabled(user.username):
                # Return partial success - MFA required
                return JSONResponse(
                    status_code=status.HTTP_202_ACCEPTED,
                    content={
                        "message": "MFA verification required",
                        "mfa_required": True,
                        "username": user.username
                    }
                )

        # Create tokens (no MFA required or MFA not enabled)
        access_token, refresh_token, access_expires, refresh_expires = await _create_tokens_for_user(
            user.username, storage
        )
        
        return _create_token_response(access_token, refresh_token, access_expires, refresh_expires)
        
    except (AuthenticationError, AuthorizationError) as e:
        raise e
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise create_authentication_error("Authentication failed")


@router.post("/login-mfa", response_model=Token)
async def login_with_mfa(
    request: Request,
    login_data: LoginWithMFARequest,
    storage: StorageInterface = Depends(get_storage)
):
    """Login with username, password, and MFA code."""
    try:
        # Authenticate user first
        user = await authenticate_user(login_data.username, login_data.password, storage, request)
        if not user:
            raise create_authentication_error("Incorrect username or password")

        mfa_manager = get_mfa_manager()
        if not mfa_manager:
            raise create_authentication_error("MFA not available")

        # Verify MFA code
        if not login_data.mfa_code:
            raise create_authentication_error("MFA code is required")

        if not await mfa_manager.verify_code(user.username, login_data.mfa_code):
            raise create_authentication_error("Invalid MFA code")

        # Create tokens
        access_token, refresh_token, access_expires, refresh_expires = await _create_tokens_for_user(
            user.username, storage
        )
        
        return _create_token_response(access_token, refresh_token, access_expires, refresh_expires)
        
    except (AuthenticationError, AuthorizationError, MFAError) as e:
        raise create_authentication_error(str(e))
    except Exception as e:
        logger.error(f"MFA login error: {e}")
        raise create_authentication_error("Authentication failed")


@router.post("/refresh-token", response_model=Token)
async def refresh_token(
    request: Request,
    refresh_token_request: Optional[RefreshTokenRequest] = None,
    storage: StorageInterface = Depends(get_storage)
):
    """Refresh access token using a valid refresh token."""
    # Get and validate refresh token
    token = await get_refresh_token(request, refresh_token_request)
    result = await validate_refresh_token(token, storage)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    username, token_id = result
    
    # Revoke the used refresh token for security
    await revoke_refresh_token(storage, username, token_id)
    
    # Create new tokens
    access_token, refresh_token, access_expires, refresh_expires = await _create_tokens_for_user(
        username, storage
    )
    
    return _create_token_response(access_token, refresh_token, access_expires, refresh_expires)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    refresh_token_request: Optional[RefreshTokenRequest] = None,
    current_user: UserResponse = Depends(get_current_user),
    storage: StorageInterface = Depends(get_storage)
):
    """Logout by revoking the refresh token."""
    try:
        token = await get_refresh_token(request, refresh_token_request)
        result = await validate_refresh_token(token, storage)
        if result:
            username, token_id = result
            # Only allow users to revoke their own tokens
            if username == current_user.username:
                await revoke_refresh_token(storage, username, token_id)
    except HTTPException:
        pass  # Continue even if no refresh token found
    
    # Clear the refresh token cookie - using Response for 204 status
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(key="refresh_token", path="/refresh-token")  # Fixed path
    return response


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all_sessions(
    current_user: UserResponse = Depends(get_current_user),
    storage: StorageInterface = Depends(get_storage)
):
    """Logout from all devices by revoking all refresh tokens."""
    await revoke_all_user_refresh_tokens(storage, current_user.username)
    
    # Clear the refresh token cookie - using Response for 204 status
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(key="refresh_token", path="/refresh-token")  # Fixed path
    return response


@router.post("/change-password", status_code=status.HTTP_200_OK)
async def change_password(
    password_change: PasswordChange,
    current_user: UserResponse = Depends(get_current_user),
    storage: StorageInterface = Depends(get_storage)
):
    """Change user password and revoke all refresh tokens."""
    user_key = f"user:{current_user.username}"
    user_data = await storage.hgetall(user_key)
    
    # Verify current password
    if not verify_password(password_change.current_password, user_data.get("password", "")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect"
        )
    
    # Update password
    hashed_password = get_password_hash(password_change.new_password)
    await storage.hset(user_key, "password", hashed_password)
    
    # Revoke all refresh tokens for security
    await revoke_all_user_refresh_tokens(storage, current_user.username)
    
    # Clear the refresh token cookie
    response = JSONResponse(content={"message": "Password updated successfully"})
    response.delete_cookie(key="refresh_token", path="/refresh-token")  # Fixed path
    return response 


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    setup_request: MFASetupRequest,
    current_user: UserResponse = Depends(get_current_user),
    storage: StorageInterface = Depends(get_storage)
):
    """Setup MFA for the current user."""
    mfa_manager = get_mfa_manager()
    if not mfa_manager:
        raise create_authentication_error("MFA not available")

    try:
        if setup_request.method == "totp":
            secret, qr_code_url, backup_codes = await mfa_manager.setup_totp(current_user.username)
            
            return MFASetupResponse(
                secret=secret,
                qr_code_url=qr_code_url,
                backup_codes=backup_codes
            )
        else:
            raise create_authentication_error("Unsupported MFA method")
            
    except Exception as e:
        logger.error(f"MFA setup error: {e}")
        raise create_authentication_error("Failed to setup MFA")


@router.post("/mfa/verify-setup")
async def verify_mfa_setup(
    verify_request: MFAVerifyRequest,
    current_user: UserResponse = Depends(get_current_user),
    storage: StorageInterface = Depends(get_storage)
):
    """Verify MFA setup and enable MFA for the user."""
    mfa_manager = get_mfa_manager()
    if not mfa_manager:
        raise create_authentication_error("MFA not available")

    try:
        if await mfa_manager.verify_setup(current_user.username, verify_request.code):
            return {"message": "MFA enabled successfully"}
        else:
            raise create_authentication_error("Invalid verification code")
            
    except MFAError as e:
        raise create_authentication_error(str(e))
    except Exception as e:
        logger.error(f"MFA verification error: {e}")
        raise create_authentication_error("Failed to verify MFA")


@router.delete("/mfa/disable")
async def disable_mfa(
    current_user: UserResponse = Depends(get_current_user),
    storage: StorageInterface = Depends(get_storage)
):
    """Disable MFA for the current user."""
    mfa_manager = get_mfa_manager()
    if not mfa_manager:
        raise create_authentication_error("MFA not available")

    try:
        await mfa_manager.disable_mfa(current_user.username)
        return {"message": "MFA disabled successfully"}
        
    except Exception as e:
        logger.error(f"MFA disable error: {e}")
        raise create_authentication_error("Failed to disable MFA")


@router.post("/mfa/regenerate-backup-codes")
async def regenerate_backup_codes(
    current_user: UserResponse = Depends(get_current_user),
    storage: StorageInterface = Depends(get_storage)
):
    """Regenerate backup codes for the current user."""
    mfa_manager = get_mfa_manager()
    if not mfa_manager:
        raise create_authentication_error("MFA not available")

    try:
        backup_codes = await mfa_manager.regenerate_backup_codes(current_user.username)
        return {"backup_codes": backup_codes}
        
    except MFAError as e:
        raise create_authentication_error(str(e))
    except Exception as e:
        logger.error(f"Backup codes regeneration error: {e}")
        raise create_authentication_error("Failed to regenerate backup codes")


@router.get("/mfa/qr-code")
async def get_mfa_qr_code(
    current_user: UserResponse = Depends(get_current_user),
    storage: StorageInterface = Depends(get_storage)
):
    """Get MFA QR code image for the current user."""
    mfa_manager = get_mfa_manager()
    if not mfa_manager:
        raise create_authentication_error("MFA not available")

    try:
        # Get the MFA data to retrieve the secret
        mfa_data = await storage.hgetall(f"mfa:{current_user.username}")
        if not mfa_data or not mfa_data.get("secret"):
            raise create_authentication_error("MFA not set up")

        import pyotp
        totp = pyotp.TOTP(mfa_data["secret"])
        qr_code_url = totp.provisioning_uri(
            name=current_user.username,
            issuer_name="Trading Terminal RBAC"
        )
        
        qr_image = mfa_manager.generate_qr_code_image(qr_code_url)
        
        return StreamingResponse(
            BytesIO(qr_image),
            media_type="image/png",
            headers={"Content-Disposition": "inline; filename=mfa-qr-code.png"}
        )
        
    except Exception as e:
        logger.error(f"QR code generation error: {e}")
        raise create_authentication_error("Failed to generate QR code")


@router.post("/password/check-strength", response_model=PasswordStrengthResponse)
async def check_password_strength(
    password_data: dict,
    storage: StorageInterface = Depends(get_storage)
):
    """Check password strength and provide feedback."""
    password = password_data.get("password", "")
    
    password_manager = get_password_manager()
    strength_info = password_manager.calculate_password_strength(password)
    
    return PasswordStrengthResponse(
        score=strength_info["score"],
        strength=strength_info["strength"],
        feedback=strength_info["feedback"]
    )


@router.post("/password/validate-policy")
async def validate_password_policy(
    password_data: dict,
    current_user: Optional[UserResponse] = Depends(get_current_user),
    storage: StorageInterface = Depends(get_storage)
):
    """Validate password against comprehensive security policy."""
    password = password_data.get("password", "")
    username = current_user.username if current_user else None
    
    password_manager = get_password_manager()
    violations = await password_manager.validate_password_policy(password, username)
    
    if violations:
        return {
            "valid": False,
            "violations": violations
        }
    else:
        return {
            "valid": True,
            "message": "Password meets all security requirements"
        } 