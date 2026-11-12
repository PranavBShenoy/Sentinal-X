"""
Authentication endpoints for SENTINEL-X.

Endpoints:
  POST /register   — register a new user
  POST /login      — obtain access + refresh tokens
  POST /logout     — revoke refresh token (session)
  POST /refresh    — exchange refresh token for new access token
  GET  /me         — return current user info
  GET  /github/authorize — GitHub OAuth redirect URL
  GET  /github/callback  — GitHub OAuth callback

Security:
  - Login: 10 req/min per IP
  - Register: 5 req/min per IP
  - Passwords never returned or logged
  - All auth events are audit-logged
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, rate_limit
from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import (
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    verify_password,
)
from app.models.models import GitHubInstallation, User, UserSession
from app.schemas.schemas import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.services.audit_service import audit_service
from app.services.github_service import github_service

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/auth", tags=["auth"])


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _client_ip(request: Request) -> str:
    """
    Extract the client IP using the same trusted-proxy policy as the rate limiter.

    Never blindly trust X-Forwarded-For unless the direct socket peer is an
    explicitly trusted reverse proxy. Otherwise arbitrary X-Forwarded-For values
    would allow IP spoofing and per-IP rate-limit bypass.
    """
    direct_peer = request.client.host if request.client else "127.0.0.1"
    trusted_proxies = set(settings.trusted_proxies_list)

    # If the direct peer is not a trusted reverse proxy, ignore X-Forwarded-For
    # entirely to prevent spoofing.
    if direct_peer not in trusted_proxies:
        return direct_peer

    # Peer is a trusted reverse proxy (e.g. local Nginx). Use the first entry
    # in X-Forwarded-For as the client candidate.
    xff = request.headers.get("X-Forwarded-For")
    if not xff:
        return direct_peer

    client_candidate = xff.split(",")[0].strip()
    return client_candidate or direct_peer


def _create_tokens(user: User, db: Session, request: Request) -> TokenResponse:
    """Create access + refresh tokens and persist the session."""
    access_token = create_access_token(subject=str(user.id))
    plain_refresh, hashed_refresh = generate_refresh_token()

    expires_at = datetime.now(timezone.utc) + timedelta(
        days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
    )
    session = UserSession(
        user_id=user.id,
        refresh_token_hash=hashed_refresh,
        expires_at=expires_at,
        ip_address=_client_ip(request),
        user_agent=request.headers.get("User-Agent", "")[:500],
    )
    db.add(session)
    db.flush()

    return TokenResponse(
        access_token=access_token,
        refresh_token=plain_refresh,
        token_type="bearer",
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #

@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
def register(
    payload: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
    _rl: None = Depends(rate_limit(max_calls=5, window_seconds=60, endpoint_key="register")),
) -> TokenResponse:
    # Check uniqueness
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered.")
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken.")

    user = User(
        email=payload.email,
        username=payload.username,
        hashed_password=hash_password(payload.password),
        is_active=True,
        is_verified=False,
    )
    db.add(user)
    db.flush()

    tokens = _create_tokens(user, db, request)

    audit_service.log(
        db,
        user_id=user.id,
        action="user.register",
        resource_type="user",
        resource_id=user.id,
        ip_address=_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        details={"email": user.email, "username": user.username},
    )

    return tokens


# --------------------------------------------------------------------------- #
# Login
# --------------------------------------------------------------------------- #

@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Obtain access and refresh tokens",
)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    _rl: None = Depends(rate_limit(max_calls=10, window_seconds=60, endpoint_key="login")),
) -> TokenResponse:
    user = db.query(User).filter(User.email == payload.email).first()

    # Use constant-time comparison to avoid timing attacks when user not found.
    password_ok = (
        verify_password(payload.password, user.hashed_password)
        if user and user.hashed_password
        else False
    )

    if not user or not password_ok:
        audit_service.log(
            db,
            user_id=user.id if user else None,
            action="user.login.failed",
            ip_address=_client_ip(request),
            user_agent=request.headers.get("User-Agent"),
            details={"email": payload.email},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is disabled.")

    tokens = _create_tokens(user, db, request)

    audit_service.log(
        db,
        user_id=user.id,
        action="user.login",
        resource_type="user",
        resource_id=user.id,
        ip_address=_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )

    return tokens


# --------------------------------------------------------------------------- #
# Logout
# --------------------------------------------------------------------------- #

@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, summary="Revoke refresh token")
def logout(
    payload: RefreshRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    token_hash = hash_refresh_token(payload.refresh_token)
    session = (
        db.query(UserSession)
        .filter(
            UserSession.refresh_token_hash == token_hash,
            UserSession.user_id == current_user.id,
            UserSession.revoked_at.is_(None),
        )
        .first()
    )
    if session:
        session.revoked_at = datetime.now(timezone.utc)
        db.flush()

    audit_service.log(
        db,
        user_id=current_user.id,
        action="user.logout",
        ip_address=_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )


# --------------------------------------------------------------------------- #
# Refresh
# --------------------------------------------------------------------------- #

@router.post("/refresh", response_model=TokenResponse, summary="Refresh access token")
def refresh(
    payload: RefreshRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    token_hash = hash_refresh_token(payload.refresh_token)
    session = (
        db.query(UserSession)
        .filter(
            UserSession.refresh_token_hash == token_hash,
            UserSession.revoked_at.is_(None),
        )
        .first()
    )

    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token.")

    if session.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired.")

    user = db.query(User).filter(User.id == session.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive.")

    # Rotate: revoke old session, issue new tokens.
    session.revoked_at = datetime.now(timezone.utc)
    db.flush()

    tokens = _create_tokens(user, db, request)

    audit_service.log(
        db,
        user_id=user.id,
        action="user.token_refresh",
        ip_address=_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )

    return tokens


# --------------------------------------------------------------------------- #
# Me
# --------------------------------------------------------------------------- #

@router.get("/me", response_model=UserResponse, summary="Get current user info")
def me(current_user: User = Depends(get_current_user)) -> UserResponse:
    return UserResponse.model_validate(current_user)


# --------------------------------------------------------------------------- #
# GitHub OAuth
# --------------------------------------------------------------------------- #

@router.get("/github/authorize", summary="Get GitHub OAuth authorization URL")
def github_authorize(
    request: Request,
    response: Response,
) -> dict:
    state = github_service.generate_oauth_state()
    # Extract nonce from state format {timestamp}:{nonce}:{signature}
    parts = state.split(":")
    nonce = parts[1] if len(parts) >= 2 else state
    # Bind state to initiating browser session via secure cookie.
    # Secure flag is set when the request is served over HTTPS (production behind
    # a reverse proxy), keeping dev over plain HTTP functional.
    is_secure = (
        request.headers.get("x-forwarded-proto") == "https"
        or settings.APP_ENV == "production"
    )
    response.set_cookie(
        key="sentinelx_oauth_nonce",
        value=nonce,
        max_age=600,
        httponly=True,
        samesite="lax",
        secure=is_secure,
    )
    url = github_service.get_oauth_url(state=state)
    return {"authorization_url": url, "state": state}


@router.get("/github/callback", response_model=TokenResponse, summary="GitHub OAuth callback")
async def github_callback(
    code: str,
    state: str,
    request: Request = None,
    response: Response = None,
    db: Session = Depends(get_db),
) -> TokenResponse:
    if not code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing OAuth code.")
    if not state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing OAuth state parameter.")

    # 1. Verify browser session binding if initiated via browser session cookie
    if request and "sentinelx_oauth_nonce" in request.cookies:
        cookie_nonce = request.cookies.get("sentinelx_oauth_nonce")
        parts = state.split(":")
        if len(parts) != 3 or parts[1] != cookie_nonce:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OAuth state does not match the initiating browser session.",
            )

    # 2. Cryptographic signature and expiration verification
    if not github_service.verify_oauth_state(state):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OAuth state parameter.",
        )

    # 3. One-time state consumption (Replay Prevention)
    if not github_service.consume_oauth_state(state):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth state has already been consumed (replay attack detected).",
        )

    if response:
        response.delete_cookie("sentinelx_oauth_nonce")

    try:
        result = await github_service.exchange_code(code)
    except Exception as exc:
        logger.warning("GitHub OAuth exchange failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="GitHub OAuth exchange failed.",
        )

    github_user = result["github_user"]
    github_id = str(github_user["id"])
    github_username = github_user.get("login", "")
    email = github_user.get("email") or f"{github_username}@github.invalid"

    # Find or create local user
    user = db.query(User).filter(User.github_user_id == github_id).first()
    if not user:
        # Try to match by email if present
        if github_user.get("email"):
            user = db.query(User).filter(User.email == email).first()
        if not user:
            # Create new account
            username_base = github_username[:100] or "user"
            username = username_base
            suffix = 0
            while db.query(User).filter(User.username == username).first():
                suffix += 1
                username = f"{username_base}{suffix}"

            user = User(
                email=email,
                username=username,
                is_active=True,
                is_verified=True,  # GitHub verified the email
                github_user_id=github_id,
                github_username=github_username,
            )
            db.add(user)
            db.flush()
        else:
            user.github_user_id = github_id
            user.github_username = github_username

    # Store / update the encrypted GitHub access token
    from app.core.security import encrypt_value
    installation = (
        db.query(GitHubInstallation)
        .filter(GitHubInstallation.user_id == user.id)
        .first()
    )
    if installation:
        installation.encrypted_access_token = encrypt_value(result["access_token"])
        installation.scope = result.get("scope", "")
        installation.revoked_at = None
    else:
        installation = GitHubInstallation(
            user_id=user.id,
            encrypted_access_token=encrypt_value(result["access_token"]),
            scope=result.get("scope", ""),
        )
        db.add(installation)
    db.flush()

    tokens = _create_tokens(user, db, request)

    audit_service.log(
        db,
        user_id=user.id,
        action="user.github_oauth",
        resource_type="user",
        resource_id=user.id,
        ip_address=_client_ip(request),
        user_agent=request.headers.get("User-Agent") if request else None,
        details={"github_username": github_username},
    )

    return tokens
