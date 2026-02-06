from __future__ import annotations

import base64
import hashlib
import secrets
import webbrowser
import dataclasses
import urllib.parse

import httpx

from ._types import DEFAULT_USER_AGENT, OAuthConfig, OAuthTokens
from ..._exceptions import AnthropicError


class OAuthFlowError(AnthropicError):
    pass


@dataclasses.dataclass
class OAuthState:
    code_verifier: str
    state: str


def generate_pkce() -> tuple[str, str]:
    """Generate a PKCE code verifier and code challenge pair.

    Returns a tuple of (code_verifier, code_challenge).
    """
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def build_authorization_url(config: OAuthConfig | None = None) -> tuple[str, OAuthState]:
    """Build the OAuth authorization URL with PKCE parameters.

    Returns a tuple of (url, OAuthState).
    """
    cfg = config or OAuthConfig()
    verifier, challenge = generate_pkce()
    state = secrets.token_urlsafe(32)
    params = {
        "code": "true",
        "client_id": cfg.client_id,
        "response_type": "code",
        "redirect_uri": cfg.redirect_uri,
        "scope": cfg.scopes,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    url = f"{cfg.authorize_url}?{urllib.parse.urlencode(params)}"
    return url, OAuthState(code_verifier=verifier, state=state)


def parse_auth_code(raw: str) -> tuple[str, str]:
    """Parse the 'code#state' string returned from the OAuth callback.

    Returns a tuple of (code, state).
    """
    if "#" not in raw:
        raise OAuthFlowError("Invalid auth code format. Expected 'code#state'.")
    code, state = raw.split("#", 1)
    if not code or not state:
        raise OAuthFlowError("Invalid auth code format. Both code and state are required.")
    return code, state


def _token_request_headers() -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "User-Agent": DEFAULT_USER_AGENT,
    }


def exchange_code_for_tokens(
    code: str,
    state: str,
    oauth_state: OAuthState,
    config: OAuthConfig | None = None,
) -> OAuthTokens:
    """Exchange an authorization code for OAuth tokens (sync)."""
    cfg = config or OAuthConfig()
    if state != oauth_state.state:
        raise OAuthFlowError("State mismatch - possible CSRF attack")
    body = {
        "code": code,
        "state": state,
        "grant_type": "authorization_code",
        "client_id": cfg.client_id,
        "redirect_uri": cfg.redirect_uri,
        "code_verifier": oauth_state.code_verifier,
    }
    with httpx.Client() as client:
        resp = client.post(cfg.token_url, json=body, headers=_token_request_headers())
        resp.raise_for_status()
        return OAuthTokens.from_token_response(resp.json())


async def async_exchange_code_for_tokens(
    code: str,
    state: str,
    oauth_state: OAuthState,
    config: OAuthConfig | None = None,
) -> OAuthTokens:
    """Exchange an authorization code for OAuth tokens (async)."""
    cfg = config or OAuthConfig()
    if state != oauth_state.state:
        raise OAuthFlowError("State mismatch - possible CSRF attack")
    body = {
        "code": code,
        "state": state,
        "grant_type": "authorization_code",
        "client_id": cfg.client_id,
        "redirect_uri": cfg.redirect_uri,
        "code_verifier": oauth_state.code_verifier,
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(cfg.token_url, json=body, headers=_token_request_headers())
        resp.raise_for_status()
        return OAuthTokens.from_token_response(resp.json())


def refresh_access_token(
    refresh_token: str,
    config: OAuthConfig | None = None,
) -> OAuthTokens:
    """Refresh an OAuth access token using a refresh token (sync)."""
    cfg = config or OAuthConfig()
    body = {
        "grant_type": "refresh_token",
        "client_id": cfg.client_id,
        "refresh_token": refresh_token,
    }
    with httpx.Client() as client:
        resp = client.post(cfg.token_url, json=body, headers=_token_request_headers())
        resp.raise_for_status()
        return OAuthTokens.from_token_response(resp.json())


async def async_refresh_access_token(
    refresh_token: str,
    config: OAuthConfig | None = None,
) -> OAuthTokens:
    """Refresh an OAuth access token using a refresh token (async)."""
    cfg = config or OAuthConfig()
    body = {
        "grant_type": "refresh_token",
        "client_id": cfg.client_id,
        "refresh_token": refresh_token,
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(cfg.token_url, json=body, headers=_token_request_headers())
        resp.raise_for_status()
        return OAuthTokens.from_token_response(resp.json())


def open_browser(url: str) -> bool:
    """Open a URL in the default web browser."""
    return webbrowser.open(url)
