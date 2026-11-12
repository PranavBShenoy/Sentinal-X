"""
Authorization Component for SENTINEL-X.

Issues asymmetric job capability tokens after verifying assessment ownership
and tenant isolation from trusted database records. The private signing key
is held ONLY by this component and is never distributed to workers, the API,
or the Runtime Host.

Three-party model:
  Authorization Component (signs with PRIVATE key)
      -> Control Plane (presents token to Runtime Host)
      -> Runtime Host (verifies with PUBLIC key only)
"""

from __future__ import annotations

from typing import Optional

from app.runtime.job_token import (
    generate_ed25519_keypair,
    sign_job_token,
)
from app.authz.component import AuthorizationComponent
from app.authz.dependencies import get_authorization_component

__all__ = [
    "AuthorizationComponent",
    "get_authorization_component",
    "generate_ed25519_keypair",
    "sign_job_token",
]
