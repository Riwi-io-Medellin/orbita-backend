"""Reference FastAPI adapter for Orbita SSO Client Contract v1.

Keep the client secret in the consuming app's backend environment. This class is framework-neutral
apart from being async, so a FastAPI route can call `authorization_url` and `exchange_code` directly.
"""

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx
from jose import jwt


@dataclass(frozen=True)
class OrbitaSsoConfig:
    base_url: str
    client_id: str
    client_secret: str
    redirect_uri: str


class OrbitaSsoClient:
    def __init__(self, config: OrbitaSsoConfig):
        self.config = config
        self._discovery: dict[str, Any] | None = None
        self._jwks: dict[str, Any] | None = None

    async def authorization_url(self, state: str) -> str:
        discovery = await self.discovery()
        query = urlencode({
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "state": state,
        })
        return f"{discovery['authorization_endpoint']}?{query}"

    async def exchange_code(self, code: str) -> tuple[dict[str, Any], dict[str, Any]]:
        discovery = await self.discovery()
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(discovery["token_endpoint"], json={
                "code": code,
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "redirect_uri": self.config.redirect_uri,
            })
            response.raise_for_status()
            token_response = response.json()
        return token_response, await self.verify_token(token_response["access_token"])

    async def verify_token(self, token: str) -> dict[str, Any]:
        jwks = await self.jwks()
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256":
            raise ValueError("Orbita JWT algorithm is not RS256")
        key = next((item for item in jwks["keys"] if item.get("kid") == header.get("kid")), None)
        if key is None:
            jwks = await self.jwks(force_refresh=True)
            key = next((item for item in jwks["keys"] if item.get("kid") == header.get("kid")), None)
        if key is None:
            raise ValueError("Orbita JWT key id is unknown")
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=self.config.client_id)
        required = {"sub", "email", "name", "roles", "exp", "jti"}
        if (
            not required.issubset(claims)
            or not all(isinstance(claims[field], str) and claims[field] for field in {"sub", "email", "name", "jti"})
            or not isinstance(claims["roles"], list)
            or not claims["roles"]
            or not all(isinstance(role, str) and role for role in claims["roles"])
        ):
            raise ValueError("Orbita JWT is missing required claims")
        return claims

    async def sync_role_catalog(self, roles: list[dict[str, str]]) -> dict[str, Any]:
        discovery = await self.discovery()
        endpoint = discovery["role_catalog_sync_endpoint"].replace("{client_id}", self.config.client_id)
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.put(endpoint, json={
                "client_secret": self.config.client_secret,
                "roles": roles,
            })
            response.raise_for_status()
            return response.json()

    async def discovery(self) -> dict[str, Any]:
        if self._discovery is None:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(f"{self.config.base_url.rstrip('/')}/api/.well-known/orbita-configuration")
                response.raise_for_status()
                self._discovery = response.json()
            if self._discovery.get("contract_version") != "1.0":
                raise ValueError(f"Unsupported Orbita contract: {self._discovery.get('contract_version')}")
            self._validate_discovery_origins(self._discovery)
        return self._discovery

    async def jwks(self, *, force_refresh: bool = False) -> dict[str, Any]:
        if self._jwks is None or force_refresh:
            discovery = await self.discovery()
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(discovery["jwks_uri"])
                response.raise_for_status()
                self._jwks = response.json()
        return self._jwks

    def _validate_discovery_origins(self, discovery: dict[str, Any]) -> None:
        configured = urlparse(self.config.base_url)
        if configured.scheme not in {"http", "https"} or not configured.netloc:
            raise ValueError("ORBITA_SSO_BASE_URL must be an absolute URL")
        expected_origin = (configured.scheme, configured.netloc)
        for field in ("authorization_endpoint", "token_endpoint", "jwks_uri", "introspection_endpoint", "role_catalog_sync_endpoint"):
            endpoint = urlparse(str(discovery.get(field, "")).replace("{client_id}", "client"))
            if (endpoint.scheme, endpoint.netloc) != expected_origin:
                raise ValueError(f"Orbita discovery endpoint {field} is outside the configured origin")
            if configured.scheme == "https" and endpoint.scheme != "https":
                raise ValueError(f"Orbita discovery endpoint {field} is not HTTPS")
