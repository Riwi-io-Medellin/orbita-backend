"""Reference FastAPI adapter for Orbita SSO Client Contract v1.

Keep the client secret in the consuming app's backend environment. This class is framework-neutral
apart from being async, so a FastAPI route can call `authorization_url` and `exchange_code` directly.
"""

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

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
        key = next((item for item in jwks["keys"] if item.get("kid") == header.get("kid")), None)
        if key is None:
            raise ValueError("Orbita JWT key id is unknown")
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=self.config.client_id)
        required = {"sub", "email", "roles", "exp", "jti"}
        if not required.issubset(claims) or not isinstance(claims["roles"], list):
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
        return self._discovery

    async def jwks(self) -> dict[str, Any]:
        if self._jwks is None:
            discovery = await self.discovery()
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(discovery["jwks_uri"])
                response.raise_for_status()
                self._jwks = response.json()
        return self._jwks
