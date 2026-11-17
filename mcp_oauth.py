"""
Sign in to an app's MCP server once (OAuth), and keep the session fresh.

For servers that take no token in a header, only a browser sign-in (Slack, HubSpot, Asana, Notion's hosted server,
and others): an admin clicks Connect in the dashboard, signs in to the app, and the gateway keeps the tokens in
data/mcp-oauth/<name>.json (only this machine can read it). The proxy for that server (mcp_hub.py) uses them and
refreshes them before they run out, with the MCP SDK's own OAuth client: discovery, client registration (or the
admin's own OAuth app: client ID and secret), PKCE.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from mcp.client.auth import OAuthClientProvider
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken


class FileTokenStorage:
    """Tokens and the registered client, in one JSON file, with when the access token runs out."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def _read(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.path)

    @property
    def expires_at(self) -> float | None:
        return self._read().get("expires_at")

    def connected(self) -> bool:
        d = self._read()
        return bool((d.get("tokens") or {}).get("access_token"))

    async def get_tokens(self) -> OAuthToken | None:
        t = self._read().get("tokens")
        return OAuthToken.model_validate(t) if t else None

    async def set_tokens(self, tokens: OAuthToken) -> None:
        data = self._read()
        data["tokens"] = tokens.model_dump(mode="json", exclude_none=True)
        data["expires_at"] = time.time() + tokens.expires_in if tokens.expires_in else None
        self._write(data)

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        c = self._read().get("client")
        return OAuthClientInformationFull.model_validate(c) if c else None

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        data = self._read()
        data["client"] = client_info.model_dump(mode="json", exclude_none=True)
        self._write(data)

    def forget(self) -> None:
        try:
            self.path.unlink()
        except OSError:
            pass


class StoredOAuth(OAuthClientProvider):
    """The SDK's provider, told when a stored access token runs out, so a restarted proxy refreshes it in time
    instead of meeting a 401 and asking for a browser sign-in it can't do."""

    async def _initialize(self) -> None:
        await super()._initialize()
        exp = getattr(self.context.storage, "expires_at", None)
        if exp:
            self.context.token_expiry_time = exp - 30          # refresh a little early


def client_metadata(redirect_uri: str, scope: str | None = None, secret: bool = False) -> OAuthClientMetadata:
    return OAuthClientMetadata(
        client_name="Squidbrake", client_uri="https://squidbrake.com", redirect_uris=[redirect_uri], scope=scope or None,
        grant_types=["authorization_code", "refresh_token"], response_types=["code"],
        token_endpoint_auth_method="client_secret_post" if secret else "none")


async def use_own_app(storage: FileTokenStorage, redirect_uri: str, client_id: str, client_secret: str | None,
                      scope: str | None) -> None:
    """An admin's own OAuth app (for servers without automatic registration, like Slack's): skip registration."""
    await storage.set_client_info(OAuthClientInformationFull(
        client_id=client_id, client_secret=client_secret or None, redirect_uris=[redirect_uri], scope=scope or None,
        grant_types=["authorization_code", "refresh_token"], response_types=["code"],
        token_endpoint_auth_method="client_secret_post" if client_secret else "none"))


def provider(server_url: str, storage: FileTokenStorage, redirect_uri: str, scope: str | None = None,
             secret: bool = False, redirect_handler=None, callback_handler=None) -> StoredOAuth:
    async def cannot_sign_in(*_):
        raise RuntimeError("the sign-in to this app ran out: an admin reconnects it in the dashboard (Settings)")
    return StoredOAuth(server_url=server_url, client_metadata=client_metadata(redirect_uri, scope, secret),
                       storage=storage, redirect_handler=redirect_handler or cannot_sign_in,
                       callback_handler=callback_handler or cannot_sign_in)
