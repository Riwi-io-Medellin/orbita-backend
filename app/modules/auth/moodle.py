from dataclasses import dataclass

import httpx

from app.config.settings import Settings
from app.modules.identity.service import normalize_email


class MoodleCredentialsError(Exception):
    pass


class MoodleUnavailableError(Exception):
    pass


@dataclass(frozen=True)
class MoodleAuthenticatedUser:
    user_id: str
    email: str
    full_name: str


class MoodleClient:
    """Thin adapter for Moodle's mobile token and REST web-service endpoints."""

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None):
        self._base_url = settings.moodle_base_url
        self._service = settings.moodle_service
        self._timeout = settings.moodle_timeout_seconds
        self._transport = transport

    @property
    def configured(self) -> bool:
        return bool(self._base_url and self._service)

    async def authenticate(self, username: str, password: str) -> MoodleAuthenticatedUser:
        if not self.configured:
            raise MoodleUnavailableError("Moodle is not configured")
        try:
            async with httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client:
                token_response = await client.post(
                    f"{self._base_url}/login/token.php",
                    data={"username": username, "password": password, "service": self._service},
                )
                token_response.raise_for_status()
                token_payload = token_response.json()
                token = token_payload.get("token")
                if not token:
                    if token_payload.get("errorcode") in {"invalidlogin", "invalidtoken"}:
                        raise MoodleCredentialsError()
                    raise MoodleUnavailableError("Moodle token request was rejected")

                site_info = await self._call(client, token, "core_webservice_get_site_info")
                user_id = site_info.get("userid")
                if not user_id:
                    raise MoodleUnavailableError("Moodle did not return userid")

                profiles = await self._call(
                    client,
                    token,
                    "core_user_get_users_by_field",
                    {"field": "id", "values[0]": str(user_id)},
                )
        except MoodleCredentialsError:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            raise MoodleUnavailableError("Moodle request failed") from exc

        if not isinstance(profiles, list) or len(profiles) != 1:
            raise MoodleUnavailableError("Moodle did not return exactly one profile")
        profile = profiles[0]
        if str(profile.get("id")) != str(user_id):
            raise MoodleUnavailableError("Moodle returned a mismatched profile")
        email = normalize_email(profile.get("email"))
        if not email:
            return MoodleAuthenticatedUser(str(user_id), "", str(profile.get("fullname") or ""))
        return MoodleAuthenticatedUser(str(user_id), email, str(profile.get("fullname") or ""))

    async def request_password_reset(self, *, identifier: str, identifier_type: str) -> None:
        """Requests Moodle's own password-reset email without a Moodle token."""
        if not self.configured:
            raise MoodleUnavailableError("Moodle is not configured")
        try:
            async with httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client:
                response = await client.post(
                    f"{self._base_url}/lib/ajax/service-nologin.php",
                    json=[{
                        "index": 0,
                        "methodname": "core_auth_request_password_reset",
                        "args": {identifier_type: identifier},
                    }],
                )
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise MoodleUnavailableError("Moodle password reset request failed") from exc

        if not isinstance(payload, list) or len(payload) != 1 or payload[0].get("error"):
            raise MoodleUnavailableError("Moodle password reset request was rejected")

    async def _call(
        self,
        client: httpx.AsyncClient,
        token: str,
        function: str,
        extra: dict[str, str] | None = None,
    ) -> dict | list:
        response = await client.post(
            f"{self._base_url}/webservice/rest/server.php",
            data={
                "wstoken": token,
                "wsfunction": function,
                "moodlewsrestformat": "json",
                **(extra or {}),
            },
        )
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, dict) and payload.get("exception"):
            raise MoodleUnavailableError("Moodle web service rejected the request")
        return payload
