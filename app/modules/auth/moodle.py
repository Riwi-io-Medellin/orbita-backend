import asyncio
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
    role_shortnames: tuple[str, ...]


MOODLE_ROLE_MAP = {
    "editingteacher": "teamleader",
    "teacher": "teamleader",
    "student": "coder",
}
MOODLE_ROLE_PRIORITY = ("teamleader", "coder")


def mapped_orbita_role(role_shortnames: tuple[str, ...]) -> str | None:
    mapped = {MOODLE_ROLE_MAP.get(role.strip().lower()) for role in role_shortnames}
    return next((role for role in MOODLE_ROLE_PRIORITY if role in mapped), None)


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
                courses = await self._call(
                    client,
                    token,
                    "core_enrol_get_users_courses",
                    {"userid": str(user_id), "returnusercount": "0"},
                )
                if not isinstance(courses, list):
                    raise MoodleUnavailableError("Moodle did not return courses")
                semaphore = asyncio.Semaphore(5)

                async def profile_roles(course_id: object) -> tuple[str, ...]:
                    async with semaphore:
                        course_profiles = await self._call(
                            client,
                            token,
                            "core_user_get_course_user_profiles",
                            {
                                "userlist[0][userid]": str(user_id),
                                "userlist[0][courseid]": str(course_id),
                            },
                        )
                    if not isinstance(course_profiles, list) or len(course_profiles) != 1:
                        raise MoodleUnavailableError("Moodle did not return the course profile")
                    course_profile = course_profiles[0]
                    if str(course_profile.get("id")) != str(user_id):
                        raise MoodleUnavailableError("Moodle returned a mismatched course profile")
                    return tuple(
                        str(role.get("shortname") or "").strip().lower()
                        for role in course_profile.get("roles", [])
                        if isinstance(role, dict) and role.get("shortname")
                    )

                role_groups = await asyncio.gather(
                    *(profile_roles(course.get("id")) for course in courses if isinstance(course, dict) and course.get("id")),
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
            return MoodleAuthenticatedUser(str(user_id), "", str(profile.get("fullname") or ""), tuple(sorted({role for group in role_groups for role in group})))
        return MoodleAuthenticatedUser(str(user_id), email, str(profile.get("fullname") or ""), tuple(sorted({role for group in role_groups for role in group})))

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
