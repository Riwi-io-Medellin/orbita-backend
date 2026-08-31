import json
from types import SimpleNamespace
from urllib.parse import parse_qs

import httpx
import pytest

from app.modules.auth.moodle import MoodleClient, MoodleCredentialsError


def moodle_settings():
    return SimpleNamespace(
        moodle_base_url="https://moodle.test",
        moodle_service="moodle_mobile_app",
        moodle_timeout_seconds=1,
    )


@pytest.mark.asyncio
async def test_moodle_client_only_queries_the_authenticated_users_profile():
    calls: list[tuple[str, dict[str, list[str]]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        fields = parse_qs(request.content.decode())
        calls.append((request.url.path, fields))
        if request.url.path == "/login/token.php":
            assert fields == {
                "username": ["ana"],
                "password": ["secret"],
                "service": ["moodle_mobile_app"],
            }
            return httpx.Response(200, json={"token": "transient-token"})
        if fields["wsfunction"] == ["core_webservice_get_site_info"]:
            return httpx.Response(200, json={"userid": 1909})
        assert fields["wsfunction"] == ["core_user_get_users_by_field"]
        assert fields["field"] == ["id"]
        assert fields["values[0]"] == ["1909"]
        return httpx.Response(200, json=[{"id": 1909, "email": "Ana@Riwi.io", "fullname": "Ana Riwi"}])

    client = MoodleClient(moodle_settings(), transport=httpx.MockTransport(handler))
    user = await client.authenticate("ana", "secret")

    assert user.user_id == "1909"
    assert user.email == "ana@riwi.io"
    assert user.full_name == "Ana Riwi"
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_moodle_client_maps_invalid_login_without_exposing_provider_details():
    client = MoodleClient(
        moodle_settings(),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"errorcode": "invalidlogin"})),
    )

    with pytest.raises(MoodleCredentialsError):
        await client.authenticate("ana", "wrong-password")


@pytest.mark.asyncio
async def test_moodle_password_reset_uses_the_no_login_service_with_one_identifier_type():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/lib/ajax/service-nologin.php"
        assert request.headers["content-type"].startswith("application/json")
        assert json.loads(request.content) == [{
            "index": 0,
            "methodname": "core_auth_request_password_reset",
            "args": {"email": "ana@riwi.io"},
        }]
        return httpx.Response(200, json=[{"error": False, "data": None}])

    client = MoodleClient(moodle_settings(), transport=httpx.MockTransport(handler))
    await client.request_password_reset(identifier="ana@riwi.io", identifier_type="email")
