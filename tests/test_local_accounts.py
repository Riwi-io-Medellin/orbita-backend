import pytest
from fastapi import HTTPException

from app.modules.auth.dependencies import get_current_user
from app.modules.users.models import User


def test_local_account_is_distinguished_from_external_identity():
    local = User(password_hash="hashed", microsoft_id=None)
    external = User(password_hash=None, microsoft_id="00000000-0000-0000-0000-000000000001")

    assert local.is_local_account is True
    assert external.is_local_account is False


@pytest.mark.asyncio
async def test_forced_password_change_blocks_normal_session_dependencies():
    user = User(must_change_password=True)

    with pytest.raises(HTTPException) as raised:
        await get_current_user(user)

    assert getattr(raised.value, "detail", None) == "password_change_required"
