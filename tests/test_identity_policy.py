from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.modules.identity.models import ExternalIdentity, Provider
from app.modules.identity.service import (
    IdentityResolver,
    can_auto_link_email,
    is_institutional_email,
    normalize_email,
)
from app.modules.users.models import User


class ExistingLinkDatabase:
    def __init__(self, provider: Provider, identity: ExternalIdentity, user: User):
        self._scalar_results = [provider, identity]
        self._user = user
        self.commits = 0

    async def scalar(self, _statement):
        return self._scalar_results.pop(0)

    async def get(self, _model, _user_id):
        return self._user

    async def commit(self):
        self.commits += 1

    async def refresh(self, _model):
        return None


class NewLinkDatabase:
    def __init__(self, provider: Provider):
        self._scalar_results = [provider, None, None]
        self.added = []

    async def scalar(self, _statement):
        return self._scalar_results.pop(0)

    def add(self, model):
        self.added.append(model)

    async def flush(self):
        for model in self.added:
            if isinstance(model, User) and model.id is None:
                model.id = uuid4()

    async def commit(self):
        return None

    async def refresh(self, _model):
        return None


def identity_settings():
    return SimpleNamespace(
        identity_email_domains=lambda: {"riwi.io"},
        allow_moodle_noninstitutional_email_linking=True,
    )


def test_normalizes_email_and_limits_first_linking_to_institutional_domain():
    settings = identity_settings()
    assert normalize_email(" Ana@Riwi.io ") == "ana@riwi.io"
    assert is_institutional_email("ana@riwi.io", settings)
    assert not is_institutional_email("ana@example.com", settings)
    assert can_auto_link_email("moodle", "ana@example.com", settings)
    assert not can_auto_link_email("microsoft", "ana@example.com", settings)


@pytest.mark.asyncio
async def test_existing_external_identity_is_resolved_by_stable_provider_subject():
    provider = Provider(id=uuid4(), code="moodle", name="Moodle", type="credentials", active=True)
    user = User(id=uuid4(), email="legacy@example.com", full_name="Ana", is_active=True)
    identity = ExternalIdentity(
        id=uuid4(),
        user_id=user.id,
        provider_id=provider.id,
        provider_user_id="1909",
        provider_tenant_id=None,
        provider_email="old@riwi.io",
    )
    db = ExistingLinkDatabase(provider, identity, user)

    result = await IdentityResolver.resolve(
        db,
        settings=identity_settings(),
        provider_code="moodle",
        provider_user_id="1909",
        provider_tenant_id=None,
        provider_email="changed@example.com",
        full_name="A different name must not overwrite the canonical user",
        activate_new_user=True,
    )

    assert result.user is user
    assert result.external_identity is identity
    assert result.events == []
    assert user.email == "legacy@example.com"
    assert identity.provider_email == "old@riwi.io"
    assert db.commits == 1


@pytest.mark.asyncio
async def test_moodle_can_create_a_user_from_a_valid_noninstitutional_email():
    provider = Provider(id=uuid4(), code="moodle", name="Moodle", type="credentials", active=True)
    db = NewLinkDatabase(provider)

    result = await IdentityResolver.resolve(
        db,
        settings=identity_settings(),
        provider_code="moodle",
        provider_user_id="coder-1909",
        provider_tenant_id=None,
        provider_email="coder@example.com",
        full_name="Coder Example",
        activate_new_user=True,
    )

    assert result.user.email == "coder@example.com"
    assert result.user.is_active is True
    assert result.external_identity.provider_user_id == "coder-1909"
    assert result.external_identity.provider_email == "coder@example.com"
