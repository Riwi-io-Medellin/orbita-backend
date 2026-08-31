import pytest
from datetime import UTC, datetime, timedelta

from app.modules.auth import microsoft


def test_microsoft_claims_require_the_configured_tenant_and_exact_issuer(monkeypatch):
    monkeypatch.setattr(microsoft.settings, "enable_microsoft_login", True)
    monkeypatch.setattr(microsoft.settings, "microsoft_tenant_id", "tenant-123")
    monkeypatch.setattr(microsoft.settings, "microsoft_client_id", "client-123")
    claims = {
        "tid": "tenant-123",
        "oid": "object-123",
        "email": "ana@riwi.io",
        "iss": "https://login.microsoftonline.com/tenant-123/v2.0",
        "aud": "client-123",
        "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
        "name": "Ana Riwi",
    }

    assert microsoft.validate_microsoft_claims(claims) == (
        "tenant-123", "object-123", "ana@riwi.io", "Ana Riwi"
    )

    claims["tid"] = "another-tenant"
    with pytest.raises(microsoft.MicrosoftTenantNotAllowedError):
        microsoft.validate_microsoft_claims(claims)
