from dataclasses import dataclass, field
from datetime import UTC, datetime

from email_validator import EmailNotValidError, validate_email
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.settings import Settings
from app.modules.identity.models import ExternalIdentity, Provider
from app.modules.users.models import User


class ProviderUnavailableError(Exception):
    pass


class InvalidInstitutionalEmailError(Exception):
    pass


class IdentityLinkConflictError(Exception):
    pass


@dataclass
class IdentityResolution:
    user: User
    external_identity: ExternalIdentity
    events: list[tuple[str, dict]] = field(default_factory=list)


def normalize_email(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return validate_email(value.strip(), check_deliverability=False).normalized.lower()
    except EmailNotValidError:
        return None


def is_institutional_email(email: str | None, settings: Settings) -> bool:
    return bool(email and "@" in email and email.rsplit("@", 1)[1] in settings.identity_email_domains())


def can_auto_link_email(provider_code: str, email: str | None, settings: Settings) -> bool:
    """Decides whether a newly observed external account may correlate by email."""
    if not email:
        return False
    return is_institutional_email(email, settings) or (
        provider_code == "moodle" and settings.allow_moodle_noninstitutional_email_linking
    )


class IdentityResolver:
    """Resolves external provider accounts into one canonical Orbita User."""

    @staticmethod
    async def get_provider(db: AsyncSession, code: str) -> Provider | None:
        return await db.scalar(select(Provider).where(Provider.code == code))

    @staticmethod
    async def resolve(
        db: AsyncSession,
        *,
        settings: Settings,
        provider_code: str,
        provider_user_id: str,
        provider_tenant_id: str | None,
        provider_email: str | None,
        full_name: str,
        activate_new_user: bool,
    ) -> IdentityResolution:
        provider = await IdentityResolver.get_provider(db, provider_code)
        if provider is None or not provider.active:
            raise ProviderUnavailableError(provider_code)

        normalized_email = normalize_email(provider_email)
        external_identity = await db.scalar(
            select(ExternalIdentity).where(
                ExternalIdentity.provider_id == provider.id,
                ExternalIdentity.provider_user_id == provider_user_id,
                ExternalIdentity.provider_tenant_id.is_(None)
                if provider_tenant_id is None
                else ExternalIdentity.provider_tenant_id == provider_tenant_id,
            )
        )

        if external_identity is not None:
            user = await db.get(User, external_identity.user_id)
            if user is None:
                raise IdentityLinkConflictError("external_identity_without_user")
            events = await IdentityResolver._refresh_existing_link(
                db, settings, user, external_identity, normalized_email, provider_code
            )
            external_identity.last_seen_at = datetime.now(UTC)
            await db.commit()
            await db.refresh(user)
            await db.refresh(external_identity)
            return IdentityResolution(user=user, external_identity=external_identity, events=events)

        if not can_auto_link_email(provider_code, normalized_email, settings):
            raise InvalidInstitutionalEmailError()

        user = await db.scalar(
            select(User).where(func.lower(func.btrim(User.email)) == normalized_email)
        )
        if user is not None:
            existing_provider_link = await db.scalar(
                select(ExternalIdentity).where(
                    ExternalIdentity.user_id == user.id,
                    ExternalIdentity.provider_id == provider.id,
                )
            )
            if existing_provider_link is not None:
                raise IdentityLinkConflictError("user_already_has_provider")
        else:
            user = User(
                email=normalized_email,
                full_name=full_name.strip() or normalized_email,
                is_active=activate_new_user,
            )
            db.add(user)
            await db.flush()

        external_identity = ExternalIdentity(
            user_id=user.id,
            provider_id=provider.id,
            provider_user_id=provider_user_id,
            provider_tenant_id=provider_tenant_id,
            provider_email=normalized_email,
            last_seen_at=datetime.now(UTC),
        )
        db.add(external_identity)
        await db.commit()
        await db.refresh(user)
        await db.refresh(external_identity)
        return IdentityResolution(user=user, external_identity=external_identity)

    @staticmethod
    async def _refresh_existing_link(
        db: AsyncSession,
        settings: Settings,
        user: User,
        external_identity: ExternalIdentity,
        incoming_email: str | None,
        provider_code: str,
    ) -> list[tuple[str, dict]]:
        if not is_institutional_email(incoming_email, settings):
            return []

        other_user = await db.scalar(
            select(User).where(
                func.lower(func.btrim(User.email)) == incoming_email,
                User.id != user.id,
            )
        )
        if other_user is not None:
            raise IdentityLinkConflictError("provider_email_owned_by_another_user")

        events: list[tuple[str, dict]] = []
        previous_provider_email = external_identity.provider_email
        external_identity.provider_email = incoming_email
        if previous_provider_email != incoming_email:
            events.append(("identity.provider_email_changed", {
                "provider": provider_code,
                "previous_email": previous_provider_email,
                "new_email": incoming_email,
            }))

        current_email = normalize_email(user.email)
        if not is_institutional_email(current_email, settings):
            user.email = incoming_email
            events.append(("identity.canonical_email_promoted", {
                "provider": provider_code,
                "new_email": incoming_email,
            }))
        elif current_email != incoming_email:
            events.append(("identity.email_mismatch", {
                "provider": provider_code,
                "canonical_email": current_email,
                "provider_email": incoming_email,
            }))
        return events
