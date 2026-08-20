import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Table, Column, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


user_global_roles = Table(
    "user_global_roles", Base.metadata,
    Column("user_id", UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("global_role_id", UUID(as_uuid=True), ForeignKey("global_roles.id", ondelete="CASCADE"), primary_key=True),
)

application_global_roles = Table(
    "application_global_roles", Base.metadata,
    Column("application_id", UUID(as_uuid=True), ForeignKey("applications.id", ondelete="CASCADE"), primary_key=True),
    Column("global_role_id", UUID(as_uuid=True), ForeignKey("global_roles.id", ondelete="CASCADE"), primary_key=True),
)

user_applications = Table(
    "user_applications", Base.metadata,
    Column("user_id", UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("application_id", UUID(as_uuid=True), ForeignKey("applications.id", ondelete="CASCADE"), primary_key=True),
    Column("granted_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
)


class GlobalRole(Base):
    __tablename__ = "global_roles"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Application(Base):
    __tablename__ = "applications"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    icon: Mapped[str | None] = mapped_column(String(50))
    is_active: Mapped[bool] = mapped_column(Boolean, server_default="true", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    event: Mapped[str] = mapped_column(String(100), nullable=False)
    application_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("applications.id", ondelete="SET NULL"))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    details: Mapped[dict] = mapped_column(JSONB, server_default="{}", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
