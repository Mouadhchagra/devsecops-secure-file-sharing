"""Database tables (see docs/erd.md for the design and security reasons)."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))  # never the real password
    is_active: Mapped[bool] = mapped_column(default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class File(Base):
    __tablename__ = "files"
    __table_args__ = (CheckConstraint("size_bytes >= 0", name="ck_files_size_positive"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    original_name: Mapped[str] = mapped_column(String(255))
    object_name: Mapped[str] = mapped_column(String(64), unique=True)  # random name in MinIO
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    mime_type: Mapped[str] = mapped_column(String(127))
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary)  # file key encrypted by MASTER_KEY
    key_nonce: Mapped[bytes] = mapped_column(LargeBinary)
    file_nonce: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class ShareLink(Base):
    __tablename__ = "share_links"
    __table_args__ = (
        CheckConstraint("download_count >= 0", name="ck_share_links_count_positive"),
        CheckConstraint("max_downloads IS NULL OR max_downloads > 0", name="ck_share_links_max_positive"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    file_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("files.id", ondelete="CASCADE"), index=True)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)  # SHA-256 hex, never the token
    password_hash: Mapped[str | None] = mapped_column(String(255))
    expires_at: Mapped[datetime]
    max_downloads: Mapped[int | None]
    download_count: Mapped[int] = mapped_column(default=0, server_default="0")
    revoked_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class AuditLog(Base):
    """Append-only: the API will never update or delete rows here."""

    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_user_created", "user_id", "created_at"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(50), index=True)
    file_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("files.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(20))  # success / failure / denied
    ip_address: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)  # NEVER secrets here
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), index=True)
