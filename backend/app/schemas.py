"""Pydantic schemas = the exact shape of data allowed IN and OUT of the API.

Anything that does not match is rejected automatically with 422, before our code runs.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

PASSWORD_MIN = 12
PASSWORD_MAX = 128  # upper limit: a 1 MB "password" would make argon2 burn CPU/RAM (DoS)


class StrictModel(BaseModel):
    # extra="forbid": unknown fields are REJECTED (blocks mass assignment, e.g. {"is_admin": true})
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ---------- Input (what the user sends) ----------

class RegisterRequest(StrictModel):
    email: EmailStr = Field(max_length=255)
    password: str = Field(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        # "Mouadh@Mail.com" and "mouadh@mail.com" must be the same account
        return v.lower()

    @field_validator("password")
    @classmethod
    def password_policy(cls, v: str) -> str:
        if len(set(v)) < 4:
            # blocks things like "aaaaaaaaaaaa" or "121212121212"
            raise ValueError("password is too simple")
        return v


class LoginRequest(StrictModel):
    email: EmailStr = Field(max_length=255)
    # no min_length here: login must not reveal the password policy, only "invalid credentials"
    password: str = Field(max_length=PASSWORD_MAX)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.lower()


# ---------- Output (what the API sends back) ----------

class UserOut(BaseModel):
    """Public view of a user: NO password_hash, ever."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
