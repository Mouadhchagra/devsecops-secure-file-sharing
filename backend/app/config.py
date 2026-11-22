"""App settings, read from environment variables / the .env file.

Secrets are NEVER written in the code: they come from .env (git-ignored).
"""

from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL

# .env lives at the project root (one level above backend/)
ROOT_ENV = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT_ENV, extra="ignore")

    postgres_user: str
    postgres_password: SecretStr  # SecretStr = hidden if printed or logged ("**********")
    postgres_db: str
    postgres_host: str = "127.0.0.1"
    postgres_port: int = 5432

    # ----- Authentication (Day 2) -----
    # min_length=32: a short secret can be brute forced offline (hashcat -m 16500) -> attacker forges tokens
    jwt_secret: SecretStr = Field(min_length=32)
    jwt_expire_minutes: int = 15  # short life: a stolen token stops working quickly
    refresh_expire_days: int = 7  # how long you stay logged in without typing the password

    @property
    def database_url(self) -> URL:
        return URL.create(
            drivername="postgresql+psycopg",
            username=self.postgres_user,
            password=self.postgres_password.get_secret_value(),
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        )


settings = Settings()
