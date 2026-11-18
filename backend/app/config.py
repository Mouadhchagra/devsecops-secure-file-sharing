"""App settings, read from environment variables / the .env file.

Secrets are NEVER written in the code: they come from .env (git-ignored).
"""

from pathlib import Path

from pydantic import SecretStr
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
