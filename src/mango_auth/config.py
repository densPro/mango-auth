from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite+aiosqlite:///./mango_auth.db"
    issuer: str = "mango-auth"
    access_token_minutes: int = 15
    refresh_token_days: int = 30
    lockout_threshold: int = 5
    lockout_minutes: int = 15
    bootstrap_admin_email: str | None = None
    bootstrap_admin_password: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
