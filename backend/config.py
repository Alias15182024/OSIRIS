"""OSIRIS application configuration.

Loads settings from environment variables.
Never commit actual secrets to version control.
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    database_url: str = "postgresql://osiris:osiris@localhost:5432/osiris"
    secret_key: str = "CHANGE-ME-IN-PRODUCTION"
    debug: bool = False
    host_id: str = "osiris-dev-host"

    model_config = {"env_prefix": "OSIRIS_"}


settings = Settings()
