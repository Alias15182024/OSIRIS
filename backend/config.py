"""OSIRIS application configuration.

Loads settings from environment variables.
Never commit actual secrets to version control.
"""

from __future__ import annotations

from typing import Any

from pydantic_settings import BaseSettings


class ConfigurationError(ValueError):
    """Raised when application configuration is invalid or insecure."""


KNOWN_INSECURE_SECRETS: frozenset[str] = frozenset(
    {
        "change-me-in-production",
        "change_me_in_production",
        "change-me",
        "change_me",
        "changeme",
        "changethis",
        "dev-only-not-for-production",
        "dev_only_not_for_production",
        "dev-only",
        "dev_only",
        "development-only",
        "secret",
        "secret_key",
        "secretkey",
        "password",
        "password123",
        "admin",
        "default",
        "dev",
        "development",
        "test",
        "testing",
        "osiris",
        "osiris-dev",
        "osiris-secret",
        "123456",
        "12345678",
        "root",
        "guest",
    }
)


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    database_url: str = "postgresql://osiris:osiris@localhost:5432/osiris"
    secret_key: str | None = "CHANGE-ME-IN-PRODUCTION"
    debug: bool = False
    host_id: str = "osiris-dev-host"

    model_config = {"env_prefix": "OSIRIS_", "env_file": ".env"}

    def __init__(
        self,
        *args: Any,
        validate_on_init: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        if validate_on_init:
            self.validate_secret_key()

    def validate_secret_key(self) -> None:
        """Validate that secret_key is safe for the current execution mode.

        In production mode (debug=False), rejects missing, empty, or known
        insecure placeholder secrets. In development mode (debug=True),
        permits development placeholders to preserve local workflow.

        Raises
        ------
        ConfigurationError
            If secret_key is missing, empty, or a known insecure placeholder in
            production mode, or if empty in development mode.
        """
        raw_key = self.secret_key
        if not isinstance(raw_key, str) or not raw_key.strip():
            raise ConfigurationError(
                "OSIRIS secret_key is not configured. A non-empty signing secret "
                "must be provided via OSIRIS_SECRET_KEY."
            )

        if not self.debug:
            normalized = raw_key.strip().lower()
            if normalized in KNOWN_INSECURE_SECRETS:
                raise ConfigurationError(
                    "Insecure or placeholder secret_key is not permitted in "
                    "production mode (debug=False). Please configure a secure "
                    "OSIRIS_SECRET_KEY."
                )


def validate_secret_key(settings_obj: Settings | None = None) -> None:
    """Validate secret_key on the given or global settings instance."""
    cfg = settings_obj if settings_obj is not None else settings
    cfg.validate_secret_key()


settings = Settings()
