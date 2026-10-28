"""Unit tests for OSIRIS secret-key configuration and fail-fast validation.

Tests:
- Production mode (debug=False) rejects missing, empty, and known placeholder secrets.
- Production mode accepts valid strong secrets and secrets with substring keywords.
- Development mode (debug=True) permits intentional development placeholders.
- Validation errors never disclose secret values in messages or representations.
- Instantiation with validate_on_init=True enforces validation on construction.
- Application startup (lifespan) fails fast before serving traffic in misconfigured
  production environments.
- Importing modules and creating settings without validation does not break test
  collection or unrelated utilities.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from backend.api.security import create_access_token, decode_access_token
from backend.config import (
    KNOWN_INSECURE_SECRETS,
    ConfigurationError,
    Settings,
    settings,
    validate_secret_key,
)
from backend.main import app


class TestSecretKeyValidation:
    """Tests for Settings.validate_secret_key fail-fast logic."""

    def test_non_string_secret_key_rejected(self) -> None:
        cfg = Settings(debug=False)
        object.__setattr__(cfg, "secret_key", 12345)
        with pytest.raises(
            ConfigurationError, match="OSIRIS secret_key is not configured"
        ):
            cfg.validate_secret_key()

    def test_production_missing_secret_rejected(self) -> None:
        cfg = Settings(debug=False, secret_key=None)
        with pytest.raises(
            ConfigurationError, match="OSIRIS secret_key is not configured"
        ):
            cfg.validate_secret_key()

    def test_production_empty_secret_rejected(self) -> None:
        cfg = Settings(debug=False, secret_key="")
        with pytest.raises(
            ConfigurationError, match="OSIRIS secret_key is not configured"
        ):
            cfg.validate_secret_key()

    def test_production_whitespace_secret_rejected(self) -> None:
        cfg = Settings(debug=False, secret_key="   \t\n  ")
        with pytest.raises(
            ConfigurationError, match="OSIRIS secret_key is not configured"
        ):
            cfg.validate_secret_key()

    def test_production_change_me_default_rejected(self) -> None:
        cfg = Settings(debug=False, secret_key="CHANGE-ME-IN-PRODUCTION")
        with pytest.raises(
            ConfigurationError, match="Insecure or placeholder secret_key"
        ):
            cfg.validate_secret_key()

    def test_production_change_me_case_insensitive_and_whitespace_rejected(
        self,
    ) -> None:
        for placeholder in [
            "  change-me-in-production  ",
            "Change-Me-In-Production",
            "CHANGE-ME-IN-PRODUCTION\n",
        ]:
            cfg = Settings(debug=False, secret_key=placeholder)
            with pytest.raises(
                ConfigurationError, match="Insecure or placeholder secret_key"
            ):
                cfg.validate_secret_key()

    def test_production_dev_only_placeholder_rejected(self) -> None:
        cfg = Settings(debug=False, secret_key="dev-only-not-for-production")
        with pytest.raises(
            ConfigurationError, match="Insecure or placeholder secret_key"
        ):
            cfg.validate_secret_key()

    def test_production_changeme_placeholder_rejected(self) -> None:
        cfg = Settings(debug=False, secret_key="changeme")
        with pytest.raises(
            ConfigurationError, match="Insecure or placeholder secret_key"
        ):
            cfg.validate_secret_key()

    @pytest.mark.parametrize("placeholder", sorted(KNOWN_INSECURE_SECRETS))
    def test_production_all_known_insecure_placeholders_rejected(
        self, placeholder: str
    ) -> None:
        cfg = Settings(debug=False, secret_key=placeholder)
        with pytest.raises(
            ConfigurationError, match="Insecure or placeholder secret_key"
        ):
            cfg.validate_secret_key()

    def test_production_valid_configured_secret_accepted(self) -> None:
        valid_secrets = [
            "a-very-strong-production-signing-secret-key-9999",
            "9f8a3c2b1e0d4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9",
            "dGVzdC1zZWNyZXQta2V5LXZhbGlkLXByb2R1Y3Rpb24tb3Npcmlz",
            "!@#$%^&*()_+~|}{[]:;?><,./-complex-passphrase",
        ]
        for sec in valid_secrets:
            cfg = Settings(debug=False, secret_key=sec)
            cfg.validate_secret_key()  # Must not raise

    def test_production_legitimate_secret_with_keyword_substring_accepted(
        self,
    ) -> None:
        """Secrets containing substrings like 'secret' must not be rejected."""
        legit_secrets = [
            "my_super_secret_jwt_signing_key_production_environment_ready",
            "secure_password_salt_derived_application_token_secret_12345",
            "enterprise_default_zone_alpha_incident_response_system_key",
        ]
        for sec in legit_secrets:
            cfg = Settings(debug=False, secret_key=sec)
            cfg.validate_secret_key()  # Must not raise

    def test_development_mode_allows_known_placeholders(self) -> None:
        for placeholder in [
            "CHANGE-ME-IN-PRODUCTION",
            "dev-only-not-for-production",
            "changeme",
            "secret",
        ]:
            cfg = Settings(debug=True, secret_key=placeholder)
            cfg.validate_secret_key()  # Must not raise in dev mode

    def test_development_mode_allows_custom_secret(self) -> None:
        cfg = Settings(debug=True, secret_key="local-dev-key")
        cfg.validate_secret_key()  # Must not raise in dev mode

    def test_development_mode_rejects_missing_or_empty_secret(self) -> None:
        for empty_val in [None, "", "   \t  "]:
            cfg = Settings(debug=True, secret_key=empty_val)
            with pytest.raises(
                ConfigurationError, match="OSIRIS secret_key is not configured"
            ):
                cfg.validate_secret_key()

    def test_error_message_does_not_disclose_secret_content(self) -> None:
        canary_secrets = [
            "CHANGE-ME-IN-PRODUCTION",
            "dev-only-not-for-production",
            "changeme",
            "password123",
            "admin",
        ]
        for sec in canary_secrets:
            cfg = Settings(debug=False, secret_key=sec)
            with pytest.raises(ConfigurationError) as exc_info:
                cfg.validate_secret_key()
            err_msg = str(exc_info.value)
            err_repr = repr(exc_info.value)
            assert sec not in err_msg
            assert sec.lower() not in err_msg.lower()
            assert sec not in err_repr

    def test_validate_on_init_option(self) -> None:
        with pytest.raises(ConfigurationError):
            Settings(
                debug=False,
                secret_key="CHANGE-ME-IN-PRODUCTION",
                validate_on_init=True,
            )

        # Valid secret on init succeeds
        cfg = Settings(
            debug=False,
            secret_key="valid-prod-secret-key-12345",
            validate_on_init=True,
        )
        assert cfg.secret_key == "valid-prod-secret-key-12345"

    def test_validate_secret_key_helper_function(self) -> None:
        valid_cfg = Settings(debug=False, secret_key="valid-key-999")
        validate_secret_key(valid_cfg)

        invalid_cfg = Settings(debug=False, secret_key="changeme")
        with pytest.raises(ConfigurationError):
            validate_secret_key(invalid_cfg)


class TestApplicationStartupSecretKey:
    """Tests for application startup fail-fast behavior in FastAPI lifespan."""

    def test_app_startup_fails_in_production_with_placeholder_secret(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "debug", False)
        monkeypatch.setattr(settings, "secret_key", "CHANGE-ME-IN-PRODUCTION")

        with pytest.raises(
            ConfigurationError, match="Insecure or placeholder secret_key"
        ):
            with TestClient(app):
                pass

    def test_app_startup_fails_in_production_with_dev_placeholder(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "debug", False)
        monkeypatch.setattr(settings, "secret_key", "dev-only-not-for-production")

        with pytest.raises(
            ConfigurationError, match="Insecure or placeholder secret_key"
        ):
            with TestClient(app):
                pass

    def test_app_startup_fails_in_production_with_empty_secret(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "debug", False)
        monkeypatch.setattr(settings, "secret_key", "")

        with pytest.raises(
            ConfigurationError, match="OSIRIS secret_key is not configured"
        ):
            with TestClient(app):
                pass

    def test_app_startup_fails_in_production_with_missing_secret(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "debug", False)
        monkeypatch.setattr(settings, "secret_key", None)

        with pytest.raises(
            ConfigurationError, match="OSIRIS secret_key is not configured"
        ):
            with TestClient(app):
                pass

    def test_app_middleware_blocks_traffic_even_when_lifespan_is_bypassed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When an ASGI caller invokes app without lifespan, middleware blocks."""
        monkeypatch.setattr(settings, "debug", False)
        monkeypatch.setattr(settings, "secret_key", "CHANGE-ME-IN-PRODUCTION")

        client = TestClient(app, raise_server_exceptions=True)
        with pytest.raises(
            ConfigurationError, match="Insecure or placeholder secret_key"
        ):
            client.get("/health")

        # Caught server exceptions yield HTTP 500, never serving 200 traffic
        safe_client = TestClient(app, raise_server_exceptions=False)
        resp = safe_client.get("/health")
        assert resp.status_code == 500

    def test_app_middleware_blocks_missing_secret_when_lifespan_bypassed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "debug", False)
        monkeypatch.setattr(settings, "secret_key", None)

        client = TestClient(app, raise_server_exceptions=True)
        with pytest.raises(
            ConfigurationError, match="OSIRIS secret_key is not configured"
        ):
            client.get("/health")

    def test_app_startup_succeeds_in_production_with_valid_secret(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "debug", False)
        monkeypatch.setattr(
            settings, "secret_key", "production-cryptographically-secure-key-99"
        )

        with TestClient(app) as client:
            resp = client.get("/health")
            assert resp.status_code == 200
            assert resp.json() == {"status": "ok", "system": "osiris"}

    def test_app_startup_succeeds_in_dev_with_placeholder(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "debug", True)
        monkeypatch.setattr(settings, "secret_key", "dev-only-not-for-production")

        with TestClient(app) as client:
            resp = client.get("/health")
            assert resp.status_code == 200
            assert resp.json() == {"status": "ok", "system": "osiris"}

    def test_app_startup_failure_discloses_no_secret(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        canary = "CHANGE-ME-IN-PRODUCTION"
        monkeypatch.setattr(settings, "debug", False)
        monkeypatch.setattr(settings, "secret_key", canary)

        with pytest.raises(ConfigurationError) as exc_info:
            with TestClient(app):
                pass
        assert canary not in str(exc_info.value)


class TestTokenSecurityFailFast:
    """Tests ensuring token signing and decoding fail fast with insecure config."""

    def test_token_creation_fails_fast_in_production_with_placeholder(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "debug", False)
        monkeypatch.setattr(settings, "secret_key", "CHANGE-ME-IN-PRODUCTION")

        with pytest.raises(
            ConfigurationError, match="Insecure or placeholder secret_key"
        ):
            create_access_token(user_id="user-123", username="alice")

    def test_token_creation_fails_fast_in_production_with_missing_secret(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "debug", False)
        monkeypatch.setattr(settings, "secret_key", None)

        with pytest.raises(
            ConfigurationError, match="OSIRIS secret_key is not configured"
        ):
            create_access_token(user_id="user-123", username="alice")

    def test_token_decoding_fails_fast_in_production_with_placeholder(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        token = create_access_token(
            user_id="user-123",
            username="alice",
            secret_key="explicit-temp-key-for-test",
        )
        monkeypatch.setattr(settings, "debug", False)
        monkeypatch.setattr(settings, "secret_key", "dev-only-not-for-production")

        with pytest.raises(
            ConfigurationError, match="Insecure or placeholder secret_key"
        ):
            decode_access_token(token)

    def test_token_creation_succeeds_in_dev_with_placeholder(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "debug", True)
        monkeypatch.setattr(settings, "secret_key", "dev-only-not-for-production")

        token = create_access_token(user_id="user-123", username="alice")
        assert isinstance(token, str)

    def test_token_creation_succeeds_in_prod_with_strong_secret(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "debug", False)
        monkeypatch.setattr(
            settings, "secret_key", "cryptographically-strong-production-signing-key-99"
        )

        token = create_access_token(user_id="user-123", username="alice")
        assert isinstance(token, str)
        payload = decode_access_token(token)
        assert payload["username"] == "alice"


class TestImportAndUtilitySafety:
    """Tests ensuring settings instantiation and imports do not cause side effects."""

    def test_instantiating_settings_without_validation_does_not_raise(
        self,
    ) -> None:
        """Utilities instantiating Settings directly should not crash."""
        cfg = Settings(debug=False, secret_key="CHANGE-ME-IN-PRODUCTION")
        assert cfg.debug is False
        assert cfg.secret_key == "CHANGE-ME-IN-PRODUCTION"

    def test_import_main_does_not_trigger_lifespan(self) -> None:
        """Module import must not run lifespan or crash test collection."""
        import backend.main

        assert backend.main.app is not None
