import re
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Self
from urllib.parse import urlsplit

from pydantic import AwareDatetime, Field, SecretStr, StringConstraints, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_PROFILE = Path(__file__).resolve().parents[1] / "config" / "profiles"
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43,128}")


class Scope(StrEnum):
    CAPABILITIES = "integration:capabilities:read"
    CREATE = "integration:tasks:create"
    TASK = "integration:tasks:read"
    CANCEL = "integration:tasks:cancel"
    EVENTS = "integration:events:read"
    ARTIFACTS = "integration:artifacts:read"
    APPROVAL = "integration:approvals:read"


IntegrationName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,47}$")]


class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NETGUARD_", hide_input_in_errors=True)

    database_path: Path = Path("data/netguard.sqlite3")


class Settings(DatabaseSettings):
    model_config = SettingsConfigDict(env_ignore_empty=True)

    profile_path: Path = DEFAULT_PROFILE / "retail-payment-hub-spoke.yaml"
    workflow_approval_ttl_seconds: Annotated[int, Field(ge=1, le=3600)] = 300
    hardware_catalog_path: Path | None = None
    llm_model: str | None = None
    llm_api_base: str | None = None
    llm_api_key: SecretStr | None = None
    honeypot_secret: SecretStr | None = None
    web_secure_cookies: bool = False
    integration_enabled: bool = False
    integration_caller: IntegrationName = "workforce"
    integration_workspace: IntegrationName = "lab"
    integration_token_sha256: SecretStr | None = None
    integration_expires_at: AwareDatetime | None = None
    integration_scopes: frozenset[Scope] = frozenset()
    demo_mode: bool = True
    viewer_token: SecretStr
    admin_token: SecretStr

    @model_validator(mode="after")
    def validate_credentials(self) -> Self:
        if bool(self.llm_model) != bool(self.llm_api_base):
            raise ValueError("Configure both the LLM model and API base or neither")
        if self.llm_model and self.llm_api_base:
            base = urlsplit(self.llm_api_base)
            ollama = self.llm_model.startswith(("ollama/", "ollama_chat/"))
            if (
                base.scheme not in ("http", "https")
                or not base.hostname
                or base.username is not None
                or base.password is not None
                or base.query
                or base.fragment
                or (
                    base.scheme == "http"
                    and base.hostname not in ("localhost", "127.0.0.1", "::1")
                )
            ):
                raise ValueError("Invalid configured LLM API base")
            if not ollama and (
                self.llm_api_key is None or not self.llm_api_key.get_secret_value()
            ):
                raise ValueError(
                    "Configure an explicit API key for the selected provider"
                )
        if self.honeypot_secret is not None and not TOKEN_PATTERN.fullmatch(
            self.honeypot_secret.get_secret_value()
        ):
            raise ValueError(
                "Generate a separate honeypot secret with token_urlsafe(32)"
            )
        if not self.demo_mode:
            raise ValueError("Foundation requires demo mode")
        viewer = self.viewer_token.get_secret_value()
        admin = self.admin_token.get_secret_value()
        if not TOKEN_PATTERN.fullmatch(viewer) or not TOKEN_PATTERN.fullmatch(admin):
            raise ValueError("Generate each local token with secrets.token_urlsafe(32)")
        if (
            self.honeypot_secret is not None
            and self.honeypot_secret.get_secret_value() in (viewer, admin)
        ):
            raise ValueError("The honeypot secret must be independent of role tokens")
        if viewer == admin:
            raise ValueError("Local roles require distinct tokens")
        if self.integration_token_sha256 is not None:
            digest = self.integration_token_sha256.get_secret_value()
            local_tokens = [viewer, admin]
            if self.honeypot_secret is not None:
                local_tokens.append(self.honeypot_secret.get_secret_value())
            if not re.fullmatch(r"[a-f0-9]{64}", digest) or any(
                sha256(token.encode()).hexdigest() == digest for token in local_tokens
            ):
                raise ValueError(
                    "Configure an independent, SHA-256 hashed integration token"
                )
        if self.integration_enabled and (
            self.integration_token_sha256 is None
            or self.integration_expires_at is None
            or self.integration_expires_at > datetime.now(UTC) + timedelta(days=30)
            or not self.integration_scopes
        ):
            raise ValueError(
                "Configure integration scopes, token digest and expiry within 30 days"
            )
        return self
