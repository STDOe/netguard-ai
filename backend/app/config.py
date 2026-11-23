import re
from pathlib import Path
from typing import Self

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_PROFILE = Path(__file__).resolve().parents[1] / "config" / "profiles"
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43,128}")


class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NETGUARD_", hide_input_in_errors=True)

    database_path: Path = Path("data/netguard.sqlite3")


class Settings(DatabaseSettings):
    profile_path: Path = DEFAULT_PROFILE / "retail-payment-hub-spoke.yaml"
    demo_mode: bool = True
    viewer_token: SecretStr
    admin_token: SecretStr

    @model_validator(mode="after")
    def validate_credentials(self) -> Self:
        if not self.demo_mode:
            raise ValueError("Foundation requires demo mode")
        viewer = self.viewer_token.get_secret_value()
        admin = self.admin_token.get_secret_value()
        if not TOKEN_PATTERN.fullmatch(viewer) or not TOKEN_PATTERN.fullmatch(admin):
            raise ValueError("Generate each local token with secrets.token_urlsafe(32)")
        if viewer == admin:
            raise ValueError("Local roles require distinct tokens")
        return self
