from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    gsb_api_key: str = ""
    vt_api_key: str = ""
    phishtank_api_key: str = ""
    urlscan_api_key: str = ""
    app_token: str = ""
    database_url: str = "sqlite+aiosqlite:///./safelink.db"
    redis_url: str = ""
    rules_signing_key_b64: str = ""
    # Client window is 1800 ms including network, so keep headroom (C-03).
    internal_deadline_s: float = 1.5
    rate_limit_per_minute: int = 30


settings = Settings()
