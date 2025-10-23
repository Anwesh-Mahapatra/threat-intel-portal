from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    POSTGRES_USER: str = "tiu"
    POSTGRES_PASSWORD: str = "tiu_pass"
    POSTGRES_DB: str = "ti_portal"
    POSTGRES_HOST: str = "db"
    POSTGRES_PORT: int = 5432

    REDIS_URL: str = "redis://redis:6379/0"

    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000

    MEILI_URL: str = "http://search:7700"
    MEILI_API_KEY: str | None = None

    OTX_API_KEY: str | None = None

    THREATFOX_API_KEY: str | None = None
    THREATFOX_AUTH_KEY: str | None = None

settings = Settings()
