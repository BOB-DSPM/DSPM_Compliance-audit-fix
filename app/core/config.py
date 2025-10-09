from typing import Optional
from pydantic import AnyHttpUrl
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    MAPPING_API_BASE: AnyHttpUrl = "http://localhost:8003"
    AWS_REGION: str = "ap-northeast-2"
    SSO_PERMISSION_SET_MAX: int = 10
    CONFORMANCE_PACK_TEMPLATE: Optional[str] = None 

    class Config:
        env_file = ".env"

settings = Settings()
