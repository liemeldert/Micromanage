import os
from pydantic import BaseSettings

class Settings(BaseSettings):
    database_url: str = "postgres://postgres:password@localhost:5432/mdm_iac"
    nanomdm_url: str = "http://nanomdm:9000"
    nanomdm_api_key: str = ""
    yaml_config_path: str = "./yaml-configs"
    sync_interval_minutes: int = 5
    cli_key: str = ""
    
    class Config:
        env_file = ".env"

settings = Settings()