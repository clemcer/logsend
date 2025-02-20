
from pydantic import (
    BaseModel,
    Field,
    field_validator,
    model_validator,
    ConfigDict,
    ValidationError
)
from typing import Dict, List, Optional, Union
import os
from typing import Dict, Union
import logging
import yaml

log_level = "INFO"
logging.getLogger().handlers.clear()
logging.basicConfig(
    level = getattr(logging, log_level.upper(), logging.INFO),
    # level = "DEBUG",
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("monitor.log", mode="w"),
        logging.StreamHandler()
    ]
)


# region Pydantic Models
class NtfyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_default=True)

    url: str = Field(..., description="Ntfy server URL")
    topic: str = Field(..., description="Ntfy topic name")
    token: Optional[str] = Field(None, description="Optional access token")
    priority: str = Field("3", description="Message priority 1-5")
    tags: str = Field("kite,mag", description="Comma-separated tags")

    @field_validator("priority")
    def validate_priority(cls, v):
        if not 1 <= int(v) <= 5:
            raise ValueError("Priority must be between 1-5")
        return v

class AppriseConfig(BaseModel):  
    model_config = ConfigDict(extra="forbid", validate_default=True)
  
    url: str = Field(..., description="Apprise compatible URL")

class ContainerConfig(BaseModel):
    model_config = ConfigDict(extra="ignore", validate_default=True)

    ntfy_tags: Optional[str] = None
    ntfy_topic: Optional[str] = None
    ntfy_priority: Optional[str] = None
    attachment_lines: Optional[int] = None
    keywords: List[Union[str, Dict[str, str]]] = []
    keywords_with_attachment: List[str] = []

    @field_validator("ntfy_priority")
    def validate_container_priority(cls, v):
        if v and not 1 <= int(v) <= 5:
            raise ValueError("Ntfy piority must be between 1-5")
        return v

class GlobalKeywords(BaseModel):
    keywords: List[str] = []
    keywords_with_attachment: List[str] = []

class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_default=True)
    
    log_level: str = Field("INFO", description="Logging level (DEBUG, INFO, WARNING, ERROR)")
    notification_cooldown: int = Field(5, description="Cooldown in seconds for repeated alerts")
    attachment_lines: int = Field(20, description="Number of log lines to include in attachments")
    multi_line_entries: bool = Field(True, description="Enable multi-line log detection")
    disable_start_message: bool = Field(False, description="Disable startup notification")
    disable_shutdown_message: bool = Field(False, description="Disable shutdown notification")
    disable_restart_message: bool = Field(False, description="Disable config reload notification")


class GlobalConfig(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        validate_default=True
    )
    containers: Dict[str, Optional[Union[ContainerConfig, List]]]

    notifications: Dict[str, Union[NtfyConfig, AppriseConfig]]
    global_keywords: GlobalKeywords
    settings: Settings

    @model_validator(mode="before")
    def transform_legacy_format(cls, values):
        # Convert list containers to dict format
        if isinstance(values.get("containers"), list):
            values["containers"] = {
                name: {} for name in values["containers"]
            }
        
        # Convert legacy global_keywords format
        if isinstance(values.get("global_keywords"), list):
            values["global_keywords"] = {
                "keywords": values["global_keywords"],
                "keywords_with_attachment": []
            }
        
        return values


def load_config():
    """
    Load config from config.yaml or override with environment variables
    """
    config = {}
    
    try:
        with open("/data/clems/Meine Dateien/PROJECTS/loggify/app/config.yaml", "r") as file:
            config = yaml.safe_load(file)
            logging.info("Konfigurationsdatei erfolgreich geladen.")
    except FileNotFoundError:
        logging.warning("config.yaml nicht gefunden. Verwende nur Umgebungsvariablen.")
    return config


def merge_yaml_and_env(yaml, env_update):
    
    for key, value in env_update.items():
        if isinstance(value, dict) and key in yaml:
            merge_yaml_and_env(yaml[key],value)
        else:
            if value:
                yaml[key] = value
    return yaml

os.environ["NTFY_URL"] = "ENV_URL"

env_config = {
    "notifications": {
        "ntfy": {
            "url": os.getenv("NTFY_URL"),
            "topic": os.getenv("NTFY_TOPIC"),
            "token": os.getenv("NTFY_TOKEN"),
            "priority": os.getenv("NTFY_PRIORITY"),
            "tags": os.getenv("NTFY_TAGS"),
        },
        "apprise": {
            "url": os.getenv("APPRISE_URL")
        }
    }
}



yaml_config = load_config()
print()
print(yaml_config)
print(f"\n\n-------------------")

merged_config = merge_yaml_and_env(yaml_config, env_config)

print(merged_config)
print(f"\n\n-------------------")


config = GlobalConfig.model_validate(merged_config)
print(config.model_dump_json(indent=2))