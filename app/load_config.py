
from pydantic import (
    BaseModel,
    Field,
    field_validator,
    model_validator,
    ConfigDict,
    SecretStr    
)
from typing import Dict, List, Optional, Union
import os
import logging
import yaml

logging.getLogger(__name__)

""" 
THIS MAY LOOK UNNECESSARILY COMPLICATED BUT I WANTED TO LEARN AND USE PYDANTIC 
I DIDN'T MANAGE TO USE PYDANTIC WITH ENVIRONMENT VARIABLES THE WAY I WANTED. 
I NEEDED ENV TO OVERRIDE YAML DATA AND YAML TO OVERRIDE DEFAULT VALUES AND I COULD NOT GET IT TO WORK
SO NOW I FIRST LOAD THE YAML AND THE ENVIRONMENT VARIABLES, MERGE THEM AND THEN I VALIDATE THE DATA WITH PYDANTIC
"""
class NtfyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_default=True)

    url: str = Field(..., description="Ntfy server URL")
    topic: str = Field(..., description="Ntfy topic name")
    token: SecretStr = Field(default=None, description="Optional access token")
    priority: Union[str, int] = Field(default=3, description="Message priority 1-5")
    tags: str = Field("kite,mag", description="Comma-separated tags")

    @field_validator("priority")
    def validate_priority(cls, v):
        if isinstance(v, int):
            if not 1 <= int(v) <= 5:
                raise ValueError("Priority must be between 1-5")
        if isinstance(v, str):
            options = ["max", "urgent", "high", "default", "low", "min"]
            if v not in options:
                raise ValueError(f"Priority must be one of {options}")
        return v

class AppriseConfig(BaseModel):  
    model_config = ConfigDict(extra="forbid", validate_default=True)
    url: SecretStr = Field(..., description="Apprise compatible URL")

class NotificationsConfig(BaseModel):
    ntfy: Optional[NtfyConfig] = Field(default=None, validate_default=False)
    apprise: Optional[AppriseConfig] = Field(default=None, validate_default=False)

    @model_validator(mode="after")
    def check_at_least_one(self) -> "NotificationsConfig":
        if self.ntfy is None and self.apprise is None:
            raise ValueError("Mindestens eine Konfiguration (apprise oder ntfy) muss angegeben werden.")
        return self

class ContainerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_default=True)

    ntfy_tags: Optional[str] = Field(default=None, validate_default=False) 
    ntfy_topic: Optional[str] = None
    ntfy_priority: Optional[int] = None
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
    disable_restart: bool = Field(False, description="Disable restart on config change")

class GlobalConfig(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        validate_default=True
    )
    containers: Dict[str, ContainerConfig]
    global_keywords: GlobalKeywords
    notifications: NotificationsConfig
    settings: Settings

    @model_validator(mode="before")
    def transform_legacy_format(cls, values):
    
        # Convert legacy global_keywords format
        if isinstance(values.get("global_keywords"), list):
            values["global_keywords"] = {
                "keywords": values["global_keywords"],
                "keywords_with_attachment": []
            }

        # Convert list containers to dict format
        if isinstance(values.get("containers"), list):
            values["containers"] = {
                name: {} for name in values["containers"]
            }

         # Convert legacy keywords format per container
        for container in values.get("containers"):
            if isinstance(values.get("containers").get(container), list):
                values["containers"][container] = {
                    "keywords": values["containers"][container],
                    "keywords_with_attachment": []
                }
            elif values.get("containers").get(container) is None:
                values["containers"][container] = {
                    "keywords": [],
                    "keywords_with_attachment": []
                }
        return values


def merge_yaml_and_env(yaml, env_update):
    for key, value in env_update.items():
        if isinstance(value, dict) and key in yaml:
            merge_yaml_and_env(yaml[key],value)
        else:
            if value is not None:
                yaml[key] = value
    return yaml


def load_config():
    yaml_config = {}
    try:
        with open("/app/config.yaml", "r") as file:
            yaml_config = yaml.safe_load(file)
            logging.info("Konfigurationsdatei erfolgreich geladen.")
    except FileNotFoundError:
        logging.warning("config.yaml nicht gefunden. Verwende nur Umgebungsvariablen.")
    """
    -------------------------LOAD ENVIRONMENT VARIABLES---------------------
    """
    env_config = { "notifications": {}, "settings": {}}
    settings_values = {
        "log_level": os.getenv("LOG_LEVEL"),
        "attachment_lines": os.getenv("ATTACHMENT_LINES"),
        "multi_line_entries": os.getenv("MULTI_LINE_ENTRIES"),
        "notification_cooldown": os.getenv("NOTIFICATION_COOLDOWN"),
        "disable_restart": os.getenv("DISABLE_RESTART"),
        "disable_start_message": os.getenv("DISABLE_START_MESSAGE"),
        "disable_restart_message": os.getenv("DISABLE_RESTART_MESSAGE"),
        "disable_shutdown_message": os.getenv("DISABLE_SHUTDOWN_MESSAGE")
        } 
    ntfy_values =  {
        "url": os.getenv("NTFY_URL"),
        "topic": os.getenv("NTFY_TOPIC"),
        "token": os.getenv("NTFY_TOKEN"),
        "priority": os.getenv("NTFY_PRIORITY"),
        "tags": os.getenv("NTFY_TAGS"),
        }
    apprise_values = {
        "url": os.getenv("APPRISE_URL")
    }
    if any(ntfy_values.values()):
        env_config["notifications"]["ntfy"] = ntfy_values
    if apprise_values["url"]: 
        env_config["notifications"]["apprise"] = apprise_values
    for key, value in settings_values.items(): 
        if value is not None:
            env_config["settings"][key] = value

    
    print(f"\nYAML: {yaml_config}\n")

    merged_config = merge_yaml_and_env(yaml_config, env_config)
    print(f"\nENV: {env_config}\n")

    print(f"\nMERGED: {merged_config}\n")

    config = GlobalConfig.model_validate(merged_config)
    return config


# os.environ["NTFY_URL"] = "ENV_URL"
# os.environ["LOG_LEVEL"] = "ERROR"

if __name__ == "__main__":

    print(f"\n\n-------------------")


    config = load_config()
    print(config.model_dump_json(indent=1))

    # print(hasattr(config.containers["audiobookshelf"], "ntfy_topic"))
    # # print(dir(config.containers["audiobookshelf"]))

    # # print(config.containers)
    # print(config.containers["audiobookshelf"].model_dump())
    # if config.containers["audiobookshelf"].ntfy_topic:
    #     print("YES")
    # else:
    #     print("No")
    # # print(GlobalConfig.model_json_schema())#
    # for c in config.containers:
    #     print(c)
    # print(config.settings.disable_restart)

    # print("HIER")
    # value = getattr(config.containers["audiobookshelf"], "ntfy_priority", config.notifications.ntfy.priority)
    # print(value)

    # print()
    # print()
    # container_config = config.containers["audiobookshelf"].model_dump
    # print()
    # print(container_config)
    # # print(container_config.get("ntfy_priority", None))
    # print([c for c in config.containers])
    # print(config.global_keywords.keywords_with_attachment)
    # print()
    # print(list(config.global_keywords.keywords_with_attachment) + list(config.containers["audiobookshelf"].keywords))
    # print(config.notifications.apprise.url.get_secret_value())
    # for v in [key, value for key: value in config.containers["audiobookshelf"].items() if key not in ["keywords", "keywords_with_attachment"]]:
    #     if v is not None:
    #         print(v)
#     print()
# # GlobalConfig.containers["audiobookshelf"]
#     for k, v in config.containers["audiobookshelf"].model_dump().items():
#         if k not in ["keywords", "keywords_with_attachment"] and v is not None:
#             print(k)