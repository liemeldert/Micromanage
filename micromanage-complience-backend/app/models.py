from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime


class MacOSAppConfig(BaseModel):
    bundleId: str
    installPath: str
    minMacosVersion: str
    dmg_url: Optional[str] = None
    pkg_url: Optional[str] = None


class AppConfig(BaseModel):
    name: str
    description: str
    macos: MacOSAppConfig


class Criteria(BaseModel):
    os: Optional[str] = None
    device_identifier: Optional[str] = None


class DeviceGroup(BaseModel):
    name: str
    description: str
    criteria: List[Criteria]
    profiles: List[str]
    apps: List[str]
    check_frequency: str


class DeviceManagementConfig(BaseModel):
    apps: List[AppConfig]
    device_groups: List[DeviceGroup]


class Tenant(BaseModel):
    id: str = Field(alias="_id")
    name: str
    description: str
    members: List[str]
    mdm_url: str
    mdm_secret: str
    webhook_secret: str
    device_management_config: Optional[DeviceManagementConfig] = None
    createdAt: datetime
    updatedAt: datetime
