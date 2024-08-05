from pymongo import MongoClient
from pymongo.collection import Collection
from models import Tenant, DeviceManagementConfig
from lib.micromdm import MicroMDM
import time
from typing import List, Dict, Any
from apscheduler.schedulers.background import BackgroundScheduler


def get_mongodb_collection() -> Collection:
    client = MongoClient('mongodb://localhost:27017')
    db = client.your_database_name
    return db.tenants


def process_tenant_changes(change_stream):
    for change in change_stream:
        if change['operationType'] in ('insert', 'update', 'replace'):
            tenant = Tenant(**change['fullDocument'])
            if tenant.device_management_config:
                process_config(tenant)


def process_config(tenant: Tenant):
    mdm_api = MicroMDMAPI(tenant.mdm_url, tenant.mdm_secret)
    config = tenant.device_management_config

    for group in config.device_groups:
        devices = get_devices_for_group(mdm_api, group.criteria)

        for device in devices:
            # Check and install required apps
            for app_name in group.apps:
                app_config = next((app for app in config.apps if app.name == app_name), None)
                if app_config:
                    ensure_app_installed(mdm_api, device, app_config)

            # Apply profiles
            for profile_url in group.profiles:
                mdm_api.install_profile(device['udid'], profile_url)


def get_devices_for_group(mdm_api: MicroMDMAPI, criteria: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    all_matching_devices = []
    for criterion in criteria:
        devices = mdm_api.get_devices_by_criteria(criterion.dict(exclude_none=True))
        all_matching_devices.extend(devices)
    return list({device['udid']: device for device in all_matching_devices}.values())


def ensure_app_installed(mdm_api: MicroMDMAPI, device: Dict[str, Any], app_config: AppConfig):
    if device['os_version'].startswith('10.'):  # Assuming this is how MicroMDM reports macOS
        macos_config = app_config.macos
        if not mdm_api.is_app_installed(device['udid'], macos_config.bundleId):
            if macos_config.dmg_url:
                mdm_api.install_app(device['udid'], macos_config.dmg_url)
            elif macos_config.pkg_url:
                mdm_api.install_app(device['udid'], macos_config.pkg_url)


def schedule_checks(tenant: Tenant):
    scheduler = BackgroundScheduler()
    config = tenant.device_management_config

    for group in config.device_groups:
        interval = parse_check_frequency(group.check_frequency)
        scheduler.add_job(process_config, 'interval', seconds=interval, args=[tenant])

    scheduler.start()


def parse_check_frequency(frequency: str) -> int:
    value = int(frequency[:-1])
    unit = frequency[-1]
    if unit == 'm':
        return value * 60
    elif unit == 'h':
        return value * 3600
    else:
        raise ValueError(f"Unsupported frequency unit: {unit}")


def main():
    collection = get_mongodb_collection()
    change_stream = collection.watch()

    # Schedule checks for existing tenants
    for doc in collection.find():
        tenant = Tenant(**doc)
        if tenant.device_management_config:
            schedule_checks(tenant)

    while True:
        try:
            process_tenant_changes(change_stream)
        except Exception as e:
            print(f"An error occurred: {e}")
            time.sleep(60)  # Wait before retrying


if __name__ == "__main__":
    main()
