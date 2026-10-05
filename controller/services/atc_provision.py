"""Provision default flows.yaml for new tenants."""

import logging
import os

from controller.services import flow_step_catalog, tenant_config
from controller.utils.coerce import env_flag

logger = logging.getLogger(__name__)

ATC_PROVISION_EXISTING_TENANTS = env_flag("ATC_PROVISION_EXISTING_TENANTS")


def ensure_enrollment_flow(tenant_id: str) -> bool:
    """Ensure a tenant has a flows.yaml with the default enrollment flow.

    Returns True if new, False if exists. Never raises (errors logged)."""
    try:
        tdir = tenant_config.tenant_dir(tenant_id)
        flows_path = tdir / "flows.yaml"
        if flows_path.exists():
            return False
        tdir.mkdir(parents=True, exist_ok=True)
        doc = {
            "version": 2,
            "flows": [flow_step_catalog.default_enrollment_flow()],
        }
        tenant_config.write_yaml_atomic(flows_path, doc, tmp=tdir / f".flows.yaml.tmp.{os.getpid()}")
        tenant_config.invalidate(tenant_id)
        logger.info("ATC: provisioned default enrollment flow for tenant %s", tenant_id)
        return True
    except Exception as exc:
        logger.warning("ATC: failed to provision default enrollment flow for tenant %s: %s",
                       tenant_id, exc)
        return False
