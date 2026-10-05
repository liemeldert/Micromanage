"""Collaborators the routers call through this module, so one assignment in a test replaces them for every route."""
from controller.services import enrollment, mdm_connector
from controller.services.task_manager import TaskManager

enrollment_svc = enrollment
MDMConnector = mdm_connector.MDMConnector
task_manager = TaskManager()


def _spawn_tenant_reconcile(tenant_id: str) -> None:
    """Ask for a reactive reconcile, coalesced per tenant (services.reconciler)."""
    from controller.services.reconciler import request_reconcile
    request_reconcile(tenant_id)
