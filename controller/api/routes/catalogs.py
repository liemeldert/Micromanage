"""Read-only catalog endpoints: device commands, flow step types, Dispatcher checks and naming variables."""
from fastapi import APIRouter, Depends

from controller.auth.dependencies import Principal, get_current_principal

router = APIRouter()


@router.get("/api/v1/commands/catalog")
async def get_command_catalog(principal: Principal = Depends(get_current_principal)):
    """Every device command this controller can send, with its parameters and the role each one takes."""
    from controller.services.command_catalog import catalog_for_role

    return {"commands": catalog_for_role(principal.is_admin)}


@router.get("/api/v1/flows/step-catalog")
async def get_flow_step_catalog(principal: Principal = Depends(get_current_principal)):
    """Every ATC flow node type with its parameters, plus the wait-signal registry.

    Same arrangement as GET /api/v1/commands/catalog: adding a node type only needs a catalog and engine change."""
    from controller.services.flow_step_catalog import catalog

    return catalog()


@router.get("/api/v1/dispatcher/check-catalog")
async def get_dispatcher_check_catalog(principal: Principal = Depends(get_current_principal)):
    """The Dispatcher compliance checks with their parameters: curated ones plus the generic attribute check.

    Same arrangement as the command and flow-step catalogs."""
    from controller.services.compliance_catalog import catalog

    return catalog()


@router.get("/api/v1/naming/variables")
async def get_naming_variables(principal: Principal = Depends(get_current_principal)):
    """The device-state variables a naming template can use, at group or tenant level.

    One server-published registry, so nothing has to guess what the controller can resolve.
    """
    from controller.services.variables import VARIABLE_SPECS

    return {"variables": VARIABLE_SPECS}
