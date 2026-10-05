"""Pydantic models for flow documents (FlowNode, Flow) and the graph and scope helpers the flow checks share."""

from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, validator

from controller.services import scoping
from controller.utils import coerce
from controller.utils.yaml_config_models import _require_match, NAME_RE, SLUG_RE


def _find_cycle_edges(edges: Dict[str, List[str]]) -> List[Tuple[str, str]]:
    """Back-edges (node, ref) that make edges cyclic. edges maps a node to its successor ids; successors not present as
    keys are ignored (dangling refs are a separate check)."""
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {n: WHITE for n in edges}
    back: List[Tuple[str, str]] = []
    for root in edges:
        if color[root] != WHITE:
            continue
        stack = [(root, iter(edges[root]))]
        color[root] = GRAY
        while stack:
            node, it = stack[-1]
            advanced = False
            for ref in it:
                if ref not in color:
                    continue  # dangling ref, reported elsewhere
                if color[ref] == GRAY:
                    back.append((node, ref))
                    continue
                if color[ref] == WHITE:
                    color[ref] = GRAY
                    stack.append((ref, iter(edges[ref])))
                    advanced = True
                    break
            if not advanced:
                color[node] = BLACK
                stack.pop()
    return back


# Anything outside these keys is ignored at runtime; the unknown-scope-key warning reports that.
_FLOW_SCOPE_KEYS = scoping.SCOPE_KEYS


def _reads_as_int(value: Any) -> bool:
    """Whether services.atc will read this as the number it says. A boolean is not a number here."""
    if isinstance(value, bool):
        return False
    try:
        int(value)
        return True
    except (TypeError, ValueError):
        return False


_reads_as_true = coerce.flag_param

# Flow steps that put something on the device's queue. A flow built only from the rest (tagging, branching, gates)
# changes nothing the device has to answer, which is what makes a run-on-every-check-in cadence safe for it.
_DEVICE_TOUCHING_STEPS = frozenset({
    "install_profiles", "install_apps", "send_command", "sync_declarations",
    "configure_accounts", "set_firmware_lock", "release_device", "set_name",
})

_scope_is_empty = scoping.scope_is_empty


def _quoted_list(items: List[str]) -> str:
    """'"a"', '"a" and "b"', '"a", "b" and "c"' for warning prose."""
    quoted = [f'"{i}"' for i in items]
    if len(quoted) <= 1:
        return quoted[0] if quoted else ""
    return ", ".join(quoted[:-1]) + " and " + quoted[-1]


def _reach_nodes(edges: Dict[str, List[str]], roots: List[str],
                 blocked: frozenset = frozenset()) -> set:
    """Node ids reachable from roots by walking edges. A blocked node is never entered."""
    seen: set = set()
    stack = [r for r in roots if r not in blocked]
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        for tgt in edges.get(n, []):
            if tgt not in seen and tgt not in blocked:
                stack.append(tgt)
    return seen


class FlowNode(BaseModel):
    """One node in a flow graph. params and edge targets are validated per-node-type imperatively, so the
    structural model stays permissive."""
    id: str
    type: str
    params: Optional[Dict[str, Any]] = {}
    next: Optional[str] = None
    on_true: Optional[str] = None
    on_false: Optional[str] = None
    on_timeout: Optional[str] = None
    # manual_gate decision handles (fixed enum; wired from params.options[].edge).
    on_release: Optional[str] = None
    on_cancel: Optional[str] = None
    on_wait: Optional[str] = None
    # Canvas position, kept apart from the logic so the YAML stays diff-friendly.
    ui: Optional[Dict[str, Any]] = None

    @validator('id')
    def validate_id(cls, v):
        return _require_match(NAME_RE, v,
                              "Flow node id must contain only alphanumeric characters, hyphens, and underscores")


class Flow(BaseModel):
    """One ATC flow out of flows.yaml; see services.flow_step_catalog. permanent marks the tenant's enrollment flow,
    draft_* marks a working copy of another flow."""
    id: str
    name: str
    description: Optional[str] = None
    enabled: Optional[bool] = True
    permanent: Optional[bool] = False
    draft_of: Optional[str] = None
    draft_base_hash: Optional[str] = None
    draft_note: Optional[str] = None
    draft_created_by: Optional[str] = None
    draft_created_at: Optional[Any] = None
    nodes: List[FlowNode]

    @validator('id')
    def validate_id(cls, v):
        return _require_match(SLUG_RE, v, "Flow id must be a slug (lowercase letters, digits, hyphens, underscores)")
