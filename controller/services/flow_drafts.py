"""Pure document surgery for ATC flow drafts.

Functions for create, promote, discard, and diff operations on drafts. See docs for detailed semantics.
"""

import copy
import logging
from typing import Any, Dict, Tuple

from controller.services import flow_step_catalog
from controller.services.flow_step_catalog import is_draft

# Must match controller.api.main._REDACTED; see docs/controller/services/flow_drafts.md.
REDACTED = "***redacted***"

logger = logging.getLogger(__name__)


class DraftError(Exception):
    def __init__(self, message: str, status: int = 400, code: str = "draft-error"):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code


def _flow_id(flow: Dict[str, Any]) -> str:
    raw = flow.get("id")
    return raw.strip() if isinstance(raw, str) else ""


def create(doc: Dict[str, Any], target_id: str, *,
           note: str = "", actor: str = "", at: str = "") -> Dict[str, Any]:
    """Create a draft of target_id in doc and return the updated document.

    Copies node params verbatim, plaintext secrets included, under the draft's own flow id (<target_id>--draft).
    """
    flows = list(doc.get("flows") or [])
    by_id = {_flow_id(f): f for f in flows if isinstance(f, dict)}
    target = by_id.get(target_id)
    if not target or is_draft(target):
        raise DraftError(f"Target flow '{target_id}' not found or is a draft", status=404,
                         code="draft-target-missing")
    draft_id = f"{target_id}--draft"
    if draft_id in by_id:
        raise DraftError(f"A draft for flow '{target_id}' already exists", status=409,
                         code="draft-duplicate")
    from controller.services import atc
    base_hash = atc._flow_hash(target)
    draft = copy.deepcopy(target)
    draft["id"] = draft_id
    draft.pop("permanent", None)
    draft.pop("enabled", None)
    draft["draft_of"] = target_id
    draft["draft_base_hash"] = base_hash
    draft["draft_note"] = note
    draft["draft_created_by"] = actor
    draft["draft_created_at"] = at

    new_flows = [f for f in flows if _flow_id(f) != draft_id] + [draft]
    return {**doc, "version": 2, "flows": new_flows}


def promote(doc: Dict[str, Any], target_id: str, *,
            force: bool = False) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Promote <target_id>--draft onto target_id.

    Returns updated document and change summary with base_drifted flag. See docs for force semantics.
    """
    flows = list(doc.get("flows") or [])
    by_id = {_flow_id(f): f for f in flows if isinstance(f, dict)}
    target = by_id.get(target_id)
    draft_id = f"{target_id}--draft"
    draft = by_id.get(draft_id)
    if not draft or not is_draft(draft) or draft.get("draft_of") != target_id:
        raise DraftError(f"No draft found for flow '{target_id}'", status=404,
                         code="draft-not-found")
    if not target:
        raise DraftError(f"Target flow '{target_id}' for draft does not exist", status=404,
                         code="draft-target-missing")

    from controller.services import atc
    current_target_hash = atc._flow_hash(target)
    stored_base_hash = draft.get("draft_base_hash")
    base_drifted = bool(stored_base_hash) and current_target_hash != stored_base_hash
    if not force and base_drifted:
        raise DraftError(
            f"Target flow '{target_id}' was modified since this draft was created. "
            "Re-review the live flow or pass force=true to overwrite.",
            status=409,
            code="draft-base-drift",
        )

    d = diff(target, draft)
    summary = dict(d.get("summary") or
                   {"added": 0, "removed": 0, "changed": 0, "unchanged": 0})
    summary["base_drifted"] = base_drifted

    promoted_target = copy.deepcopy(target)
    promoted_target["name"] = draft.get("name") or target.get("name")
    if "description" in draft:
        promoted_target["description"] = draft["description"]
    promoted_target["nodes"] = copy.deepcopy(draft.get("nodes") or [])

    new_flows = []
    for f in flows:
        fid = _flow_id(f)
        if fid == draft_id:
            continue
        elif fid == target_id:
            new_flows.append(promoted_target)
        else:
            new_flows.append(f)
    return {**doc, "version": 2, "flows": new_flows}, summary


def discard(doc: Dict[str, Any], target_id: str) -> Dict[str, Any]:
    """Discard <target_id>--draft from doc."""
    draft_id = f"{target_id}--draft"
    flows = [f for f in (doc.get("flows") or []) if isinstance(f, dict)]
    new_flows = [f for f in flows if _flow_id(f) != draft_id]
    if len(new_flows) == len(flows):
        raise DraftError(f"No draft found for flow '{target_id}'", status=404,
                         code="draft-not-found")
    return {**doc, "version": 2, "flows": new_flows}


def _display(node: Dict[str, Any]) -> Dict[str, Any]:
    """A node with its secret params replaced by the sentinel, for anything that goes back to a client."""
    params = node.get("params")
    if not isinstance(params, dict):
        return node
    names = [k for k in flow_step_catalog.secret_param_names(node.get("type"))
             if params.get(k)]
    if not names:
        return node
    return {**node, "params": {**params, **{k: REDACTED for k in names}}}


def diff(target: Dict[str, Any], draft: Dict[str, Any]) -> Dict[str, Any]:
    """Compute the semantic diff between a flow and its draft.

    Only output is redacted; ui positions excluded. See docs for redaction strategy and why it matters.
    """
    target_nodes = {n["id"]: n for n in (target.get("nodes") or [])
                    if isinstance(n, dict) and n.get("id")}
    draft_nodes = {n["id"]: n for n in (draft.get("nodes") or [])
                   if isinstance(n, dict) and n.get("id")}

    added_nodes = []
    removed_nodes = []
    changed_nodes = []
    unchanged_count = 0

    all_node_ids = sorted(set(target_nodes.keys()) | set(draft_nodes.keys()))
    node_entries = []

    for nid in all_node_ids:
        in_t = target_nodes.get(nid)
        in_d = draft_nodes.get(nid)
        if in_d and not in_t:
            entry = {"id": nid, "change": "added", "type": in_d.get("type"),
                     "params": _display(in_d).get("params") or {}}
            node_entries.append(entry)
            added_nodes.append(nid)
        elif in_t and not in_d:
            entry = {"id": nid, "change": "removed", "type": in_t.get("type")}
            node_entries.append(entry)
            removed_nodes.append(nid)
        else:
            # Both exist: compare type and params.
            p_t = in_t.get("params") or {}
            p_d = in_d.get("params") or {}
            type_changed = in_t.get("type") != in_d.get("type")
            params_changed = p_t != p_d
            if type_changed or params_changed:
                secret = (flow_step_catalog.secret_param_names(in_t.get("type"))
                          | flow_step_catalog.secret_param_names(in_d.get("type")))
                diff_params = {}
                for k in sorted(set(p_t.keys()) | set(p_d.keys())):
                    if p_t.get(k) == p_d.get(k):
                        continue
                    if k in secret:
                        diff_params[k] = {"from": REDACTED if p_t.get(k) else None,
                                          "to": REDACTED if p_d.get(k) else None}
                    else:
                        diff_params[k] = {"from": p_t.get(k), "to": p_d.get(k)}
                entry = {
                    "id": nid,
                    "change": "changed",
                    "type": in_d.get("type"),
                    "params_diff": diff_params if diff_params else None,
                }
                node_entries.append(entry)
                changed_nodes.append(nid)
            else:
                unchanged_count += 1

    # Edge diffs
    edges_t = {}
    edges_d = {}
    from controller.services.flow_step_catalog import GATE_EDGE_HANDLES, node_edges
    for nid, n in target_nodes.items():
        handles = GATE_EDGE_HANDLES if n.get("type") == "manual_gate" else node_edges(n.get("type"))
        for h in handles:
            if n.get(h):
                edges_t[(nid, h)] = n[h]
    for nid, n in draft_nodes.items():
        handles = GATE_EDGE_HANDLES if n.get("type") == "manual_gate" else node_edges(n.get("type"))
        for h in handles:
            if n.get(h):
                edges_d[(nid, h)] = n[h]

    edge_entries = []
    for (nid, h) in sorted(set(edges_t.keys()) | set(edges_d.keys())):
        tgt_t = edges_t.get((nid, h))
        tgt_d = edges_d.get((nid, h))
        if tgt_t != tgt_d:
            edge_entries.append({
                "from": nid,
                "handle": h,
                "change": "added" if not tgt_t else ("removed" if not tgt_d else "changed"),
                "to_from": tgt_t,
                "to_to": tgt_d,
            })

    from controller.services import atc
    base_hash = draft.get("draft_base_hash") or ""
    current_target_hash = atc._flow_hash(target)
    base_drifted = bool(base_hash and current_target_hash != base_hash)

    return {
        "flow_id": _flow_id(target),
        "draft_id": _flow_id(draft),
        "base_hash": base_hash,
        "base_drifted": base_drifted,
        "note": draft.get("draft_note") or "",
        "created_by": draft.get("draft_created_by") or "",
        "created_at": draft.get("draft_created_at") or "",
        "summary": {
            "added": len(added_nodes),
            "removed": len(removed_nodes),
            "changed": len(changed_nodes),
            "unchanged": unchanged_count,
        },
        "nodes": node_entries,
        "edges": edge_entries,
        "meta_diff": {
            "name": {"from": target.get("name"), "to": draft.get("name")} if target.get("name") != draft.get(
                "name") else None,
            "description": {"from": target.get("description"), "to": draft.get("description")} if target.get(
                "description") != draft.get("description") else None,
        },
    }
