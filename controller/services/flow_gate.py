"""Channel B of the ATC flow checks: blocks flows save only, not other config files.

See docs/controller/services/flow_gate.md for the three-channel architecture.
"""

import os
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional, Set

from controller.services.flow_step_catalog import (
    ACCOUNT_ADMIN_REQUIREMENT,
    ENROLLMENT_ONLY_START_KINDS,
    GATE_EDGE_HANDLES,
    node_edges,
    node_scope,
    start_kind_scope,
)
# Imported not reimplemented to stay in sync with validator's semantic warnings; see docs.
from controller.utils.yaml_validator import _reach_nodes

# Deployment limits, read from environment at import (can be overridden in tests).
MAX_FLOWS_PER_TENANT = int(os.getenv("ATC_MAX_FLOWS_PER_TENANT", "25"))
MAX_DRAFTS_PER_TENANT = int(os.getenv("ATC_MAX_DRAFTS_PER_TENANT", "10"))
MAX_NODES_PER_FLOW = int(os.getenv("ATC_MAX_NODES_PER_FLOW", "100"))
MAX_NODES_PER_TENANT = int(os.getenv("ATC_MAX_NODES_PER_TENANT", "600"))
MAX_SCHEDULE_STARTS_PER_TENANT = int(
    os.getenv("ATC_MAX_SCHEDULE_STARTS_PER_TENANT", "10"))
MAX_CHECKIN_STARTS_PER_TENANT = int(
    os.getenv("ATC_MAX_CHECKIN_STARTS_PER_TENANT", "10"))
MIN_SCHEDULE_INTERVAL_MINUTES = int(
    os.getenv("ATC_MIN_SCHEDULE_INTERVAL_MINUTES", "15"))
MIN_CHECKIN_COOLDOWN_MINUTES = int(
    os.getenv("ATC_MIN_CHECKIN_COOLDOWN_MINUTES", "0"))

# Findings about draft shape in the document; never marked advisory (see check_flows_document).
DRAFT_SHAPE_CODES: FrozenSet[str] = frozenset({
    "draft-target-missing",
    "draft-of-draft",
    "draft-duplicate",
})

# Codes that acknowledgement cannot waive: structural document issues, not author intent.
NON_ACKNOWLEDGEABLE: FrozenSet[str] = frozenset({
    "permanent-flow-deleted",
    "permanent-flow-renamed",
    "flow-duplicate-id",
    "flow-missing-id",
}) | DRAFT_SHAPE_CODES


@dataclass
class GateFinding:
    code: str
    message: str
    flow_id: Optional[str] = None
    node_id: Optional[str] = None
    # True for findings on drafts: drafts never block saves, only promotions (DRAFT_SHAPE_CODES never marked advisory).
    advisory: bool = False

    @property
    def acknowledgeable(self) -> bool:
        return self.code not in NON_ACKNOWLEDGEABLE

    def to_dict(self) -> Dict[str, Any]:
        return {"code": self.code, "message": self.message,
                "flow_id": self.flow_id, "node_id": self.node_id,
                "advisory": self.advisory,
                "acknowledgeable": self.acknowledgeable}


def raw_flows(doc: Any) -> List[Dict[str, Any]]:
    """The flow entries of a flows.yaml payload as authored, with nothing repaired. Accepts the current form and both
    older ones, since the raw YAML editor and the CLI can send any of them."""
    if not isinstance(doc, dict):
        return []
    listed = doc.get("flows")
    if isinstance(listed, list):
        return [f for f in listed if isinstance(f, dict)]
    single = doc.get("flow")
    return [single] if isinstance(single, dict) and single else []


def _flow_id(flow: Dict[str, Any]) -> str:
    raw = flow.get("id")
    return raw.strip() if isinstance(raw, str) else ""


def _is_draft(flow: Dict[str, Any]) -> bool:
    return bool(flow.get("draft_of"))


def _nodes(flow: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [n for n in (flow.get("nodes") or []) if isinstance(n, dict)]


def _edges(flow: Dict[str, Any]) -> Dict[str, List[str]]:
    """Adjacency for one flow, keyed by node id (mirrors yaml_validator._flow_edges)."""
    out: Dict[str, List[str]] = {}
    for node in _nodes(flow):
        nid = node.get("id")
        if not isinstance(nid, str) or nid in out:
            continue
        handles = (GATE_EDGE_HANDLES if node.get("type") == "manual_gate"
                   else node_edges(node.get("type")))
        out[nid] = [node[h] for h in handles
                    if isinstance(node.get(h), str) and node[h]]
    return out


def _start_nodes(flow: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [n for n in _nodes(flow) if n.get("type") == "start" and n.get("id")]


def _start_kind(node: Dict[str, Any]) -> str:
    kind = (node.get("params") or {}).get("kind")
    return kind if isinstance(kind, str) else ""


def _as_int(value: Any) -> Optional[int]:
    """The value only if a whole-number int, not a bool (YAML reads yes as True, int(True)=1)."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _dep_awaits(profile: Any) -> bool:
    """Whether this enrollment profile holds devices at Remote Management until a flow releases them."""

    def get(key: str) -> Any:
        if isinstance(profile, dict):
            return profile.get(key)
        return getattr(profile, key, None)

    is_dep = bool(get("dep_profile")) or (get("type") or "configuration") == "enrollment"
    if not is_dep:
        return False
    settings = get("payload") or get("enrollment") or {}
    return isinstance(settings, dict) and bool(settings.get("await_device_configured"))


def _flagged_permanent_id(flows: List[Dict[str, Any]]) -> Optional[str]:
    """The id of the flow carrying permanent: true, or None (drafts never count)."""
    for flow in flows:
        if flow.get("permanent") is True and not _is_draft(flow):
            return _flow_id(flow) or None
    return None


def _permanent_id(flows: List[Dict[str, Any]]) -> Optional[str]:
    """Which flow will BE the enrollment flow: flagged flow or first live (must match normalize_flow_document)."""
    flagged = _flagged_permanent_id(flows)
    if flagged is not None:
        return flagged
    for flow in flows:
        if not _is_draft(flow):
            return _flow_id(flow) or None
    return None


def check_flows_document(doc: Any, *, profiles: Optional[List[Any]] = None,
                         prior: Any = None) -> List[GateFinding]:
    """Every channel B finding for a candidate flows.yaml (see docs for prior/profiles params)."""
    flows = raw_flows(doc)
    findings: List[GateFinding] = []
    if not flows:
        return findings

    prior_flows = raw_flows(prior)
    perm_id = _permanent_id(flows)

    findings.extend(_check_shape(flows))
    protection = _check_protection(flows, prior_flows, perm_id)
    findings.extend(protection)
    # Skip scoping/enrollment checks if permanent-flow-deleted/renamed found; the document is refused either way.
    if not any(f.code in ("permanent-flow-deleted", "permanent-flow-renamed")
               for f in protection):
        findings.extend(_check_scoping(flows, perm_id))
        findings.extend(_check_enrollment(flows, perm_id, profiles))
    findings.extend(_check_limits(flows))

    # Mark findings on drafts as advisory except DRAFT_SHAPE_CODES (attached to document, not its content).
    drafts = {_flow_id(f) for f in flows if _is_draft(f)}
    for finding in findings:
        if (finding.flow_id and finding.flow_id in drafts
            and finding.code not in DRAFT_SHAPE_CODES):
            finding.advisory = True
    return findings


def _check_shape(flows: List[Dict[str, Any]]) -> List[GateFinding]:
    out: List[GateFinding] = []
    seen: Set[str] = set()
    live: Set[str] = set()
    for flow in flows:
        fid = _flow_id(flow)
        if not fid:
            out.append(GateFinding(
                "flow-missing-id",
                f"A flow named {flow.get('name')!r} has no id. Every flow needs a "
                "slug id: it is what run history is recorded against."))
            continue
        if fid in seen:
            out.append(GateFinding(
                "flow-duplicate-id", flow_id=fid,
                message=f"There is more than one flow with the id '{fid}'. Flow "
                        "ids have to be unique: runs are recorded against the id, "
                        "so two flows sharing one cannot be told apart afterwards."))
            continue
        seen.add(fid)
        if not _is_draft(flow):
            live.add(fid)

    all_ids = {_flow_id(f) for f in flows if _flow_id(f)}
    drafted: Set[str] = set()
    for flow in flows:
        if not _is_draft(flow):
            continue
        fid = _flow_id(flow)
        target = flow.get("draft_of")
        if not isinstance(target, str) or target not in live:
            if isinstance(target, str) and target in all_ids:
                out.append(GateFinding(
                    "draft-of-draft", flow_id=fid,
                    message=f"Draft '{fid}' drafts '{target}', which is itself a "
                            "draft. Draft the live flow instead."))
            else:
                out.append(GateFinding(
                    "draft-target-missing", flow_id=fid,
                    message=f"Draft '{fid}' drafts '{target}', which is not a live "
                            "flow in this document. A draft is a working copy, so "
                            "with nothing to promote it into it can only sit there."))
        elif target in drafted:
            out.append(GateFinding(
                "draft-duplicate", flow_id=fid,
                message=f"'{target}' already has a draft. One draft per flow: two "
                        "would both claim to be the next version of it, and "
                        "promoting either would silently discard the other."))
        else:
            drafted.add(target)
    return out


def _check_protection(flows: List[Dict[str, Any]], prior_flows: List[Dict[str, Any]],
                      perm_id: Optional[str]) -> List[GateFinding]:
    """The enrollment flow cannot be deleted, renamed, disabled, or lose its permanent flag."""
    out: List[GateFinding] = []
    prior_perm = _permanent_id(prior_flows)
    flagged = _flagged_permanent_id(flows)
    if prior_perm is None:
        return out  # first save, or a tenant that had no flows: nothing to protect

    by_id = {_flow_id(f): f for f in flows}
    prior_ids = {_flow_id(f) for f in prior_flows}

    if prior_perm not in by_id:
        # Distinguish rename from delete by whether perm_id is a new flow or None.
        if perm_id is not None and perm_id not in prior_ids:
            out.append(GateFinding(
                "permanent-flow-renamed", flow_id=perm_id,
                message=f"The enrollment flow '{prior_perm}' has been renamed to "
                        f"'{perm_id}'. Its id cannot change: every flow run ever "
                        "recorded is keyed to it, and so are the check-in cooldown "
                        "and the run-once guard. Change the flow's name instead; "
                        "only the id is fixed."))
        else:
            out.append(GateFinding(
                "permanent-flow-deleted", flow_id=prior_perm,
                message=f"The enrollment flow '{prior_perm}' is missing from this "
                        "document. It cannot be deleted: every device that enrolls "
                        "runs it, and a tenant without one leaves Automated "
                        "Enrollment devices sitting at Remote Management with "
                        "nothing coming to release them."))
        return out

    if flagged is None and perm_id != prior_perm:
        # Silent re-adoption when first live flow is the prior enrollment flow (v1 tenant normal case).
        out.append(GateFinding(
            "permanent-flow-missing", flow_id=prior_perm,
            message="No flow in this document is marked as the enrollment flow. "
                    f"'{prior_perm}' was, and without the flag '{perm_id}' would "
                    "take its place. Put the flag back on it."))
    elif flagged is not None and flagged != prior_perm:
        out.append(GateFinding(
            "permanent-flag-moved", flow_id=flagged,
            message=f"The enrollment flow has moved from '{prior_perm}' to "
                    f"'{flagged}'. That changes which flow every enrolling device "
                    "runs, and which one may hold Setup Assistant steps."))

    if by_id[prior_perm].get("enabled") is False:
        out.append(GateFinding(
            "permanent-flow-disabled", flow_id=prior_perm,
            message=f"The enrollment flow '{prior_perm}' is switched off. A "
                    "disabled flow never starts, so nothing would run when a "
                    "device enrolls."))
    return out


def _check_scoping(flows: List[Dict[str, Any]],
                   perm_id: Optional[str]) -> List[GateFinding]:
    """Setup Assistant steps belong to the enrollment flow and nowhere else."""
    out: List[GateFinding] = []
    for flow in flows:
        fid = _flow_id(flow)
        if perm_id is not None and _scope_owner(flow, perm_id) == perm_id:
            continue
        for node in _nodes(flow):
            nid = node.get("id")
            ntype = node.get("type")
            if node_scope(ntype) == "enrollment":
                out.append(GateFinding(
                    "enrollment-node-outside-enrollment-flow", flow_id=fid,
                    node_id=nid if isinstance(nid, str) else None,
                    message=f"Node '{nid}' ({ntype}) only does anything while a "
                            "device is still in Setup Assistant, so it belongs to "
                            f"the enrollment flow. Move it there, or take it out of "
                            f"'{fid}'."))
            if ntype == "start" and start_kind_scope(_start_kind(node)) == "enrollment":
                out.append(GateFinding(
                    "enrollment-trigger-outside-enrollment-flow", flow_id=fid,
                    node_id=nid if isinstance(nid, str) else None,
                    message=f"Start '{nid}' runs on enrollment, which is the "
                            "enrollment flow's trigger. Two flows starting on the "
                            "same enrollment would both provision the device."))
    return out


def _scope_owner(flow: Dict[str, Any], perm_id: Optional[str]) -> Optional[str]:
    """Whose scope rules apply: self for live flows, draft_of for drafts."""
    if _is_draft(flow):
        target = flow.get("draft_of")
        return target if isinstance(target, str) else None
    return _flow_id(flow) or None


def _check_enrollment(flows: List[Dict[str, Any]], perm_id: Optional[str],
                      profiles: Optional[List[Any]]) -> List[GateFinding]:
    """Guards on the enrollment flow itself and its drafts (see docs for breakage modes)."""
    out: List[GateFinding] = []
    if perm_id is None:
        return out
    for flow in flows:
        if _scope_owner(flow, perm_id) != perm_id:
            continue
        fid = _flow_id(flow)
        edges = _edges(flow)
        by_id = {n["id"]: n for n in _nodes(flow) if isinstance(n.get("id"), str)}
        starts = _start_nodes(flow)

        enroll_starts = [n for n in starts
                         if _start_kind(n) in ENROLLMENT_ONLY_START_KINDS]
        if not enroll_starts:
            out.append(GateFinding(
                "enrollment-no-start", flow_id=fid,
                message="The enrollment flow has no enrollment trigger, so nothing "
                        "runs when a device enrolls. Add a start on Automated "
                        "Enrollment or on OTA / manual enrollment."))

        for start in starts:
            reached = _reach_nodes(edges, [start["id"]])
            if not any(by_id.get(n, {}).get("type") == "end" for n in reached):
                out.append(GateFinding(
                    "enrollment-start-unreachable-end", flow_id=fid,
                    node_id=start["id"],
                    message=f"No path from start '{start['id']}' reaches an End "
                            "node, so a run entering here can never finish."))

        release_ids = [n["id"] for n in _nodes(flow)
                       if n.get("type") == "release_device" and n.get("id")]

        if profiles is not None and any(_dep_awaits(p) for p in profiles):
            for start in enroll_starts:
                if _start_kind(start) != "enroll_dep":
                    continue
                if not (_reach_nodes(edges, [start["id"]]) & set(release_ids)):
                    out.append(GateFinding(
                        "enrollment-dep-await-no-release", flow_id=fid,
                        node_id=start["id"],
                        message="An enrollment profile turns on 'Await final "
                                "configuration', so devices wait at Remote "
                                f"Management until a flow releases them, but no "
                                f"path from start '{start['id']}' has a Release "
                                "step. Those devices stay in Setup Assistant."))

        for rid in release_ids:
            below = _reach_nodes(edges, edges.get(rid, []))
            for aid in sorted(n for n in below
                              if by_id.get(n, {}).get("type") == "configure_accounts"):
                out.append(GateFinding(
                    "enrollment-accounts-after-release", flow_id=fid, node_id=aid,
                    message=f"Node '{aid}' can run after '{rid}' has let the device "
                            "out of Setup Assistant. Account setup only applies "
                            "while a Mac is still in Setup Assistant, so after the "
                            "release it does nothing. Move it above the release "
                            "step."))

        for node in _nodes(flow):
            if node.get("type") != "configure_accounts":
                continue
            params = node.get("params") or {}
            mode = params.get("primary_account")
            if mode in ("skip", "prompt_standard") and not params.get("managed_admin"):
                out.append(GateFinding(
                    "enrollment-accounts-no-admin", flow_id=fid,
                    node_id=node.get("id"),
                    message=f"Node '{node.get('id')}' is set to '{mode}' with no "
                            f"managed admin, so the Mac could finish setup with no "
                            f"administrator at all. {ACCOUNT_ADMIN_REQUIREMENT}."))
    return out


def _check_limits(flows: List[Dict[str, Any]]) -> List[GateFinding]:
    """Deployment caps (drafts counted separately from live flows)."""
    out: List[GateFinding] = []
    live = [f for f in flows if not _is_draft(f)]
    drafts = [f for f in flows if _is_draft(f)]

    if len(live) > MAX_FLOWS_PER_TENANT:
        out.append(GateFinding(
            "limit-flows",
            f"This document has {len(live)} flows and the deployment allows "
            f"{MAX_FLOWS_PER_TENANT} (ATC_MAX_FLOWS_PER_TENANT)."))
    if len(drafts) > MAX_DRAFTS_PER_TENANT:
        out.append(GateFinding(
            "limit-drafts",
            f"This document has {len(drafts)} drafts and the deployment allows "
            f"{MAX_DRAFTS_PER_TENANT} (ATC_MAX_DRAFTS_PER_TENANT)."))

    total_nodes = 0
    schedule_starts = 0
    checkin_starts = 0
    for flow in flows:
        fid = _flow_id(flow)
        nodes = _nodes(flow)
        total_nodes += len(nodes)
        if len(nodes) > MAX_NODES_PER_FLOW:
            out.append(GateFinding(
                "limit-nodes-per-flow", flow_id=fid,
                message=f"Flow '{fid}' has {len(nodes)} nodes and the deployment "
                        f"allows {MAX_NODES_PER_FLOW} per flow "
                        "(ATC_MAX_NODES_PER_FLOW)."))
        if _is_draft(flow):
            continue  # a draft never runs, so its starts cost no poller time
        for node in _start_nodes(flow):
            kind = _start_kind(node)
            if kind == "schedule":
                schedule_starts += 1
                interval = _as_int((node.get("params") or {}).get("interval_minutes"))
                if interval is not None and 0 < interval < MIN_SCHEDULE_INTERVAL_MINUTES:
                    out.append(GateFinding(
                        "limit-schedule-interval", flow_id=fid, node_id=node["id"],
                        message=f"Start '{node['id']}' runs every {interval} minutes "
                                f"and the deployment's floor is "
                                f"{MIN_SCHEDULE_INTERVAL_MINUTES} "
                                "(ATC_MIN_SCHEDULE_INTERVAL_MINUTES). A schedule "
                                "costs one scope evaluation per in-scope device on "
                                "every poll tick, whether or not it launches "
                                "anything."))
            elif kind == "checkin":
                checkin_starts += 1
                cooldown = _as_int((node.get("params") or {}).get("cooldown_minutes"))
                if (MIN_CHECKIN_COOLDOWN_MINUTES > 0 and cooldown is not None
                    and cooldown < MIN_CHECKIN_COOLDOWN_MINUTES):
                    out.append(GateFinding(
                        "limit-checkin-cooldown", flow_id=fid, node_id=node["id"],
                        message=f"Start '{node['id']}' has a {cooldown} minute "
                                "cooldown and the deployment's floor is "
                                f"{MIN_CHECKIN_COOLDOWN_MINUTES} "
                                "(ATC_MIN_CHECKIN_COOLDOWN_MINUTES)."))

    if total_nodes > MAX_NODES_PER_TENANT:
        out.append(GateFinding(
            "limit-nodes-per-tenant",
            f"This document has {total_nodes} nodes in total and the deployment "
            f"allows {MAX_NODES_PER_TENANT} (ATC_MAX_NODES_PER_TENANT)."))
    if schedule_starts > MAX_SCHEDULE_STARTS_PER_TENANT:
        out.append(GateFinding(
            "limit-schedule-starts",
            f"This document has {schedule_starts} scheduled starts and the "
            f"deployment allows {MAX_SCHEDULE_STARTS_PER_TENANT} "
            "(ATC_MAX_SCHEDULE_STARTS_PER_TENANT)."))
    if checkin_starts > MAX_CHECKIN_STARTS_PER_TENANT:
        out.append(GateFinding(
            "limit-checkin-starts",
            f"This document has {checkin_starts} check-in starts and the "
            f"deployment allows {MAX_CHECKIN_STARTS_PER_TENANT} "
            "(ATC_MAX_CHECKIN_STARTS_PER_TENANT)."))
    return out


def blocking(findings: List[GateFinding],
             acknowledged: Optional[Set[str]] = None) -> List[GateFinding]:
    """The findings that must stop this save (drafts/acknowledged codes downgraded to advisory)."""
    ack = acknowledged or set()
    return [f for f in findings
            if not f.advisory
            and not (f.code in ack and f.acknowledgeable)]
