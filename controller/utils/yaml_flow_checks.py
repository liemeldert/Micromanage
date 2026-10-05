"""Flow document checks (structure, node params, graph, warnings) run by YAMLValidator.
The first parameter of every function is the YAMLValidator instance."""

import difflib
import re
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from controller.utils.coerce import str_list
from controller.utils.yaml_config_models import (
    App, Condition, Group, Profile, _condition_tag_refs, _dep_profile_awaits, _is_dep_profile, _model_error,
)
from controller.utils.yaml_dispatcher_models import VALID_SEVERITIES
from controller.utils.yaml_flow_models import (
    Flow, FlowNode, _DEVICE_TOUCHING_STEPS, _FLOW_SCOPE_KEYS, _find_cycle_edges, _quoted_list, _reach_nodes,
    _reads_as_int, _reads_as_true, _scope_is_empty,
)


def _validate_flows(validator, groups: Optional[List[Group]],
                    apps: Optional[List[App]],
                    profiles: Optional[List[Profile]],
                    known_tags: Optional[set]) -> Optional[set]:
    """Validate the optional flows.yaml (every ATC flow in it). Returns the set of flow ids, or None when there is
    no document."""
    from controller.services.flow_step_catalog import normalize_flow_document

    path = validator.tenant_path / 'flows.yaml'
    if not path.exists():
        return None
    data = validator._load_yaml('flows.yaml')
    if not data:
        return None

    flow_docs, warns = normalize_flow_document(data)
    for w in warns:
        validator.warnings.append(w)
    if not flow_docs:
        return None

    group_names = {g.name for g in groups} if groups else set()
    profile_ids = {p.id for p in profiles} if profiles else set()
    app_ids = {a.id for a in apps} if apps else set()

    flows: List[Flow] = []
    for fdata in flow_docs:
        try:
            flows.append(Flow(**fdata))
        except Exception as e:
            validator.errors.append(f"Invalid flow: {_model_error(e)}")
    if not flows:
        return None

    # Normalization adopts a permanent flow when a document has none, so the only shape that survives to here is the
    # one it will not choose between.
    permanent = [f for f in flows if f.permanent and not f.draft_of]
    if len(permanent) > 1:
        validator.errors.append(
            "flows.yaml has more than one permanent flow ("
            + _quoted_list(sorted(f.id for f in permanent))
            + "); exactly one flow may carry 'permanent: true'"
        )
    permanent_id = permanent[0].id if len(permanent) == 1 else None

    for flow in flows:
        owner = f"flow '{flow.id}'"

        with validator._draft_errors_demoted(flow):
            nodes_by_id: Dict[str, FlowNode] = {}
            for node in flow.nodes:
                if node.id in nodes_by_id:
                    validator.errors.append(f"{owner} has a duplicate node id: {node.id}")
                    continue  # keep the first definition for graph/edge analysis
                nodes_by_id[node.id] = node

            starts = [n for n in nodes_by_id.values() if n.type == "start"]
            if not starts:
                validator.errors.append(f"{owner} has no 'start' node (add an entry point)")

            edges = validator._flow_edges(owner, flow, nodes_by_id)

            for node in flow.nodes:
                validator._check_flow_node_params(
                    owner, node, group_names, profile_ids, app_ids, known_tags
                )

            validator._check_flow_graph(owner, edges, nodes_by_id, [s.id for s in starts])

            # A draft borrows its target's standing: a draft of the enrollment flow is reviewed as the enrollment
            # flow, because that is what it becomes when somebody promotes it.
            is_enrollment = permanent_id is not None and flow.id == permanent_id
            if flow.draft_of and permanent_id is not None:
                is_enrollment = flow.draft_of == permanent_id
            validator._warn_flow_semantics(flow.id, edges, nodes_by_id,
                                           [s.id for s in starts], profiles, is_enrollment)

    return {f.id for f in flows}


@contextmanager
def _draft_errors_demoted(validator, flow: "Flow"):
    """Send a draft's structural errors to the warning channel instead. A draft never runs; nothing is
    waived, since promotion re-validates it as the live flow."""
    if not flow.draft_of:
        yield
        return
    outer = validator.errors
    validator.errors = []
    try:
        yield
    finally:
        demoted, validator.errors = validator.errors, outer
        for message in demoted:
            validator.warnings.append(f"{message} (a draft, so it does not block the save)")


def _check_flow_scope(validator, owner: str, scope: Dict[str, Any],
                      group_names: set, known_tags: Optional[set]) -> None:
    """Validate a flow trigger's match scope (conditions + group refs)."""
    if not isinstance(scope, dict):
        validator.errors.append(f"{owner} match must be a mapping")
        return
    conditions: List[Condition] = []
    for cdata in scope.get('conditions', []) or []:
        try:
            conditions.append(Condition(**cdata))
        except Exception as e:
            validator.errors.append(f"{owner} has an invalid condition: {_model_error(e)}")
    validator._check_conditions(owner, conditions, group_names)
    for g in scope.get('groups', []) or []:
        if g not in group_names:
            validator.errors.append(f"{owner} references unknown group: {g}")
    for key in ("include_devices", "exclude_devices"):
        vals = scope.get(key)
        if vals is not None and not isinstance(vals, list):
            validator.errors.append(f"{owner} {key} must be a list of serial numbers")
    if known_tags:
        validator._warn_tag_condition_refs(owner, conditions, known_tags)


def _warn_tag_condition_refs(validator, owner: str, conditions: List[Condition],
                             known_tags: set) -> None:
    for condition in conditions:
        for ref in _condition_tag_refs(condition):
            if ref not in known_tags:
                validator.warnings.append(
                    f"{owner} references tag '{ref}' which is not defined in tags.yaml"
                )


def _flow_edges(validator, owner: str, flow: Flow,
                nodes_by_id: Dict[str, "FlowNode"]) -> Dict[str, List[str]]:
    """Validate each node's edges against the step catalog and return the adjacency map (node id -> [target node
    ids])."""
    from controller.services.flow_step_catalog import (
        GATE_EDGE_HANDLES, VALID_NODE_TYPES, node_edges,
    )

    edges: Dict[str, List[str]] = {}
    for node in flow.nodes:
        if node.type not in VALID_NODE_TYPES:
            validator.errors.append(
                f"{owner} node '{node.id}' has an unknown type: {node.type}"
            )
            edges[node.id] = []
            continue
        handle_field = {
            "next": node.next, "on_true": node.on_true,
            "on_false": node.on_false, "on_timeout": node.on_timeout,
            "on_release": node.on_release, "on_cancel": node.on_cancel,
            "on_wait": node.on_wait,
        }
        # A manual_gate only requires the handles its options name; other gate handles are optional. Everything else
        # uses the static catalog edges (wait_for's on_timeout is optional -> defaults to failing the run).
        allowed = node_edges(node.type)
        if node.type == "manual_gate":
            opts = (node.params or {}).get("options") or []
            required = {o.get("edge") for o in opts
                        if isinstance(o, dict) and o.get("edge") in GATE_EDGE_HANDLES}
        else:
            required = {h for h in allowed
                        if not (node.type == "wait_for" and h == "on_timeout")}
        targets: List[str] = []
        for h in allowed:
            val = handle_field.get(h)
            if val is None:
                if h in required:
                    validator.errors.append(
                        f"{owner} node '{node.id}' ({node.type}) is missing its '{h}' edge"
                    )
                continue
            if val not in nodes_by_id:
                validator.errors.append(
                    f"{owner} node '{node.id}' edge '{h}' references unknown node: {val}"
                )
            else:
                targets.append(val)
        # Reject edges the node type does not have (e.g. a 'next' on a branch).
        for h, val in handle_field.items():
            if val is not None and h not in allowed:
                validator.errors.append(
                    f"{owner} node '{node.id}' ({node.type}) must not define a '{h}' edge"
                )
        edges[node.id] = targets
    return edges


def _check_flow_node_params(validator, owner: str, node: "FlowNode",
                            group_names: set, profile_ids: set, app_ids: set,
                            known_tags: Optional[set]) -> None:
    from controller.auth import DESTRUCTIVE_COMMANDS
    from controller.services.command_catalog import (
        RETIRED_COMMANDS, VALID_COMMAND_TYPES,
    )
    from controller.services.flow_step_catalog import (
        GATE_EDGE_HANDLES, is_start_kind, is_wait_signal,
    )
    from controller.services.variables import is_self_referential, unknown_variables

    p = node.params or {}
    where = f"{owner} node '{node.id}'"
    t = node.type

    # The engine only honours a literal false for gate; a hand-typed "false" or 0 still holds the flow up.
    if "gate" in p and not isinstance(p.get("gate"), bool):
        validator.warnings.append(
            f"{where} has gate: {p.get('gate')!r}, which is neither true nor "
            "false, so the step keeps holding the flow up. Use true or false."
        )

    if t == "start":
        kind = p.get("kind")
        if not is_start_kind(kind):
            validator.errors.append(
                f"{where} (start) has an unknown trigger kind: {kind!r}"
            )
        if kind == "schedule":
            iv = p.get("interval_minutes")
            if isinstance(iv, bool) or not isinstance(iv, int) or iv <= 0:
                validator.errors.append(
                    f"{where} (start) scheduled trigger requires a positive integer "
                    "'interval_minutes'"
                )
            elif iv < 5:
                validator.warnings.append(
                    f"{where} (start) interval_minutes={iv} is very short; a schedule "
                    "start effectively runs every poll tick below ~5 minutes"
                )
        if kind == "checkin":
            validator._warn_checkin_start_params(where, p)
        validator._check_flow_scope(f"{where} match", p.get("match") or {},
                                    group_names, known_tags)
    elif t == "manual_gate":
        if not str(p.get("summary") or "").strip():
            validator.errors.append(f"{where} (manual_gate) requires a 'summary'")
        if p.get("severity") not in VALID_SEVERITIES:
            validator.errors.append(
                f"{where} (manual_gate) severity must be one of {VALID_SEVERITIES}"
            )
        opts = p.get("options")
        if not isinstance(opts, list) or not opts:
            validator.errors.append(
                f"{where} (manual_gate) requires a non-empty 'options' list"
            )
        else:
            for o in opts:
                if not isinstance(o, dict) or not str(o.get("label") or "").strip():
                    validator.errors.append(f"{where} (manual_gate) option needs a 'label'")
                elif o.get("edge") not in GATE_EDGE_HANDLES:
                    validator.errors.append(
                        f"{where} (manual_gate) option '{o.get('label')}' has an "
                        f"invalid edge {o.get('edge')!r} (one of {GATE_EDGE_HANDLES})"
                    )
        # Optional, unlike wait_for's: an absent timeout means the engine's escalation ladder. A malformed one is
        # the same hard error as on wait_for, because the engine would silently ignore it.
        tmo = p.get("timeout_minutes")
        if tmo is not None and (isinstance(tmo, bool)
                                or not isinstance(tmo, int) or tmo <= 0):
            validator.errors.append(
                f"{where} (manual_gate) 'timeout_minutes' is optional, but when "
                "set it must be a positive integer"
            )
    elif t in ("assign_tag", "remove_tag"):
        tags = str_list(p.get("tags"))
        if not tags:
            validator.errors.append(f"{where} ({t}) requires a non-empty 'tags' list")
        if known_tags:
            for tg in tags:
                if tg not in known_tags:
                    validator.warnings.append(
                        f"{where} references tag '{tg}' which is not defined in tags.yaml"
                    )
    elif t == "set_name":
        tmpl = str(p.get("template") or "").strip()
        if not tmpl:
            validator.errors.append(f"{where} (set_name) requires a 'template'")
        else:
            for var in unknown_variables(tmpl):
                validator.warnings.append(
                    f"{where} naming template references unknown variable '{{{var}}}'"
                )
            if is_self_referential(tmpl):
                validator.warnings.append(
                    f"{where} naming template uses {{hostname}}; prefer a stable "
                    "identifier like {serial}."
                )
    elif t == "install_profiles":
        ids = p.get("profile_ids")
        if not isinstance(ids, list) or not ids:
            validator.errors.append(
                f"{where} (install_profiles) requires a non-empty 'profile_ids' list"
            )
        for pid in (ids if isinstance(ids, list) else []):
            if pid not in profile_ids:
                validator.errors.append(f"{where} references unknown profile: {pid}")
    elif t == "install_apps":
        ids = p.get("app_ids")
        if not isinstance(ids, list) or not ids:
            validator.errors.append(
                f"{where} (install_apps) requires a non-empty 'app_ids' list"
            )
        for aid in (ids if isinstance(ids, list) else []):
            if aid not in app_ids:
                validator.errors.append(f"{where} references unknown app: {aid}")
    elif t == "send_command":
        cmd = p.get("command")
        cparams = p.get("params")
        if cparams is not None and not isinstance(cparams, dict):
            validator.errors.append(f"{where} (send_command) 'params' must be a mapping")
        if cmd in RETIRED_COMMANDS:
            # Retired, not misspelled: warns rather than errors.
            validator.warnings.append(
                f"{where} (send_command) uses '{cmd}', which this deployment "
                f"retired: {RETIRED_COMMANDS[cmd]}. The step fails when the "
                "flow reaches it, so drop it from flows.yaml or choose "
                "another command."
            )
        elif not cmd or cmd not in VALID_COMMAND_TYPES:
            validator.errors.append(
                f"{where} (send_command) references unknown command: {cmd}"
            )
        elif cmd in DESTRUCTIVE_COMMANDS:
            validator.errors.append(
                f"{where} (send_command) uses destructive command '{cmd}', which is "
                "forbidden as an automated flow step"
            )
        else:
            # Catch missing required parameters at save time (mirrors command_catalog.build_generic_fields).
            # "mac"-required params are device-dependent, so only unconditionally-required ones apply.
            from controller.services.command_catalog import get_command, missing_required_params
            for label in missing_required_params(get_command(cmd) or {}, cparams):
                validator.errors.append(f"{where} (send_command) is missing required parameter '{label}'")
    elif t == "branch":
        cond = p.get("condition")
        if not isinstance(cond, dict):
            validator.errors.append(f"{where} (branch) requires a 'condition' mapping")
        else:
            try:
                c = Condition(**cond)
                validator._check_conditions(where, [c], group_names)
                if known_tags:
                    validator._warn_tag_condition_refs(where, [c], known_tags)
            except Exception as e:
                validator.errors.append(f"{where} (branch) has an invalid condition: {_model_error(e)}")
    elif t == "wait_for":
        if not is_wait_signal(p.get("signal")):
            validator.errors.append(
                f"{where} (wait_for) has an unknown signal: {p.get('signal')}"
            )
        tmo = p.get("timeout_minutes")
        if isinstance(tmo, bool) or not isinstance(tmo, int) or tmo <= 0:
            validator.errors.append(
                f"{where} (wait_for) requires a positive integer 'timeout_minutes'"
            )
    elif t == "configure_accounts":
        mode = p.get("primary_account")
        if mode not in ("prompt_admin", "prompt_standard", "skip"):
            validator.errors.append(
                f"{where} (configure_accounts) 'primary_account' must be one of "
                "prompt_admin / prompt_standard / skip"
            )
        if p.get("managed_admin"):
            src = p.get("managed_admin_password_source") or "generate"
            if src not in ("generate", "static"):
                validator.errors.append(
                    f"{where} (configure_accounts) 'managed_admin_password_source' "
                    "must be 'generate' or 'static'"
                )
            if src == "static" and not str(p.get("managed_admin_password") or "").strip():
                validator.errors.append(
                    f"{where} (configure_accounts) a static managed-admin password "
                    "source requires 'managed_admin_password'"
                )
            short = str(p.get("managed_admin_shortname") or "").strip()
            if short and not re.match(r'^[a-z_][a-z0-9_.-]*$', short):
                validator.errors.append(
                    f"{where} (configure_accounts) 'managed_admin_shortname' must be a "
                    "valid Unix short name (lowercase, starts with a letter/underscore)"
                )
        elif mode in ("skip", "prompt_standard"):
            # Warning, not error: the step itself refuses to send in this shape.
            from controller.services.flow_step_catalog import (
                ACCOUNT_ADMIN_REQUIREMENT,
            )
            validator.warnings.append(
                f"{where} (configure_accounts) is set to '{mode}' with no managed "
                f"admin, so the Mac could end up with no administrator at all. "
                f"{ACCOUNT_ADMIN_REQUIREMENT}. Enable 'managed_admin', or the step "
                "will refuse to send when the flow reaches it."
            )
    elif t == "set_firmware_lock":
        src = p.get("password_source")
        if src not in ("generate", "static"):
            validator.errors.append(
                f"{where} (set_firmware_lock) 'password_source' must be 'generate' or 'static'"
            )
        if src == "static" and not str(p.get("password") or "").strip():
            validator.errors.append(
                f"{where} (set_firmware_lock) a static password source requires 'password'"
            )


def _check_flow_graph(validator, owner: str, edges: Dict[str, List[str]],
                      nodes_by_id: Dict[str, "FlowNode"],
                      starts: List[str]) -> None:
    """Reject reachable cycles (a flow must be a DAG), require every start to reach an end, and warn on nodes
    unreachable from any start. Reachability is computed before cycle detection."""
    starts = [s for s in starts if s in nodes_by_id]
    if not starts:
        return  # no-start already reported by the caller

    reachable = _reach_nodes(edges, starts)
    reachable_edges = {
        n: [t for t in edges.get(n, []) if t in reachable] for n in reachable
    }
    cycles = _find_cycle_edges(reachable_edges)
    for node, ref in cycles:
        validator.errors.append(
            f"{owner} has a cycle involving '{node}' and '{ref}' "
            "(a flow must be acyclic)"
        )

    if not cycles:
        for s in starts:
            if not any(nodes_by_id[n].type == "end"
                       for n in _reach_nodes(edges, [s]) if n in nodes_by_id):
                validator.errors.append(
                    f"{owner} has no reachable 'end' node from start '{s}'"
                )
    for nid in nodes_by_id:
        if nid not in reachable:
            validator.warnings.append(f"{owner} node '{nid}' is unreachable from any start")


def _warn_checkin_start_params(validator, where: str, params: Dict[str, Any]) -> None:
    """Say when a check-in start's two knobs will not be read as written. services.atc reads both defensively and
    never raises."""
    from controller.services.atc import CHECKIN_COOLDOWN_DEFAULT_MINUTES

    if "cooldown_minutes" in params and not _reads_as_int(params["cooldown_minutes"]):
        # Booleans are the case worth catching: YAML reads a bare yes as True and int(True) is 1, so the key meant
        # to space runs out would set a one-minute cooldown. atc._checkin_cooldown_minutes refuses the coercion too.
        validator.warnings.append(
            f"{where} (start) cooldown_minutes is {params['cooldown_minutes']!r}, "
            "which is not a number of minutes, so the engine ignores it and waits "
            f"the default {CHECKIN_COOLDOWN_DEFAULT_MINUTES} minutes between runs "
            "on a device. Write a whole number of minutes, or 0 to run on every "
            "check-in."
        )
    if "once" in params and not isinstance(params["once"], bool):
        # atc._truthy_param reads a string as a word rather than by emptiness, so "false" and "no" are off, and so
        # is anything outside its four words, which is how a start meant to run once ends up running forever.
        reading = "true" if _reads_as_true(params["once"]) else "false"
        validator.warnings.append(
            f"{where} (start) once is {params['once']!r}, which is not true or "
            f"false, so the engine reads it as {reading}. Write it as a boolean to "
            "say which you meant."
        )


def _flow_warn(validator, flow_id: str, node_id: Optional[str], code: str,
               message: str) -> None:
    """One structured flow warning, mirrored into the plain warnings list too."""
    validator.warnings.append(message)
    validator.flow_warnings.append({"flow_id": flow_id, "node_id": node_id,
                                    "code": code, "message": message})


def _warn_flow_semantics(validator, flow_id: str, edges: Dict[str, List[str]],
                         nodes_by_id: Dict[str, "FlowNode"],
                         starts: List[str],
                         profiles: Optional[List[Profile]],
                         is_enrollment: bool) -> None:
    """Semantic flow warnings: graphs the engine runs fine but that rarely mean what the author meant. Warnings
    only, never errors."""
    live = _reach_nodes(edges, starts)
    release_ids = [nid for nid, n in nodes_by_id.items()
                   if n.type == "release_device"]

    # release-ordering is a warning, not an error, since releasing early is a legitimate choice for some fleets.
    for nid, node in nodes_by_id.items():
        barrier = validator._INSTALL_BARRIERS.get(node.type)
        if not barrier or nid not in live:
            continue
        if (node.params or {}).get("gate") is False:
            continue
        signal, what = barrier
        barriers = frozenset(
            b for b, bn in nodes_by_id.items()
            if bn.type == "wait_for" and (bn.params or {}).get("signal") == signal
        )
        unbarriered = _reach_nodes(edges, edges.get(nid, []), blocked=barriers)
        for rid in release_ids:
            if rid in unbarriered:
                validator._flow_warn(
                    flow_id, rid, "release-ordering",
                    f'Node "{rid}" can release devices before {what} from "{nid}" are confirmed installed. Add a wait '
                    f'step between them if the {what} must land first.'
                )

    # A wait that holds nothing back on any run (_wait_already_satisfied skips it).
    for signal, wording in validator._WAIT_PRODUCERS.items():
        ptype, subject, none_above, step_label = wording
        waits = frozenset(
            nid for nid, n in nodes_by_id.items()
            if n.type == "wait_for" and (n.params or {}).get("signal") == signal
        )
        producers = [nid for nid, n in nodes_by_id.items()
                     if n.type == ptype and nid in live]
        gated = [p for p in producers
                 if (nodes_by_id[p].params or {}).get("gate") is not False]
        gated_roots = [t for p in gated for t in edges.get(p, [])]
        for wid in sorted(w for w in waits if w in live):
            # gate: false on the wait itself is the author saying this one is allowed to find nothing waiting. Take
            # them at their word.
            if (nodes_by_id[wid].params or {}).get("gate") is False:
                continue
            if wid in _reach_nodes(edges, gated_roots, blocked=waits - {wid}):
                continue  # a producer reaches it with its list still intact
            head = f'Node "{wid}" waits for {subject}, but '
            from_producers = _reach_nodes(edges, gated_roots)
            ungated = sorted(p for p in producers if p not in gated
                             and wid in _reach_nodes(edges, edges.get(p, [])))
            if wid in from_producers:
                # Reachable from a producer, but only through an earlier wait on the same signal, which took the
                # list with it.
                earlier = _quoted_list(sorted(
                    b for b in waits - {wid}
                    if b in from_producers
                    and wid in _reach_nodes(edges, edges.get(b, []))
                ))
                body = (f'{earlier} above it already waited for the same thing, '
                        'and a wait clears its list when it finishes, so this one '
                        'holds nothing back and the run carries straight on. Take '
                        f'this wait out, or put {step_label} step between it and '
                        f'{earlier}.')
            elif ungated:
                names = _quoted_list(ungated)
                verb = "is" if len(ungated) == 1 else "are"
                fix = ("Turn that back on" if len(ungated) == 1
                       else "Turn one of those back on")
                body = (f'{names} above it {verb} set not to hold the flow up '
                        '(gate: false), so nothing is queued for this wait to hold '
                        f'and the run carries straight on. {fix}, or take the wait '
                        'out.')
            else:
                body = (f'no step above it {none_above}, so this wait holds nothing '
                        'back and the run carries straight on. Put '
                        f'{step_label} step above it, or take the wait out.')
            validator._flow_warn(flow_id, wid, "barrier-empty", head + body)

    # accounts-after-release: AccountConfiguration only takes effect before Setup Assistant ends.
    for rid in sorted(r for r in release_ids if r in live):
        for aid in sorted(n for n in _reach_nodes(edges, edges.get(rid, []))
                          if n in nodes_by_id
                             and nodes_by_id[n].type == "configure_accounts"):
            validator._flow_warn(
                flow_id, aid, "accounts-after-release",
                f'Node "{aid}" can run after "{rid}" has let the device out of '
                'Setup Assistant, and account setup only lands while a Mac is '
                'still in Setup Assistant, so it does nothing there. Move it above '
                'the release step.'
            )

    # DEP await_device_configured with no release on the path: the device sits at Remote Management until a
    # release_device step (or a human) sends DeviceConfigured, and nothing on the timeline says why.
    dep_profiles = ([p for p in profiles or [] if _is_dep_profile(p)]
                    if is_enrollment else [])
    awaiting = [p.id for p in dep_profiles if _dep_profile_awaits(p)]
    if awaiting:
        names = _quoted_list(awaiting)
        label = "profile" if len(awaiting) == 1 else "profiles"
        verb = "sets" if len(awaiting) == 1 else "set"
        head = (f'DEP {label} {names} {verb} await_device_configured, so '
                'devices wait at Remote Management until this flow releases them, ')
        dep_starts = [sid for sid in starts
                      if (nodes_by_id[sid].params or {}).get("kind") == "enroll_dep"]
        if not dep_starts:
            validator._flow_warn(
                flow_id, None, "dep-await-no-release",
                head + 'but this flow has no Automated Enrollment start. Those devices stay in Setup Assistant until '
                       'someone releases them by hand.'
            )
        else:
            for sid in dep_starts:
                if not (_reach_nodes(edges, [sid]) & set(release_ids)):
                    validator._flow_warn(
                        flow_id, sid, "dep-await-no-release",
                        head + f'but no path from start "{sid}" has a '
                               'release_device step. Devices that enroll through '
                               'this start stay in Setup Assistant.'
                    )
    elif dep_profiles:
        # release-without-await, the converse case: a release step with no DEP profile waiting on it.
        for rid in sorted(r for r in release_ids if r in live):
            validator._flow_warn(
                flow_id, rid, "release-without-await",
                f'Node "{rid}" releases devices from Setup Assistant, but none of '
                'this tenant\'s enrollment profiles turns on '
                'await_device_configured ("Await final configuration"), so no '
                'device is ever held there and this step does nothing. Turn that '
                'setting on in the enrollment profile if devices should wait for '
                'this flow to finish.'
            )

    # checkin-every-event. Only an explicit cooldown_minutes: 0 runs a start on every check-in.
    for sid in starts:
        params = nodes_by_id[sid].params or {}
        if params.get("kind") != "checkin" or _reads_as_true(params.get("once")):
            continue
        # Read as atc._checkin_cooldown_minutes reads it; a non-numeric value draws its own warning elsewhere.
        if not _reads_as_int(params.get("cooldown_minutes")):
            continue
        if max(int(params["cooldown_minutes"]), 0) > 0:
            continue
        touching = sorted(
            nid for nid in _reach_nodes(edges, [sid])
            if nodes_by_id[nid].type in _DEVICE_TOUCHING_STEPS
        )
        if not touching:
            continue
        validator._flow_warn(
            flow_id, sid, "checkin-every-event",
            f'Start "{sid}" runs on every check-in (cooldown_minutes: 0) and '
            f'reaches {", ".join(repr(n) for n in touching)}, which queue work '
            'on the device. Each answer the device sends is another check-in, '
            'so the flow can keep restarting itself for as long as the device '
            'stays connected. Leave cooldown_minutes unset for the default '
            'wait, or keep 0 only for a flow that just tags or branches.'
        )

    # Start scope shapes that match something other than what was typed.
    for sid in starts:
        match = (nodes_by_id[sid].params or {}).get("match")
        # No scope matches every device. Plain warnings channel, not _flow_warn, to avoid drowning it.
        if _scope_is_empty(match):
            validator.warnings.append(
                f'Start "{sid}" has no scope, so it fires for every device of '
                'its trigger kind. That is a normal choice for a fleet-wide '
                'flow. Add groups or conditions if you meant to narrow it.'
            )
        if not isinstance(match, dict):
            continue
        # Only exclusions set: evaluate_scope needs groups, conditions or include_devices to match anyone, so this
        # start never runs.
        if match.get("exclude_devices") and not any(
            match.get(k) for k in ("groups", "conditions", "include_devices")):
            validator._flow_warn(
                flow_id, sid, "exclude-only-scope",
                f'Start "{sid}" matches no devices because its scope only '
                'excludes devices. Add groups or conditions to say which '
                'devices it covers; an exclude list by itself matches nothing.'
            )
        # Unknown keys are ignored at runtime, so a typo such as "group" for "groups" silently stops narrowing the
        # scope.
        for key in sorted(k for k in match if k not in _FLOW_SCOPE_KEYS):
            close = difflib.get_close_matches(str(key), _FLOW_SCOPE_KEYS, 1, 0.6)
            tail = (f'Did you mean "{close[0]}"?' if close
                    else "Valid keys: " + ", ".join(_FLOW_SCOPE_KEYS) + ".")
            validator._flow_warn(
                flow_id, sid, "unknown-scope-key",
                f'Start "{sid}" scope has an unknown key "{key}". The engine '
                'ignores unknown keys, so this key does not narrow which '
                f'devices match. {tail}'
            )
