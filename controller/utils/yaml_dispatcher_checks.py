"""Dispatcher document checks (webhooks, rules, checks, actions) run by YAMLValidator.
The first parameter of every function is the YAMLValidator instance."""

from typing import Any, Dict, List, Optional

from controller.utils.yaml_config_models import App, Group, Profile, _model_error
from controller.utils.yaml_dispatcher_models import DispatcherAction, DispatcherRule, DispatcherWebhook
from controller.utils.yaml_flow_models import _scope_is_empty

# How long a save waits for the Dispatcher's webhook-target predicate to answer. It resolves a hostname, so it is the
# one check here that can be slowed by something outside the process; past this the save goes ahead unwarned.
_WEBHOOK_CHECK_TIMEOUT_SECONDS = 2.0


def _validate_dispatcher(validator, groups: Optional[List[Group]],
                         apps: Optional[List[App]],
                         profiles: Optional[List[Profile]],
                         known_tags: Optional[set]) -> Optional[set]:
    """Validate the optional dispatcher.yaml (compliance rules + webhooks). Returns the set of rule ids, or None
    when there is no document."""
    path = validator.tenant_path / 'dispatcher.yaml'
    if not path.exists():
        return None
    data = validator._load_yaml('dispatcher.yaml')
    if not data:
        return None

    group_names = {g.name for g in groups} if groups else set()
    profile_ids = {p.id for p in profiles} if profiles else set()
    app_ids = {a.id for a in apps} if apps else set()
    # Profiles that reach nobody through profiles.yaml, read the way the scope engine reads a profile.
    unscoped_profiles = {
        p.id for p in (profiles or [])
        if not (p.groups or []) and not (p.conditions or [])
           and not (p.include_devices or [])
    }

    webhook_names: set = set()
    for idx, wdata in enumerate(data.get('webhooks', []) or []):
        try:
            webhook = DispatcherWebhook(**wdata)
        except Exception as e:
            validator.errors.append(f"Invalid dispatcher webhook at index {idx}: {_model_error(e)}")
            continue
        if webhook.name in webhook_names:
            validator.errors.append(f"Duplicate dispatcher webhook name: {webhook.name}")
        webhook_names.add(webhook.name)
        validator._warn_webhook_target(webhook)

    rule_ids: set = set()
    for idx, rdata in enumerate(data.get('rules', []) or []):
        try:
            rule = DispatcherRule(**rdata)
        except Exception as e:
            validator.errors.append(f"Invalid dispatcher rule at index {idx}: {_model_error(e)}")
            continue
        owner = f"rule '{rule.id}'"
        if rule.id in rule_ids:
            validator.errors.append(f"Duplicate rule id: {rule.id}")
        rule_ids.add(rule.id)

        validator._check_flow_scope(f"{owner} scope", rule.scope or {}, group_names, known_tags)
        # An unscoped rule watches the whole fleet. "enabled" is read off the raw document, not the pydantic
        # field, because the two disagree on edge cases.
        if rdata.get("enabled", True) and _scope_is_empty(rule.scope):
            validator.warnings.append(
                f"Rule '{rule.id}' has no scope, so it watches every device. "
                "That is a normal choice for a fleet-wide rule. Add groups "
                "or conditions if you meant to narrow it."
            )
        validator._check_dispatcher_check(owner, rule.check or {}, profile_ids,
                                          enabled=rdata.get("enabled", True))
        for action in rule.actions or []:
            validator._check_dispatcher_action(
                owner, action, webhook_names, profile_ids, app_ids, known_tags,
                unscoped_profiles=unscoped_profiles,
            )

    return rule_ids


def _warn_webhook_target(validator, webhook: "DispatcherWebhook") -> None:
    """Say at save time what a delivery attempt to this target will do. Warnings, never errors."""
    if not webhook.secret:
        validator.warnings.append(
            f"Webhook '{webhook.name}' has no secret, so alerts are delivered "
            "unsigned and whatever receives them cannot tell an alert from this "
            "server apart from anything else that can reach that URL. Set "
            "'secret' to have each delivery carry an HMAC signature."
        )
    if validator._webhook_delivery_blocked(webhook.url):
        validator.warnings.append(
            f"Webhook '{webhook.name}' points at an address deliveries are "
            "refused for: the target resolves to a private, loopback or "
            "otherwise non-public address, and every alert aimed at it is "
            "dropped before it is sent, leaving only a line in the server log. "
            "Point it at a public address, or list this host in "
            "DISPATCHER_WEBHOOK_PRIVATE_ALLOWLIST if this server is meant to "
            "reach an internal collector. (The deprecated "
            "DISPATCHER_WEBHOOK_ALLOW_PRIVATE still works, but it admits every "
            "private target at once rather than this one.)"
        )


def _webhook_delivery_blocked(validator, url: str) -> bool:
    """The Dispatcher's own answer for this URL, asked from synchronous code. Imports the delivery path's own
    predicate rather than restating it, and runs it in a worker thread with a short deadline."""
    from concurrent.futures import ThreadPoolExecutor
    import asyncio

    try:
        from controller.services.dispatcher import _webhook_target_blocked
    except Exception:
        return False
    # No with block: that would join a stuck worker on the way out, defeating the deadline.
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        return bool(pool.submit(
            lambda: asyncio.run(_webhook_target_blocked(str(url)))
        ).result(timeout=_WEBHOOK_CHECK_TIMEOUT_SECONDS))
    except Exception:
        return False
    finally:
        pool.shutdown(wait=False)


def _check_dispatcher_check(validator, owner: str, check: Dict[str, Any],
                            profile_ids: set, enabled: Any = True) -> None:
    """Errors bind whether or not the rule runs; enabled (read the way the engine reads it) suppresses warnings only."""
    from controller.services.compliance_catalog import VALID_CHECK_TYPES

    ctype = check.get('type')
    if ctype not in VALID_CHECK_TYPES:
        validator.errors.append(f"{owner} has an unknown check type: {ctype}")
        return
    # Inputs may sit under params or flat alongside type; evaluate_check resolves both the same way.
    params = check.get('params') or {k: v for k, v in check.items() if k != 'type'}
    if ctype == 'os_below' and not str(params.get('min') or '').strip():
        validator.errors.append(f"{owner} check os_below requires a 'min' version")
    if ctype == 'not_seen_for':
        try:
            int(params.get('days'))
        except (TypeError, ValueError):
            validator.errors.append(f"{owner} check not_seen_for requires an integer 'days'")
    if ctype == 'missing_profile':
        pid = params.get('profile_id')
        if not pid:
            validator.errors.append(f"{owner} check missing_profile requires a 'profile_id'")
        elif pid not in profile_ids:
            validator.errors.append(f"{owner} check references unknown profile: {pid}")
    if ctype == 'tagged':
        tags = params.get('tags')
        if not isinstance(tags, list) or not tags:
            validator.errors.append(f"{owner} check tagged requires a non-empty 'tags' list")
    if ctype == 'flow_parked_for' and enabled:
        # Warning, unlike os_below/not_seen_for above: harmless, it simply never matches.
        try:
            float(params.get('hours'))
        except (TypeError, ValueError):
            validator.warnings.append(
                f"{owner} check flow_parked_for has no numeric 'hours', so "
                "it never fires. Set 'hours' to how long a run may sit "
                "parked before somebody should hear about it."
            )
    if ctype == 'attribute':
        if not str(params.get('key') or '').strip():
            validator.errors.append(f"{owner} check attribute requires a 'key' path")
        if params.get('operator') not in (
                'equals', 'not_equals', 'exists', 'gt', 'lt', 'regex'
        ):
            validator.errors.append(
                f"{owner} check attribute has an invalid operator: {params.get('operator')}"
            )
    if ctype == 'declaration_drift':
        ids = params.get('ids')
        if ids is not None and not isinstance(ids, list):
            validator.errors.append(
                f"{owner} check declaration_drift 'ids' must be a list of declaration ids"
            )
    if ctype == 'ddm_status':
        if not str(params.get('path') or '').strip():
            validator.errors.append(f"{owner} check ddm_status requires a 'path'")
        if params.get('operator') not in (
                'equals', 'not_equals', 'contains', 'gte', 'lte', 'exists', 'not_exists'
        ):
            validator.errors.append(
                f"{owner} check ddm_status has an invalid operator: {params.get('operator')}"
            )


def _check_dispatcher_action(validator, owner: str, action: "DispatcherAction",
                             webhook_names: set, profile_ids: set, app_ids: set,
                             known_tags: Optional[set],
                             unscoped_profiles: Optional[set] = None) -> None:
    from controller.auth import DESTRUCTIVE_COMMANDS
    from controller.services.command_catalog import (
        RETIRED_COMMANDS, VALID_COMMAND_TYPES, get_command, missing_required_params,
    )

    t = action.type
    p = action.params or {}
    valid = {"webhook", "assign_tag", "remove_tag", "install_profiles",
             "install_apps", "send_command"}
    if t not in valid:
        validator.errors.append(f"{owner} has an unknown action type: {t}")
        return

    if t == "webhook":
        target = p.get("target")
        if not target or target not in webhook_names:
            validator.errors.append(
                f"{owner} webhook action targets unknown webhook: {target}"
            )
    elif t in ("assign_tag", "remove_tag"):
        tags = p.get("tags")
        tags = tags if isinstance(tags, list) else ([tags] if tags else [])
        if not tags:
            validator.errors.append(f"{owner} {t} action requires a non-empty 'tags' list")
        if known_tags:
            for tg in (str(x) for x in tags if x):
                if tg not in known_tags:
                    validator.warnings.append(
                        f"{owner} references tag '{tg}' which is not defined in tags.yaml"
                    )
    elif t == "install_profiles":
        ids = p.get("profile_ids")
        if not isinstance(ids, list) or not ids:
            validator.errors.append(f"{owner} install_profiles action requires 'profile_ids'")
        # A remediation install is held on the device for as long as the rule exists.
        unscoped = unscoped_profiles or set()
        for pid in (ids if isinstance(ids, list) else []):
            if pid not in profile_ids:
                validator.errors.append(f"{owner} references unknown profile: {pid}")
            elif pid in unscoped:
                validator.warnings.append(
                    f"{owner} installs profile '{pid}' as a remediation, and nothing "
                    f"in profiles.yaml scopes '{pid}' to a device on its own, so "
                    "nothing releases it while this rule exists: resolving the alert "
                    "does not take it off the device, and neither does disabling the "
                    "rule."
                )
            else:
                validator.warnings.append(
                    f"{owner} installs profile '{pid}' as a remediation, and nothing "
                    "releases it while this rule exists: resolving the alert does not "
                    "take it off the device, and neither does disabling the rule."
                )
    elif t == "install_apps":
        ids = p.get("app_ids")
        if not isinstance(ids, list) or not ids:
            validator.errors.append(f"{owner} install_apps action requires 'app_ids'")
        for aid in (ids if isinstance(ids, list) else []):
            if aid not in app_ids:
                validator.errors.append(f"{owner} references unknown app: {aid}")
    elif t == "send_command":
        cmd = p.get("command")
        cparams = p.get("params")
        if cparams is not None and not isinstance(cparams, dict):
            validator.errors.append(f"{owner} send_command action 'params' must be a mapping")
        if cmd in RETIRED_COMMANDS:
            # Legal when written, warns rather than errors.
            validator.warnings.append(
                f"{owner} send_command names '{cmd}', which this deployment "
                f"retired: {RETIRED_COMMANDS[cmd]}. The action fails when the "
                "rule fires, so drop it from dispatcher.yaml or choose "
                "another command."
            )
        elif not cmd or cmd not in VALID_COMMAND_TYPES:
            validator.errors.append(f"{owner} send_command references unknown command: {cmd}")
        elif cmd in DESTRUCTIVE_COMMANDS:
            # Allowed, but the engine turns it into a pending-approval task an admin has to confirm, which is worth
            # flagging at save time.
            validator.warnings.append(
                f"{owner} send_command '{cmd}' is destructive; it will require "
                "manual admin approval and never auto-remediates"
            )
        else:
            for label in missing_required_params(get_command(cmd) or {}, cparams):
                validator.errors.append(f"{owner} send_command is missing required parameter '{label}'")
