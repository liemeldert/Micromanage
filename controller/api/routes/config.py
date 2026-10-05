"""YAML configuration management, validation, versioning, and history endpoints."""
from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response
import yaml

from controller.api.config_io import _atomic_write_yaml, _config_document_text, _tenant_config_doc
from controller.api.redaction import (
    _redact_s3_config,
    config_redactor,
    redact_config_history,
    restore_config_secrets,
)
from controller.api import runtime
from controller.auth import MEMBER_WRITABLE_CONFIG_TYPES
from controller.auth.dependencies import Principal, get_current_principal
from controller.services import filevault_escrow
from controller.services.audit import record_audit
from controller.services.tenant_config import (
    tenant_dir as _tenant_dir,
    yaml_base as _yaml_base,
)
from controller.utils.yaml_validator import YAMLValidator

logger = logging.getLogger(__name__)

router = APIRouter()

_EDITABLE_CONFIG_TYPES = ["groups", "apps", "profiles", "tags", "flows", "dispatcher",
                          "declarations"]
_READABLE_CONFIG_TYPES = _EDITABLE_CONFIG_TYPES + ["config"]

_OPTIONAL_CONFIG_FILES = ["tags.yaml", "flows.yaml", "dispatcher.yaml", "declarations.yaml"]

_RAW_YAML_KEY = "__yaml_text__"

_RAW_YAML_MAX_CHARS = 512 * 1024

_CONFIG_VERSION_HEADER = "X-Config-Version"


def _config_version(path: Path) -> Optional[str]:
    """Version of the config document on disk; None when there is no file."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        return None
    except OSError:
        logger.exception("config: cannot read %s to version it", path)
        return None


def _check_config_version(yaml_path: Path, if_match: Any) -> None:
    """Refuse a write whose base version differs from the one on disk."""
    expected = if_match.strip().strip('"') if isinstance(if_match, str) else ""
    if not expected:
        return
    current = _config_version(yaml_path)
    if current is None or current == expected:
        return
    raise HTTPException(status_code=409, detail={
        "error": "conflict",
        "message": "This document was changed by someone else since you loaded it. Reload and reapply your edits.",
        "current_version": current,
    })


def _set_config_version_header(response: Any, yaml_path: Path) -> None:
    """Report the version a write just produced, for the client to keep editing.

    response is None when the test suite calls the route function directly instead of serving it.
    """
    if response is None:
        return
    version = _config_version(yaml_path)
    if version:
        response.headers[_CONFIG_VERSION_HEADER] = version


def _gate_profiles(principal: Principal):
    """The tenant's enrollment profiles for the flow gate's DEP cross-check.

    Returns None, never [], on a read failure; the gate treats None as unchecked and [] as checked and clear."""
    from controller.services import tenant_config

    try:
        return tenant_config.load_profiles(str(principal.tenant.id))
    except Exception:
        logger.exception("flows: could not read profiles for the save gate")
        return None


@router.get("/api/v1/config/{config_type}")
async def get_yaml_config(
    config_type: str,
    raw: bool = False,
    principal: Principal = Depends(get_current_principal),
    response: Response = None,
):
    """Get one tenant's YAML configuration by type (groups, apps, profiles, config), or, with raw=true, the redacted
    document itself as text/plain."""
    if config_type not in _READABLE_CONFIG_TYPES:
        raise HTTPException(status_code=400, detail="Invalid config type")

    tenant = principal.tenant
    yaml_path = _tenant_dir(tenant.id) / f"{config_type}.yaml"

    if not yaml_path.exists():
        raise HTTPException(status_code=404, detail="Configuration not found")

    with open(yaml_path, "r") as f:
        text = f.read()
    version = _config_version(yaml_path)
    config = yaml.safe_load(text) or {}

    # config.yaml embeds tenant.s3, which can carry credentials.
    redacted = False
    if config_type == "config" and isinstance(config.get("tenant"), dict):
        if "s3" in config["tenant"]:
            config["tenant"]["s3"] = _redact_s3_config(config["tenant"]["s3"])
            redacted = True
    # Webhook urls and secrets, flow node passwords, and profile payload secrets. A dispatcher.yaml read always counts
    # as redacted.
    redact = config_redactor(config_type, principal.is_admin)
    if redact is not None:
        redacted_config = redact(config)
        redacted = redacted or config_type == "dispatcher" or redacted_config != config
        config = redacted_config

    if raw:
        # Serve the authored file verbatim (comments intact) unless redaction forced a re-render.
        body = yaml.safe_dump(config, default_flow_style=False, sort_keys=False) if redacted else text
        return Response(content=body, media_type="text/plain; charset=utf-8",
                        headers={_CONFIG_VERSION_HEADER: version} if version else None)

    if config_type == "flows":
        from controller.services.flow_step_catalog import normalize_flow_document
        flows, _warns = normalize_flow_document(config)
        config = {"version": 2, "flows": flows}

    if response is not None and version:
        response.headers[_CONFIG_VERSION_HEADER] = version
    return config


# Config history: every successful save snapshots the previous document, so a breaking change can be rolled back.
_HISTORY_LIMIT = 50
_HISTORY_ID_RE = re.compile(r"^\d{8}T\d{6,12}Z$")


def _history_dir(tenant_id: str, config_type: str) -> Path:
    return _tenant_dir(tenant_id) / "_history" / config_type


def _snapshot_config_history(tenant_id: str, config_type: str, user: str) -> Optional[str]:
    """Snapshot the current on-disk config before it is overwritten, best-effort so a history failure never blocks
    the save. Returns the snapshot's version id, or None if it was skipped or failed."""
    src = _tenant_dir(tenant_id) / f"{config_type}.yaml"
    if not src.exists():
        return None
    try:
        hdir = _history_dir(tenant_id, config_type)
        hdir.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc)
        vid = now.strftime("%Y%m%dT%H%M%S%fZ")
        (hdir / f"{vid}.json").write_text(json.dumps({
            "id": vid,
            "saved_at": now.isoformat(),
            "user": user,
            "content": src.read_text(),
        }))
        # Prune oldest beyond the cap (ids are lexicographically time-ordered).
        entries = sorted(hdir.glob("*.json"))
        for old in entries[:-_HISTORY_LIMIT]:
            old.unlink()
        return vid
    except (OSError, ValueError):
        # A non-UTF-8 outgoing file raises UnicodeDecodeError, which is a ValueError.
        logger.exception("config history snapshot failed for %s/%s", tenant_id, config_type)
        return None


def _autofill_rollout_starts(config_type: str, config_data: Dict[str, Any]) -> None:
    """Stamp rollout.start (now, UTC) on any rollout block that lacks one.

    Wave math needs a fixed start in the document to keep the runtime stateless; clearing it restarts the waves.
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    def fill(obj: Any) -> None:
        if not isinstance(obj, dict):
            return
        rollout = obj.get("rollout")
        if isinstance(rollout, dict) and rollout and not rollout.get("start"):
            rollout["start"] = now_iso

    if config_type == "profiles":
        for profile in config_data.get("profiles") or []:
            fill(profile)
    elif config_type == "declarations":
        # A declaration rollout without a start makes the coverage function fail open at 100%, so the whole fleet gets
        # it at once (services.ddm_manager).
        for declaration in config_data.get("declarations") or []:
            fill(declaration)
    elif config_type == "apps":
        for app_entry in config_data.get("apps") or []:
            if isinstance(app_entry, dict):
                for version in app_entry.get("versions") or []:
                    fill(version)


@router.put("/api/v1/config/{config_type}")
async def update_yaml_config(
    config_type: str,
    config_data: Dict[str, Any],
    principal: Principal = Depends(get_current_principal),
    dry_run: bool = False,
    acknowledge: Optional[str] = Query(None, description="Comma-separated gate finding codes to acknowledge"),
    if_match: Optional[str] = Header(None, alias="If-Match"),
    response: Response = None,
):
    """Replace one YAML config document after validating it (admin only outside MEMBER_WRITABLE_CONFIG_TYPES),
    supporting dry_run and If-Match concurrency control."""
    yaml_text = config_data.pop(_RAW_YAML_KEY, None)
    if not isinstance(yaml_text, str):
        yaml_text = None
    elif len(yaml_text) > _RAW_YAML_MAX_CHARS:
        logger.warning("config: %s text for %s is %d characters, over the %d cap; saving the document without it",
                       _RAW_YAML_KEY, config_type, len(yaml_text), _RAW_YAML_MAX_CHARS)
        yaml_text = None
    if config_type not in _EDITABLE_CONFIG_TYPES:
        raise HTTPException(status_code=400, detail="Invalid config type")
    if config_type not in MEMBER_WRITABLE_CONFIG_TYPES and not principal.is_admin:
        raise HTTPException(
            status_code=403,
            detail=f"Editing '{config_type}' requires the admin role",
        )
    yaml_path = _tenant_dir(principal.tenant.id) / f"{config_type}.yaml"
    # Ahead of every side effect, so a conflict leaves no snapshot, no audit row and no reconcile behind.
    if not dry_run:
        _check_config_version(yaml_path, if_match)
    # Put back any secret that came back redacted, before validation and the write.
    restore_config_secrets(config_type, principal.tenant.id, config_data)

    acknowledged_set = (
        {c.strip() for c in acknowledge.split(",") if c.strip()}
        if isinstance(acknowledge, str)
        else set()
    )
    gate_findings: List[Dict[str, Any]] = []
    if config_type == "flows":
        from controller.services import flow_gate, tenant_config
        prior_doc = tenant_config._load(str(principal.tenant.id), "flows.yaml")
        findings = flow_gate.check_flows_document(
            config_data, profiles=_gate_profiles(principal), prior=prior_doc)
        gate_findings = [f.to_dict() for f in findings]
        blocking_findings = flow_gate.blocking(findings, acknowledged_set)
        if blocking_findings and not dry_run:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "Flow save gate refused this document",
                    "gate_findings": gate_findings,
                },
            )

    result = await _apply_config_update(principal, config_type, config_data,
                                        dry_run=dry_run, yaml_text=yaml_text)
    if config_type == "flows":
        result["gate_findings"] = gate_findings
        if not dry_run and acknowledged_set:
            from controller.services.audit import record_audit
            effective_ack = [f["code"] for f in gate_findings if f["code"] in acknowledged_set]
            if effective_ack:
                await record_audit(
                    principal, "flow.gate_acknowledged",
                    target_type="config", target_id="flows",
                    detail={"codes": effective_ack},
                )
    if not dry_run:
        _set_config_version_header(response, yaml_path)
    return result


async def _apply_config_update(
    principal: Principal, config_type: str, config_data: Dict[str, Any],
    dry_run: bool = False, yaml_text: Optional[str] = None,
) -> Dict[str, Any]:
    """Shared validate, snapshot, write and reconcile path used by both a normal save and a history restore.

    dry_run stops after validation and reports the result instead of raising.
    """
    tenant = principal.tenant
    tenant_dir = _tenant_dir(tenant.id)
    # New rollout blocks get their wave clock started at save time.
    _autofill_rollout_starts(config_type, config_data)
    yaml_path = tenant_dir / f"{config_type}.yaml"
    # A tenant created through the console or bootstrap exists in the DB but may have no config dir on disk yet.
    try:
        if not dry_run:
            tenant_dir.mkdir(parents=True, exist_ok=True)
            config_yaml = tenant_dir / "config.yaml"
            if not config_yaml.exists():
                _atomic_write_yaml(config_yaml, _tenant_config_doc(tenant))
            from controller.services import atc_provision
            atc_provision.ensure_enrollment_flow(str(tenant.id))
    except OSError as exc:
        # Almost always permissions: the controller runs as uid 1000 and the yaml-configs volume is root-owned.
        logger.exception("Cannot prepare tenant config dir %s", tenant_dir)
        raise HTTPException(
            status_code=500,
            detail=(
                f"Server cannot write the config directory ({tenant_dir}): {exc}. "
                "The controller runs as uid 1000, so the yaml-configs volume needs "
                "to be owned by 1000:1000. The yaml-init service in "
                "docker-compose.prod.yml handles that."
            ),
        )

    # Validate the candidate against a private copy of the tenant dir, so cross-file checks run without touching a live
    # file until it is valid. validate_all() requires all four files, so any missing on disk get a minimal stub.
    stubs = {
        "config.yaml": {"tenant": {"id": tenant.id, "name": tenant.name, "allowed_users": []}},
        "groups.yaml": {"groups": []},
        "apps.yaml": {"apps": []},
        "profiles.yaml": {"profiles": []},
    }
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        for fn in ["config.yaml", "groups.yaml", "apps.yaml", "profiles.yaml"]:
            src = tenant_dir / fn
            if src.exists():
                shutil.copy(src, tdp / fn)
            else:
                with open(tdp / fn, "w") as f:
                    yaml.safe_dump(stubs[fn], f, default_flow_style=False)
        # Optional docs (e.g. tags.yaml) are copied when present so cross-document checks resolve during any save; they
        # have no required stub.
        for fn in _OPTIONAL_CONFIG_FILES:
            src = tenant_dir / fn
            if src.exists():
                shutil.copy(src, tdp / fn)
        # Overwrite the file being updated with the submitted candidate data (this wins even if the same file was copied
        # above as an optional doc).
        with open(tdp / f"{config_type}.yaml", "w") as f:
            yaml.safe_dump(config_data, f, default_flow_style=False)

        validator = YAMLValidator(
            tdp,
            filevault_escrow_configured=filevault_escrow.is_configured(tenant))
        valid, errors, warnings = validator.validate_all()
        flow_warnings = validator.flow_warnings

    if dry_run:
        return {"valid": valid, "errors": errors, "warnings": warnings,
                "flow_warnings": flow_warnings}

    if not valid:
        raise HTTPException(
            status_code=400, detail={"errors": errors, "warnings": warnings}
        )

    # Snapshot the outgoing document so this save can be rolled back.
    history_id = _snapshot_config_history(tenant.id, config_type, principal.email)

    try:
        _atomic_write_yaml(
            yaml_path, config_data,
            text=_config_document_text(yaml_path, config_data, yaml_text),
        )
    except OSError as exc:
        logger.exception("Cannot write %s", yaml_path)
        raise HTTPException(
            status_code=500,
            detail=f"Server failed to persist {config_type} configuration: {exc}",
        )

    # The history snapshot labels the OUTGOING document with the INCOMING saver's email; no document content in the
    # audit detail, since apps, profiles and flows can all carry secrets.
    await record_audit(
        principal,
        "config.update",
        target_type="config",
        target_id=config_type,
        detail={"warnings": len(warnings)} if warnings else None,
    )

    # Reconcile reactively so the change produces tasks now, not at the next scheduled sync (which remains the periodic
    # safety net).
    runtime._spawn_tenant_reconcile(tenant.id)

    return {"message": f"{config_type} configuration updated",
            "warnings": warnings, "flow_warnings": flow_warnings,
            "history_id": history_id}


@router.post("/api/v1/config/validate")
async def validate_yaml_configs(principal: Principal = Depends(get_current_principal)):
    """Validate this tenant's config documents as they stand on disk, and return the errors, warnings and flow warnings.
    Writes nothing."""
    tenant = principal.tenant
    validator = YAMLValidator(
        _tenant_dir(tenant.id),
        filevault_escrow_configured=filevault_escrow.is_configured(tenant))

    valid, errors, warnings = validator.validate_all()

    return {"valid": valid, "errors": errors, "warnings": warnings,
            "flow_warnings": validator.flow_warnings}


def _load_history_entry(tenant_id: str, config_type: str, version_id: str) -> Dict[str, Any]:
    if config_type not in _EDITABLE_CONFIG_TYPES:
        raise HTTPException(status_code=400, detail="Invalid config type")
    if not _HISTORY_ID_RE.match(version_id):
        raise HTTPException(status_code=400, detail="Invalid version id")
    path = _history_dir(tenant_id, config_type) / f"{version_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Version not found")
    try:
        entry = json.loads(path.read_text())
    except (OSError, ValueError):
        logger.exception("unreadable history entry %s", path)
        raise HTTPException(status_code=500, detail="History entry is unreadable")
    if not isinstance(entry, dict):  # valid JSON, but not an object
        raise HTTPException(status_code=500, detail="History entry is malformed")
    return entry


@router.get("/api/v1/config/{config_type}/history")
async def list_config_history(
    config_type: str,
    principal: Principal = Depends(get_current_principal),
):
    """Previous versions of a config document (newest first)."""
    if config_type not in _EDITABLE_CONFIG_TYPES:
        raise HTTPException(status_code=400, detail="Invalid config type")
    hdir = _history_dir(principal.tenant.id, config_type)
    versions = []
    if hdir.exists():
        for path in sorted(hdir.glob("*.json"), reverse=True):
            try:
                entry = json.loads(path.read_text())
                if not isinstance(entry, dict):
                    raise ValueError("not a JSON object")
                versions.append({
                    "id": entry.get("id") or path.stem,
                    "saved_at": entry.get("saved_at"),
                    "user": entry.get("user"),
                    "size": len(entry.get("content") or ""),
                })
            except (OSError, ValueError):
                logger.warning("skipping unreadable history entry %s", path)
    return {"versions": versions}


@router.get("/api/v1/config/{config_type}/history/{version_id}")
async def get_config_history_version(
    config_type: str,
    version_id: str,
    principal: Principal = Depends(get_current_principal),
):
    """One historical config document, including its full YAML content."""
    entry = _load_history_entry(principal.tenant.id, config_type, version_id)
    content = entry.get("content") or ""
    # History snapshots store raw secrets (a restore needs them). Redact the response the same way the live GET does, so
    # an old version can't leak one.
    content = redact_config_history(config_type, content, principal.is_admin)
    return {
        "id": entry.get("id") or version_id,
        "saved_at": entry.get("saved_at"),
        "user": entry.get("user"),
        "content": content,
    }


@router.post("/api/v1/config/{config_type}/history/{version_id}/restore")
async def restore_config_history_version(
    config_type: str,
    version_id: str,
    principal: Principal = Depends(get_current_principal),
    if_match: Optional[str] = Header(None, alias="If-Match"),
    response: Response = None,
):
    """Restore a historical config version through the same validate, snapshot, write and reconcile path as a normal
    save, checking If-Match against the live document rather than the version being restored."""
    # Unknown type is a 400 before the role check, matching update_yaml_config, so a typo does not come back as a
    # missing-admin-role refusal. _load_history_entry checks it again; this is only about the order.
    if config_type not in _EDITABLE_CONFIG_TYPES:
        raise HTTPException(status_code=400, detail="Invalid config type")
    if config_type not in MEMBER_WRITABLE_CONFIG_TYPES and not principal.is_admin:
        raise HTTPException(
            status_code=403,
            detail=f"Restoring '{config_type}' requires the admin role",
        )
    yaml_path = _tenant_dir(principal.tenant.id) / f"{config_type}.yaml"
    _check_config_version(yaml_path, if_match)
    entry = _load_history_entry(principal.tenant.id, config_type, version_id)
    content = entry.get("content") or ""
    try:
        config_data = yaml.safe_load(content) or {}
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Stored version is not valid YAML: {exc}")
    if not isinstance(config_data, dict):
        raise HTTPException(status_code=400, detail="Stored version is not a YAML mapping")
    # A hand-edited tenant file could carry the reserved key; drop it here too, since it is never document content.
    config_data.pop(_RAW_YAML_KEY, None)
    result = await _apply_config_update(principal, config_type, config_data,
                                        yaml_text=content)
    # _apply_config_update already logged config.update. This second row is what separates a rollback from an ordinary
    # save, and names the version so the restored content can be identified afterwards.
    await record_audit(
        principal,
        "config.restore",
        target_type="config",
        target_id=config_type,
        detail={"version_id": version_id},
    )
    result["message"] = f"{config_type} configuration restored from {version_id}"
    _set_config_version_header(response, yaml_path)
    return result


@router.post("/api/v1/sync")
async def sync_now(principal: Principal = Depends(get_current_principal)):
    """Reconcile this tenant's declared YAML state against its devices now (also triggered automatically after
    config saves)."""
    from controller.services.reconciler import reconcile_tenant

    summary = await reconcile_tenant(principal.tenant, _yaml_base())
    return {"message": "Sync complete", **summary}
