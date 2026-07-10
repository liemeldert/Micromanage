import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional

import yaml
from controller.utils.yaml_validator import YAMLValidator
from fastapi import FastAPI, HTTPException, Depends, Request, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field
from tortoise.contrib.fastapi import register_tortoise

from controller.auth import ROLE_ADMIN, ROLE_MEMBER, ROLES, DESTRUCTIVE_COMMANDS
from controller.auth.dependencies import Principal, get_current_principal, require_admin
from controller.auth.passwords import hash_password, verify_password
from controller.auth.ratelimit import login_limiter
from controller.auth.tokens import issue_session_token, JWT_TTL_SECONDS
from controller.models.database import DATABASE_URL
from controller.models.tenant import (
    Tenant,
    User,
    Device,
    Task,
    AppDeployment,
    ProfileDeployment,
    FlowRun,
    Alert,
)
from controller.services.app_manager import AppManager
from controller.services.mdm_connector import MDMConnector
from controller.services.task_manager import TaskManager
from controller.services import enrollment as enrollment_svc

app = FastAPI(title="MDM IAC API", version="1.0.0")
logger = logging.getLogger(__name__)

# Base directory for per-tenant YAML config. Mirror the sync service
# (controller/main.py), which honors YAML_CONFIG_PATH, so the API (writer) and the
# sync loop (reader) always resolve to the same directory. Defaults to
# ./yaml-configs (== /app/yaml-configs under the image WORKDIR).
YAML_BASE = Path(os.getenv("YAML_CONFIG_PATH", "./yaml-configs"))


def _tenant_dir(tenant_id: str) -> Path:
    """Filesystem config dir for a tenant."""
    return YAML_BASE / "tenants" / str(tenant_id)

# Shared task manager so cancellation/state is visible across requests within
# this process (a per-request instance made cancel a no-op).
task_manager = TaskManager()

# CORS: the browser talks to the controller only through the Next.js proxy
# (same-origin), so cross-origin access should be tightly scoped. Configure
# explicit origins via CORS_ALLOWED_ORIGINS (comma-separated); default to the
# local dev web UI. Never "*" on a control-plane API.
_cors_origins = [
    o.strip()
    for o in os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Tenant-Id"],
    expose_headers=["Content-Disposition"],
)

_SECRET_S3_KEYS = ("secret_access_key", "access_key_id", "session_token")

# Precomputed hash used to equalize login timing when the user is missing or has
# no local password, so response latency doesn't reveal account existence.
_DUMMY_PASSWORD_HASH = hash_password("timing-equalization-placeholder")


def _redact_s3_config(s3_config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Strip credential material from an S3 config before returning it."""
    cfg = dict(s3_config or {})
    for key in _SECRET_S3_KEYS:
        if key in cfg:
            cfg[key] = "***redacted***"
    return cfg


_REDACTED = "***redacted***"


def _restore_tenant_s3_secrets(
    stored: Optional[Dict[str, Any]], incoming: Dict[str, Any]
) -> Dict[str, Any]:
    """Before saving a tenant's S3 config, replace any secret the UI echoed back
    still redacted with the value currently stored, so an edit that never
    revealed a credential can't overwrite it with the ``***redacted***``
    sentinel (GET redacts every _SECRET_S3_KEYS value). Returns a new dict;
    inputs are not mutated. The tenant analog of _restore_dispatcher_secrets."""
    stored = stored or {}
    result = dict(incoming or {})
    for key in _SECRET_S3_KEYS:
        if result.get(key) == _REDACTED:
            if key in stored:
                result[key] = stored[key]
            else:
                # Placeholder for a key that was never stored: drop the sentinel
                # rather than persist it as a live credential.
                result.pop(key, None)
    return result
# A Dispatcher webhook's url is itself a credential (e.g. a Slack incoming
# webhook URL), so both url and secret are redacted from every API response.
_SECRET_WEBHOOK_KEYS = ("url", "secret")


def _redact_dispatcher_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of dispatcher.yaml with webhook url/secret redacted."""
    cfg = dict(config or {})
    hooks = cfg.get("webhooks")
    if isinstance(hooks, list):
        cfg["webhooks"] = [
            {**h, **{k: _REDACTED for k in _SECRET_WEBHOOK_KEYS if k in h}}
            if isinstance(h, dict) else h
            for h in hooks
        ]
    return cfg


def _redact_dispatcher_history(content: str) -> str:
    """Redact webhook url/secret from a raw dispatcher.yaml history snapshot so
    the history-view endpoint can't leak a secret the live GET already hides.
    Fails safe (returns empty) if the snapshot can't be parsed."""
    try:
        doc = yaml.safe_load(content)
        if not isinstance(doc, dict):
            return content
        return yaml.safe_dump(_redact_dispatcher_config(doc), sort_keys=False)
    except Exception:
        logger.exception("could not redact dispatcher history snapshot")
        return ""


def _restore_dispatcher_secrets(tenant_id: str, config_data: Dict[str, Any]) -> None:
    """Before saving dispatcher.yaml, replace any redacted webhook url/secret the
    UI echoed back with the value currently on disk (matched by webhook name), so
    an edit that never revealed a secret can't overwrite it with the sentinel."""
    hooks = config_data.get("webhooks")
    if not isinstance(hooks, list):
        return
    existing_path = _tenant_dir(tenant_id) / "dispatcher.yaml"
    stored: Dict[str, Dict[str, Any]] = {}
    if existing_path.exists():
        try:
            doc = yaml.safe_load(existing_path.read_text()) or {}
            for h in doc.get("webhooks", []) or []:
                if isinstance(h, dict) and h.get("name"):
                    stored[h["name"]] = h
        except (OSError, yaml.YAMLError):
            logger.exception("dispatcher: could not read existing webhooks for %s", tenant_id)
    for h in hooks:
        if not isinstance(h, dict):
            continue
        prior = stored.get(h.get("name"))
        for key in _SECRET_WEBHOOK_KEYS:
            if h.get(key) == _REDACTED:
                if prior and key in prior:
                    h[key] = prior[key]
                else:
                    # No stored value to restore (e.g. a new webhook): drop the
                    # sentinel so validation can flag a genuinely-missing url.
                    h.pop(key, None)


def _atomic_write_yaml(path: Path, data: Dict[str, Any]) -> None:
    """Write YAML to ``path`` atomically (write temp + os.replace)."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w") as f:
        yaml.safe_dump(data, f, default_flow_style=False)
    os.replace(tmp, path)


def _truthy(value: Any) -> bool:
    """Interpret a command parameter (usually a string) as a boolean."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes", "on")


def _os_at_least(os_version: Optional[str], major: int) -> bool:
    """True if the device OS major version is >= ``major`` (False if unparseable)."""
    from packaging import version
    try:
        return version.parse(str(os_version or "")).major >= major
    except Exception:
        return False


# Base models
class LoginRequest(BaseModel):
    tenant_id: str
    user_email: str
    password: str


class UserCreate(BaseModel):
    email: str
    password: Optional[str] = None
    role: str = ROLE_MEMBER
    external_id: Optional[str] = None


class UserUpdate(BaseModel):
    password: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TenantCreate(BaseModel):
    id: str = Field(..., regex="^[a-zA-Z0-9-_]+$")
    name: str
    allowed_users: List[str] = []
    s3_bucket: Optional[str] = None
    s3_region: str = "us-east-1"
    dep_enabled: bool = False


class TenantUpdate(BaseModel):
    name: Optional[str] = None
    allowed_users: Optional[List[str]] = None
    s3_config: Optional[Dict[str, Any]] = None
    dep_enabled: Optional[bool] = None
    is_active: Optional[bool] = None


class GroupConfig(BaseModel):
    groups: List[Dict[str, Any]]


class AppConfig(BaseModel):
    apps: List[Dict[str, Any]]


class ProfileConfig(BaseModel):
    profiles: List[Dict[str, Any]]


class CommandRequest(BaseModel):
    command_type: str
    parameters: Dict[str, Any] = {}


class DeviceFilter(BaseModel):
    group: Optional[str] = None
    model: Optional[str] = None
    os_version: Optional[str] = None
    last_seen_days: Optional[int] = None


# Authentication / authorization dependencies live in controller.auth
# (get_current_principal / require_admin are imported above).


# Auth endpoints
@app.post("/api/v1/auth/login", response_model=TokenResponse)
async def login(request: LoginRequest, http_request: Request):
    """Authenticate a local user (email + password) and return a session token.

    Tenants configured for an external provider (Clerk/OIDC) do not use this
    endpoint; their clients present a provider-issued token directly.
    """
    throttle_key = f"{request.tenant_id}:{request.user_email}"
    if not login_limiter.check(throttle_key):
        raise HTTPException(status_code=429, detail="Too many attempts; try again later")

    # Generic error to avoid tenant/user enumeration.
    invalid = HTTPException(status_code=401, detail="Invalid credentials")

    tenant = await Tenant.get_or_none(id=request.tenant_id)
    if not tenant or not tenant.is_active:
        raise invalid

    if tenant.auth_provider != "local":
        raise HTTPException(
            status_code=400,
            detail=f"Tenant uses '{tenant.auth_provider}' authentication; "
                   f"present a provider-issued token in the Authorization header",
        )

    user = await User.get_or_none(tenant=tenant, email=request.user_email)
    if user and user.is_active and user.password_hash:
        ok = verify_password(request.password, user.password_hash)
    else:
        # Always do the bcrypt work so timing doesn't reveal user existence.
        verify_password(request.password, _DUMMY_PASSWORD_HASH)
        ok = False
    if not ok:
        raise invalid

    token = issue_session_token(
        user_id=str(user.id), tenant_id=tenant.id, email=user.email, role=user.role
    )
    return TokenResponse(access_token=token, expires_in=JWT_TTL_SECONDS)


@app.get("/api/v1/auth/me")
async def whoami(principal: Principal = Depends(get_current_principal)):
    """Return the authenticated principal (UI uses this to gate admin actions)."""
    return {
        "tenant_id": principal.tenant.id,
        "email": principal.email,
        "role": principal.role,
        "is_admin": principal.is_admin,
    }


class DiscoverRequest(BaseModel):
    email: str


@app.post("/api/v1/auth/discover")
async def discover_login(request: DiscoverRequest, http_request: Request):
    """Email-first sign-in: which tenants can this email sign in to, and how.

    Deliberate tradeoff: this necessarily reveals whether an email has access
    (that's the point of an email-first flow). It is throttled with the same
    limiter as login so it can't be used for bulk enumeration, and it returns
    only what the sign-in flow needs -- never role or user details.
    """
    email = request.email.strip().lower()
    if not email or not login_limiter.check(f"discover:{email}"):
        raise HTTPException(status_code=429, detail="Too many attempts; try again later")

    users = await User.filter(email__iexact=email, is_active=True).prefetch_related("tenant")
    tenants = []
    for u in users:
        t = u.tenant
        if not t.is_active:
            continue
        cfg = t.auth_config or {}
        entry = {"tenant_id": t.id, "name": t.name, "provider": t.auth_provider}
        # External IdP tenants may configure where the browser should go to
        # obtain a provider token (e.g. a Clerk-hosted sign-in page).
        if t.auth_provider != "local" and cfg.get("login_url"):
            entry["login_url"] = cfg["login_url"]
        tenants.append(entry)

    return {"tenants": tenants}


# User management (admin only)
@app.get("/api/v1/users")
async def list_users(admin: Principal = Depends(require_admin)):
    users = await User.filter(tenant=admin.tenant).all()
    return {
        "users": [
            {
                "id": str(u.id),
                "email": u.email,
                "role": u.role,
                "is_active": u.is_active,
                "has_password": bool(u.password_hash),
                "external_id": u.external_id,
            }
            for u in users
        ]
    }


@app.post("/api/v1/users", status_code=201)
async def create_user(payload: UserCreate, admin: Principal = Depends(require_admin)):
    if payload.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"role must be one of {sorted(ROLES)}")
    if await User.get_or_none(tenant=admin.tenant, email=payload.email):
        raise HTTPException(status_code=409, detail="User already exists")
    if admin.tenant.auth_provider == "local" and not payload.password:
        raise HTTPException(status_code=400, detail="password required for local-auth tenants")

    user = await User.create(
        tenant=admin.tenant,
        email=payload.email,
        role=payload.role,
        external_id=payload.external_id,
        password_hash=hash_password(payload.password) if payload.password else None,
    )
    return {"id": str(user.id), "email": user.email, "role": user.role}


@app.put("/api/v1/users/{user_id}")
async def update_user(user_id: str, payload: UserUpdate, admin: Principal = Depends(require_admin)):
    user = await User.get_or_none(id=user_id, tenant=admin.tenant)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if payload.role is not None:
        if payload.role not in ROLES:
            raise HTTPException(status_code=400, detail=f"role must be one of {sorted(ROLES)}")
        user.role = payload.role
    if payload.password is not None:
        user.password_hash = hash_password(payload.password)
    if payload.is_active is not None:
        # Don't let an admin deactivate themselves and risk locking the tenant out.
        if not payload.is_active and str(user.id) == str(admin.user.id):
            raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
        user.is_active = payload.is_active
    await user.save()
    return {"message": "User updated"}


@app.delete("/api/v1/users/{user_id}")
async def delete_user(user_id: str, admin: Principal = Depends(require_admin)):
    user = await User.get_or_none(id=user_id, tenant=admin.tenant)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if str(user.id) == str(admin.user.id):
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    await user.delete()
    return {"message": "User deleted"}


# Tenant management
@app.get("/api/v1/tenant", response_model=Dict[str, Any])
async def get_tenant_info(principal: Principal = Depends(get_current_principal)):
    """Get current tenant information"""
    tenant = principal.tenant
    return {
        "id": tenant.id,
        "name": tenant.name,
        "allowed_users": tenant.allowed_users,
        "s3_config": _redact_s3_config(tenant.s3_config),
        "auth_provider": tenant.auth_provider,
        "dep_enabled": tenant.dep_enabled,
        "created_at": tenant.created_at,
        "is_active": tenant.is_active,
    }


@app.put("/api/v1/tenant")
async def update_tenant(update: TenantUpdate, admin: Principal = Depends(require_admin)):
    """Update tenant settings (admin only)."""
    tenant = admin.tenant

    if update.name is not None:
        tenant.name = update.name
    if update.allowed_users is not None:
        tenant.allowed_users = update.allowed_users
    if update.s3_config is not None:
        # Access key ID and secret access key are a pair. Reject a request that
        # sends a fresh value for exactly one of them (the other being the
        # redaction sentinel or absent) -- restoring the partner from the stored
        # value would silently persist a mismatched credential. This enforces
        # the form's both-or-neither rule server-side so a direct API call
        # (curl, a script, a stale build) can't corrupt the pair either.
        incoming_s3 = update.s3_config

        def _s3_fresh(key: str) -> bool:
            return key in incoming_s3 and incoming_s3.get(key) != _REDACTED

        if _s3_fresh("access_key_id") != _s3_fresh("secret_access_key"):
            raise HTTPException(
                status_code=400,
                detail="S3 access key ID and secret access key must be set together",
            )
        # Never let a redacted secret the UI echoed back overwrite the stored
        # credential; restore any ***redacted*** sentinel from the current value.
        tenant.s3_config = _restore_tenant_s3_secrets(tenant.s3_config, update.s3_config)
    if update.dep_enabled is not None:
        tenant.dep_enabled = update.dep_enabled
    if update.is_active is not None:
        # Guard against an admin locking the whole tenant out irrecoverably.
        if not update.is_active:
            raise HTTPException(
                status_code=400,
                detail="Deactivating a tenant via this API is not allowed; use admin tooling",
            )
        tenant.is_active = update.is_active

    await tenant.save()

    # Mirror non-secret fields into the YAML config (atomic write).
    yaml_path = _tenant_dir(tenant.id) / "config.yaml"
    if yaml_path.exists():
        try:
            with open(yaml_path, "r") as f:
                config = yaml.safe_load(f) or {}

            config.setdefault("tenant", {})
            config["tenant"]["name"] = tenant.name
            config["tenant"]["allowed_users"] = tenant.allowed_users
            if tenant.s3_config:
                config["tenant"]["s3"] = tenant.s3_config
            config["tenant"].setdefault("dep", {})
            config["tenant"]["dep"]["enabled"] = tenant.dep_enabled

            _atomic_write_yaml(yaml_path, config)
        except OSError as exc:
            # The DB row is already saved; only the on-disk mirror failed.
            logger.exception("Cannot mirror tenant config to %s", yaml_path)
            raise HTTPException(
                status_code=500,
                detail=f"Tenant saved, but updating its config file failed: {exc}",
            )

    return {"message": "Tenant updated successfully"}


# YAML Configuration Management

# Editable YAML config documents: validated PUT + version history. Grows as
# subsystems land (tags in Phase 0; flows / dispatcher follow in later phases).
# "config" is READABLE but not editable via the API -- it embeds S3 secrets --
# so reads allow it while writes/history do not.
_EDITABLE_CONFIG_TYPES = ["groups", "apps", "profiles", "tags", "flows", "dispatcher"]
_READABLE_CONFIG_TYPES = _EDITABLE_CONFIG_TYPES + ["config"]
# Config docs whose authoring can act on devices (send commands, auto-remediate)
# or reach arbitrary URLs (webhook SSRF), so writing them is admin-only even
# though other config types are member-writable.
_ADMIN_ONLY_CONFIG_TYPES = {"flows", "dispatcher"}
# Optional config docs (advisory registries / new-subsystem documents) that have
# no required-file stub. Copied into the validation sandbox when present so
# cross-document checks (e.g. a tag referenced by a group, a profile referenced
# by a flow) resolve on any save.
_OPTIONAL_CONFIG_FILES = ["tags.yaml", "flows.yaml", "dispatcher.yaml"]


@app.get("/api/v1/config/{config_type}")
async def get_yaml_config(
        config_type: str,
        raw: bool = False,
        principal: Principal = Depends(get_current_principal),
):
    """Get YAML configuration by type (groups, apps, profiles, config).

    With ``raw=true`` the response is the YAML document itself (text/plain) --
    used by the YAML viewer. config.yaml is re-rendered after credential
    redaction in raw mode too, so S3 secrets never leave the server.
    """
    if config_type not in _READABLE_CONFIG_TYPES:
        raise HTTPException(status_code=400, detail="Invalid config type")

    tenant = principal.tenant
    yaml_path = _tenant_dir(tenant.id) / f"{config_type}.yaml"

    if not yaml_path.exists():
        raise HTTPException(status_code=404, detail="Configuration not found")

    with open(yaml_path, "r") as f:
        text = f.read()
    config = yaml.safe_load(text) or {}

    # config.yaml embeds tenant.s3 which may carry credentials -- never return them.
    redacted = False
    if config_type == "config" and isinstance(config.get("tenant"), dict):
        if "s3" in config["tenant"]:
            config["tenant"]["s3"] = _redact_s3_config(config["tenant"]["s3"])
            redacted = True
    # dispatcher.yaml webhook url/secret are credentials -- redact from responses.
    if config_type == "dispatcher":
        config = _redact_dispatcher_config(config)
        redacted = True

    if raw:
        # Serve the authored file verbatim (comments intact) unless redaction
        # forced a re-render.
        body = yaml.safe_dump(config, default_flow_style=False, sort_keys=False) if redacted else text
        return Response(content=body, media_type="text/plain; charset=utf-8")

    return config


# ── Config history ─────────────────────────────────────────────────────────
# Every successful config save snapshots the PREVIOUS document so breaking
# changes can be recovered from within the editor. Bounded per config type.
_HISTORY_LIMIT = 50
_HISTORY_ID_RE = re.compile(r"^\d{8}T\d{6,12}Z$")


def _history_dir(tenant_id: str, config_type: str) -> Path:
    return _tenant_dir(tenant_id) / "_history" / config_type


def _snapshot_config_history(tenant_id: str, config_type: str, user: str) -> None:
    """Snapshot the current on-disk config before it is overwritten.

    Best-effort: a history failure must never block the save itself.
    """
    src = _tenant_dir(tenant_id) / f"{config_type}.yaml"
    if not src.exists():
        return
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
    except (OSError, ValueError):
        # Best-effort: a history failure (incl. a non-UTF-8 outgoing file, which
        # raises UnicodeDecodeError -- a ValueError) must NEVER block the save.
        logger.exception("config history snapshot failed for %s/%s", tenant_id, config_type)


def _autofill_rollout_starts(config_type: str, config_data: Dict[str, Any]) -> None:
    """Stamp ``rollout.start`` (now, UTC) on any rollout block that lacks one.

    Keeps the runtime stateless: wave math needs a fixed start, and authors
    shouldn't have to hand-write timestamps. An existing start is never touched
    (edit a rollout's start -- or clear it -- to restart its waves).
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
    elif config_type == "apps":
        for app_entry in config_data.get("apps") or []:
            if isinstance(app_entry, dict):
                for version in app_entry.get("versions") or []:
                    fill(version)


@app.put("/api/v1/config/{config_type}")
async def update_yaml_config(
        config_type: str,
        config_data: Dict[str, Any],
        principal: Principal = Depends(get_current_principal),
):
    """Update YAML configuration.

    Validates the SUBMITTED data (not the existing on-disk files) by validating
    it in an isolated copy of the tenant config dir, and only commits -- atomically
    -- when validation passes. The previous document is snapshotted to history.
    """
    if config_type not in _EDITABLE_CONFIG_TYPES:
        raise HTTPException(status_code=400, detail="Invalid config type")
    if config_type in _ADMIN_ONLY_CONFIG_TYPES and not principal.is_admin:
        raise HTTPException(
            status_code=403,
            detail=f"Editing '{config_type}' requires the admin role",
        )
    # Preserve webhook secrets the UI echoed back redacted (never overwrite a
    # secret with the sentinel) before validation + write.
    if config_type == "dispatcher":
        _restore_dispatcher_secrets(principal.tenant.id, config_data)
    return await _apply_config_update(principal, config_type, config_data)


def _spawn_tenant_reconcile(tenant_id: str) -> None:
    """Fire-and-forget a reactive reconcile for a tenant.

    Used after any change that alters desired-vs-observed state (config save,
    device tag update). ``_spawn`` keeps a strong reference -- a bare
    ``create_task`` handle can be garbage-collected mid-run. Best-effort: a
    reconcile failure is logged, never surfaced to the caller.
    """
    from controller.services.reconciler import reconcile_tenant, _spawn

    async def _run() -> None:
        try:
            t = await Tenant.get_or_none(id=tenant_id)
            if t:
                await reconcile_tenant(t, YAML_BASE)
        except Exception:
            logger.exception("reactive reconcile failed for tenant %s", tenant_id)

    _spawn(_run())


async def _apply_config_update(
        principal: Principal, config_type: str, config_data: Dict[str, Any],
) -> Dict[str, Any]:
    """Shared validate → snapshot → write → reconcile path (save and restore)."""
    tenant = principal.tenant
    tenant_dir = _tenant_dir(tenant.id)
    # New rollout blocks get their wave clock started at save time.
    _autofill_rollout_starts(config_type, config_data)
    yaml_path = tenant_dir / f"{config_type}.yaml"
    # Tenants created via the admin console / bootstrap exist in the DB but may have
    # no on-disk config dir yet -- scaffold it (and a minimal config.yaml) lazily so
    # the first save works instead of 404-ing.
    try:
        tenant_dir.mkdir(parents=True, exist_ok=True)
        config_yaml = tenant_dir / "config.yaml"
        if not config_yaml.exists():
            _atomic_write_yaml(
                config_yaml,
                {"tenant": {"id": tenant.id, "name": tenant.name, "allowed_users": []}},
            )
    except OSError as exc:
        # Almost always a permissions problem: the controller runs as uid 1000 but
        # the yaml-configs volume is root-owned. Surface it instead of a bare 500.
        logger.exception("Cannot prepare tenant config dir %s", tenant_dir)
        raise HTTPException(
            status_code=500,
            detail=(
                f"Server cannot write the config directory ({tenant_dir}): {exc}. "
                "The controller runs as uid 1000 -- ensure the yaml-configs volume is "
                "owned by 1000:1000 (the yaml-init service in docker-compose.prod.yml "
                "handles this)."
            ),
        )

    # Validate the candidate config against a private copy of the tenant dir so
    # cross-file checks run, without ever touching live files until it's valid.
    # validate_all() requires all four files to exist, so stub any that are
    # absent on disk with a minimal valid document.
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
        # Optional docs (e.g. tags.yaml) are copied when present so cross-document
        # checks resolve during any save; they have no required stub.
        for fn in _OPTIONAL_CONFIG_FILES:
            src = tenant_dir / fn
            if src.exists():
                shutil.copy(src, tdp / fn)
        # Overwrite the file being updated with the submitted candidate data (this
        # wins even if the same file was copied above as an optional doc).
        with open(tdp / f"{config_type}.yaml", "w") as f:
            yaml.safe_dump(config_data, f, default_flow_style=False)

        valid, errors, warnings = YAMLValidator(tdp).validate_all()

    if not valid:
        raise HTTPException(
            status_code=400, detail={"errors": errors, "warnings": warnings}
        )

    # Snapshot the outgoing document so this save can be rolled back.
    _snapshot_config_history(tenant.id, config_type, principal.email)

    try:
        _atomic_write_yaml(yaml_path, config_data)
    except OSError as exc:
        logger.exception("Cannot write %s", yaml_path)
        raise HTTPException(
            status_code=500,
            detail=f"Server failed to persist {config_type} configuration: {exc}",
        )

    # Reconcile reactively so the change produces tasks now, not at the next
    # scheduled sync (which remains the periodic safety net).
    _spawn_tenant_reconcile(tenant.id)

    return {"message": f"{config_type} configuration updated", "warnings": warnings}


@app.post("/api/v1/config/validate")
async def validate_yaml_configs(principal: Principal = Depends(get_current_principal)):
    """Validate all YAML configurations"""
    tenant = principal.tenant
    validator = YAMLValidator(_tenant_dir(tenant.id))

    valid, errors, warnings = validator.validate_all()

    return {"valid": valid, "errors": errors, "warnings": warnings}


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
    if not isinstance(entry, dict):  # tampered/corrupt: valid JSON but not an object
        raise HTTPException(status_code=500, detail="History entry is malformed")
    return entry


@app.get("/api/v1/config/{config_type}/history")
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


@app.get("/api/v1/config/{config_type}/history/{version_id}")
async def get_config_history_version(
        config_type: str,
        version_id: str,
        principal: Principal = Depends(get_current_principal),
):
    """One historical config document, including its full YAML content."""
    entry = _load_history_entry(principal.tenant.id, config_type, version_id)
    content = entry.get("content") or ""
    # dispatcher.yaml history stores raw webhook url/secret; redact them from the
    # response the same way the live GET does, so an old version can't leak one.
    if config_type == "dispatcher" and content:
        content = _redact_dispatcher_history(content)
    return {
        "id": entry.get("id") or version_id,
        "saved_at": entry.get("saved_at"),
        "user": entry.get("user"),
        "content": content,
    }


@app.post("/api/v1/config/{config_type}/history/{version_id}/restore")
async def restore_config_history_version(
        config_type: str,
        version_id: str,
        principal: Principal = Depends(get_current_principal),
):
    """Restore a historical version.

    Runs the exact same validate → snapshot → write → reconcile path as a
    normal save (the current document is snapshotted first, so a restore is
    itself undoable).
    """
    if config_type in _ADMIN_ONLY_CONFIG_TYPES and not principal.is_admin:
        raise HTTPException(
            status_code=403,
            detail=f"Restoring '{config_type}' requires the admin role",
        )
    entry = _load_history_entry(principal.tenant.id, config_type, version_id)
    try:
        config_data = yaml.safe_load(entry.get("content") or "") or {}
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Stored version is not valid YAML: {exc}")
    if not isinstance(config_data, dict):
        raise HTTPException(status_code=400, detail="Stored version is not a YAML mapping")
    result = await _apply_config_update(principal, config_type, config_data)
    result["message"] = f"{config_type} configuration restored from {version_id}"
    return result


@app.post("/api/v1/sync")
async def sync_now(principal: Principal = Depends(get_current_principal)):
    """Reconcile this tenant's declared YAML state against its devices now.

    Runs the same reconciliation the sync service performs on its schedule and
    returns a summary of what was queued (also triggered automatically after
    config saves).
    """
    from controller.services.reconciler import reconcile_tenant

    summary = await reconcile_tenant(principal.tenant, YAML_BASE)
    return {"message": "Sync complete", **summary}


# ── Map tiles ─────────────────────────────────────────────────────────────────
# Same-origin proxy for OpenStreetMap raster tiles so the device-location map
# works under the app's strict CSP (img-src 'self' blob:) WITHOUT the browser
# ever contacting a third-party tile CDN -- device locations don't leak to OSM,
# only the controller does (and it caches). Authenticated; the browser fetches
# tiles with its bearer token and renders them as blob: images.
from collections import OrderedDict

_TILE_CACHE: "OrderedDict[str, bytes]" = OrderedDict()
_TILE_CACHE_MAX = 4096
_tile_client: Optional[Any] = None


def _get_tile_client():
    global _tile_client
    if _tile_client is None:
        import httpx
        _tile_client = httpx.AsyncClient(
            timeout=10.0,
            # OSM's tile usage policy requires an identifying User-Agent.
            headers={"User-Agent": "MicromanageIAC/1.0 (self-hosted MDM; device location map)"},
        )
    return _tile_client


@app.get("/api/v1/map/tile/{z}/{x}/{y}")
async def map_tile(z: int, x: int, y: int, principal: Principal = Depends(get_current_principal)):
    """Proxy a single OSM raster tile (cached). Coordinates are strictly bounded
    to the standard slippy-map range, so this can only ever fetch public tiles."""
    if not (0 <= z <= 19):
        raise HTTPException(status_code=404, detail="bad zoom")
    n = 1 << z
    if not (0 <= x < n and 0 <= y < n):
        raise HTTPException(status_code=404, detail="tile out of range")

    key = f"{z}/{x}/{y}"
    data = _TILE_CACHE.get(key)
    if data is None:
        try:
            resp = await _get_tile_client().get(f"https://tile.openstreetmap.org/{z}/{x}/{y}.png")
            resp.raise_for_status()
            data = resp.content
        except Exception as exc:
            logger.warning(f"tile fetch failed for {key}: {exc}")
            raise HTTPException(status_code=502, detail="tile fetch failed")
        _TILE_CACHE[key] = data
        _TILE_CACHE.move_to_end(key)
        while len(_TILE_CACHE) > _TILE_CACHE_MAX:
            _TILE_CACHE.popitem(last=False)

    return Response(content=data, media_type="image/png",
                    headers={"Cache-Control": "private, max-age=86400"})


# Device Management
@app.get("/api/v1/commands/catalog")
async def get_command_catalog(principal: Principal = Depends(get_current_principal)):
    """All device commands this controller can send, with role-aware metadata.

    The UI renders its command menus from this catalog, so newly added
    commands appear without frontend changes (unknown ones get a generic
    parameter form).
    """
    from controller.services.command_catalog import catalog_for_role

    return {"commands": catalog_for_role(principal.is_admin)}


@app.get("/api/v1/flows/step-catalog")
async def get_flow_step_catalog(principal: Principal = Depends(get_current_principal)):
    """The ATC flow node palette + wait-signal registry.

    The visual editor renders its palette and per-node parameter forms from
    this, so adding a node type is a catalog + engine change with no bespoke
    frontend wiring (mirrors GET /api/v1/commands/catalog)."""
    from controller.services.flow_step_catalog import catalog

    return catalog()


@app.get("/api/v1/dispatcher/check-catalog")
async def get_dispatcher_check_catalog(principal: Principal = Depends(get_current_principal)):
    """The Dispatcher compliance-check palette (curated checks + generic attribute).

    Drives the rule editor's check picker + param forms data-driven (mirrors the
    command / flow-step catalogs)."""
    from controller.services.compliance_catalog import catalog

    return catalog()


@app.get("/api/v1/naming/variables")
async def get_naming_variables(principal: Principal = Depends(get_current_principal)):
    """The device-state variables usable in naming templates (group/tenant).

    A single server-published registry so the naming-template editors (groups
    UI, rename helper) stay in sync with what the controller can actually
    resolve. See controller/services/variables.py.
    """
    from controller.services.variables import VARIABLE_SPECS

    return {"variables": VARIABLE_SPECS}


def _device_summary(device: Device) -> Dict[str, Any]:
    """Identity + lifecycle fields shared by the list and detail responses."""
    from controller.services.naming import display_name
    return {
        "id": str(device.id),
        "udid": device.udid,
        "name": device.name,
        "display_name": display_name(device),
        "serial_number": device.serial_number,
        "device_model": device.device_model,
        "os_version": device.os_version,
        "hostname": device.hostname,
        "groups": device.groups,
        "tags": device.tags or [],
        "enrollment_state": device.enrollment_state,
        "management_type": device.management_type,
        "enrollment_date": device.enrollment_date,
        "unenrolled_at": device.unenrolled_at,
        "last_seen": device.last_seen,
    }


class PlaceholderDeviceCreate(BaseModel):
    serial_number: str
    device_model: Optional[str] = None
    management_type: str = "apple_mdm"
    groups: List[str] = []


@app.get("/api/v1/devices")
async def list_devices(
        skip: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=500),
        group: Optional[str] = None,
        tag: Optional[str] = None,
        model: Optional[str] = None,
        search: Optional[str] = None,
        state: Optional[str] = Query(None, description="enrolled | unenrolled | pending"),
        principal: Principal = Depends(get_current_principal),
):
    """List devices (all lifecycle states by default) with optional filtering."""
    tenant = principal.tenant

    query = Device.filter(tenant=tenant)

    if state in ("enrolled", "unenrolled", "pending"):
        query = query.filter(enrollment_state=state)
    if group:
        query = query.filter(groups__contains=[group])
    if tag:
        query = query.filter(tags__contains=[tag])
    if model:
        query = query.filter(device_model__icontains=model)
    if search:
        # One box that finds a device by any of its identifying fields.
        from tortoise.expressions import Q
        query = query.filter(
            Q(serial_number__icontains=search)
            | Q(hostname__icontains=search)
            | Q(device_model__icontains=search)
            | Q(udid__icontains=search)
        )

    # Enrolled first, then most-recently-seen -- keeps active devices on top even
    # when unenrolled/pending records are shown.
    total = await query.count()
    devices = (
        await query.order_by("enrollment_state", "-last_seen").offset(skip).limit(limit).all()
    )

    # Per-state counts so the UI can label its filter without extra round-trips.
    from tortoise.functions import Count
    counts_raw = (
        await Device.filter(tenant=tenant)
        .annotate(count=Count("id")).group_by("enrollment_state")
        .values("enrollment_state", "count")
    )
    counts = {c["enrollment_state"]: c["count"] for c in counts_raw}

    return {
        "total": total,
        "counts": {
            "all": sum(counts.values()),
            "enrolled": counts.get("enrolled", 0),
            "unenrolled": counts.get("unenrolled", 0),
            "pending": counts.get("pending", 0),
        },
        "devices": [_device_summary(device) for device in devices],
    }


@app.post("/api/v1/devices", status_code=201)
async def create_placeholder_device(
        body: PlaceholderDeviceCreate,
        admin: Principal = Depends(require_admin),
):
    """Pre-provision a device by serial before it enrolls (e.g. DEP).

    Its pre-defined group membership is applied when the physical device
    enrolls and is adopted by serial. Admin only.
    """
    tenant = admin.tenant
    serial = body.serial_number.strip()
    if not serial:
        raise HTTPException(status_code=400, detail="serial_number is required")
    if len(serial) > 20:
        raise HTTPException(status_code=400, detail="serial_number too long (max 20 characters)")
    if body.management_type not in ("apple_mdm",):
        raise HTTPException(status_code=400, detail="unsupported management_type")

    existing = await Device.filter(tenant=tenant, serial_number=serial).first()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"A device with serial {serial} already exists ({existing.enrollment_state})",
        )

    from tortoise.exceptions import IntegrityError
    try:
        device = await Device.create(
            tenant=tenant,
            udid=None,
            serial_number=serial,
            device_model=body.device_model or "",
            os_version="",
            hostname=None,
            enrollment_state="pending",
            management_type=body.management_type,
            groups=body.groups or [],
        )
    except IntegrityError:
        # Lost a race with a concurrent create (unique serial index).
        raise HTTPException(status_code=409, detail=f"A device with serial {serial} already exists")
    return _device_summary(device)


@app.delete("/api/v1/devices/{device_id}")
async def forget_device(
        device_id: str,
        admin: Principal = Depends(require_admin),
):
    """Forget a device: remove its record and all of its deployments, tasks,
    flow runs and alerts from the console.

    Only a device that is NOT actively enrolled may be forgotten. An enrolled
    device still has a live MDM channel, so the webhook would simply re-create
    the row on its next check-in and the roster entry would reappear -- the
    admin must let it check out / be unenrolled first. This removes the
    console's record only; it does not send any command to the hardware (and for
    an unenrolled device it could not). Admin only.
    """
    tenant = admin.tenant
    device = await Device.get_or_none(id=device_id, tenant=tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    if device.enrollment_state == "enrolled":
        raise HTTPException(
            status_code=409,
            detail=(
                "Device is enrolled; unenroll it or let it check out before "
                "forgetting it, otherwise it will reappear on its next check-in."
            ),
        )

    serial = device.serial_number  # captured for the audit log before deletion

    # Remove child rows explicitly inside one transaction rather than relying on
    # DB-level ON DELETE CASCADE, so the cleanup is predictable regardless of how
    # the schema's foreign keys were generated.
    from tortoise.transactions import in_transaction

    async with in_transaction():
        await AppDeployment.filter(device=device).delete()
        await ProfileDeployment.filter(device=device).delete()
        await FlowRun.filter(device=device).delete()
        await Alert.filter(device=device).delete()
        await Task.filter(device=device).delete()
        await device.delete()

    logger.info(
        "Forgot device %s (serial=%s) for tenant %s by %s",
        device_id, serial, tenant.id, admin.email,
    )
    return {"message": "Device forgotten"}


@app.get("/api/v1/devices/{device_id}")
async def get_device_details(device_id: str, principal: Principal = Depends(get_current_principal)):
    """Get detailed device information"""
    tenant = principal.tenant
    device = await Device.get_or_none(id=device_id, tenant=tenant)

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Get installed apps and profiles
    apps = await AppDeployment.filter(device=device).all()
    profiles = await ProfileDeployment.filter(device=device).all()
    tasks = await Task.filter(device=device).order_by("-created_at").limit(10).all()

    # Why did the last operation on this device fail (if it did)? A dedicated,
    # tenant-scoped, limit-1 lookup -- deliberately NOT derived from the
    # `tasks` slice above, since the most recent failure could be older than
    # the last 10 tasks. Single-device path only (see list_devices) so this
    # never becomes an N+1 across a device list.
    last_failed_task = (
        await Task.filter(device=device, tenant=tenant, status="failed")
        .order_by("-created_at")
        .first()
    )
    last_task_error = (
        {
            "task_id": str(last_failed_task.id),
            "task_type": last_failed_task.type,
            "error": last_failed_task.error,
            "created_at": last_failed_task.created_at,
            "completed_at": last_failed_task.completed_at,
        }
        if last_failed_task
        else None
    )

    # Name the governing naming template would produce for this device -- offered
    # in the rename UI as a one-click suggestion. Group-scoped first (first
    # matching group with a template, in config order), else the tenant template.
    # Purely advisory: fail soft so a bad groups.yaml regex can't 500 the page.
    suggested_name = None
    try:
        from controller.services.group_manager import GroupManager
        from controller.services.naming import suggested_name_for
        from controller.services.tenant_config import load_groups
        groups_config = load_groups(tenant.id)
        group_names = GroupManager(tenant.id).evaluate_device_groups(device, groups_config)
        suggested_name = suggested_name_for(
            device, tenant.device_naming or {}, groups_config, group_names
        )
    except Exception:
        logger.exception("suggested_name computation failed for device %s", device_id)

    return {
        "device": {
            **_device_summary(device),
            "suggested_name": suggested_name,
            # Everything the device has reported about itself (DeviceInformation
            # QueryResponses + SecurityInfo) -- rendered data-driven by the UI.
            "attributes": device.attributes or {},
            # Why the last operation on this device failed, if it did (null
            # otherwise) -- so an admin doesn't have to dig through recent_tasks.
            "last_task_error": last_task_error,
        },
        # Inventory as reported BY THE DEVICE (ProfileList / InstalledApplicationList),
        # distinct from the management-intent deployments below.
        "device_profiles": device.installed_profiles or [],
        "device_apps": device.installed_apps if isinstance(device.installed_apps, list) else [],
        "installed_apps": [
            {
                "app_id": app.app_id,
                "version": app.app_version,
                "status": app.status,
                "install_date": app.install_date,
            }
            for app in apps
        ],
        "installed_profiles": [
            {
                "profile_id": profile.profile_id,
                "status": profile.status,
                "install_date": profile.install_date,
            }
            for profile in profiles
        ],
        "recent_tasks": [task.to_dict() for task in tasks],
    }


def _explain_scope(
    device: Device,
    device_groups: List[str],
    scope: Dict[str, Any],
    item_key: str,
    now: datetime,
) -> Dict[str, Any]:
    """Evaluate one profile/app-version scope against a device and narrate WHY.

    The matched/unmatched decision at every step is delegated to
    services.scoping (evaluate_condition / evaluate_scope / device_in_rollout)
    -- this only walks the SAME precedence order evaluate_scope already
    encodes (exclude > include > groups+conditions, then rollout) to explain
    which step decided the outcome, rather than re-deriving the boolean itself.
    """
    from controller.services.scoping import (
        device_in_rollout,
        evaluate_condition,
        evaluate_scope,
        rollout_coverage,
    )

    serial = getattr(device, "serial_number", "") or ""
    exclude = scope.get("exclude_devices") or []
    if serial and serial in exclude:
        return {"matched": False, "reason": f"excluded: serial {serial} is in exclude_devices"}

    include = scope.get("include_devices") or []
    if serial and serial in include:
        matched = evaluate_scope(device, device_groups, scope)
        cherry_pick_reason = f"included: serial {serial} is cherry-picked in include_devices"
        if not matched:  # defensive; evaluate_scope agrees include wins outright
            return {"matched": False, "reason": cherry_pick_reason}
    else:
        groups = scope.get("groups") or []
        conditions = scope.get("conditions") or []
        if not groups and not conditions:
            return {
                "matched": False,
                "reason": "no groups or conditions configured on this scope "
                          "(include-only; this device was not cherry-picked)",
            }
        if groups and not any(g in device_groups for g in groups):
            return {
                "matched": False,
                "reason": f"not in any of the scoped groups: {', '.join(groups)}",
            }
        failing_condition = next(
            (c for c in conditions if not evaluate_condition(device, c, device_groups)),
            None,
        )
        if failing_condition is not None:
            neg = "negated " if failing_condition.get("negate") else ""
            return {
                "matched": False,
                "reason": (
                    f"{neg}condition did not match: {failing_condition.get('type')} "
                    f"{failing_condition.get('operator')} {failing_condition.get('value')!r}"
                ),
            }
        cherry_pick_reason = None

    # Groups/conditions (or a cherry-pick) matched -- last gate is gradual rollout.
    rollout = scope.get("rollout")
    if rollout:
        if not device_in_rollout(device, rollout, item_key, now):
            coverage = rollout_coverage(rollout, now)
            return {
                "matched": False,
                "reason": f"scoped, but held by gradual rollout (currently covering "
                          f"{coverage}% of devices; this device's wave hasn't opened yet)",
            }
        base = cherry_pick_reason or "matched by group/condition scope"
        return {"matched": True, "reason": f"{base}; in the current rollout wave"}

    return {"matched": True, "reason": cherry_pick_reason or "matched by group/condition scope"}


@app.get("/api/v1/devices/{device_id}/scope-explain")
async def explain_device_scope(
        device_id: str, principal: Principal = Depends(get_current_principal),
):
    """Explain WHY this device does or doesn't receive each scoped profile,
    app and group -- read-only, for troubleshooting "why didn't this device
    get X". Reuses services.scoping's evaluation for every decision; this
    endpoint only narrates the precedence order that decided the outcome.
    """
    tenant = principal.tenant
    device = await Device.get_or_none(id=device_id, tenant=tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    from controller.services.group_manager import GroupManager
    from controller.services.profile_manager import ProfileManager
    from controller.services.tenant_config import load_apps, load_groups, load_profiles

    groups_config = load_groups(tenant.id)
    apps_config = load_apps(tenant.id)
    profiles_config = load_profiles(tenant.id)

    now = datetime.now(timezone.utc)
    device_groups = GroupManager(tenant.id).evaluate_device_groups(device, groups_config)
    device_platform = ProfileManager._device_platform(device)

    groups_out = []
    for group in groups_config:
        name = group.get("name")
        if not name:
            continue
        matched = name in device_groups
        if matched:
            reason = "matched by group's conditions (or a cherry-picked serial)"
        else:
            serial = getattr(device, "serial_number", "") or ""
            if serial and serial in (group.get("exclude_devices") or []):
                reason = f"excluded: serial {serial} is in exclude_devices"
            elif not (group.get("conditions") or []):
                reason = "group has no conditions (include-only; device not cherry-picked)"
            else:
                from controller.services.scoping import evaluate_condition
                failing = next(
                    (c for c in group.get("conditions") or []
                     if not evaluate_condition(device, c, device_groups)),
                    None,
                )
                if failing is not None:
                    neg = "negated " if failing.get("negate") else ""
                    reason = (
                        f"{neg}condition did not match: {failing.get('type')} "
                        f"{failing.get('operator')} {failing.get('value')!r}"
                    )
                else:
                    reason = "did not match this group's conditions"
        groups_out.append({"id": name, "name": name, "matched": matched, "reason": reason})

    profiles_out = []
    for profile in profiles_config:
        pid = profile.get("id")
        if not pid:
            continue
        if profile.get("dep_profile") or profile.get("type") == "enrollment":
            profiles_out.append({
                "id": pid, "name": profile.get("name", pid), "matched": False,
                "reason": "enrollment/DEP profile -- not pushed as managed config",
            })
            continue
        platforms = profile.get("platforms")
        if platforms and device_platform not in platforms:
            profiles_out.append({
                "id": pid, "name": profile.get("name", pid), "matched": False,
                "reason": f"excluded by platform: device is {device_platform}, "
                          f"profile targets {', '.join(platforms)}",
            })
            continue
        outcome = _explain_scope(device, device_groups, profile, f"profile:{pid}", now)
        profiles_out.append({
            "id": pid, "name": profile.get("name", pid),
            "matched": outcome["matched"], "reason": outcome["reason"],
        })

    apps_out = []
    for app_entry in apps_config:
        app_id = app_entry.get("id")
        if not app_id:
            continue
        versions = app_entry.get("versions") or []
        # Mirror AppManager._get_applicable_version: newest-first, first scoped
        # (and waved-in) version wins; a version held by rollout falls through
        # to the next-older version rather than reporting "no match".
        chosen = None
        version_reasons = []
        for version in reversed(versions):
            outcome = _explain_scope(
                device, device_groups, version,
                f"app:{app_id}:{version.get('version')}", now,
            )
            version_reasons.append((version.get("version"), outcome))
            if outcome["matched"]:
                chosen = version
                break
        if chosen is not None:
            reason = f"version {chosen.get('version')} matched: {version_reasons[-1][1]['reason']}"
            apps_out.append({
                "id": app_id, "name": app_entry.get("name", app_id),
                "matched": True, "reason": reason,
            })
        elif version_reasons:
            # Nothing matched -- report the most recent (newest) version's reason,
            # since that's the one an author most likely expected to apply.
            newest_version, newest_outcome = version_reasons[0]
            apps_out.append({
                "id": app_id, "name": app_entry.get("name", app_id),
                "matched": False,
                "reason": f"no version matched (newest, {newest_version}: "
                          f"{newest_outcome['reason']})",
            })
        else:
            apps_out.append({
                "id": app_id, "name": app_entry.get("name", app_id),
                "matched": False, "reason": "app has no versions configured",
            })

    return {"profiles": profiles_out, "apps": apps_out, "groups": groups_out}


class DeviceRename(BaseModel):
    name: str


@app.patch("/api/v1/devices/{device_id}/name")
async def rename_device(
        device_id: str,
        body: DeviceRename,
        principal: Principal = Depends(get_current_principal),
):
    """Set a device's managed name and, if it's enrolled, push the rename to the
    device (Apple Settings/DeviceName -- supervised devices only)."""
    tenant = principal.tenant
    device = await Device.get_or_none(id=device_id, tenant=tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name cannot be empty")
    if len(name) > 255:
        raise HTTPException(status_code=400, detail="Name too long (max 255 characters)")

    device.name = name
    await device.save(update_fields=["name"])

    # Push to the physical device when it has an active MDM channel. Renaming
    # actually takes effect on supervised devices; the command is a no-op error
    # otherwise, surfaced as a failed task.
    task_id = None
    if device.enrollment_state == "enrolled" and device.udid:
        task = await task_manager.create_task(
            tenant=tenant, task_type="set_name",
            description=f"Rename {device.serial_number} to {name!r}",
            device=device, user=principal.email, details={},
        )
        mdm_connector = MDMConnector()
        try:
            result = await mdm_connector.set_device_name(device.udid, name)
            task.details["command_uuid"] = result.get("command_uuid")
            task.status = "running"
            await task.save()
            task_id = str(task.id)
        except Exception as exc:
            task.status = "failed"
            task.error = str(exc)
            await task.save()
            logger.error(f"Rename push failed for {device.udid}: {exc}")
        finally:
            await mdm_connector.close()

    return {"device": _device_summary(device), "pushed": task_id is not None, "task_id": task_id}


class DeviceTagsUpdate(BaseModel):
    add: List[str] = []
    remove: List[str] = []


@app.post("/api/v1/devices/{device_id}/tags")
async def update_device_tags(
        device_id: str,
        body: DeviceTagsUpdate,
        principal: Principal = Depends(get_current_principal),
):
    """Add and/or remove imperative tags on a device (member+).

    Additive and idempotent: the listed tags are added, the listed tags removed,
    and nothing else is touched -- so a tag applied elsewhere (by hand, an ATC
    flow, or a Dispatcher rule) is never clobbered. Tags can drive group
    membership, so after the write we recompute the device's groups and queue a
    reactive reconcile (tags -> groups -> profile/app scoping). Audited as a
    ``tag_update`` Task.
    """
    tenant = principal.tenant
    device = await Device.get_or_none(id=device_id, tenant=tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    def _clean(items: List[str]) -> List[str]:
        seen: List[str] = []
        for raw in items or []:
            s = str(raw).strip()
            if not s:
                continue
            if len(s) > 100:
                raise HTTPException(
                    status_code=400, detail=f"Tag too long (max 100 characters): {s[:20]}..."
                )
            if s not in seen:
                seen.append(s)
        return seen

    add = _clean(body.add)
    remove = _clean(body.remove)
    if not add and not remove:
        raise HTTPException(status_code=400, detail="No tags to add or remove")

    current = [str(t) for t in (device.tags or [])]
    before = set(current)
    remove_set = set(remove)
    # Preserve existing order; drop removals, then append genuinely-new tags.
    result = [t for t in current if t not in remove_set]
    for t in add:
        if t not in result:
            result.append(t)
    after = set(result)

    if after == before:
        # Idempotent no-op -- skip the write, reconcile and audit entirely.
        return {"device": _device_summary(device), "changed": False,
                "added": [], "removed": []}

    device.tags = result
    await device.save(update_fields=["tags"])

    added = sorted(after - before)
    removed = sorted(before - after)

    # Tags can drive group membership -> recompute so profile/app scoping follows.
    # Best-effort: a malformed groups.yaml must not fail the tag write.
    groups_changed = False
    try:
        from controller.services.group_manager import GroupManager
        from controller.services.tenant_config import load_groups
        groups_config = load_groups(tenant.id)
        new_groups = GroupManager(tenant.id).evaluate_device_groups(device, groups_config)
        # Compare as sets: a pure reorder of the same membership is not a change
        # and must not trigger a spurious write or a misleading groups_changed.
        if set(new_groups) != set(device.groups or []):
            device.groups = new_groups
            await device.save(update_fields=["groups"])
            groups_changed = True
    except Exception:
        logger.exception("group recompute after tag update failed for device %s", device_id)

    # Audit trail. A tag write is synchronous, so complete the task immediately.
    try:
        task = await task_manager.create_task(
            tenant=tenant, task_type="tag_update",
            description=f"Tags updated on {device.serial_number}",
            device=device, user=principal.email,
            details={"added": added, "removed": removed, "tags": result},
        )
        await task.update_progress(100, "completed")
    except Exception:
        logger.exception("tag_update audit task failed for device %s", device_id)

    _spawn_tenant_reconcile(tenant.id)

    return {"device": _device_summary(device), "changed": True,
            "added": added, "removed": removed, "groups_changed": groups_changed}


# ── ATC flow runs ────────────────────────────────────────────────────────────

class FlowRunStart(BaseModel):
    flow_id: str


@app.get("/api/v1/devices/{device_id}/flow-runs")
async def list_device_flow_runs(
        device_id: str,
        principal: Principal = Depends(get_current_principal),
):
    """ATC flow runs for a device (most recent first)."""
    tenant = principal.tenant
    device = await Device.get_or_none(id=device_id, tenant=tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    runs = await FlowRun.filter(device=device).order_by("-started_at").limit(50).all()
    return {"flow_runs": [run.to_dict() for run in runs]}


@app.get("/api/v1/flow-runs/{run_id}")
async def get_flow_run(run_id: str, principal: Principal = Depends(get_current_principal)):
    """One flow run, including the pinned flow snapshot it is executing so the
    run viewer can render the exact graph with the taken path highlighted."""
    run = await FlowRun.get_or_none(id=run_id, tenant=principal.tenant)
    if not run:
        raise HTTPException(status_code=404, detail="Flow run not found")
    data = run.to_dict()
    # The pinned definition (flow_hash), so the viewer highlights the real graph
    # even if flows.yaml has since been edited.
    data["flow"] = (run.context or {}).get("flow")
    return data


@app.post("/api/v1/devices/{device_id}/flow-runs", status_code=201)
async def start_device_flow_run(
        device_id: str,
        body: FlowRunStart,
        principal: Principal = Depends(get_current_principal),
):
    """Manually start a flow against a device (testing / re-run). Ignores the
    trigger match (the operator asked for this flow explicitly)."""
    tenant = principal.tenant
    device = await Device.get_or_none(id=device_id, tenant=tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.enrollment_state != "enrolled":
        raise HTTPException(
            status_code=409,
            detail=f"Device is {device.enrollment_state}; flows run only on enrolled devices",
        )
    from controller.services import atc
    run = await atc.start_flow_by_id(device, body.flow_id.strip())
    if run is None:
        raise HTTPException(
            status_code=400,
            detail=f"Flow '{body.flow_id}' not found or has no valid start node",
        )
    return run.to_dict()


# ── Dispatcher alerts ────────────────────────────────────────────────────────

async def _enrich_alerts(alerts: List[Alert]) -> List[Dict[str, Any]]:
    """Alert dicts + a small device summary for the triage board, sorted by
    severity (black -> green) then most-recently updated."""
    from controller.services.dispatcher import SEVERITY_RANK
    from controller.services.naming import display_name

    device_ids = {a.device_id for a in alerts if a.device_id}
    devices = {
        str(d.id): d for d in await Device.filter(id__in=list(device_ids)).all()
    } if device_ids else {}
    out = []
    for a in alerts:
        item = a.to_dict()
        dev = devices.get(str(a.device_id))
        item["device"] = {
            "serial_number": dev.serial_number if dev else None,
            "display_name": display_name(dev) if dev else None,
        } if dev else None
        out.append(item)
    out.sort(key=lambda i: (SEVERITY_RANK.get(i["severity"], 0), i["updated_at"] or ""),
             reverse=True)
    return out


@app.get("/api/v1/alerts")
async def list_alerts(
        severity: Optional[str] = None,
        status: Optional[str] = None,
        device_id: Optional[str] = None,
        principal: Principal = Depends(get_current_principal),
):
    """Compliance alerts (triage board), newest/most-severe first."""
    query = Alert.filter(tenant=principal.tenant)
    if severity:
        query = query.filter(severity=severity)
    if status:
        query = query.filter(status=status)
    if device_id:
        query = query.filter(device_id=device_id)
    alerts = await query.limit(1000).all()
    items = await _enrich_alerts(alerts)
    # Board header counts: ALL active (non-resolved) alerts by severity, computed
    # independent of the severity/status VIEW filters so selecting one severity
    # chip doesn't zero the others (which would hide e.g. black alerts mid-triage).
    count_q = Alert.filter(tenant=principal.tenant).exclude(status="resolved")
    if device_id:
        count_q = count_q.filter(device_id=device_id)
    active_alerts = await count_q.all()
    counts = {s: 0 for s in ("black", "red", "yellow", "green")}
    for a in active_alerts:
        if a.severity in counts:
            counts[a.severity] += 1
    return {"alerts": items, "counts": counts, "active": len(active_alerts)}


@app.get("/api/v1/alerts/{alert_id}")
async def get_alert(alert_id: str, principal: Principal = Depends(get_current_principal)):
    alert = await Alert.get_or_none(id=alert_id, tenant=principal.tenant)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return (await _enrich_alerts([alert]))[0]


@app.post("/api/v1/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, principal: Principal = Depends(get_current_principal)):
    alert = await Alert.get_or_none(id=alert_id, tenant=principal.tenant)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.status == "resolved":
        raise HTTPException(status_code=409, detail="Alert is already resolved")
    alert.status = "acknowledged"
    alert.acknowledged_at = datetime.now(timezone.utc)
    alert.acknowledged_by = principal.email
    await alert.save(update_fields=["status", "acknowledged_at", "acknowledged_by"])
    return alert.to_dict()


@app.post("/api/v1/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str, principal: Principal = Depends(get_current_principal)):
    """Manually resolve an alert (reverses reversible actions like a noncompliant tag)."""
    alert = await Alert.get_or_none(id=alert_id, tenant=principal.tenant)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.status == "resolved":
        return alert.to_dict()
    from controller.services import dispatcher
    device = await Device.get_or_none(id=alert.device_id)
    if device is not None:
        await dispatcher._resolve_alert(alert, device, f"resolved by {principal.email}")
    else:
        alert.status = "resolved"
        alert.resolved_at = datetime.now(timezone.utc)
        await alert.save(update_fields=["status", "resolved_at"])
    return alert.to_dict()


class RemediateRequest(BaseModel):
    action_key: str


@app.post("/api/v1/alerts/{alert_id}/remediate")
async def approve_alert_remediation(
        alert_id: str,
        body: RemediateRequest,
        admin: Principal = Depends(require_admin),
):
    """Admin-approve a queued destructive remediation for an alert. Runs through
    the audited command path with the admin's authority; never auto-fired."""
    alert = await Alert.get_or_none(id=alert_id, tenant=admin.tenant)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    from controller.services import dispatcher
    try:
        result = await dispatcher.approve_remediation(alert, body.action_key, admin.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"message": "Remediation approved", **result, "alert": alert.to_dict()}


@app.post("/api/v1/dispatcher/evaluate")
async def dispatcher_evaluate_now(principal: Principal = Depends(get_current_principal)):
    """Force a compliance sweep for this tenant now (mirrors POST /api/v1/sync)."""
    from controller.services import dispatcher
    evaluated = await dispatcher.sweep(principal.tenant)
    return {"message": "Compliance sweep complete", "devices_evaluated": evaluated}


@app.post("/api/v1/devices/{device_id}/command")
async def send_device_command(
        device_id: str,
        command: CommandRequest,
        principal: Principal = Depends(get_current_principal),
):
    """Send a command to a device.

    Destructive commands (restart/shutdown/clear_passcode) require the admin
    role. Every command creates a Task row for auditability (who/when/what).
    """
    tenant = principal.tenant

    # Authorization: destructive commands are admin-only.
    if command.command_type in DESTRUCTIVE_COMMANDS and principal.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=403,
            detail=f"'{command.command_type}' requires the admin role",
        )

    device = await Device.get_or_none(id=device_id, tenant=tenant)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.enrollment_state != "enrolled":
        # Unenrolled/pending devices have no active MDM channel.
        raise HTTPException(
            status_code=409,
            detail=f"Device is {device.enrollment_state}; commands can only be sent to enrolled devices",
        )

    mdm_connector = MDMConnector()

    try:
        # Map command types to handlers
        if command.command_type == "install_app":
            app_info = command.parameters.get("app_info")
            if not app_info:
                raise HTTPException(status_code=400, detail="app_info required")

            task = await task_manager.create_task(
                tenant=tenant,
                task_type="app_install",
                description=f"Install {app_info['name']}",
                device=device,
                user=principal.email,
                details={"app_info": app_info},
            )

            from controller.services.task_handlers import handle_app_install_task
            from controller.services.reconciler import _spawn

            # _spawn keeps a strong reference; a bare asyncio.create_task can be
            # garbage-collected mid-flight, silently dropping the install.
            _spawn(task_manager.execute_task(task, handle_app_install_task))

            return {"task_id": str(task.id), "message": "App installation started"}

        elif command.command_type == "remove_app":
            app_id = command.parameters.get("app_id")
            bundle_id = command.parameters.get("bundle_id")

            if not app_id or not bundle_id:
                raise HTTPException(
                    status_code=400, detail="app_id and bundle_id required"
                )

            task = await task_manager.create_task(
                tenant=tenant,
                task_type="app_remove",
                description=f"Remove app {app_id}",
                device=device,
                user=principal.email,
                details={"app_id": app_id, "bundle_id": bundle_id},
            )

            from controller.services.task_handlers import handle_app_remove_task
            from controller.services.reconciler import _spawn

            # _spawn keeps a strong reference; a bare asyncio.create_task can be
            # garbage-collected mid-flight, silently dropping the removal.
            _spawn(task_manager.execute_task(task, handle_app_remove_task))

            return {"task_id": str(task.id), "message": "App removal started"}

        # Direct, immediately-issued commands: validate here, then dispatch via
        # the shared audited path (services.device_commands) so this endpoint,
        # ATC send_command steps and Dispatcher remediation all enforce the same
        # catalog / secret-redaction / destructive-gating rules.
        from controller.services.command_catalog import get_command

        entry = get_command(command.command_type)
        if entry is None:
            raise HTTPException(status_code=400, detail="Invalid command type")

        params = command.parameters or {}
        pin = params.get("pin")
        if command.command_type in ("lock", "erase"):
            # macOS requires a 6-digit unlock PIN for DeviceLock/EraseDevice.
            is_mac = "mac" in (device.device_model or "").lower()
            if pin is not None and not re.fullmatch(r"\d{6}", str(pin)):
                raise HTTPException(status_code=400, detail="PIN must be exactly 6 digits")
            if is_mac and not pin:
                raise HTTPException(
                    status_code=400,
                    detail="Macs require a 6-digit PIN for this command (needed to unlock afterwards)",
                )
        if command.command_type == "enable_lost_mode" and not params.get("message"):
            raise HTTPException(status_code=400, detail="Lost Mode requires a lock screen message")

        # Return to Service: erase + automatic re-enroll (supervised iOS/iPadOS 17+).
        rts_payload = None
        if command.command_type == "erase" and _truthy(params.get("return_to_service")):
            attrs = device.attributes or {}
            is_mac = "mac" in (device.device_model or "").lower()
            if is_mac:
                raise HTTPException(
                    status_code=400,
                    detail="Return to Service is an iOS/iPadOS feature; it isn't supported on Macs.",
                )
            if attrs.get("IsSupervised") is not True:
                raise HTTPException(
                    status_code=400,
                    detail="Return to Service requires a supervised device.",
                )
            if not _os_at_least(device.os_version, 17):
                raise HTTPException(
                    status_code=400,
                    detail="Return to Service requires iOS/iPadOS 17 or later "
                           f"(device reports {device.os_version or 'unknown'}).",
                )
            wifi_ssid = (params.get("wifi_ssid") or "").strip()
            if not wifi_ssid:
                raise HTTPException(
                    status_code=400,
                    detail="Return to Service needs a Wi-Fi network so the wiped device can reach the server.",
                )
            enroll_info = enrollment_svc.enrollment_details(tenant)
            if not enroll_info.get("configured"):
                raise HTTPException(
                    status_code=400,
                    detail="Enrollment isn't fully configured, so the re-enrollment profile "
                           f"can't be built (missing: {', '.join(enroll_info.get('missing') or [])}).",
                )
            rts_payload = {
                "enrollment_profile": enrollment_svc.build_enrollment_mobileconfig(tenant),
                "wifi_profile": enrollment_svc.build_wifi_mobileconfig(
                    wifi_ssid,
                    password=params.get("wifi_password") or None,
                    hidden=_truthy(params.get("wifi_hidden")),
                    org=tenant.name,
                ),
            }

        from controller.services.device_commands import (
            CommandError, CommandSendError, dispatch_catalog_command,
        )
        try:
            outcome = await dispatch_catalog_command(
                device,
                command.command_type,
                params,
                user=principal.email,
                tenant=tenant,
                # The admin-role gate above already authorized any destructive
                # command; the helper's own gate is what protects automated
                # callers (ATC/Dispatcher), which pass allow_destructive=False.
                allow_destructive=True,
                rts_payload=rts_payload,
                mdm_connector=mdm_connector,
            )
        except CommandSendError as exc:
            raise HTTPException(status_code=502, detail=str(exc))
        except CommandError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        return {"task_id": outcome["task_id"], "message": "Command sent",
                "result": outcome["result"]}

    finally:
        await mdm_connector.close()


# Task Management
@app.get("/api/v1/tasks")
async def list_tasks(
        skip: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=500),
        status: Optional[str] = None,
        device_id: Optional[str] = None,
        principal: Principal = Depends(get_current_principal),
):
    """List tasks with optional filtering"""
    tenant = principal.tenant

    query = Task.filter(tenant=tenant)

    if status:
        query = query.filter(status=status)
    if device_id:
        query = query.filter(device_id=device_id)

    total = await query.count()
    tasks = (
        await query.order_by("-created_at")
        .offset(skip)
        .limit(limit)
        .prefetch_related("device")
        .all()
    )

    return {"total": total, "tasks": [_task_with_device(task) for task in tasks]}


def _task_with_device(task: Task) -> Dict[str, Any]:
    """Task dict enriched with device identity (device is prefetched)."""
    d = task.to_dict()
    if task.device:
        d["device"] = {
            "serial_number": task.device.serial_number,
            "hostname": task.device.hostname,
            "device_model": task.device.device_model,
        }
    return d


@app.get("/api/v1/tasks/{task_id}")
async def get_task_details(task_id: str, principal: Principal = Depends(get_current_principal)):
    """Get task details"""
    tenant = principal.tenant
    task = await Task.get_or_none(id=task_id, tenant=tenant).prefetch_related("device")

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    return _task_with_device(task)


@app.post("/api/v1/tasks/{task_id}/cancel")
async def cancel_task(task_id: str, principal: Principal = Depends(get_current_principal)):
    """Cancel a pending or running task.

    Cancellation is DB-backed: tasks may live in another process (sync service)
    or be awaiting a device response, so there is often no in-memory handle to
    cancel -- the status flip is what stops the webhook from completing it later.
    A command already queued on the device cannot be recalled; cancelling stops
    the controller from tracking it further.
    """
    tenant = principal.tenant
    task = await Task.get_or_none(id=task_id, tenant=tenant)

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if task.status not in ["pending", "running"]:
        raise HTTPException(
            status_code=400, detail=f"Task is already {task.status} and cannot be cancelled"
        )

    # Best-effort: stop the in-process handler if this process owns it.
    await task_manager.cancel_task(str(task.id))

    task.status = "cancelled"
    task.completed_at = datetime.now(timezone.utc)
    await task.save(update_fields=["status", "completed_at"])

    return {"message": "Task cancelled"}


@app.post("/api/v1/tasks/{task_id}/retry")
async def retry_task(task_id: str, principal: Principal = Depends(get_current_principal)):
    """Retry a failed or cancelled task by re-dispatching it through the same
    handler its task_type originally used.

    Only terminal, non-successful tasks (failed/cancelled) may be retried --
    pending/running tasks are already in flight and completed tasks have
    nothing to retry. A fresh Task row is created (copying tenant/type/
    description/device/user/details) rather than mutating the old one, so the
    original failure stays in the audit history and the retry gets its own
    lifecycle -- the same pattern the reconciler and send_device_command use
    when queueing work. task_types with no registered handler (e.g. the
    synchronous set_name/tag_update audit tasks) are not safely re-runnable
    and are rejected.
    """
    tenant = principal.tenant
    task = await Task.get_or_none(id=task_id, tenant=tenant).prefetch_related("device")

    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if task.status not in ("failed", "cancelled"):
        raise HTTPException(
            status_code=409,
            detail=f"Task is {task.status}; only failed or cancelled tasks can be retried",
        )

    from controller.services.task_handlers import TASK_HANDLERS

    handler = TASK_HANDLERS.get(task.type)
    if handler is None:
        raise HTTPException(
            status_code=400,
            detail=f"Task type '{task.type}' has no re-runnable handler and cannot be retried",
        )

    # Copy the input details but drop command_uuid -- that's an output the
    # failed attempt wrote (correlates a webhook to a specific device command)
    # and must not leak into the new task's row before the handler issues its
    # own command.
    retry_details = dict(task.details or {})
    retry_details.pop("command_uuid", None)

    new_task = await task_manager.create_task(
        tenant=tenant,
        task_type=task.type,
        description=f"Retry: {task.description}",
        device=task.device,
        user=principal.email,
        details=retry_details,
    )

    from controller.services.reconciler import _spawn

    # _spawn keeps a strong reference; a bare asyncio.create_task can be
    # garbage-collected mid-flight, silently dropping the retry.
    _spawn(task_manager.execute_task(new_task, handler))

    return {"task_id": str(new_task.id), "message": "Task retry started"}


# Reports and Statistics
@app.get("/api/v1/stats/overview")
async def get_overview_stats(principal: Principal = Depends(get_current_principal)):
    """Get overview statistics"""
    tenant = principal.tenant

    device_count = await Device.filter(tenant=tenant).count()
    active_devices = await Device.filter(
        tenant=tenant, last_seen__gte=datetime.now(timezone.utc) - timedelta(days=7)
    ).count()

    task_stats = await task_manager.get_task_stats(tenant)

    app_deployments = await AppDeployment.filter(
        tenant=tenant, status="installed"
    ).count()
    profile_deployments = await ProfileDeployment.filter(
        tenant=tenant, status="installed"
    ).count()

    return {
        "devices": {"total": device_count, "active_7d": active_devices},
        "tasks": task_stats,
        "deployments": {"apps": app_deployments, "profiles": profile_deployments},
    }


@app.get("/api/v1/stats/devices/by-model")
async def get_devices_by_model(principal: Principal = Depends(get_current_principal)):
    """Get device distribution by model"""
    tenant = principal.tenant

    from tortoise.functions import Count

    stats = (
        await Device.filter(tenant=tenant)
        .annotate(count=Count("id"))
        .group_by("device_model")
        .values("device_model", "count")
    )

    return stats


@app.get("/api/v1/stats/devices/by-os")
async def get_devices_by_os(principal: Principal = Depends(get_current_principal)):
    """Get device distribution by OS version"""
    tenant = principal.tenant

    from tortoise.functions import Count

    stats = (
        await Device.filter(tenant=tenant)
        .annotate(count=Count("id"))
        .group_by("os_version")
        .values("os_version", "count")
    )

    return stats


# File Management
_SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9._-]+$")


@app.post("/api/v1/apps/upload")
async def upload_app_package(
        file: UploadFile = File(...),
        app_id: str = Query(..., min_length=1),
        version: str = Query(..., min_length=1),
        principal: Principal = Depends(get_current_principal),
):
    """Upload an app package to S3"""
    tenant = principal.tenant

    if not (tenant.s3_config or {}).get("bucket"):
        raise HTTPException(status_code=400, detail="S3 not configured for tenant")

    # Reject anything that could escape the intended key namespace (path/object
    # injection or overwriting another app's package).
    if not _SAFE_KEY_RE.match(app_id) or not _SAFE_KEY_RE.match(version):
        raise HTTPException(
            status_code=400,
            detail="app_id and version may contain only letters, digits, '.', '_' and '-'",
        )

    file_extension = os.path.splitext(file.filename or "")[1]
    if file_extension and not _SAFE_KEY_RE.match(file_extension.lstrip(".")):
        raise HTTPException(status_code=400, detail="Unsupported file name")

    s3_key = f"{app_id}/{app_id}-{version}{file_extension}"

    app_manager = AppManager(tenant)
    s3_config = tenant.s3_config

    try:
        app_manager.s3_client.upload_fileobj(
            file.file, s3_config["bucket"], f"{s3_config.get('prefix', '')}{s3_key}"
        )

        return {"s3_key": s3_key, "message": "File uploaded successfully"}
    except Exception as e:
        logger.error(f"App upload failed for tenant {tenant.id}: {e}")
        raise HTTPException(status_code=500, detail="Upload failed")


# App Manifest Endpoints
@app.get("/api/manifests/{deployment_id}")
async def get_app_manifest(deployment_id: str):
    """Get app installation manifest for MDM"""
    # Note: This endpoint doesn't require authentication because devices need to access it
    # The deployment_id acts as a secure token

    # Get the deployment
    deployment = await AppDeployment.get_or_none(id=deployment_id).prefetch_related(
        "tenant", "device"
    )

    if not deployment:
        raise HTTPException(status_code=404, detail="Deployment not found")

    # Get app configuration
    tenant = deployment.tenant
    yaml_path = _tenant_dir(tenant.id) / "apps.yaml"

    if not yaml_path.exists():
        raise HTTPException(status_code=404, detail="App configuration not found")

    with open(yaml_path, "r") as f:
        apps_config = yaml.safe_load(f)

    # Find the app and version
    app_info = None
    for app in apps_config.get("apps", []):
        if app["id"] == deployment.app_id:
            for version in app.get("versions", []):
                if version["version"] == deployment.app_version:
                    app_info = {
                        "id": app["id"],
                        "name": app["name"],
                        "bundle_id": app["bundle_id"],
                        "version": version["version"],
                        "s3_key": version["s3_key"],
                        "sha256": version.get("sha256", ""),
                    }
                    break
            break

    if not app_info:
        raise HTTPException(status_code=404, detail="App version not found")

    # Integrity is mandatory: refuse to hand a device a download URL we cannot
    # bind to a known-good content hash.
    if not re.match(r"^[a-fA-F0-9]{64}$", app_info.get("sha256") or ""):
        logger.error(
            f"Refusing manifest for {deployment.app_id} {deployment.app_version}: missing sha256"
        )
        raise HTTPException(status_code=500, detail="App version is missing an integrity hash")

    # Generate presigned URL for the app package
    app_manager = AppManager(tenant)
    s3_config = tenant.s3_config

    try:
        download_url = app_manager.s3_client.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": s3_config["bucket"],
                "Key": f"{s3_config.get('prefix', '')}{app_info['s3_key']}",
            },
            ExpiresIn=3600,  # 1 hour
        )
    except Exception as e:
        logger.error(f"Failed to generate presigned URL: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate download URL")

    # Build the manifest plist
    manifest = {
        "items": [
            {
                "assets": [{"kind": "software-package", "url": download_url}],
                "metadata": {
                    "bundle-identifier": app_info["bundle_id"],
                    "bundle-version": app_info["version"],
                    "kind": "software",
                    "title": app_info["name"],
                },
            }
        ]
    }

    # SHA256 is guaranteed present (enforced above).
    manifest["items"][0]["assets"][0]["sha256"] = app_info["sha256"]

    # Convert to plist format
    import plistlib

    plist_data = plistlib.dumps(manifest)

    # Return as plist with appropriate content type
    return Response(
        content=plist_data,
        media_type="application/x-plist",
        headers={
            "Content-Disposition": (
                f"attachment; filename={app_info['id']}-{app_info['version']}.plist"
            )
        },
    )


@app.get("/api/manifests/{deployment_id}/info")
async def get_app_manifest_info(
        deployment_id: str, principal: Principal = Depends(get_current_principal)
):
    """Get information about an app manifest (authenticated endpoint)"""
    # This endpoint requires authentication and provides info about the manifest

    deployment = await AppDeployment.get_or_none(
        id=deployment_id, tenant=principal.tenant
    ).prefetch_related("device")

    if not deployment:
        raise HTTPException(status_code=404, detail="Deployment not found")

    return {
        "deployment_id": str(deployment.id),
        "app_id": deployment.app_id,
        "app_version": deployment.app_version,
        "device_id": str(deployment.device.id),
        "device_serial": deployment.device.serial_number,
        "status": deployment.status,
        "created_at": deployment.created_at,
        "manifest_url": f"{os.getenv('PUBLIC_API_URL')}/api/manifests/{deployment_id}",
    }


# Enrollment
@app.get("/api/v1/enrollment")
async def get_enrollment(principal: Principal = Depends(get_current_principal)):
    """Enrollment details for the current tenant (server URLs, topic, enroll URL)."""
    return enrollment_svc.enrollment_details(principal.tenant)


@app.get("/api/v1/enroll/{tenant_id}/{token}")
async def download_enrollment_profile(tenant_id: str, token: str):
    """Serve the over-the-air enrollment .mobileconfig for a device to install.

    Unauthenticated (devices have no JWT) but gated by a per-tenant token.
    """
    tenant = await Tenant.get_or_none(id=tenant_id)
    if not tenant or not tenant.is_active:
        raise HTTPException(status_code=404, detail="Not found")
    if not enrollment_svc.verify_enrollment_token(tenant_id, token):
        raise HTTPException(status_code=403, detail="Forbidden")

    # Refuse to hand a device a structurally-valid but dead profile (empty APNs
    # topic, SCEP challenge, or URLs) -- it would install and never check in.
    details = enrollment_svc.enrollment_details(tenant)
    if not details["configured"]:
        raise HTTPException(
            status_code=503,
            detail=f"Enrollment is not fully configured; missing: {', '.join(details['missing'])}",
        )

    data = enrollment_svc.build_enrollment_mobileconfig(tenant)
    return Response(
        content=data,
        media_type="application/x-apple-aspen-config",
        headers={
            "Content-Disposition": f'attachment; filename="enroll-{tenant_id}.mobileconfig"'
        },
    )


# Health check
@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc)}


# Register Tortoise ORM
register_tortoise(
    app,
    db_url=DATABASE_URL,
    modules={"models": ["controller.models.tenant"]},
    generate_schemas=True,
    add_exception_handlers=True,
)


# Late-added columns (registered AFTER register_tortoise so the connection exists
# when this startup handler runs -- FastAPI runs startup hooks in add order).
@app.on_event("startup")
async def _apply_aux_ddl():
    from controller.models.database import ensure_aux_columns
    await ensure_aux_columns()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
