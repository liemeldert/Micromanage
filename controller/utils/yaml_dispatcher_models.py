"""Pydantic models for the Dispatcher document (webhooks, rules, actions) and the severity scale."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, validator

from controller.utils.yaml_config_models import _require_match, NAME_RE, SLUG_RE

# ==Dispatcher (dispatcher.yaml)==

VALID_SEVERITIES = ('black', 'red', 'yellow', 'green')


class DispatcherWebhook(BaseModel):
    """A named delivery target. url (and secret if present) are secrets:
    redacted from all API responses (see controller/api/redaction.py)."""
    name: str
    url: str
    secret: Optional[str] = None

    @validator('name')
    def validate_name(cls, v):
        return _require_match(NAME_RE, v,
                              "Webhook name must contain only alphanumeric characters, hyphens, and underscores")

    @validator('url')
    def validate_url(cls, v):
        if not str(v or '').strip():
            raise ValueError("Webhook url cannot be empty")
        return v


class DispatcherAction(BaseModel):
    """One rule action. params are validated per action-type imperatively. dry_run records what a remediation WOULD do
    without doing it."""
    type: str
    params: Optional[Dict[str, Any]] = {}
    dry_run: Optional[bool] = False


class DispatcherRule(BaseModel):
    id: str
    name: str
    enabled: Optional[bool] = True
    severity: str
    scope: Optional[Dict[str, Any]] = {}
    check: Dict[str, Any]
    # Anti-flap: only raise after this many minutes continuously non-compliant.
    grace_minutes: Optional[int] = 0
    actions: Optional[List[DispatcherAction]] = []
    auto_resolve: Optional[bool] = False

    @validator('id')
    def validate_id(cls, v):
        return _require_match(SLUG_RE, v, "Rule id must be a slug (lowercase letters, digits, hyphens, underscores)")

    @validator('severity')
    def validate_severity(cls, v):
        if v not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {VALID_SEVERITIES}")
        return v

    @validator('grace_minutes')
    def validate_grace(cls, v):
        if v is not None and v < 0:
            raise ValueError("grace_minutes cannot be negative")
        return v
