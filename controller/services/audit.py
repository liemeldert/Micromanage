import logging
from typing import Any, Dict, Optional

from controller.auth.dependencies import Principal
from controller.models.tenant import AuditLog

logger = logging.getLogger(__name__)


async def record_audit(
    principal: Principal,
    action: str,
    *,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    detail: Optional[Dict[str, Any]] = None,
) -> None:
    """Best-effort: record an admin action in the tenant-scoped audit log.

    Called AFTER the primary action has already succeeded, so it swallows and
    logs every failure -- an audit-write error must NEVER break (or roll back)
    the action the operator actually performed. Mirrors the best-effort shape
    of webhook_handler._log_attempt / reconciler background tasks.

    SECURITY: ``detail`` must contain NO secrets (passwords, tokens, keys).
    The row is scoped to ``principal.tenant`` and records who acted
    (``actor_email`` / ``actor_role``) plus a small non-secret target/context.
    """
    try:
        await AuditLog.create(
            tenant=principal.tenant,
            actor_email=principal.email,
            actor_role=principal.role,
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=detail or {},
        )
    except Exception:
        logger.exception("audit: failed to record action %s (target=%s/%s)",
                         action, target_type, target_id)
