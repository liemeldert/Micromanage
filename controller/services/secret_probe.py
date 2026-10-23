"""Whether the stored secrets decrypt with the current key, checked against a probe row and the newest value in each
encrypted column. Returns column names only, never a value."""

from dataclasses import dataclass
from typing import List, Optional, Tuple, Type

from tortoise.exceptions import IntegrityError
from tortoise.models import Model

from controller.models.tenant import (
    DepServer, Device, DeviceAgent, DeviceSecret, EnrollmentLink, SecretProbe, Tenant, UserMFA,
)
from controller.services import crypto_secrets

PROBE_PLAINTEXT = "micromanage secret probe v1"
PROBE_BINDING = "readiness/secret_probe"
PROBE_ID = 1

# (model, encrypted column, field the newest row is chosen by)
COLUMNS: Tuple[Tuple[Type[Model], str, str], ...] = (
    (Tenant, "fv_escrow_private_key_enc", "updated_at"),
    (Tenant, "profile_signing_key_enc", "updated_at"),
    (UserMFA, "secret_enc", "updated_at"),
    (Device, "push_token_enc", "last_seen"),
    (Device, "bootstrap_token_enc", "last_seen"),
    (EnrollmentLink, "token_enc", "created_at"),
    (DepServer, "private_key_enc", "updated_at"),
    (DepServer, "token_enc", "updated_at"),
    (DeviceSecret, "value_enc", "updated_at"),
    (DeviceAgent, "pending_token_enc", "pending_token_issued_at"),
)

PROBE_COLUMN = "secret_probe.token"


@dataclass(frozen=True)
class SecretsResult:
    """ok when every sampled value and the probe decrypt; failed names each one that does not as table.column."""

    ok: bool
    failed: Tuple[str, ...] = ()
    probe_written: bool = False


def _label(model: Type[Model], column: str) -> str:
    return f"{model._meta.db_table}.{column}"


async def sample_failures() -> List[str]:
    """The columns whose newest stored value does not decrypt with the current key, as table.column."""
    failed: List[str] = []
    for model, column, order in COLUMNS:
        newest = await (model.filter(**{f"{column}__isnull": False}).order_by(f"-{order}").limit(1)
                        .values_list(column, flat=True))
        if newest and newest[0] and not crypto_secrets.opens(newest[0]):
            failed.append(_label(model, column))
    return failed


def _probe_opens(token: Optional[str]) -> bool:
    """Whether the probe decrypts under its binding to PROBE_PLAINTEXT. decrypt runs only once opens succeeds, as it
    logs every failure."""
    return crypto_secrets.opens(token) and crypto_secrets.decrypt(token, aad=PROBE_BINDING) == PROBE_PLAINTEXT


async def _write_probe() -> bool:
    """Insert the probe row, True when it is present afterwards. Several workers may insert at once."""
    token = crypto_secrets.encrypt(PROBE_PLAINTEXT, aad=PROBE_BINDING)
    try:
        await SecretProbe.create(id=PROBE_ID, token=token)
    except IntegrityError:
        pass
    return await SecretProbe.exists(id=PROBE_ID)


async def ensure_probe() -> bool:
    """Write the probe row when it is absent, a key resolves and every sampled value decrypts. True when the row is
    present afterwards."""
    if crypto_secrets.key_source() is None:
        return False
    if await SecretProbe.exists(id=PROBE_ID):
        return True
    if await sample_failures():
        return False
    return await _write_probe()


async def run_check() -> SecretsResult:
    """Sample every column and the probe, writing the probe when it is absent and every sampled value decrypts. ok when
    no key resolves."""
    if crypto_secrets.key_source() is None:
        return SecretsResult(ok=True)
    failed = await sample_failures()
    row = await SecretProbe.get_or_none(id=PROBE_ID)
    written = False
    if row is None:
        if not failed:
            written = await _write_probe()
    elif not _probe_opens(row.token):
        failed.insert(0, PROBE_COLUMN)
    return SecretsResult(ok=not failed, failed=tuple(failed), probe_written=written)
