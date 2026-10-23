"""What this deployment is configured to do, asked one capability at a time.

One predicate per thing this server does. check(capability, tenant=...) returns a Status that is ready or carries the
reason it is not.
"""

import base64
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Nothing from controller.* is imported at module scope, to avoid an import cycle.
# Every predicate below that needs one of them imports it inside the function instead.

DEPLOYMENT = "deployment"
TENANT = "tenant"

ENROLL = "enroll"
ADE = "ade"
APP_INSTALL = "app_install"
DDM_BRIDGE = "ddm_bridge"
DDM_SYNC = "ddm_sync"
MDM_ENQUEUE = "mdm_enqueue"
ESCROW = "escrow"
WEBHOOK_INGEST = "webhook_ingest"
SECRETS = "secrets"

# Every capability, in the order the API reports them. A caller keys off the name, not the position.
CAPABILITIES: Tuple[str, ...] = (
    ENROLL, ADE, APP_INSTALL, DDM_BRIDGE, DDM_SYNC, MDM_ENQUEUE, ESCROW,
    WEBHOOK_INGEST, SECRETS,
)

# The placeholder secrets the shipped env templates carry. Matched as exact strings, not by prefix.
PLACEHOLDER_VALUES = frozenset({
    "your-secret-key-change-in-production",
    "changeme_long_random_secret",  # JWT_SECRET
    "changeme_webhook_secret",  # WEBHOOK_SECRET
    "changeme_random_api_key",  # NANOMDM_API_KEY
    "changeme_strong_password",  # DB_PASSWORD
    "change-me-now",  # CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD
})


@dataclass(frozen=True)
class Status:
    """One capability's answer.

    reason is prose, empty when ready. missing/broken carry setting names only, never a value.
    """

    ready: bool
    reason: str = ""
    missing: Tuple[str, ...] = ()
    broken: Tuple[str, ...] = ()
    scope: str = DEPLOYMENT
    warnings: Tuple[str, ...] = ()

    def to_dict(self, capability: str) -> Dict[str, Any]:
        return {
            "capability": capability,
            "ready": self.ready,
            "reason": self.reason,
            "missing": list(self.missing),
            "broken": list(self.broken),
            "scope": self.scope,
            "warnings": list(self.warnings),
        }


def Ready(*, warnings: Any = ()) -> Status:  # noqa: N802 - reads as a constructor
    return Status(True, warnings=tuple(warnings))


def Blocked(reason: str, missing: Any = (), scope: str = DEPLOYMENT,  # noqa: N802
            warnings: Any = (), broken: Any = ()) -> Status:
    return Status(False, reason=reason, missing=tuple(missing),
                  broken=tuple(broken), scope=scope, warnings=tuple(warnings))


# ==Reading settings==

def _value(name: str) -> str:
    """One environment value, or empty. Read now, never cached."""
    return os.getenv(name) or ""


def is_placeholder(value: Optional[str]) -> bool:
    """Whether a value is one of the strings the env templates ship."""
    return (value or "").strip() in PLACEHOLDER_VALUES


def public_api_url() -> str:
    """The deployment's public address, trailing slash removed, or empty.

    The single reader for it, so the trailing-slash handling cannot differ between call sites.
    """
    return _value("PUBLIC_API_URL").rstrip("/")


def dep_ade_require_apple_signature() -> bool:
    """Whether the ADE endpoint rejects a MachineInfo that does not verify. On unless set to a false word."""
    from controller.utils.coerce import env_flag
    return env_flag("DEP_ADE_REQUIRE_APPLE_SIGNATURE", "true")


def scep_webhook_secret_path() -> str:
    """The file holding the step-ca challenge webhook's secret."""
    return _value("SCEP_WEBHOOK_SECRET_FILE") or "/stepca-webhook/scep_webhook_secret"


def scep_webhook_id_path() -> str:
    """The file holding the step-ca challenge webhook's id."""
    return _value("SCEP_WEBHOOK_ID_FILE") or "/stepca-webhook/scep_webhook_id"


def _file_text(path: str) -> str:
    """A file's contents without surrounding whitespace, or empty when it cannot be read."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except (OSError, UnicodeDecodeError):
        return ""


def scep_webhook_key() -> Optional[bytes]:
    """The step-ca challenge webhook's secret decoded from the standard base64 its file holds, or None when the file is
    missing, empty or not base64."""
    text = _file_text(scep_webhook_secret_path())
    if not text:
        return None
    try:
        return base64.b64decode(text, validate=True) or None
    except (ValueError, TypeError):
        return None


def scep_webhook_id() -> str:
    """The step-ca challenge webhook's id, or empty when its file cannot be read."""
    return _file_text(scep_webhook_id_path())


def scep_name() -> str:
    """The name of step-ca's SCEP provisioner, SCEP_NAME or mdm_device_scep."""
    return _value("SCEP_NAME") or "mdm_device_scep"


def ddm_secret() -> str:
    """The key NanoMDM signs DDM check-ins with, falling back to the webhook's."""
    return _value("DDM_HMAC_SECRET") or _value("WEBHOOK_SECRET")


def fernet_key_error(value: Optional[str]) -> Optional[str]:
    """Why value is not a Fernet key (32 bytes of urlsafe base64), or None if it is one."""
    if not value:
        return None
    try:
        if len(base64.urlsafe_b64decode(value.strip().encode())) == 32:
            return None
    except Exception:
        pass
    return ("SECRET_ENCRYPTION_KEY is set but it is not a Fernet key (32 bytes "
            "of urlsafe base64). Generate one with "
            "\"python -c 'from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())'\", or unset it to derive the "
            "key from JWT_SECRET instead.")


def _jwt_secret_missing() -> bool:
    """Whether JWT_SECRET is unset or still a template value."""
    from controller.auth.tokens import AuthConfigError, _secret

    try:
        _secret()
    except AuthConfigError:
        return True
    return False


def _http_warning(where: str) -> Optional[str]:
    """The clear-text warning, when the public address is http rather than https."""
    public = public_api_url()
    if public and not public.startswith("https://"):
        return (f"PUBLIC_API_URL is '{public}', which is not https, so {where} "
                "travels in clear text. Serve this deployment over https and "
                "point PUBLIC_API_URL at its https address.")
    return None


# ==The predicates==

def _cutover_done() -> bool:
    """The identity cutover state as this process last read it. warm_enroll_state refreshes it."""
    from controller.services import identity
    return identity.cutover_done_cached()


def _check_enroll(tenant, active_tenants: Optional[int]) -> Status:
    """Over-the-air enrollment: whether this server can hand a device a live profile."""
    from controller.services import enrollment

    missing: List[str] = []
    if not _value("MDM_TOPIC"):
        missing.append("MDM_TOPIC")
    if not public_api_url():
        missing.append("PUBLIC_API_URL")
    if _jwt_secret_missing():
        missing.append("JWT_SECRET")

    # MDM_HOSTNAME is only required when MDM_SERVER_URL or SCEP_URL is not set outright.
    if not _value("MDM_HOSTNAME") and (
        not _value("MDM_SERVER_URL") or not _value("SCEP_URL")):
        missing.append("MDM_HOSTNAME")

    # Reported as broken, not missing: a set-and-broken path breaks the profile.
    broken: List[str] = []
    sentences: List[str] = []
    ca_error = enrollment.embedded_ca_error()
    if ca_error:
        broken.append("MDM_EMBED_CA_CERT_PATH")
        sentences.append(ca_error)
    secret_path = scep_webhook_secret_path()
    if scep_webhook_key() is None:
        broken.append("SCEP_WEBHOOK_SECRET_FILE")
        sentences.append(
            f"The step-ca challenge webhook secret at {secret_path} is missing, empty or not base64, so the controller "
            "refuses every SCEP challenge. It is written when step-ca attaches the webhook.")
    # The two conditions below are not settings, so they block with a sentence and add nothing to broken.
    if not _cutover_done():
        sentences.append(
            "The identity cutover has not run, so certificates issued before it are not yet recorded. It runs when "
            "the controller starts and can reach NanoMDM's database.")
    webhook = _SCEP_WEBHOOK_PROBE.get("state")
    if webhook == "detached":
        sentences.append(
            f"step-ca's {scep_name()} provisioner has no SCEPCHALLENGE webhook with the id in "
            f"{scep_webhook_id_path()}, so step-ca does not ask the controller about SCEP challenges.")

    warnings: List[str] = []
    http = _http_warning("the enrollment profile, with its SCEP challenge,")
    if http:
        warnings.append(http)
    if webhook == "unreachable":
        warnings.append(
            "step-ca could not be reached to confirm that its SCEP provisioner calls the controller's challenge "
            "webhook.")
    legacy = (_LEGACY_PROBE.get("counts") or {}).get(str(tenant.id)) if tenant is not None else None
    if legacy:
        warnings.append(
            f"{legacy} enrolled device(s) still hold an identity certificate issued before per-enrollment SCEP "
            "challenges. They keep working and move to a new certificate when it is renewed.")
    schema = _NANOMDM_SCHEMA_PROBE.get("warning")
    if schema:
        warnings.append(schema)

    if not missing and not sentences:
        return Ready(warnings=warnings)

    # Built from the unset settings only; each set-and-broken item and each other problem has its own sentence.
    parts = []
    if missing:
        parts.append(f"Enrollment cannot be served: {_names(missing)} "
                     f"{'is' if len(missing) == 1 else 'are'} not configured.")
    parts.extend(sentences)
    return Blocked(" ".join(parts), missing=missing, broken=broken,
                   scope=DEPLOYMENT, warnings=warnings)


def _check_ade(tenant, active_tenants: Optional[int]) -> Status:
    """Automated Device Enrollment: whether there is a URL Apple can send a device to."""
    missing: List[str] = []
    if not public_api_url():
        missing.append("PUBLIC_API_URL")
    if _jwt_secret_missing():
        missing.append("JWT_SECRET")

    warnings: List[str] = []
    http = _http_warning("the enrollment profile Setup Assistant downloads")
    if http:
        warnings.append(http)
    if not dep_ade_require_apple_signature():
        warnings.append(
            "DEP_ADE_REQUIRE_APPLE_SIGNATURE is off, so the ADE enrollment endpoint issues an enrollment profile to "
            "any caller holding this tenant's enrollment token who names a serial DEP lists for this tenant and that "
            "is not enrolled. Confirm real devices verify against an Apple anchor in staging, then turn it on.")

    if not missing:
        return Ready(warnings=warnings)
    return Blocked(
        f"Automated Device Enrollment needs an enrollment URL, and {_names(missing)} "
        f"{'is' if len(missing) == 1 else 'are'} not configured, so there is "
        "nothing to push to Apple.",
        missing=missing, scope=DEPLOYMENT, warnings=warnings)


def _check_app_install(tenant, active_tenants: Optional[int]) -> Status:
    """Installing an app package: a bucket to sign a download from, and an https ManifestURL."""
    warnings: List[str] = []
    http = _http_warning("the package manifest, with its presigned download URL,")
    if http:
        warnings.append(http)

    # Deployment-scoped blocker first, so a both-blocked answer doesn't flip scope when the first is fixed.
    public = public_api_url()
    if not public:
        return Blocked(
            "PUBLIC_API_URL is not set, so there is no address to serve the "
            "package manifest from and no ManifestURL to send a device.",
            missing=["PUBLIC_API_URL"], scope=DEPLOYMENT, warnings=warnings)
    if not public.startswith("https://"):
        return Blocked(
            f"PUBLIC_API_URL is '{public}', which is not https, and Apple "
            "requires an https ManifestURL, so every device would refuse the "
            "install. Serve this deployment over https and set PUBLIC_API_URL to "
            "its https address.",
            missing=["PUBLIC_API_URL"], scope=DEPLOYMENT, warnings=warnings)

    if tenant is not None:
        from controller.services.app_manager import (
            S3ConfigError, no_bucket_error, resolve_s3_settings,
        )

        try:
            settings = resolve_s3_settings(tenant)
        except S3ConfigError as exc:
            # Everything resolve_s3_settings refuses is the tenant's own s3 block.
            return Blocked(str(exc), missing=["s3"], scope=TENANT,
                           warnings=warnings)
        if not settings.bucket:
            # Only reachable from the ambient environment; a tenant's own object store already names a bucket.
            return Blocked(str(no_bucket_error(tenant.id)),
                           missing=["AWS_S3_BUCKET"], scope=DEPLOYMENT,
                           warnings=warnings)

    return Ready(warnings=warnings)


def _check_ddm_bridge(tenant, active_tenants: Optional[int]) -> Status:
    """The legacy profile bridge: an https address the device can download from."""
    public = public_api_url()
    if not public:
        return Blocked(
            "PUBLIC_API_URL is not set, so there is no address for a device to download the bridged profile from.",
            missing=["PUBLIC_API_URL"], scope=DEPLOYMENT)
    if not public.startswith("https://"):
        return Blocked(
            f"PUBLIC_API_URL ({public}) is not https, and "
            "com.apple.configuration.legacy requires an https ProfileURL.",
            missing=["PUBLIC_API_URL"], scope=DEPLOYMENT)
    return Ready()


def _check_ddm_sync(tenant, active_tenants: Optional[int]) -> Status:
    """Declarative management check-ins: the key their signatures are made with."""
    warnings: List[str] = []
    if not _value("DDM_HMAC_SECRET") and _value("WEBHOOK_SECRET"):
        warnings.append(
            "DDM_HMAC_SECRET is not set, so declarative management falls back to WEBHOOK_SECRET. One value then proves "
            "webhook authenticity, every DDM check-in signature and every bridged-profile URL, so a leak of any one of "
            "them is a leak of all three. Set DDM_HMAC_SECRET to a separate random value.")
    if not ddm_secret():
        return Blocked(
            "Declarative management check-ins are signed, and neither DDM_HMAC_SECRET nor WEBHOOK_SECRET is set, so "
            "every check-in and every bridged-profile download is rejected. WEBHOOK_HMAC_KEY does not cover this: it "
            "keys the webhook's own body signature, and NanoMDM signs declarative check-ins with a separate key.",
            missing=["DDM_HMAC_SECRET", "WEBHOOK_SECRET"], scope=DEPLOYMENT)
    return Ready(warnings=warnings)


def _check_mdm_enqueue(tenant, active_tenants: Optional[int]) -> Status:
    """Sending anything to a device: the key NanoMDM's management API needs."""
    key = _value("NANOMDM_API_KEY")
    warnings: List[str] = []
    if is_placeholder(key):
        warnings.append(
            "NANOMDM_API_KEY is still the value from the env template. It works as long as NanoMDM carries the same "
            "string, and anyone who has read the template knows it. Generate a random one for both sides.")
    if not key:
        return Blocked(
            "NANOMDM_API_KEY is not set, so the controller cannot authenticate "
            "to NanoMDM and no command or push can be sent to any device.",
            missing=["NANOMDM_API_KEY"], scope=DEPLOYMENT)
    return Ready(warnings=warnings)


def _check_escrow(tenant, active_tenants: Optional[int]) -> Status:
    """Encryption at rest for DEP credentials and escrowed device passwords."""
    explicit = _value("SECRET_ENCRYPTION_KEY")
    error = fernet_key_error(explicit)
    if error:
        return Blocked(error, missing=["SECRET_ENCRYPTION_KEY"], scope=DEPLOYMENT)
    if explicit:
        return Ready()
    # Same check as the token module: a JWT_SECRET still at the template value is public, so a derived key is too.
    if not _jwt_secret_missing():
        return Ready(warnings=[
            "SECRET_ENCRYPTION_KEY is not set, so the encryption key is derived from JWT_SECRET. That works, and it "
            "means rotating JWT_SECRET makes every stored DEP credential and escrowed password unreadable. Set "
            "SECRET_ENCRYPTION_KEY to rotate the two independently."])
    return Blocked(
        "There is no key to encrypt stored secrets with: SECRET_ENCRYPTION_KEY is not set, and JWT_SECRET is unset or "
        "still a value from the env template, which is public and so cannot be used to derive one. Linking a DEP "
        "server or escrowing a device password is refused.",
        missing=["SECRET_ENCRYPTION_KEY", "JWT_SECRET"], scope=DEPLOYMENT)


def _check_webhook_ingest(tenant, active_tenants: Optional[int]) -> Status:
    """Taking in NanoMDM's check-ins and command acknowledgements."""
    hmac_key = _value("WEBHOOK_HMAC_KEY")
    secret = _value("WEBHOOK_SECRET")
    warnings: List[str] = []
    if is_placeholder(secret):
        warnings.append(
            "WEBHOOK_SECRET is still the value from the env template, so anyone who can reach the controller's "
            "internal port and has read the template can forge a check-in. Generate a random one for both sides.")
    if not hmac_key and secret:
        warnings.append(
            "WEBHOOK_HMAC_KEY is not set, so check-ins are authenticated by a secret carried in the webhook URL, which "
            "appears in docker inspect, in any compose render and in an access log line for every device check-in. Set "
            "WEBHOOK_HMAC_KEY on both the controller and NanoMDM: a later release drops the URL secret and will "
            "require it.")
    if not hmac_key and not secret:
        return Blocked(
            "Neither WEBHOOK_HMAC_KEY nor WEBHOOK_SECRET is set, so every device check-in and every command "
            "acknowledgement from NanoMDM is rejected. The fleet looks like it went quiet while the devices are fine.",
            missing=["WEBHOOK_HMAC_KEY", "WEBHOOK_SECRET"], scope=DEPLOYMENT)
    return Ready(warnings=warnings)


def _check_secrets(tenant, active_tenants: Optional[int]) -> Status:
    """Whether the stored secrets decrypt with the current key, as probe_secrets last found."""
    if _SECRETS_PROBE.get("error"):
        return Ready(warnings=["Stored secrets could not be checked because the database query failed. Check the "
                               "controller's database connection."])
    failed = _SECRETS_PROBE.get("failed")
    if not failed:
        return Ready()
    columns = ", ".join(failed)
    if _SECRETS_PROBE.get("source") == "SECRET_ENCRYPTION_KEY":
        return Blocked(
            f"Stored secrets do not decrypt with the current SECRET_ENCRYPTION_KEY (failed: {columns}). Restore its "
            "previous value, or unset it if they were stored under the key derived from JWT_SECRET, and restart the "
            "controller.",
            broken=["SECRET_ENCRYPTION_KEY"], scope=DEPLOYMENT)
    return Blocked(
        f"Stored secrets do not decrypt with the key derived from JWT_SECRET (failed: {columns}). Restore the previous "
        "JWT_SECRET, or set SECRET_ENCRYPTION_KEY to the key that stored them, and restart the controller.",
        broken=["JWT_SECRET"], scope=DEPLOYMENT)


_PREDICATES = {
    ENROLL: _check_enroll,
    ADE: _check_ade,
    APP_INSTALL: _check_app_install,
    DDM_BRIDGE: _check_ddm_bridge,
    DDM_SYNC: _check_ddm_sync,
    MDM_ENQUEUE: _check_mdm_enqueue,
    ESCROW: _check_escrow,
    WEBHOOK_INGEST: _check_webhook_ingest,
    SECRETS: _check_secrets,
}


def _names(missing: List[str]) -> str:
    """A setting list as English: "A", "A and B", "A, B and C"."""
    if len(missing) == 1:
        return missing[0]
    return ", ".join(missing[:-1]) + " and " + missing[-1]


def settings_to_check(answer: Any) -> str:
    """The setting names from a readiness answer, as one comma-separated string, empty when none is named."""
    if isinstance(answer, Status):
        missing, broken = answer.missing, answer.broken
    else:
        missing = (answer or {}).get("missing") or []
        broken = (answer or {}).get("broken") or []
    return ", ".join(list(missing) + list(broken))


def check(capability: str, tenant=None, active_tenants: Optional[int] = None
          ) -> Status:
    """Whether capability can be performed, and if not, what to set."""
    predicate = _PREDICATES.get(capability)
    if predicate is None:
        raise KeyError(f"unknown capability {capability!r}")
    return predicate(tenant, active_tenants)


def check_all(tenant=None, active_tenants: Optional[int] = None
              ) -> List[Tuple[str, Status]]:
    """Every capability, in report order. One env read per setting per call."""
    return [(name, check(name, tenant=tenant, active_tenants=active_tenants))
            for name in CAPABILITIES]


def report(tenant=None, active_tenants: Optional[int] = None) -> Dict[str, Any]:
    """The readiness answer as the API serves it. Names only, never values."""
    rows = check_all(tenant=tenant, active_tenants=active_tenants)
    return {
        "ready": all(status.ready for _name, status in rows),
        "capabilities": [status.to_dict(name) for name, status in rows],
    }


# ==Boot==

def bootstrap_admin_error() -> Optional[str]:
    """Why the first-run admin bootstrap must not run, or None. Only checked when an email is set."""
    if not _value("CONTROLLER_BOOTSTRAP_ADMIN_EMAIL"):
        return None
    if not is_placeholder(_value("CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD")):
        return None
    return (
        "CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD is still the value the env template ships, so starting would create an "
        "administrator whose password is published in this repository. Set a real password, or clear "
        "CONTROLLER_BOOTSTRAP_ADMIN_EMAIL to skip the first-run bootstrap entirely. If this deployment has already "
        "started once with that value, sign in and change that account's password as well, because clearing the "
        "variable does not change an account that already exists."
    )


def boot_error() -> Optional[str]:
    """The misconfigurations this server refuses to start with, or None. Starting is worse than not, for both."""
    return (fernet_key_error(_value("SECRET_ENCRYPTION_KEY"))
            or bootstrap_admin_error())


def log_boot_warnings() -> None:
    """One line per readiness warning, at startup. Only the readiness endpoint would show these otherwise."""
    for name, status in check_all():
        for warning in status.warnings:
            logger.warning("readiness[%s]: %s", name, warning)
    if is_placeholder(_value("DB_PASSWORD")):
        # No capability reads DB_PASSWORD, so it is worth saying once here instead.
        logger.warning(
            "readiness: DB_PASSWORD is still the value from the env template. Anyone who has read the template knows "
            "this deployment's database password.")


def enforce_boot() -> None:
    """Log the warnings, and stop the process on the one fatal misconfiguration."""
    log_boot_warnings()
    fatal = boot_error()
    if fatal:
        logger.critical("Refusing to start: %s", fatal)
        raise SystemExit(1)


async def _nanomdm_connection():
    """A connection to NanoMDM's database, or None with a warning logged when it cannot be reached."""
    from controller.services import nanomdm_store

    try:
        return await nanomdm_store._connect()
    except Exception as exc:
        logger.warning("readiness: cannot connect to NanoMDM database: %s", exc)
        return None


async def check_nanomdm_storage() -> Optional[str]:
    """Check NanoMDM database for retained command results indicating delete=1 is not active."""
    conn = await _nanomdm_connection()
    if conn is None:
        return None
    try:
        query = (
            "SELECT count(*) FROM command_results WHERE status <> 'NotNow' AND created_at > NOW() - INTERVAL '1 hour'"
        )
        count = await conn.fetchval(query)
        if count and count > 0:
            return (
                f"NanoMDM has {count} completed command result(s) retained in the last hour. "
                "NanoMDM delete=1 storage option may not be active."
            )
        return None
    except Exception as exc:
        logger.warning("readiness: query on NanoMDM command_results failed: %s", exc)
        return None
    finally:
        await conn.close()


NANOMDM_COLUMNS: Dict[str, Tuple[str, ...]] = {
    "devices": ("id", "identity_cert", "serial_number", "unlock_token", "bootstrap_token_b64", "bootstrap_token_at"),
    "enrollments": ("id", "token_hex", "push_magic", "enabled"),
    "cert_auth_associations": ("id", "sha256", "created_at"),
}


async def check_nanomdm_schema() -> Optional[str]:
    """The NANOMDM_COLUMNS entries NanoMDM's database lacks, as a sentence, or None when it has them all or cannot be
    read."""
    conn = await _nanomdm_connection()
    if conn is None:
        return None
    try:
        rows = await conn.fetch(
            "SELECT table_name, column_name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = ANY($1::text[])", list(NANOMDM_COLUMNS))
    except Exception as exc:
        logger.warning("readiness: reading NanoMDM's columns failed: %s", exc)
        return None
    finally:
        await conn.close()
    present = {(row["table_name"], row["column_name"]) for row in rows}
    missing = [f"{table}.{column}" for table, columns in NANOMDM_COLUMNS.items() for column in columns
               if (table, column) not in present]
    if not missing:
        return None
    return (f"NanoMDM's database has no {', '.join(missing)} column{'' if len(missing) == 1 else 's'}, which the "
            "controller reads and writes. Check that NANOMDM_DATABASE_URL, or DATABASE_URL when it is unset, names "
            "NanoMDM's database and that its schema is the version this release expects.")


_PROBE_TTL_SECONDS = 60
# Process-local results the sync enroll predicate reads
_SCEP_WEBHOOK_PROBE: Dict[str, Any] = {}
_LEGACY_PROBE: Dict[str, Any] = {}
_NANOMDM_SCHEMA_PROBE: Dict[str, Any] = {}
_SECRETS_PROBE: Dict[str, Any] = {}


def _fresh(cache: Dict[str, Any]) -> bool:
    checked = cache.get("checked_at")
    return checked is not None and time.monotonic() - checked < _PROBE_TTL_SECONDS


def _webhook_attached(provisioners: Any, name: str, webhook_id: str) -> bool:
    """Whether the named provisioner carries a SCEPCHALLENGE webhook with this id."""
    if not webhook_id or not isinstance(provisioners, list):
        return False
    for provisioner in provisioners:
        if not isinstance(provisioner, dict) or provisioner.get("name") != name:
            continue
        hooks = (provisioner.get("options") or {}).get("webhooks") or provisioner.get("webhooks") or []
        if any(isinstance(h, dict) and h.get("kind") == "SCEPCHALLENGE" and h.get("id") == webhook_id
               for h in hooks):
            return True
    return False


async def warm_enroll_state() -> None:
    """Read the identity cutover state and the step-ca webhook probe into this process, so the sync enroll predicate
    uses current values."""
    from controller.services import identity

    try:
        await identity.cutover_done()
    except Exception as exc:
        logger.warning("readiness: cannot read the identity cutover state: %s", exc)
    try:
        await probe_scep_webhook()
    except Exception as exc:
        logger.warning("readiness: cannot probe step-ca's SCEP webhook: %s", exc)


async def probe_scep_webhook() -> Optional[str]:
    """Whether step-ca's SCEP provisioner calls the controller's challenge webhook: attached, detached or unreachable.
    Cached per process for 60 s."""
    if _fresh(_SCEP_WEBHOOK_PROBE):
        return _SCEP_WEBHOOK_PROBE.get("state")
    import ssl

    import httpx

    base = (_value("STEPCA_URL") or "https://step-ca:9000").rstrip("/")
    root = _value("STEPCA_ROOT_FILE") or "/stepca-certs/root_ca.crt"
    try:
        context = ssl.create_default_context(cafile=root)
        async with httpx.AsyncClient(verify=context, timeout=3) as client:
            response = await client.get(f"{base}/provisioners", params={"limit": 100})
            response.raise_for_status()
    except Exception as exc:
        logger.warning("readiness: cannot read step-ca's provisioners from %s: %s", base, exc)
        state = "unreachable"
    else:
        # step-ca answered, so a body that does not parse counts as detached.
        try:
            body = response.json()
            provisioners = body.get("provisioners") if isinstance(body, dict) else None
        except ValueError:
            logger.warning("readiness: step-ca's provisioners answer from %s is not JSON", base)
            provisioners = None
        attached = _webhook_attached(provisioners, scep_name(), scep_webhook_id())
        state = "attached" if attached else "detached"
    _SCEP_WEBHOOK_PROBE.update(state=state, checked_at=time.monotonic())
    return state


async def probe_legacy_identities() -> Optional[Dict[str, int]]:
    """Per tenant id, how many enrolled devices hold a certificate with a pre-cutover subject, or None when NanoMDM
    cannot be read. Cached per process for 60 s."""
    if _fresh(_LEGACY_PROBE):
        return _LEGACY_PROBE.get("counts")
    from controller.models.tenant import Device
    from controller.services import identity, nanomdm_store

    counts: Optional[Dict[str, int]]
    try:
        rows = await Device.filter(enrollment_state="enrolled", udid__isnull=False).values_list("tenant_id", "udid")
        tenant_of = {udid: str(tenant_id) for tenant_id, udid in rows if udid}
        identities = await nanomdm_store.list_identities(list(tenant_of)) if tenant_of else {}
        counts = {}
        for udid, found in identities.items():
            if udid in tenant_of and identity.LEGACY_CN.match(found.subject_cn or ""):
                counts[tenant_of[udid]] = counts.get(tenant_of[udid], 0) + 1
    except Exception as exc:
        logger.warning("readiness: cannot count legacy identity certificates: %s", exc)
        counts = None
    _LEGACY_PROBE.update(counts=counts, checked_at=time.monotonic())
    return counts


async def probe_nanomdm_schema() -> Optional[str]:
    """check_nanomdm_schema's warning, cached per process for 60 s."""
    if _fresh(_NANOMDM_SCHEMA_PROBE):
        return _NANOMDM_SCHEMA_PROBE.get("warning")
    try:
        warning = await check_nanomdm_schema()
    except Exception as exc:
        logger.warning("readiness: cannot check NanoMDM's columns: %s", exc)
        warning = None
    _NANOMDM_SCHEMA_PROBE.update(warning=warning, checked_at=time.monotonic())
    return warning


async def probe_enrollment() -> None:
    """Run every enrollment probe so the next report reads current results."""
    await warm_enroll_state()
    await probe_legacy_identities()
    await probe_nanomdm_schema()


async def probe_secrets() -> None:
    """Check that the stored secrets decrypt with the current key, cached per process for 60 s. Logs an error only
    when the failed columns change."""
    if _fresh(_SECRETS_PROBE):
        return
    from controller.services import crypto_secrets, secret_probe

    previous = _SECRETS_PROBE.get("failed")
    try:
        result = await secret_probe.run_check()
    except Exception as exc:
        logger.warning("readiness: cannot check stored secrets (%s)", type(exc).__name__)
        _SECRETS_PROBE.update(error=True, failed=None, source=None, checked_at=time.monotonic())
        return
    failed = tuple(result.failed)
    _SECRETS_PROBE.update(error=False, failed=failed, source=crypto_secrets.key_source(),
                          checked_at=time.monotonic())
    if failed and failed != previous:
        logger.error("readiness[%s]: %s", SECRETS, _check_secrets(None, None).reason)


def forget_secrets_probe() -> None:
    """Clear the cached stored-secrets result, for tests."""
    _SECRETS_PROBE.clear()
