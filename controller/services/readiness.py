"""What this deployment is configured to do, asked one capability at a time.

One predicate per thing this server does.

    status = readiness.check("app_install", tenant=tenant)
    if not status.ready:
        raise HTTPException(status_code=400, detail=status.reason)
"""

import base64
import logging
import os
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

# Every capability, in the order the API reports them. A caller keys off the name, not the position.
CAPABILITIES: Tuple[str, ...] = (
    ENROLL, ADE, APP_INSTALL, DDM_BRIDGE, DDM_SYNC, MDM_ENQUEUE, ESCROW,
    WEBHOOK_INGEST,
)

# The placeholder secrets the shipped env templates carry. Matched as exact strings, not by prefix.
PLACEHOLDER_VALUES = frozenset({
    "your-secret-key-change-in-production",
    "changeme_long_random_secret",  # JWT_SECRET
    "changeme_webhook_secret",  # WEBHOOK_SECRET
    "changeme_random_api_key",  # NANOMDM_API_KEY
    "changeme_scep_challenge",  # SCEP_CHALLENGE
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
    """Whether the ADE endpoint rejects a MachineInfo that does not verify."""
    return _value("DEP_ADE_REQUIRE_APPLE_SIGNATURE").strip().lower() in (
        "1", "true", "yes", "on")


def allow_unsigned_tenant_claim() -> bool:
    """Whether a device may claim a tenant on its ServerURL without a signature."""
    return _value("MDM_ALLOW_UNSIGNED_TENANT_CLAIM").strip().lower() in (
        "1", "true", "yes", "on")


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

def _check_enroll(tenant, active_tenants: Optional[int]) -> Status:
    """Over-the-air enrollment: whether this server can hand a device a live profile."""
    from controller.services import enrollment

    missing: List[str] = []
    if not _value("MDM_TOPIC"):
        missing.append("MDM_TOPIC")
    if not _value("SCEP_CHALLENGE"):
        missing.append("SCEP_CHALLENGE")
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
    ca_error = enrollment.embedded_ca_error()
    if ca_error:
        broken.append("MDM_EMBED_CA_CERT_PATH")

    warnings: List[str] = []
    http = _http_warning("the enrollment profile, with the SCEP challenge in it,")
    if http:
        warnings.append(http)
    if is_placeholder(_value("SCEP_CHALLENGE")):
        warnings.append(
            "SCEP_CHALLENGE is still the value from the env template. It works "
            "as long as step-ca's provisioner carries the same string, and "
            "anyone who has read the template knows it, which is enough to get "
            "a device identity certificate from this deployment.")
    # Only when SCEP_URL is unset (the bundled step-ca): it bakes its secret in at init and never reads it back.
    if _value("SCEP_CHALLENGE") and not _value("SCEP_URL"):
        warnings.append(
            "The SCEP challenge the controller puts in enrollment profiles "
            "cannot be compared with the one the bundled step-ca will accept: "
            "step-ca bakes its provisioner secret in at first-run init and "
            "nothing reads it back. If SCEP enrollments fail at step-ca, a "
            "SCEP_CHALLENGE rotated since that init is the first thing to check.")
    if allow_unsigned_tenant_claim() and (
        active_tenants is None or active_tenants > 1):
        warnings.append(
            "MDM_ALLOW_UNSIGNED_TENANT_CLAIM is on, so a device may name its own "
            "tenant on check-in without a signature. Anyone holding one tenant's "
            "enrollment profile can edit it and enrol into another fleet. Turn it "
            "off once every device in the field has a profile carrying a signed "
            "tenant claim.")

    if not missing and not broken:
        return Ready(warnings=warnings)

    # Built from the unset settings only; a set-and-broken setting brings its own sentence via ca_error.
    parts = []
    if missing:
        parts.append(f"Enrollment cannot be served: {_names(missing)} "
                     f"{'is' if len(missing) == 1 else 'are'} not configured.")
    if ca_error:
        parts.append(ca_error)
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
            "DEP_ADE_REQUIRE_APPLE_SIGNATURE is off, so the ADE enrollment "
            "endpoint serves the enrollment profile, SCEP challenge included, to "
            "any caller holding this tenant's enrollment token, which never "
            "rotates. Confirm real devices verify against an Apple anchor in "
            "staging, then turn it on.")

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
            "PUBLIC_API_URL is not set, so there is no address for a device to "
            "download the bridged profile from.",
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
            "DDM_HMAC_SECRET is not set, so declarative management falls back to "
            "WEBHOOK_SECRET. One value then proves webhook authenticity, every "
            "DDM check-in signature and every bridged-profile URL, so a leak of "
            "any one of them is a leak of all three. Set DDM_HMAC_SECRET to a "
            "separate random value.")
    if not ddm_secret():
        return Blocked(
            "Declarative management check-ins are signed, and neither "
            "DDM_HMAC_SECRET nor WEBHOOK_SECRET is set, so every check-in and "
            "every bridged-profile download is rejected. WEBHOOK_HMAC_KEY does "
            "not cover this: it keys the webhook's own body signature, and "
            "NanoMDM signs declarative check-ins with a separate key.",
            missing=["DDM_HMAC_SECRET", "WEBHOOK_SECRET"], scope=DEPLOYMENT)
    return Ready(warnings=warnings)


def _check_mdm_enqueue(tenant, active_tenants: Optional[int]) -> Status:
    """Sending anything to a device: the key NanoMDM's management API needs."""
    key = _value("NANOMDM_API_KEY")
    warnings: List[str] = []
    if is_placeholder(key):
        warnings.append(
            "NANOMDM_API_KEY is still the value from the env template. It works "
            "as long as NanoMDM carries the same string, and anyone who has read "
            "the template knows it. Generate a random one for both sides.")
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
            "SECRET_ENCRYPTION_KEY is not set, so the encryption key is derived "
            "from JWT_SECRET. That works, and it means rotating JWT_SECRET makes "
            "every stored DEP credential and escrowed password unreadable. Set "
            "SECRET_ENCRYPTION_KEY to rotate the two independently."])
    return Blocked(
        "There is no key to encrypt stored secrets with: SECRET_ENCRYPTION_KEY "
        "is not set, and JWT_SECRET is unset or still a value from the env "
        "template, which is public and so cannot be used to derive one. Linking "
        "a DEP server or escrowing a device password is refused.",
        missing=["SECRET_ENCRYPTION_KEY", "JWT_SECRET"], scope=DEPLOYMENT)


def _check_webhook_ingest(tenant, active_tenants: Optional[int]) -> Status:
    """Taking in NanoMDM's check-ins and command acknowledgements."""
    hmac_key = _value("WEBHOOK_HMAC_KEY")
    secret = _value("WEBHOOK_SECRET")
    warnings: List[str] = []
    if is_placeholder(secret):
        warnings.append(
            "WEBHOOK_SECRET is still the value from the env template, so anyone "
            "who can reach the controller's internal port and has read the "
            "template can forge a check-in. Generate a random one for both sides.")
    if not hmac_key and secret:
        warnings.append(
            "WEBHOOK_HMAC_KEY is not set, so check-ins are authenticated by a "
            "secret carried in the webhook URL, which appears in docker "
            "inspect, in any compose render and in an access log line for every "
            "device check-in. Set WEBHOOK_HMAC_KEY on both the controller and "
            "NanoMDM: a later release drops the URL secret and will require it.")
    if not hmac_key and not secret:
        return Blocked(
            "Neither WEBHOOK_HMAC_KEY nor WEBHOOK_SECRET is set, so every device "
            "check-in and every command acknowledgement from NanoMDM is "
            "rejected. The fleet looks like it went quiet while the devices are "
            "fine.",
            missing=["WEBHOOK_HMAC_KEY", "WEBHOOK_SECRET"], scope=DEPLOYMENT)
    return Ready(warnings=warnings)


_PREDICATES = {
    ENROLL: _check_enroll,
    ADE: _check_ade,
    APP_INSTALL: _check_app_install,
    DDM_BRIDGE: _check_ddm_bridge,
    DDM_SYNC: _check_ddm_sync,
    MDM_ENQUEUE: _check_mdm_enqueue,
    ESCROW: _check_escrow,
    WEBHOOK_INGEST: _check_webhook_ingest,
}


def _names(missing: List[str]) -> str:
    """A setting list as English: "A", "A and B", "A, B and C"."""
    if len(missing) == 1:
        return missing[0]
    return ", ".join(missing[:-1]) + " and " + missing[-1]


def settings_to_check(answer: Any) -> str:
    """The setting names from a readiness answer, as one comma-separated string."""
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
    """One line per configured-but-noteworthy setting, at startup. Only readiness endpoint would show these otherwise."""
    for name, status in check_all():
        for warning in status.warnings:
            logger.warning("readiness[%s]: %s", name, warning)
    if is_placeholder(_value("DB_PASSWORD")):
        # No capability reads DB_PASSWORD, so it is worth saying once here instead.
        logger.warning(
            "readiness: DB_PASSWORD is still the value from the env template. "
            "Anyone who has read the template knows this deployment's database "
            "password.")


def enforce_boot() -> None:
    """Log the warnings, and stop the process on the one fatal misconfiguration."""
    log_boot_warnings()
    fatal = boot_error()
    if fatal:
        logger.critical("Refusing to start: %s", fatal)
        raise SystemExit(1)
