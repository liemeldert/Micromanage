"""The capability readiness registry, on in-memory sqlite.

Run: PYTHONPATH=. ./.venv/bin/python tests/verify_readiness.py

services/readiness.py answers, one capability at a time, whether this deployment is configured for what it is being
asked to do. Every predicate is exercised both ways, blocked and ready, because a predicate that only ever answers
one of the two is indistinguishable from a constant.

The settings are read on every call, so the checks below mutate the environment after the module is imported and
assert the answer moves. Beyond the registry itself: the readiness endpoint's authorization and its setting names
without values, the uniform 404 on the unauthenticated device endpoints with the real reason recorded server-side,
the boot refusal on a malformed encryption key, and source guards over the modules that read these settings.
"""

import ast
import base64
import logging
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Set before the modules below are imported, so the per-call read is what the environment-moves checks measure.
os.environ["JWT_SECRET"] = "verify-readiness-secret-long-enough-for-hs256"
os.environ.pop("SECRET_ENCRYPTION_KEY", None)

from tortoise import Tortoise  # noqa: E402

from controller.auth.tokens import AuthConfigError, _secret, issue_session_token  # noqa: E402
from controller.models.tenant import Tenant, User  # noqa: E402
from controller.services import readiness  # noqa: E402

PASS, FAIL = [], []


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


class _Env:
    """Set environment variables for a block and put them back afterwards.

    Every check leaves the environment as it found it, since the module under test reads it at the moment of the call.
    """

    def __init__(self, **values):
        self._values = values
        self._saved = {}

    def __enter__(self):
        for name, value in self._values.items():
            self._saved[name] = os.environ.get(name)
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        return self

    def __exit__(self, *exc):
        for name, saved in self._saved.items():
            if saved is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = saved
        return False


# A working deployment, for the checks that want one capability broken and everything else fine.
CONFIGURED = {
    "MDM_TOPIC": "com.apple.mgmt.External.verify",
    "SCEP_CHALLENGE": "verify-challenge",
    "PUBLIC_API_URL": "https://mdm.example.test",
    "MDM_HOSTNAME": "mdm.example.test",
    "MDM_SERVER_URL": None,
    "SCEP_URL": None,
    "MDM_EMBED_CA_CERT_PATH": None,
    "NANOMDM_API_KEY": "verify-nanomdm-key",
    "WEBHOOK_SECRET": "verify-webhook-secret",
    "WEBHOOK_HMAC_KEY": "verify-webhook-hmac-key",
    "DDM_HMAC_SECRET": "verify-ddm-secret",
    "SECRET_ENCRYPTION_KEY": None,
    "AWS_S3_BUCKET": "verify-packages",
    "AWS_ACCESS_KEY_ID": "AKIA-VERIFY",
    "AWS_SECRET_ACCESS_KEY": "VERIFY-SECRET",
    "MDM_ALLOW_UNSIGNED_TENANT_CLAIM": None,
    "DEP_ADE_REQUIRE_APPLE_SIGNATURE": "true",
}


def configured(**overrides):
    """The working deployment, with the named settings changed."""
    return _Env(**{**CONFIGURED, **overrides})


def test_predicates_both_ways(tenant):
    print("\n1) every capability answers blocked and ready")

    # enroll
    with configured():
        check("enroll is ready on a configured deployment",
              readiness.check("enroll").ready)
    for setting in ("MDM_TOPIC", "SCEP_CHALLENGE", "PUBLIC_API_URL"):
        with configured(**{setting: None}):
            status = readiness.check("enroll")
            check(f"enroll is blocked with no {setting}",
                  not status.ready and setting in status.missing)
            check(f"...and the reason for {setting} is a sentence naming it",
                  setting in status.reason and status.reason.endswith("."))

    # MDM_HOSTNAME is only needed for the URLs that are not set outright, so it
    # is reported missing when it is unset and something is built from it, and
    # not reported when both URLs are given explicitly.
    with configured(MDM_HOSTNAME=None):
        check("enroll is blocked with no hostname and no explicit URLs",
              "MDM_HOSTNAME" in readiness.check("enroll").missing)
    with configured(MDM_HOSTNAME=None,
                    MDM_SERVER_URL="https://mdm.example.test/mdm"):
        check("...still blocked when only the ServerURL is explicit, since the "
              "SCEP URL is still built from the hostname",
              "MDM_HOSTNAME" in readiness.check("enroll").missing)
    with configured(MDM_HOSTNAME=None,
                    MDM_SERVER_URL="https://mdm.example.test/mdm",
                    SCEP_URL="https://mdm.example.test/scep/x"):
        check("...and not blocked when both URLs are set outright, since "
              "nothing would read the hostname",
              readiness.check("enroll").ready)

    # A fresh install with no hostname and no public URL, everything else filled in: enrollment refuses and names
    # both settings.
    with configured(MDM_HOSTNAME=None, PUBLIC_API_URL=None,
                    MDM_SERVER_URL=None, SCEP_URL=None):
        status = readiness.check("enroll")
        check("a fresh install with the host settings blank refuses, and names "
              "them both",
              not status.ready and "MDM_HOSTNAME" in status.missing
              and "PUBLIC_API_URL" in status.missing)

    # JWT_SECRET, the one setting whose absence is discovered through the token module instead of being read here.
    with configured(JWT_SECRET=None):
        check("enroll is blocked with no JWT_SECRET",
              "JWT_SECRET" in readiness.check("enroll").missing)
    with configured(JWT_SECRET="changeme_long_random_secret"):
        check("...and by a JWT_SECRET still set to the value the template ships",
              "JWT_SECRET" in readiness.check("enroll").missing)

    # ade
    with configured():
        check("ade is ready on a configured deployment",
              readiness.check("ade").ready)
    with configured(PUBLIC_API_URL=None):
        status = readiness.check("ade")
        check("ade is blocked with no public address",
              not status.ready and status.missing == ("PUBLIC_API_URL",))
    with configured(JWT_SECRET=None):
        check("ade is blocked with no signing key",
              "JWT_SECRET" in readiness.check("ade").missing)
    with configured(MDM_TOPIC=None):
        check("ade does not care about the APNs topic, which the OTA gate owns",
              readiness.check("ade").ready)

    # app_install, the one capability whose answer depends on the tenant
    with configured():
        check("app_install is ready with a bucket and an https address",
              readiness.check("app_install", tenant=tenant).ready)
    with configured(AWS_S3_BUCKET=None):
        status = readiness.check("app_install", tenant=tenant)
        check("app_install is blocked with no bucket",
              not status.ready and "AWS_S3_BUCKET" in status.missing)
        check("...and that is a deployment problem, not a tenant one",
              status.scope == "deployment")
    with configured(PUBLIC_API_URL="http://mdm.example.test"):
        status = readiness.check("app_install", tenant=tenant)
        check("app_install is blocked by a public address that is not https",
              not status.ready and "https" in status.reason)
    with configured(PUBLIC_API_URL=None):
        check("app_install is blocked with no public address at all",
              not readiness.check("app_install", tenant=tenant).ready)
    with configured():
        check("app_install asked with no tenant answers the deployment half",
              readiness.check("app_install").ready)

    # A tenant that brings its own object store and half describes it, so the block is tenant-scoped rather than
    # pointing at a deployment setting.
    tenant.s3_config = {"bucket": "tenant-packages"}
    with configured():
        status = readiness.check("app_install", tenant=tenant)
        check("an incomplete tenant object store is a tenant-scoped block",
              not status.ready and status.scope == "tenant"
              and "incomplete S3 configuration" in status.reason)
    tenant.s3_config = {}

    # ddm_bridge
    with configured():
        check("ddm_bridge is ready with an https address",
              readiness.check("ddm_bridge").ready)
    with configured(PUBLIC_API_URL="http://mdm.example.test"):
        check("ddm_bridge is blocked by http",
              not readiness.check("ddm_bridge").ready)
    with configured(PUBLIC_API_URL=None):
        check("ddm_bridge is blocked with no address",
              not readiness.check("ddm_bridge").ready)

    # ddm_sync
    with configured():
        check("ddm_sync is ready with its own secret",
              readiness.check("ddm_sync").ready)
    with configured(DDM_HMAC_SECRET=None):
        check("...and ready on the webhook secret alone",
              readiness.check("ddm_sync").ready)
    with configured(DDM_HMAC_SECRET=None, WEBHOOK_SECRET=None):
        status = readiness.check("ddm_sync")
        check("ddm_sync is blocked when neither secret is set",
              not status.ready and set(status.missing)
              == {"DDM_HMAC_SECRET", "WEBHOOK_SECRET"})

    # mdm_enqueue
    with configured():
        check("mdm_enqueue is ready with an API key",
              readiness.check("mdm_enqueue").ready)
    with configured(NANOMDM_API_KEY=None):
        status = readiness.check("mdm_enqueue")
        check("mdm_enqueue is blocked with none",
              not status.ready and status.missing == ("NANOMDM_API_KEY",))

    # escrow
    key = base64.urlsafe_b64encode(b"k" * 32).decode()
    with configured(SECRET_ENCRYPTION_KEY=key):
        check("escrow is ready with a real Fernet key",
              readiness.check("escrow").ready)
    with configured(SECRET_ENCRYPTION_KEY=None):
        check("...and ready deriving one from JWT_SECRET",
              readiness.check("escrow").ready)
    with configured(SECRET_ENCRYPTION_KEY="not-a-fernet-key"):
        status = readiness.check("escrow")
        check("escrow is blocked by a key that is not a Fernet key",
              not status.ready and "SECRET_ENCRYPTION_KEY" in status.missing)
    with configured(SECRET_ENCRYPTION_KEY=None, JWT_SECRET=None):
        check("escrow is blocked with no key material at all",
              not readiness.check("escrow").ready)
    # A JWT_SECRET still holding a template value is published in this repository, so HKDF over it derives a key
    # anybody can recompute and every escrowed secret would be encrypted under it. All three readers refuse it.
    with configured(SECRET_ENCRYPTION_KEY=None,
                    JWT_SECRET="changeme_long_random_secret"):
        from controller.services import crypto_secrets as cs
        status = readiness.check("escrow")
        check("escrow is blocked by a JWT_SECRET still at a template value",
              not status.ready and "JWT_SECRET" in status.missing)
        check("...and the encryption module refuses to derive from it either",
              not cs.is_available()
              and _raises(lambda: cs.encrypt("x"), cs.SecretEncryptionUnavailable))

    # webhook_ingest. Two schemes are accepted at once, so either key set means check-ins arrive.
    with configured():
        check("webhook_ingest is ready on the shared secret alone",
              readiness.check("webhook_ingest").ready)
    with configured(WEBHOOK_SECRET=None, WEBHOOK_HMAC_KEY="verify-hmac-key"):
        status = readiness.check("webhook_ingest")
        check("...and on the body-HMAC key alone",
              status.ready and status.warnings == ())
    with configured(WEBHOOK_SECRET=None, WEBHOOK_HMAC_KEY=None):
        status = readiness.check("webhook_ingest")
        check("webhook_ingest is blocked only when neither is set",
              not status.ready
              and set(status.missing) == {"WEBHOOK_HMAC_KEY", "WEBHOOK_SECRET"})

    # Dropping the shared secret for the body HMAC takes the DDM signature's fallback with it, since NanoMDM signs
    # declarative check-ins with a separate key.
    with configured(WEBHOOK_SECRET=None, WEBHOOK_HMAC_KEY="verify-hmac-key",
                    DDM_HMAC_SECRET=None):
        status = readiness.check("ddm_sync")
        check("dropping WEBHOOK_SECRET for WEBHOOK_HMAC_KEY blocks ddm_sync, "
              "and the reason says the two keys are not the same one",
              not status.ready and "WEBHOOK_HMAC_KEY" in status.reason)

    # The registry as a whole
    with configured():
        rows = readiness.report(tenant=tenant)
        check("a configured deployment reports ready",
              rows["ready"] is True)
        check("every capability is reported, whatever its state",
              [r["capability"] for r in rows["capabilities"]]
              == list(readiness.CAPABILITIES))
    with configured(MDM_TOPIC=None):
        check("one blocked capability makes the summary not ready",
              readiness.report(tenant=tenant)["ready"] is False)
    check("an unknown capability is a programming error, not a false answer",
          _raises(lambda: readiness.check("no-such-capability"), KeyError))


def _raises(fn, exc):
    try:
        fn()
        return False
    except exc:
        return True


def test_settings_are_read_per_call(tenant):
    print("\n2) settings are read on every call, never snapshotted at import")
    # The module has been imported for the whole of this file, so a predicate that snapshotted its settings at import
    # would answer with the environment as it stood then.
    with configured(MDM_TOPIC=None):
        first = readiness.check("enroll")
    with configured():
        second = readiness.check("enroll")
    check("the same predicate answers differently after the environment moves",
          not first.ready and second.ready)

    with configured(PUBLIC_API_URL="https://one.example.test"):
        one = readiness.public_api_url()
    with configured(PUBLIC_API_URL="https://two.example.test"):
        two = readiness.public_api_url()
    check("the public address reader follows the environment too",
          one == "https://one.example.test" and two == "https://two.example.test")
    with configured(PUBLIC_API_URL="https://three.example.test/"):
        check("...and strips one trailing slash, which is what every call site "
              "used to do for itself",
              readiness.public_api_url() == "https://three.example.test")


def test_warnings(tenant):
    print("\n3) warnings say something without blocking anything")
    with configured(DDM_HMAC_SECRET=None):
        status = readiness.check("ddm_sync")
        check("a DDM secret falling back to the webhook secret warns",
              status.ready and any("DDM_HMAC_SECRET" in w for w in status.warnings))
    with configured():
        check("...and says nothing once the two are separate",
              readiness.check("ddm_sync").warnings == ())

    with configured(DEP_ADE_REQUIRE_APPLE_SIGNATURE=None):
        status = readiness.check("ade")
        check("an ADE endpoint that does not check Apple's signature warns",
              status.ready
              and any("DEP_ADE_REQUIRE_APPLE_SIGNATURE" in w for w in status.warnings))
    with configured():
        check("...and says nothing with the check on",
              not any("DEP_ADE_REQUIRE_APPLE_SIGNATURE" in w
                      for w in readiness.check("ade").warnings))

    with configured(PUBLIC_API_URL="http://mdm.example.test"):
        check("a clear-text public address warns on enrollment",
              any("clear text" in w for w in readiness.check("enroll").warnings))
    with configured():
        check("...and not on an https one",
              not any("clear text" in w for w in readiness.check("enroll").warnings))

    with configured(MDM_ALLOW_UNSIGNED_TENANT_CLAIM="true"):
        one_tenant = readiness.check("enroll", active_tenants=1)
        many = readiness.check("enroll", active_tenants=4)
        check("an unsigned tenant claim warns where there is a fleet to cross into",
              any("MDM_ALLOW_UNSIGNED_TENANT_CLAIM" in w for w in many.warnings))
        check("...and stays quiet on a single-tenant deployment, where the "
              "setting it describes can reach nobody else",
              not any("MDM_ALLOW_UNSIGNED_TENANT_CLAIM" in w
                      for w in one_tenant.warnings))
        check("...and never makes enrollment unready",
              many.ready)

    with configured():
        check("a configured SCEP challenge still warns that nothing can compare "
              "it with step-ca",
              any("step-ca" in w for w in readiness.check("enroll").warnings))
    with configured(SCEP_CHALLENGE="changeme_scep_challenge"):
        check("a SCEP challenge still set to the template value warns as well",
              any("env template" in w for w in readiness.check("enroll").warnings))
    with configured(SCEP_CHALLENGE="changeme-scep-challenge"):
        check("...and one that merely resembles it does not, since only the "
              "exact shipped strings are known to be public",
              not any("env template" in w for w in readiness.check("enroll").warnings))


async def test_bootstrap_admin():
    print("\n3b) the first-run admin bootstrap writes no published credential")
    # The second lock, on the method that writes the row: an account whose password is published in this repository
    # must not be created by any route in, including one that skipped the startup check.
    from controller.main import MDMController

    controller = MDMController()
    with _Env(CONTROLLER_BOOTSTRAP_ADMIN_EMAIL="bootstrap@example.com",
              CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD="change-me-now",
              CONTROLLER_BOOTSTRAP_TENANT="bootstrap-check"):
        with _Capture("controller.main") as cap:
            await controller._bootstrap_admin()
        created = await User.filter(email="bootstrap@example.com").count()
        check("no admin account is created for a template password", created == 0)
        check("...and the refusal says why, naming the variable",
              any("CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD" in m for m in cap.messages))
        check("...and no password reaches the log",
              not any("change-me-now" in m for m in cap.messages))

    with _Env(CONTROLLER_BOOTSTRAP_ADMIN_EMAIL="bootstrap@example.com",
              CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD="a-real-chosen-password",
              CONTROLLER_BOOTSTRAP_TENANT="bootstrap-check"):
        await controller._bootstrap_admin()
        user = await User.get_or_none(email="bootstrap@example.com")
        check("a chosen password still bootstraps the way it always did",
              user is not None and user.role == "admin")


async def test_migrated_call_sites(tenant):
    print("\n4) the migrated operation sites answer as they did before")
    from controller.services import ddm_manager, enrollment as enroll
    from controller.services.app_manager import AppManager

    with configured():
        details = enroll.enrollment_details(tenant)
        check("enrollment_details reports configured on a working deployment",
              details["configured"] and details["missing"] == [])
        check("...and carries the URLs it builds",
              details["mdm_server_url"] == "https://mdm.example.test/mdm"
              and details["hostname"] == "mdm.example.test")
    with configured(MDM_TOPIC=None):
        details = enroll.enrollment_details(tenant)
        check("enrollment_details keeps its shape when something is missing",
              details["configured"] is False and "MDM_TOPIC" in details["missing"])
    with configured(MDM_HOSTNAME=None):
        details = enroll.enrollment_details(tenant)
        check("no hostname is reported rather than defaulted to a host nobody owns",
              details["hostname"] is None
              and details["mdm_server_url"] is None
              and "MDM_HOSTNAME" in details["missing"])

    # A set-but-broken CA path refuses; an unset one never does.
    bad_cert = REPO / "tests" / ".readiness-not-a-cert"
    bad_cert.write_text("this is not a certificate")
    try:
        with configured(MDM_EMBED_CA_CERT_PATH=str(bad_cert)):
            details = enroll.enrollment_details(tenant)
            status = readiness.check("enroll")
            check("a CA path that holds no certificate refuses enrollment",
                  details["configured"] is False)
            # A set variable reported as missing would send an operator to set a value that is already there. Broken
            # is a different list and a different sentence.
            check("...as broken rather than missing, since it is set",
                  details["broken"] == ["MDM_EMBED_CA_CERT_PATH"]
                  and "MDM_EMBED_CA_CERT_PATH" not in details["missing"])
            check("...and the reason never claims a set variable is unconfigured",
                  "is not configured" not in status.reason
                  and "no certificate can be read" in status.reason)
            check("...and the reason says the fix is one edit either way",
                  "unset MDM_EMBED_CA_CERT_PATH" in status.reason)
            check("...and the page can show that sentence instead of a name",
                  details["reason"] == status.reason)
            # The device-facing 503 names it too, so a broken certificate path does not produce an empty list.
            check("the wording covers both lists and names the setting",
                  readiness.settings_to_check(details) == "MDM_EMBED_CA_CERT_PATH")
        with configured(MDM_EMBED_CA_CERT_PATH=str(bad_cert) + "-missing"):
            check("a CA path naming no file at all refuses too",
                  "MDM_EMBED_CA_CERT_PATH"
                  in enroll.enrollment_details(tenant)["broken"])
        with configured(MDM_EMBED_CA_CERT_PATH=str(bad_cert), MDM_TOPIC=None):
            details = enroll.enrollment_details(tenant)
            check("an unset setting and a broken one are reported side by side",
                  details["missing"] == ["MDM_TOPIC"]
                  and details["broken"] == ["MDM_EMBED_CA_CERT_PATH"])
            check("...and both reach the caller building the 503",
                  readiness.settings_to_check(details)
                  == "MDM_TOPIC, MDM_EMBED_CA_CERT_PATH")
    finally:
        bad_cert.unlink()
    with configured(MDM_EMBED_CA_CERT_PATH=None):
        check("an unset CA path never refuses, since nobody asked for the payload",
              enroll.enrollment_details(tenant)["configured"])

    with configured():
        check("ade_enroll_url builds a URL when ADE is ready",
              (enroll.ade_enroll_url(tenant.id) or "").startswith(
                  "https://mdm.example.test/api/v1/dep/enroll/"))
    with configured(PUBLIC_API_URL=None):
        check("...and none when it is not",
              enroll.ade_enroll_url(tenant.id) is None)

    with configured():
        check("package_store_error holds nothing on a working tenant",
              AppManager(tenant).package_store_error() is None)
    with configured(AWS_S3_BUCKET=None):
        reason = AppManager(tenant).package_store_error()
        check("...and still answers a string naming the setting",
              isinstance(reason, str) and "AWS_S3_BUCKET" in reason)

    bridge = {"id": "b", "type": "com.apple.configuration.legacy", "profile": "wifi"}
    with configured(PUBLIC_API_URL=None):
        reason = ddm_manager.undeliverable_reason(bridge, tenant.id)
        check("an unservable bridge still reports the sentence its callers show",
              isinstance(reason, str) and "PUBLIC_API_URL" in reason)
        check("...with no trailing full stop, since callers compose it",
              not reason.endswith("."))
        check("and no bridge URL is built",
              ddm_manager.profile_bridge_url(tenant.id, "wifi") is None)
    with configured(PUBLIC_API_URL="http://mdm.example.test"):
        reason = ddm_manager.undeliverable_reason(bridge, tenant.id)
        check("an http address is its own reason, naming https",
              isinstance(reason, str) and "https" in reason)

    # With no credentials the connector refuses before sending, rather than sending none and reading NanoMDM's 401 as
    # a transport failure.
    from controller.services import mdm_connector as mc
    with configured(NANOMDM_API_KEY=None):
        conn = mc.MDMConnector()
        sent = []

        # Records the attempted send rather than raising, so a regression here is one FAIL line and the rest of the
        # file still runs.
        class _Client:
            async def put(self, url, content=None, headers=None):
                sent.append(url)
                return None

        conn.client = _Client()
        refusal = None
        try:
            await conn.install_profile("UDID-1", {"PayloadType": "Configuration"})
        except mc.EnqueueError as exc:
            refusal = exc
        check("a command with no API key is refused before it is sent",
              refusal is not None and not sent)
        check("...and the refusal names the setting",
              "NANOMDM_API_KEY" in str(refusal))

    with configured():
        conn = mc.MDMConnector()

        class _OkClient:
            def __init__(self):
                self.urls = []

            async def put(self, url, content=None, headers=None):
                self.urls.append(url)
                return _Resp()

        class _Resp:
            status_code = 200
            content = b"{}"

            def json(self):
                return {"command_uuid": "CMD-1", "request_type": "InstallProfile"}

            def raise_for_status(self):
                return None

        conn.client = _OkClient()
        result = await conn.install_profile("UDID-1", {"PayloadType": "Configuration"})
        check("a command with an API key goes through untouched",
              result.get("command_uuid") == "CMD-1" and conn.client.urls)


async def test_endpoint(tenant, admin, member):
    print("\n5) GET /api/v1/readiness is admin-only and 404s an anonymous caller")
    from fastapi import HTTPException
    from fastapi.security import HTTPAuthorizationCredentials
    from starlette.datastructures import Headers

    from controller.api.main import get_readiness

    class _Req:
        def __init__(self, headers=None):
            self.headers = Headers(headers or {})

    async def call(credentials):
        try:
            return await get_readiness(_Req(), credentials), None
        except HTTPException as exc:
            return None, exc.status_code

    _body, status = await call(None)
    check("no credentials at all get 404, not 401 or 403, so the endpoint's "
          "existence is not confirmed to an anonymous caller", status == 404)

    # FastAPI also hands the endpoint None for a header it cannot parse as a bearer token, which has to reach the same
    # 404 rather than an authenticated branch.
    _body, status = await call(
        HTTPAuthorizationCredentials(scheme="Basic", credentials="abc"))
    check("a bearer token that is not one gets the same 404", status == 404)

    _body, status = await call(
        HTTPAuthorizationCredentials(scheme="Bearer", credentials="not.a.token"))
    check("a token that does not resolve to anybody gets the same 404",
          status == 404)

    with configured():
        member_token = issue_session_token(
            user_id=str(member.id), tenant_id=tenant.id, email=member.email,
            role="member")
        admin_token = issue_session_token(
            user_id=str(admin.id), tenant_id=tenant.id, email=admin.email,
            role="admin")

        _body, status = await call(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials=member_token))
        check("an authenticated member gets a named 403, being inside the "
              "deployment already", status == 403)

        body, status = await call(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials=admin_token))
        check("an admin gets the report", status is None and body is not None)

    if body is None:
        return
    check("the report says whether the deployment is ready",
          body["ready"] is True)
    rows = {row["capability"]: row for row in body["capabilities"]}
    check("every capability is a row", set(rows) == set(readiness.CAPABILITIES))
    shape = all(
        set(row) == {"capability", "ready", "reason", "missing", "broken",
                     "scope", "warnings"}
        and isinstance(row["missing"], list) and isinstance(row["warnings"], list)
        and isinstance(row["broken"], list)
        and row["scope"] in ("deployment", "tenant")
        for row in body["capabilities"]
    )
    check("every row carries the published keys and nothing else", shape)

    # Setting names only: no value behind one ever reaches the body.
    with configured(MDM_TOPIC=None, WEBHOOK_SECRET=None, WEBHOOK_HMAC_KEY=None):
        blocked = await get_readiness(
            _Req(), HTTPAuthorizationCredentials(scheme="Bearer",
                                                 credentials=admin_token))
    serialized = repr(blocked)
    secrets = [CONFIGURED["SCEP_CHALLENGE"], CONFIGURED["NANOMDM_API_KEY"],
               CONFIGURED["DDM_HMAC_SECRET"], os.environ["JWT_SECRET"]]
    check("no setting value appears anywhere in the body",
          not any(secret in serialized for secret in secrets))
    check("the blocked rows name their settings",
          "MDM_TOPIC" in serialized and "WEBHOOK_SECRET" in serialized)

    # The 404 above is only worth having while nothing else on this app lists the routes, so on the publicly served
    # app the schema and the interactive docs are off unless somebody asks for them.
    from controller.api import main as api_main
    check("the interactive docs and the schema are off by default",
          api_main.app.openapi_url is None and api_main.app.docs_url is None
          and api_main.app.redoc_url is None)
    check("...so nothing on this app serves the route list to an anonymous "
          "caller, which is what the 404 above is worth having against",
          not any(getattr(r, "path", "") in ("/openapi.json", "/docs", "/redoc")
                  for r in api_main.app.routes))
    # The opt-in is read at import, so it takes a fresh interpreter to see: reloading the module in place re-registers
    # its pydantic validators and raises.
    probe = subprocess.run(
        [sys.executable, "-c",
         "import controller.api.main as m;"
         " print(m.app.openapi_url, m.app.docs_url, m.app.redoc_url)"],
        cwd=REPO, capture_output=True, text=True, timeout=60,
        env={**os.environ, "MDM_ENABLE_API_DOCS": "1", "PYTHONPATH": ".",
             "PYTHONDONTWRITEBYTECODE": "1"},
    )
    check("...and come back for a development environment that asks for them",
          probe.stdout.strip() == "/openapi.json /docs /redoc")


async def test_uniform_404(tenant):
    print("\n6) the unauthenticated device endpoints answer one 404")
    from fastapi import HTTPException
    from starlette.datastructures import Headers

    from controller.api.main import download_enrollment_profile
    from controller.api.ddm import download_bridged_profile
    from controller.services import enrollment as enroll

    class _Peer:
        host = "198.51.100.9"

    class _Req:
        headers = Headers({})
        client = _Peer()

    async def status_of(coro):
        try:
            await coro
            return None
        except HTTPException as exc:
            return exc.status_code

    with configured():
        good = enroll.enrollment_token(tenant.id)
        check("an unknown tenant gets 404",
              await status_of(download_enrollment_profile(
                  "no-such-tenant", good, _Req())) == 404)
        check("a bad token on a real tenant gets the same 404, so the two "
              "cannot be told apart",
              await status_of(download_enrollment_profile(
                  tenant.id, "wrong-token", _Req())) == 404)
        check("a bad bridge signature gets 404 rather than 403",
              await status_of(download_bridged_profile(
                  tenant.id, "wifi", _Req(), sig="wrong")) == 404)
        check("an unknown tenant on the bridge gets the same 404",
              await status_of(download_bridged_profile(
                  "no-such-tenant", "wifi", _Req(), sig="wrong")) == 404)

        # The wire says one thing and the server records the other, so a broken enrollment link leaves something to
        # read.
        with _Capture("controller.services.enrollment") as cap:
            await status_of(download_enrollment_profile(
                tenant.id, "wrong-token", _Req()))
        recorded = " ".join(cap.messages)
        check("the real reason is recorded server-side",
              "token" in recorded and tenant.id in recorded)
        check("...along with where it came from",
              "198.51.100.9" in recorded)

        # The tenant id and the profile id are unauthenticated path segments going into that log, and a newline in one
        # would forge a second record.
        with _Capture("controller.services.enrollment") as cap:
            await status_of(download_enrollment_profile(
                "evil\nWARNING:root:all is well", "token", _Req()))
        check("a control character in the tenant id cannot forge a log record",
              len(cap.records) == 1
              and "\n" not in cap.records[0].getMessage())
        with _Capture("controller.services.enrollment") as cap:
            await status_of(download_bridged_profile(
                tenant.id, "wifi\nWARNING:root:all is well", _Req(), sig="x"))
        check("...and neither can one in the profile id",
              len(cap.records) == 1
              and "\n" not in cap.records[0].getMessage())

        # Beyond the ASCII control range: some log viewers and JSON consumers render U+2028 and U+2029 as line breaks,
        # and a bidi override reverses the display order of everything after it, all without a newline.
        for label, hostile in (("a line separator", "evil root: fine"),
                               ("a paragraph separator", "evil root: fine"),
                               ("a bidi override", "evil‮elbisiv")):
            with _Capture("controller.services.enrollment") as cap:
                await status_of(download_enrollment_profile(hostile, "t", _Req()))
            message = cap.records[0].getMessage() if cap.records else ""
            check(f"{label} in the tenant id is stripped from the log line",
                  len(cap.records) == 1
                  and not any(ch in message
                              for ch in (" ", " ", "‮")))


class _Capture:
    """Collect log records from one logger for the duration of a block."""

    def __init__(self, name):
        self._logger = logging.getLogger(name)
        self.records = []

    def __enter__(self):
        capture = self

        class _Handler(logging.Handler):
            def emit(self, record):
                capture.records.append(record)

        self._handler = _Handler()
        self._logger.addHandler(self._handler)
        self._previous = self._logger.level
        self._logger.setLevel(logging.DEBUG)
        return self

    def __exit__(self, *exc):
        self._logger.removeHandler(self._handler)
        self._logger.setLevel(self._previous)
        return False

    @property
    def messages(self):
        return [r.getMessage() for r in self.records]


def test_boot():
    print("\n7) boot refuses one misconfiguration and only that one")
    with configured(SECRET_ENCRYPTION_KEY="not-a-fernet-key"):
        check("a key that is not a Fernet key stops the process",
              _raises(readiness.enforce_boot, SystemExit))
        check("...and the message says how to make one",
              "Fernet.generate_key" in (readiness.boot_error() or ""))
    with configured(SECRET_ENCRYPTION_KEY=None):
        check("an unset key does not, since deriving one from JWT_SECRET works",
              readiness.boot_error() is None)
        readiness.enforce_boot()
    with configured(SECRET_ENCRYPTION_KEY=None, JWT_SECRET=None):
        check("nor does having no key material at all, which gates one feature "
              "rather than everything", readiness.boot_error() is None)
    with configured(SECRET_ENCRYPTION_KEY=base64.urlsafe_b64encode(b"k" * 32).decode()):
        check("a real key starts cleanly", readiness.boot_error() is None)

    # The other thing that must not start: a first-run admin bootstrap carrying the password the production template
    # ships. The template fills in both the email and the password, so deploying it unedited would create a working
    # administrator whose password is published in this repository.
    with _Env(CONTROLLER_BOOTSTRAP_ADMIN_EMAIL="admin@example.com",
              CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD="change-me-now"):
        message = readiness.bootstrap_admin_error() or ""
        check("a template bootstrap password stops the process",
              message and _raises(readiness.enforce_boot, SystemExit))
        check("...and the message names the variable and both ways out",
              "CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD" in message
              and "CONTROLLER_BOOTSTRAP_ADMIN_EMAIL" in message)
        check("...and says that clearing it later does not fix an account "
              "an earlier boot already created",
              "already started" in message)
        check("...and quotes no password anywhere in it",
              "change-me-now" not in message)
    # Only when the bootstrap would actually run. A placeholder password beside
    # no email creates nothing, and refusing to start over a value nothing reads
    # is the boot creep this module is otherwise careful about.
    with _Env(CONTROLLER_BOOTSTRAP_ADMIN_EMAIL=None,
              CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD="change-me-now"):
        check("a template password with no bootstrap email does not refuse",
              readiness.bootstrap_admin_error() is None)
    with _Env(CONTROLLER_BOOTSTRAP_ADMIN_EMAIL="admin@example.com",
              CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD="a-real-chosen-password"):
        check("a chosen password is left alone",
              readiness.bootstrap_admin_error() is None)
    # The dev stack's own value has to keep working: it is weak, and weak is not
    # what this refuses. It refuses published.
    with _Env(CONTROLLER_BOOTSTRAP_ADMIN_EMAIL="admin@localhost.dev",
              CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD="devpassword"):
        check("a password that is merely weak is not a template value",
              readiness.bootstrap_admin_error() is None)

    # Every warn-only row reaches the log at boot, since that is the only place
    # they appear for an operator who never opens the console.
    with configured(DDM_HMAC_SECRET=None, DB_PASSWORD="changeme_strong_password"):
        with _Capture("controller.services.readiness") as cap:
            readiness.log_boot_warnings()
        text = " ".join(cap.messages)
        check("a shared DDM secret is said once at boot", "DDM_HMAC_SECRET" in text)
        check("a database password still set to the template value is said too",
              "DB_PASSWORD" in text)

    # The encryption module and the readiness predicate have to agree about what
    # a key is, or one refuses to start and the other quietly reads nothing.
    from controller.services import crypto_secrets
    with configured(SECRET_ENCRYPTION_KEY="not-a-fernet-key"):
        check("encrypt refuses a malformed key by naming it, not by claiming "
              "no key is set",
              _raises(lambda: crypto_secrets.encrypt("x"),
                      crypto_secrets.SecretEncryptionUnavailable))
        try:
            crypto_secrets.encrypt("x")
        except crypto_secrets.SecretEncryptionUnavailable as exc:
            check("...and the message is the same one the readiness row carries",
                  "SECRET_ENCRYPTION_KEY is set" in str(exc))

    # The refusal has to arrive as one line and a clean exit, not a traceback inside a restart loop. Run for real,
    # because the risk is the shutdown path it unwinds through: a scheduler that never started raises on its way out
    # and buries the sentence. The process dies before it opens a database connection.
    proc = subprocess.run(
        [sys.executable, "-m", "controller.main"],
        cwd=REPO, capture_output=True, text=True, timeout=60,
        env={**os.environ, "SECRET_ENCRYPTION_KEY": "not-a-fernet-key",
             "PYTHONPATH": ".", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    output = proc.stdout + proc.stderr
    check("the controller refuses to start on a malformed encryption key",
          proc.returncode == 1)
    check("...saying so in one line an operator can act on",
          "Refusing to start" in output and "SECRET_ENCRYPTION_KEY" in output)
    check("...and exits cleanly rather than on a traceback",
          "Traceback" not in output)

    # The same key through the API process, a different exit path. Starlette catches BaseException out of a startup
    # hook and folds it into the lifespan failure message, which buries the useful line under asgi frames. Driven
    # through the real ASGI lifespan the way uvicorn does it, since that is the only place the difference shows.
    lifespan_driver = (
        "import asyncio, controller.api.main as m\n"
        "async def go():\n"
        "    recv = asyncio.Queue()\n"
        "    await recv.put({'type': 'lifespan.startup'})\n"
        "    async def send(msg):\n"
        "        print('SENT', msg.get('type'))\n"
        "    await m.app({'type': 'lifespan'}, recv.get, send)\n"
        "asyncio.run(go())\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", lifespan_driver],
        cwd=REPO, capture_output=True, text=True, timeout=60,
        env={**os.environ, "SECRET_ENCRYPTION_KEY": "not-a-fernet-key",
             "PYTHONPATH": ".", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    api_output = proc.stdout + proc.stderr
    check("the API process refuses to start on the same key",
          proc.returncode == 1 and "Refusing to start" in api_output)
    check("...without the asgi traceback starlette would wrap it in",
          "Traceback" not in api_output
          and "lifespan.startup.failed" not in api_output)

    # The bootstrap refusal takes the same exit, run for real for the same
    # reason: what can go wrong is the shutdown path it unwinds through, not the
    # refusal. Exits before any database connection is opened.
    proc = subprocess.run(
        [sys.executable, "-m", "controller.main"],
        cwd=REPO, capture_output=True, text=True, timeout=60,
        env={**os.environ, "CONTROLLER_BOOTSTRAP_ADMIN_EMAIL": "admin@example.com",
             "CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD": "change-me-now",
             "PYTHONPATH": ".", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    output = proc.stdout + proc.stderr
    check("a template bootstrap password refuses the controller process too",
          proc.returncode == 1 and "Refusing to start" in output
          and "CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD" in output)
    check("...on one line, with no traceback and no password in it",
          "Traceback" not in output and "change-me-now" not in output)

    # The placeholder list is shared, so the token module refuses exactly the
    # values the templates ship and nothing else.
    for value in ("changeme_long_random_secret", "your-secret-key-change-in-production"):
        with _Env(JWT_SECRET=value):
            check(f"a JWT_SECRET of {value!r} is refused",
                  _raises(_secret, AuthConfigError))
    with _Env(JWT_SECRET="changeme-scep-challenge"):
        check("a secret that merely looks like a template value is accepted, "
              "since refusing a working secret has no visible cause",
              _secret() == "changeme-scep-challenge")
    for name in ("changeme_webhook_secret", "changeme_random_api_key",
                 "changeme_scep_challenge", "changeme_strong_password"):
        check(f"the shared list knows {name!r}", readiness.is_placeholder(name))


def test_source_guards():
    print("\n8) the migrated modules no longer read these settings for themselves")
    # Guards against duplication rather than migration: a predicate in readiness.py while the inline read stays at the
    # call site leaves two sources of truth that can drift apart unnoticed.
    migrated = [
        "controller/services/enrollment.py",
        "controller/services/app_manager.py",
        "controller/services/ddm_manager.py",
        "controller/utils/yaml_validator.py",
        "controller/api/main.py",
        "controller/api/dep.py",
    ]
    # Settings readiness.py is the only reader of. Asserted on the parsed module rather than its text, so any spelling
    # of an os.getenv call is caught.
    single_reader = ("PUBLIC_API_URL", "DDM_HMAC_SECRET",
                     "DEP_ADE_REQUIRE_APPLE_SIGNATURE")
    for path in migrated + ["controller/services/mdm_connector.py",
                            "controller/main.py"]:
        tree = ast.parse((REPO / path).read_text())
        read = _getenv_names(tree) & set(single_reader)
        check(f"{path} calls getenv on none of the single-reader settings",
              not read)

    reader = ast.parse((REPO / "controller/services/readiness.py").read_text())
    check("readiness.py imports nothing from controller at module scope, which "
          "is what lets auth.tokens import its placeholder list",
          not _module_scope_controller_imports(reader))

    # Every method that talks to NanoMDM either goes through the guarded dispatch, checks the credentials itself, or
    # refuses before it builds anything. Written as a rule over every method rather than a count, so a command method
    # added later is covered. The attribute scan takes in self.client, which a new method could reach directly.
    connector = ast.parse((REPO / "controller/services/mdm_connector.py").read_text())
    klass = next(n for n in ast.walk(connector)
                 if isinstance(n, ast.ClassDef) and n.name == "MDMConnector")

    # The wire primitives, allowed to reach self.client because checking the
    # credentials is somebody else's job for them.
    wire = {"enqueue_command", "_dispatch", "close"}

    def calls(method, name):
        return any(isinstance(node, ast.Attribute) and node.attr == name
                   for node in ast.walk(method))

    unguarded, direct = [], []
    for method in klass.body:
        if not isinstance(method, ast.AsyncFunctionDef) or method.name in wire:
            continue
        if calls(method, "enqueue_command"):
            direct.append(method.name)
        reaches_nanomdm = calls(method, "client") or calls(method, "enqueue_command")
        guarded = calls(method, "_dispatch") or calls(method, "_require_api_key")
        # A method that only validates its input and raises (never reaching a
        # wire call) is fine unguarded; the credentials check is the job of the
        # _dispatch it would call after.
        refuses = any(isinstance(node, ast.Raise) for node in ast.walk(method))
        if reaches_nanomdm and not guarded and not refuses:
            unguarded.append(method.name)

    check("every method that reaches NanoMDM checks the credentials first",
          not unguarded)
    check("no command method calls the wire enqueue directly", not direct)
    check("and the guard it is all routed through exists",
          any(isinstance(n, ast.FunctionDef) and n.name == "_require_api_key"
              for n in klass.body))


def _getenv_names(tree):
    """Every literal name passed to a getenv call in this module."""
    names = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = getattr(func, "attr", None) or getattr(func, "id", None)
        if name != "getenv" or not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            names.add(first.value)
    return names


def _module_scope_controller_imports(tree):
    return [
        node for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
           and (getattr(node, "module", "") or "").startswith("controller")
    ]


async def main():
    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    tenant = await Tenant.create(id="readiness", name="Readiness Inc",
                                 auth_config={"provider": "local"})
    admin = await User.create(tenant=tenant, email="admin@example.test",
                              role="admin", password_hash="x")
    member = await User.create(tenant=tenant, email="member@example.test",
                               role="member", password_hash="x")

    test_predicates_both_ways(tenant)
    test_settings_are_read_per_call(tenant)
    test_warnings(tenant)
    await test_bootstrap_admin()
    await test_migrated_call_sites(tenant)
    await test_endpoint(tenant, admin, member)
    await test_uniform_404(tenant)
    test_boot()
    test_source_guards()

    await Tortoise.close_connections()

    print()
    if FAIL:
        print(f"FAILED: {len(FAIL)} check(s):")
        for f in FAIL:
            print(f"  - {f}")
        return 1
    print(f"All readiness checks passed ({len(PASS)}).")
    return 0


if __name__ == "__main__":
    from tests._verify_harness import run

    run(main)
