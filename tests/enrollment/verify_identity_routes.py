"""Admin routes for enrollment identity: the device action that allows re-enrollment, the device detail fields, and the
enrollment links API. Route functions are called directly with a Principal, on in-memory sqlite.

Run: PYTHONPATH=. python tests/enrollment/verify_identity_routes.py
"""
import os
import tempfile
import uuid
from datetime import timedelta

from cryptography.fernet import Fernet

_TMP = tempfile.mkdtemp(prefix="verify-identity-routes-")
os.environ["SECRET_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["JWT_SECRET"] = "test-secret-for-identity-routes"
os.environ["PUBLIC_API_URL"] = "https://mdm.example.test/"
os.environ["YAML_CONFIG_PATH"] = _TMP

from tortoise import Tortoise  # noqa: E402

from controller.auth.dependencies import Principal, require_admin  # noqa: E402
from controller.models.tenant import AuditLog, Device, EnrollmentLink, Tenant, User  # noqa: E402
from controller.utils.timeutil import as_utc, utcnow  # noqa: E402
from tests._verify_harness import admin_only, make_check, status_of  # noqa: E402

PASS, FAIL = [], []
check = make_check(FAIL, PASS)


async def test_allow_reenrollment(admin, member, other_admin):
    from controller.api.routes import devices as routes

    print("\n1) allow-reenrollment")
    dev = await Device.create(tenant=admin.tenant, udid="U-ALLOW", serial_number="S-ALLOW", device_model="Mac",
                              os_version="15.0", identity_sha256="a" * 64, push_token_enc="sealed")
    before = utcnow()
    body = await routes.allow_reenrollment(str(dev.id), admin)
    stored = await Device.get(id=dev.id)
    until = as_utc(stored.reenrollment_allowed_until) if stored.reenrollment_allowed_until else None
    check("the allowance is set 24 hours ahead",
          until is not None and timedelta(hours=23, minutes=59) < until - before <= timedelta(hours=24, seconds=5))
    check("the response carries the allowance", body.get("reenrollment_allowed_until") == until.isoformat()
          if until else False, str(body.get("reenrollment_allowed_until")))
    check("the response carries the device", body.get("device", {}).get("id") == str(dev.id))
    audit = await AuditLog.filter(action="device.allow_reenrollment", target_id=str(dev.id)).first()
    check("the action is audited", audit is not None and audit.actor_email == admin.email)

    check("the route depends on require_admin", admin_only(routes.allow_reenrollment))
    check("a member is refused with 403", await status_of(require_admin(member)) == 403)
    check("an unknown id is 404", await status_of(routes.allow_reenrollment(str(uuid.uuid4()), admin)) == 404)
    check("another tenant's device is 404", await status_of(routes.allow_reenrollment(str(dev.id), other_admin)) == 404)

    print("\n2) the device detail")
    detail = (await routes.get_device_details(str(dev.id), admin))["device"]
    check("lists reenrollment_allowed_until", detail.get("reenrollment_allowed_until") == until.isoformat()
          if until else False)
    check("lists identity_sha256", detail.get("identity_sha256") == "a" * 64)
    check("never lists push_token_enc", "push_token_enc" not in detail and "sealed" not in str(detail))


async def test_links(admin, member, other_admin):
    from controller.api.routes import enrollment as routes

    print("\n3) enrollment links API")
    for fn in (routes.list_enrollment_links, routes.create_enrollment_link, routes.revoke_enrollment_link):
        check(f"{fn.__name__} depends on require_admin", admin_only(fn))

    created = await routes.create_enrollment_link(
        routes.EnrollmentLinkCreate(label="  Front desk  ", expires_in_days=7, max_downloads=3), admin)
    check("create answers the link", created.get("label") == "Front desk" and created.get("max_downloads") == 3,
          str(created))
    check("create answers a URL under PUBLIC_API_URL",
          str(created.get("url") or "").startswith("https://mdm.example.test/api/v1/enroll/"), str(created.get("url")))
    link = await EnrollmentLink.get(id=created["id"])
    check("the link expires in 7 days",
          timedelta(days=6, hours=23) < as_utc(link.expires_at) - utcnow() <= timedelta(days=7))
    check("create is audited", await AuditLog.filter(action="enrollment_link.create", target_id=created["id"]).exists())

    expired = await EnrollmentLink.create(tenant=admin.tenant, token_enc="x", token_hash="h-expired", label="old",
                                          created_by=admin.email, expires_at=utcnow() - timedelta(minutes=1))
    listed = await routes.list_enrollment_links(admin)
    ids = [row["id"] for row in listed["links"]]
    check("list shows the live link", created["id"] in ids)
    check("list leaves out the expired one", str(expired.id) not in ids)
    check("another tenant sees none of them", not (await routes.list_enrollment_links(other_admin))["links"])

    check("revoking another tenant's link is 404",
          await status_of(routes.revoke_enrollment_link(created["id"], other_admin)) == 404)
    check("revoking an unknown link is 404",
          await status_of(routes.revoke_enrollment_link(str(uuid.uuid4()), admin)) == 404)
    revoked = await routes.revoke_enrollment_link(created["id"], admin)
    check("revoke answers revoked_at", bool(revoked.get("revoked_at")))
    check("revoke is audited", await AuditLog.filter(action="enrollment_link.revoke", target_id=created["id"]).exists())
    check("a revoked link leaves the list",
          created["id"] not in [row["id"] for row in (await routes.list_enrollment_links(admin))["links"]])
    check("a member is refused with 403", await status_of(require_admin(member)) == 403)

    used_up = await EnrollmentLink.create(tenant=admin.tenant, token_enc="x", token_hash="h-used", label="used",
                                          created_by=admin.email, expires_at=utcnow() + timedelta(days=1),
                                          max_downloads=2, downloads=2)
    partly = await EnrollmentLink.create(tenant=admin.tenant, token_enc="x", token_hash="h-partly", label="partly",
                                         created_by=admin.email, expires_at=utcnow() + timedelta(days=1),
                                         max_downloads=2, downloads=1)
    ids = [row["id"] for row in (await routes.list_enrollment_links(admin))["links"]]
    check("a link with no downloads left leaves the list", str(used_up.id) not in ids)
    check("...while one with downloads left stays", str(partly.id) in ids)

    print("\n4) enrollment link validation")
    from pydantic import ValidationError

    def refused(**body):
        try:
            routes.EnrollmentLinkCreate(**body)
        except ValidationError:
            return True
        return False

    check("an expiry of 2 days is refused", refused(expires_in_days=2))
    check("a label of 121 characters is refused", refused(expires_in_days=1, label="x" * 121))
    check("...and one of 120 is accepted", not refused(expires_in_days=1, label="x" * 120))
    check("max_downloads of 0 is refused", refused(expires_in_days=1, max_downloads=0))
    check("max_downloads past 100000 is refused", refused(expires_in_days=1, max_downloads=100001))
    check("...and 100000 is accepted", not refused(expires_in_days=1, max_downloads=100000))

    from controller.services import crypto_secrets, enrollment_links

    real_create = enrollment_links.create_link

    async def no_key(*args, **kwargs):
        raise crypto_secrets.SecretEncryptionUnavailable("no encryption key")

    enrollment_links.create_link = no_key
    try:
        unavailable = await status_of(routes.create_enrollment_link(
            routes.EnrollmentLinkCreate(expires_in_days=1), admin))
    finally:
        enrollment_links.create_link = real_create
    check("create answers 400 when secrets cannot be encrypted", unavailable == 400)

    os.environ["PUBLIC_API_URL"] = ""
    try:
        unset = await routes.create_enrollment_link(routes.EnrollmentLinkCreate(expires_in_days=1), admin)
    finally:
        os.environ["PUBLIC_API_URL"] = "https://mdm.example.test/"
    check("a link has no url while PUBLIC_API_URL is unset", unset.get("url") is None, str(unset.get("url")))
    check("...and the same link has one once it is set",
          str(routes._link_body(await EnrollmentLink.get(id=unset["id"])).get("url") or "").startswith("https://"))
    undecryptable = routes._link_body(used_up)
    check("a link whose token cannot be decrypted has no url", undecryptable.get("url") is None)


async def test_download(admin):
    from types import SimpleNamespace

    from controller.api import runtime
    from controller.api.routes import enrollment as routes
    from controller.services import enrollment_links

    print("\n5) a failed profile mint does not count the download")
    link, token = await enrollment_links.create_link(admin.tenant, admin.email, "mint",
                                                     utcnow() + timedelta(days=1), 1)
    request = SimpleNamespace(client=SimpleNamespace(host="198.51.100.4"))

    async def warm():
        return None

    async def broken_mint(*args, **kwargs):
        raise RuntimeError("database went away")

    async def good_mint(*args, **kwargs):
        return b"<plist/>"

    svc = runtime.enrollment_svc
    saved = (routes.require_enrollment_configured, routes.readiness.warm_enroll_state, svc.issue_profile)
    routes.require_enrollment_configured = lambda *args: None
    routes.readiness.warm_enroll_state = warm
    svc.issue_profile = broken_mint
    try:
        try:
            await routes.download_enrollment_profile(token, request)
            raised = None
        except RuntimeError as exc:
            raised = exc
        check("the mint's error reaches the caller", raised is not None and "went away" in str(raised))
        check("...and the download is not counted", (await EnrollmentLink.get(id=link.id)).downloads == 0)
        svc.issue_profile = good_mint
        response = await routes.download_enrollment_profile(token, request)
        check("a working mint serves the profile", response.body == b"<plist/>")
        check("...and counts the download", (await EnrollmentLink.get(id=link.id)).downloads == 1)
        used_up = await status_of(routes.download_enrollment_profile(token, request))
        check("the used-up link answers 404", used_up == 404)
    finally:
        routes.require_enrollment_configured, routes.readiness.warm_enroll_state, svc.issue_profile = saved


async def main():
    await Tortoise.init(db_url="sqlite://:memory:", modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()
    tenant = await Tenant.create(id="t1", name="Routes Tenant")
    other = await Tenant.create(id="t2", name="Other Tenant")
    admin_user = await User.create(tenant=tenant, email="admin@t1", role="admin")
    member_user = await User.create(tenant=tenant, email="member@t1", role="member")
    other_user = await User.create(tenant=other, email="admin@t2", role="admin")
    admin = Principal(tenant=tenant, user=admin_user, email=admin_user.email, role="admin")
    member = Principal(tenant=tenant, user=member_user, email=member_user.email, role="member")
    other_admin = Principal(tenant=other, user=other_user, email=other_user.email, role="admin")

    await test_allow_reenrollment(admin, member, other_admin)
    await test_links(admin, member, other_admin)
    await test_download(admin)

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    return 1 if FAIL else 0


from tests._verify_harness import run  # noqa: E402

run(main)
