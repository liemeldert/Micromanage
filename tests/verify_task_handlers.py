"""The four MDM task handlers, on the bound path and the cold path.

Verifies handler fetch behavior, binding, and deployment state across six test sections.
"""
import ast
import os
import tempfile
from functools import partial
from pathlib import Path

import httpx
from tortoise import Tortoise, connections

PASS, FAIL = [], []
REPO = Path(__file__).resolve().parent.parent


def check(label, cond):
    (PASS if cond else FAIL).append(label)
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


class FakeS3Client:
    """boto3's client, minus the network. The install path does not touch S3 itself: the manifest, and the presigned
    download inside it, are built by GET /api/manifests/{id} when the device asks for them."""

    def generate_presigned_url(self, operation, Params, ExpiresIn):
        return f"https://signed.example/{Params['Bucket']}/{Params['Key']}"


class FakeConnector:
    """NanoMDM, minus the network. Records what was enqueued for which udid."""

    def __init__(self):
        self.calls = []
        self._n = 0

    def _uuid(self, kind, udid):
        self._n += 1
        self.calls.append((kind, udid))
        return {"status": "queued", "command_uuid": f"cmd-{kind}-{self._n}"}

    async def install_app(self, udid, manifest_url, management_flags=1,
                          install_as_managed=True):
        self.last_install = {"manifest_url": manifest_url,
                             "management_flags": management_flags,
                             "install_as_managed": install_as_managed}
        return self._uuid("install_app", udid)

    async def remove_app(self, udid, bundle_id):
        return self._uuid("remove_app", udid)

    async def install_profile(self, udid, payload):
        self.last_payload = payload
        return self._uuid("install_profile", udid)

    async def remove_profile(self, udid, identifier):
        self.last_identifier = identifier
        return self._uuid("remove_profile", udid)


APP_INFO = {"app_id": "slack", "name": "Slack", "version": "1.0",
            "bundle_id": "com.tinyspeck.slackmacgap",
            "s3_key": "apps/slack-1.0.pkg", "sha256": "a" * 64}
PROFILE_INFO = {"id": "wifi", "name": "Corporate Wi-Fi",
                "payload": {"PayloadType": "com.apple.wifi", "SSID_STR": "CorpNet"}}


def _only_fields(path: Path, func_name: str):
    """Extract the field list from Device.filter(...).only(...) in func."""
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != func_name:
            continue
        for call in ast.walk(node):
            if not (isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and call.func.attr == "only"):
                continue
            recv = call.func.value
            if not (isinstance(recv, ast.Call) and isinstance(recv.func, ast.Attribute)
                    and recv.func.attr == "filter"
                    and getattr(recv.func.value, "id", None) == "Device"):
                continue
            return {a.value for a in call.args if isinstance(a, ast.Constant)}
    return set()


async def main():
    base = Path(tempfile.mkdtemp())
    os.environ["YAML_CONFIG_PATH"] = str(base)
    os.environ["PUBLIC_API_URL"] = "https://mdm.example.com"

    await Tortoise.init(db_url="sqlite://:memory:",
                        modules={"models": ["controller.models.tenant"]})
    await Tortoise.generate_schemas()

    import controller.services.app_manager as app_manager
    import controller.services.task_handlers as th
    from controller.models.tenant import (
        AppDeployment, Device, ProfileDeployment, Task, Tenant,
    )
    from controller.services.task_manager import TaskManager

    app_manager.boto3.client = lambda **kw: FakeS3Client()
    connector = FakeConnector()
    th.shared_connector = lambda: connector

    tenant = await Tenant.create(
        id="sp11", name="SP11 Tenant",
        s3_config={"bucket": "pkgs", "access_key_id": "AK", "secret_access_key": "SK"})
    other_tenant = await Tenant.create(
        id="sp11-other", name="Other Org",
        s3_config={"bucket": "pkgs", "access_key_id": "AK", "secret_access_key": "SK"})

    conn = connections.get("default")
    seen_sql = []

    class _Spy:
        """Records the SQL a block issues, so the query arithmetic can be counted rather than argued."""

        def __enter__(self):
            self._q, self._qd = conn.execute_query, conn.execute_query_dict

            async def spy_q(sql, values=None):
                seen_sql.append(sql)
                return await self._q(sql, values)

            async def spy_qd(sql, values=None):
                seen_sql.append(sql)
                return await self._qd(sql, values)

            seen_sql.clear()
            conn.execute_query, conn.execute_query_dict = spy_q, spy_qd
            return self

        def __exit__(self, *exc):
            conn.execute_query, conn.execute_query_dict = self._q, self._qd
            return False

    def _selects(table):
        return [s for s in seen_sql
                if s.lstrip().upper().startswith("SELECT") and f'"{table}"' in s]

    seq = {"n": 0}

    async def new_device(tnt=None):
        seq["n"] += 1
        n = seq["n"]
        return await Device.create(
            tenant=tnt or tenant, udid=f"UDID-{n}", serial_number=f"SP11-{n}",
            device_model="MacBookPro18,3", os_version="15.5",
            hostname=f"sp11-{n}.local", name=f"Lab {n}",
            enrollment_state="enrolled", management_type="apple_mdm",
            groups=[], tags=[], attributes={})

    async def new_task(device, ttype, details):
        task = await Task.create(
            tenant=device.tenant_id and tenant, type=ttype, status="pending",
            device=device, user="system", description=f"{ttype}",
            details=dict(details))
        # Read back with no prefetch, which is what retry_task and send_device_command hand a handler. Tortoise 0.20
        # leaves .device an awaitable QuerySet on such a row, so the fetch reads task.device_id instead.
        return await Task.get(id=task.id)

    DETAILS = {
        "profile_install": {"profile_info": PROFILE_INFO},
        "profile_remove": {"profile_id": "wifi"},
        "app_install": {"app_info": APP_INFO},
        "app_remove": {"app_id": "slack", "bundle_id": APP_INFO["bundle_id"]},
    }
    HANDLERS = {
        "profile_install": th.handle_profile_install_task,
        "profile_remove": th.handle_profile_remove_task,
        "app_install": th.handle_app_install_task,
        "app_remove": th.handle_app_remove_task,
    }
    # Task type to the MDM command the deploy path behind it has to enqueue.
    MDM_KIND = {
        "profile_install": "install_profile",
        "profile_remove": "remove_profile",
        "app_install": "install_app",
        "app_remove": "remove_app",
    }

    async def seed_removable(device, kind):
        """The remove handlers delete a deployment row, so there has to be one."""
        if kind == "profile_remove":
            await ProfileDeployment.create(
                tenant=tenant, device=device, profile_id="wifi", status="installed")
        elif kind == "app_remove":
            await AppDeployment.create(
                tenant=tenant, device=device, app_id="slack", app_version="1.0",
                status="installed")

    async def reached_mdm(task, kind, device):
        """Check if the handler reached MDM enqueue and did not fail. Distinguish from task failure."""
        row = await Task.get(id=task.id)
        uuid_ok = str(row.details.get("command_uuid", "")).startswith(f"cmd-{kind}")
        addressed = connector.calls[-1] == (kind, device.udid) if connector.calls else False
        return row, uuid_ok and addressed and row.status != "failed"

    print("\n== 1. Cold path: no kwargs, a Task read back with no prefetch ==")
    for kind, handler in HANDLERS.items():
        dev = await new_device()
        await seed_removable(dev, kind)
        task = await new_task(dev, kind, DETAILS[kind])
        with _Spy():
            await handler(task)
        row, ok = await reached_mdm(task, MDM_KIND[kind], dev)
        check(f"{kind}: the fetch path reaches the MDM enqueue "
              f"(status={row.status}, error={row.error!r})", ok)
        check(f"{kind}: the fetch costs one device SELECT and one tenant SELECT "
              f"(got {len(_selects('devices'))} and {len(_selects('tenants'))})",
              len(_selects("devices")) == 1 and len(_selects("tenants")) == 1)

    check("profile_install created its deployment row on the cold path",
          await ProfileDeployment.filter(
              tenant=tenant, profile_id="wifi", status="installing").count() == 1)
    check("app_install created its deployment row on the cold path",
          await AppDeployment.filter(
              tenant=tenant, app_id="slack", status="installing").count() == 1)
    check("profile_remove deleted the row it was given",
          await ProfileDeployment.filter(status="installed").count() == 0)
    check("app_remove deleted the row it was given",
          await AppDeployment.filter(status="installed").count() == 0)

    print("\n== 2. Bound path at all three narrowed widths ==")
    # The three .only() widths that can reach a handler (reconciler, dispatcher, poller).
    WIDTHS = {
        "reconciler": _only_fields(REPO / "controller/services/reconciler.py",
                                   "reconcile_tenant"),
        "dispatcher._SWEEP_DEVICE_FIELDS": None,  # imported below
        "poller.poll_tenant": _only_fields(REPO / "controller/services/poller.py",
                                           "poll_tenant"),
    }
    from controller.services.dispatcher import _SWEEP_DEVICE_FIELDS
    WIDTHS["dispatcher._SWEEP_DEVICE_FIELDS"] = set(_SWEEP_DEVICE_FIELDS)
    check("all three narrowed widths were found in the source",
          all(bool(w) for w in WIDTHS.values()))

    for width_name, fields in WIDTHS.items():
        for kind, handler in HANDLERS.items():
            dev = await new_device()
            await seed_removable(dev, kind)
            task = await new_task(dev, kind, DETAILS[kind])
            partial_dev = await Device.filter(id=dev.id).only(*sorted(fields)).first()
            with _Spy():
                await handler(task, device=partial_dev, tenant=tenant)
            row, ok = await reached_mdm(task, MDM_KIND[kind], dev)
            check(f"{width_name} + {kind}: reaches the enqueue off a partial row "
                  f"(status={row.status}, error={row.error!r})", ok)
            check(f"{width_name} + {kind}: no device or tenant SELECT "
                  f"(got {len(_selects('devices'))} and {len(_selects('tenants'))})",
                  not _selects("devices") and not _selects("tenants"))

    print("\n== 3. Bound equals cold, and the bound objects are the ones used ==")
    cold_dev = await new_device()
    warm_dev = await new_device()
    cold_task = await new_task(cold_dev, "profile_install", DETAILS["profile_install"])
    warm_task = await new_task(warm_dev, "profile_install", DETAILS["profile_install"])
    await HANDLERS["profile_install"](cold_task)
    await HANDLERS["profile_install"](warm_task, device=warm_dev, tenant=tenant)
    cold_row = await ProfileDeployment.get(device=cold_dev, profile_id="wifi")
    warm_row = await ProfileDeployment.get(device=warm_dev, profile_id="wifi")
    cold_task = await Task.get(id=cold_task.id)
    warm_task = await Task.get(id=warm_task.id)
    check("both shapes leave the same deployment state",
          (cold_row.status, cold_row.payload_hash, cold_row.last_error)
          == (warm_row.status, warm_row.payload_hash, warm_row.last_error))
    check("both shapes leave the same task state and both carry a command_uuid",
          cold_task.status == warm_task.status
          and bool(cold_task.details.get("command_uuid"))
          and bool(warm_task.details.get("command_uuid")))
    check("both stamped last_task_id on the row they made",
          str(cold_row.last_task_id) == str(cold_task.id)
          and str(warm_row.last_task_id) == str(warm_task.id))

    # The bound tenant is what the profile is built from, not something the manager re-derives from device.tenant.
    foreign_dev = await new_device()
    foreign_task = await new_task(foreign_dev, "profile_install", DETAILS["profile_install"])
    await HANDLERS["profile_install"](foreign_task, device=foreign_dev, tenant=other_tenant)
    check("the bound tenant is the one on the wire (PayloadOrganization)",
          getattr(connector, "last_payload", {}).get("PayloadOrganization")
          == other_tenant.name)

    # Device bound and tenant omitted costs one tenant read, rather than passing None into the manager.
    half_dev = await new_device()
    half_task = await new_task(half_dev, "profile_install", DETAILS["profile_install"])
    with _Spy():
        await HANDLERS["profile_install"](half_task, device=half_dev)
    half_row, half_ok = await reached_mdm(half_task, "install_profile", half_dev)
    check("device bound with tenant omitted still deploys", half_ok)
    check("...at one tenant SELECT and no device SELECT "
          f"(got {len(_selects('tenants'))} and {len(_selects('devices'))})",
          len(_selects("tenants")) == 1 and not _selects("devices"))

    print("\n== 4. Query arithmetic: bound is flat, cold is two per task ==")
    n = 5
    bound_devs = [await new_device() for _ in range(n)]
    bound_tasks = [await new_task(d, "profile_install", DETAILS["profile_install"])
                   for d in bound_devs]
    with _Spy():
        for d, t in zip(bound_devs, bound_tasks):
            await HANDLERS["profile_install"](t, device=d, tenant=tenant)
    bound_reads = len(_selects("devices")) + len(_selects("tenants"))
    cold_devs = [await new_device() for _ in range(n)]
    cold_tasks = [await new_task(d, "profile_install", DETAILS["profile_install"])
                  for d in cold_devs]
    with _Spy():
        for t in cold_tasks:
            await HANDLERS["profile_install"](t)
    cold_reads = len(_selects("devices")) + len(_selects("tenants"))
    check(f"{n} bound tasks read no device or tenant rows (got {bound_reads})",
          bound_reads == 0)
    check(f"{n} cold tasks read exactly two rows each (got {cold_reads}, want {2 * n})",
          cold_reads == 2 * n)

    print("\n== 5. The three .only() lists keep the fields the handlers read ==")
    # id, udid and serial_number must stay: they are critical fields read by deploy path and profile/app managers.
    HANDLER_DEVICE_FIELDS = {"id", "udid", "serial_number"}
    for width_name, fields in WIDTHS.items():
        missing = sorted(HANDLER_DEVICE_FIELDS - fields)
        check(f"{width_name} still lists id, udid and serial_number "
              f"(missing: {missing})", not missing)
    check("...and all three carry tenant_id, which the tenant-less branch reads",
          all("tenant_id" in fields for fields in WIDTHS.values()))

    print("\n== 6. Every services-layer spawn binds, and a partial survives ==")
    # A dropped binding is silent: the handler falls back to the fetch and still works, two queries per task slower, so
    # it is asserted structurally.
    for module in ("reconciler", "dispatcher", "atc"):
        tree = ast.parse((REPO / f"controller/services/{module}.py").read_text())
        bound = set()
        for call in ast.walk(tree):
            if not (isinstance(call, ast.Call)
                    and getattr(call.func, "id", None) == "partial"):
                continue
            kwargs = {k.arg for k in call.keywords}
            if call.args and isinstance(call.args[0], ast.Name) \
                and {"device", "tenant"} <= kwargs:
                bound.add(id(call.args[0]))
        used = [n for n in ast.walk(tree) if isinstance(n, ast.Name)
                and n.id.startswith("handle_") and n.id.endswith("_task")]
        unbound = sorted({n.id for n in used if id(n) not in bound})
        check(f"{module}.py binds device and tenant at every handler spawn "
              f"(unbound: {unbound})", bool(used) and not unbound)

    check("TASK_HANDLERS is still the bare functions, so retry_task keeps "
          "exercising the fetch",
          all(th.TASK_HANDLERS[k] is HANDLERS[k] for k in HANDLERS))

    # execute_task calls handler(task) positionally, so a partial carrying only keyword arguments has to survive it. It
    # is also the only place here that drives the handler the way the reconciler does.
    exec_dev = await new_device()
    exec_task = await new_task(exec_dev, "app_install", DETAILS["app_install"])
    with _Spy():
        await TaskManager().execute_task(
            exec_task,
            partial(th.handle_app_install_task, device=exec_dev, tenant=tenant))
    exec_row, exec_ok = await reached_mdm(exec_task, "install_app", exec_dev)
    check("a bound partial survives TaskManager.execute_task", exec_ok)
    check("...and execute_task did not re-read the device or the tenant either "
          f"(got {len(_selects('devices'))} and {len(_selects('tenants'))})",
          not _selects("devices") and not _selects("tenants"))
    check("execute_task left the task running for the webhook to finish",
          exec_row.status == "running")

    # NanoMDM 0.9.0 fixture responses: stored vs refused commands.
    # Stored and push are separate: a queued command with push failure still awaits device check-in.
    print("\n8) enqueue tells a stored command from a refused one")
    import controller.services.mdm_connector as mc

    certless = {"push_error": "retrieving push cert for topic \"t\": "
                              "sql: no rows in result set",
                "command_uuid": "ABC-123", "request_type": "DeviceInformation"}
    per_id_push = {"status": {"UDID-1": {"push_error": "BadDeviceToken"}},
                   "command_uuid": "ABC-124", "request_type": "DeviceInformation"}
    per_id_enqueue = {"status": {"UDID-1": {"command_error": "no such enrollment"}},
                      "command_uuid": "ABC-125", "request_type": "DeviceInformation"}
    call_wide_enqueue = {"command_error": "storing command: connection refused",
                         "command_uuid": "ABC-126", "request_type": "DeviceInformation"}

    class _Resp:
        def __init__(self, status_code, doc):
            self.status_code = status_code
            self._doc = doc
            self.content = b"x"

        def json(self):
            if isinstance(self._doc, Exception):
                raise self._doc
            return self._doc

        def raise_for_status(self):
            if self.status_code >= 400:
                raise RuntimeError(f"HTTP {self.status_code}")

    one = ["UDID-1"]
    check("a call-wide push failure leaves the command stored",
          mc._command_stored(certless, one))
    check("an APNs rejection under status.<id> leaves it stored too",
          mc._command_stored(per_id_push, one))
    check("a per-id enqueue error means it was not stored",
          not mc._command_stored(per_id_enqueue, one))
    # NanoMDM copies command_uuid off the command before it calls the store, so a failed enqueue reports one too:
    # command_error, not the UUID, says whether anything was stored.
    check("a call-wide enqueue error means it was not stored, UUID or no UUID",
          not mc._command_stored(call_wide_enqueue, one))
    check("a body with no command_uuid at all is not a stored command",
          not mc._command_stored({"command_error": "decoding command: EOF"}, one))
    check("an unreadable body is read as no body rather than raising",
          mc._api_result(_Resp(500, ValueError("no json"))) is None)
    check("errors are collected from both levels, keyed by id",
          mc._errors({"push_error": "no cert",
                      "status": {"UDID-1": {"push_error": "BadDeviceToken"}}},
                     one, "push_error")
          == ["no cert", "UDID-1: BadDeviceToken"])

    class _StubClient:
        def __init__(self, resp):
            self._resp = resp
            self.urls = []

        async def put(self, url, content=None, headers=None):
            self.urls.append(url)
            return self._resp

    conn = mc.MDMConnector()
    conn.client = _StubClient(_Resp(500, certless))
    got = await conn.enqueue_command("UDID-1", b"<plist/>")
    check("a command stored on a server with no push cert comes back queued",
          got.get("command_uuid") == "ABC-123" and bool(got.get("push_error")))
    conn.client = _StubClient(_Resp(500, per_id_push))
    got = await conn.enqueue_command("UDID-1", b"<plist/>")
    check("...and so does one whose push APNs rejected for that enrollment",
          got.get("command_uuid") == "ABC-124")

    async def enqueue_error(resp, enrollment_id="UDID-1"):
        """The EnqueueError raised, or None if the call came back instead."""
        conn.client = _StubClient(resp)
        try:
            await conn.enqueue_command(enrollment_id, b"<plist/>")
            return None
        except mc.EnqueueError as exc:
            return exc

    exc = await enqueue_error(_Resp(500, per_id_enqueue))
    check("a per-id enqueue refusal raises, carrying NanoMDM's own reason",
          exc is not None and "no such enrollment" in str(exc))
    # A refused enqueue is an ordinary operational state, and callers sort those by httpx type to keep one log line
    # instead of a traceback per device, so the refusal has to stay an httpx status error.
    check("...and it is still an httpx status error, so log routing is unchanged",
          isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 500)
    exc = await enqueue_error(_Resp(500, call_wide_enqueue))
    check("a call-wide enqueue refusal raises even though a UUID came back",
          exc is not None and "connection refused" in str(exc))

    # Several ids at once: NanoMDM takes them comma-separated on the path and answers 207 when some stored and some did
    # not, which httpx treats as a success. Only every id coming back clean counts as queued.
    two = {"status": {"UDID-A": {"push_result": "apns-1"},
                      "UDID-B": {"push_error": "Unregistered"}},
           "command_uuid": "ABC-127", "request_type": "DeviceInformation"}
    conn.client = _StubClient(_Resp(207, two))
    got = await conn.enqueue_command("UDID-A,UDID-B", b"<plist/>")
    check("two ids, one unpushable: the command is still queued for both",
          got.get("command_uuid") == "ABC-127")
    one_refused = {"status": {"UDID-A": {"push_result": "apns-1"},
                              "UDID-B": {"command_error": "no such enrollment"}},
                   "command_uuid": "ABC-128", "request_type": "DeviceInformation"}
    exc = await enqueue_error(_Resp(207, one_refused), "UDID-A,UDID-B")
    check("two ids, one refused: 207 is not allowed to read as success",
          exc is not None and "UDID-B" in str(exc))

    # A queued command whose push failed reaches the device only at its next check-in, so the answer carries the failure
    # rather than reporting a clean success, normalized across the two levels NanoMDM reports at.
    conn.client = _StubClient(_Resp(500, certless))
    got = await conn.enqueue_command("UDID-1", b"<plist/>")
    check("a call-wide push failure is reported against every id it covers",
          got.get("push_failed") is True
          and set(got.get("push_errors") or {}) == {"UDID-1"}
          and "no rows in result set" in (got.get("push_errors") or {}).get("UDID-1", ""))
    conn.client = _StubClient(_Resp(500, per_id_push))
    got = await conn.enqueue_command("UDID-1", b"<plist/>")
    check("an APNs rejection is reported against the enrollment it happened to",
          got.get("push_failed") is True
          and got.get("push_errors") == {"UDID-1": "BadDeviceToken"})
    conn.client = _StubClient(_Resp(207, two))
    got = await conn.enqueue_command("UDID-A,UDID-B", b"<plist/>")
    check("with several ids, only the one that failed is named",
          got.get("push_failed") is True
          and got.get("push_errors") == {"UDID-B": "Unregistered"})
    clean = {"command_uuid": "ABC-129", "request_type": "DeviceInformation",
             "status": {"UDID-1": {"push_result": "apns-9"}}}
    conn.client = _StubClient(_Resp(200, clean))
    got = await conn.enqueue_command("UDID-1", b"<plist/>")
    # Both keys on every answer, so a caller can ask without knowing which branch produced it.
    check("a push that worked answers the same question with no",
          got.get("push_failed") is False and got.get("push_errors") == {}
          and {"push_failed", "push_errors"} <= set(got))

    # An httpx.HTTPStatusError is expected to carry the request that produced it, and Response.request raises rather
    # than returning None when nothing bound one, so building the refusal must not be what fails.
    exc = await enqueue_error(_Resp(500, call_wide_enqueue))
    try:
        carried = str(exc.request.url)
    except Exception:
        carried = ""
    check("the refusal carries a request, as every httpx status error does",
          carried.endswith("/v1/enqueue/UDID-1"))
    # So reading it has to be guarded wherever it is read.
    check("...even when the response it came from has no request of its own",
          isinstance(mc._request_of(httpx.Response(500), "/v1/enqueue/X"),
                     httpx.Request))

    # A 2xx that promised a body and sent something unreadable has said nothing about what it stored. Binding a task to
    # that would leave it running forever, waiting on a webhook for a command that may not exist.
    conn.client = _StubClient(_Resp(200, ValueError("truncated")))
    unreadable = None
    try:
        await conn.enqueue_command("UDID-1", b"<plist/>", command_uuid="local-1")
    except mc.EnqueueError as exc:
        unreadable = exc
    check("a success with a body this cannot read is not a queued command",
          unreadable is not None and "could not read" in str(unreadable))

    print("\n9) InstallApplication: managed installs and the manifest URL")
    from controller.services.app_manager import AppManager

    mac_dev = await new_device()
    ipad_dev = await Device.create(
        tenant=tenant, udid="UDID-IPAD-9", serial_number="SP11-IPAD",
        device_model="iPad13,8", os_version="17.5", enrollment_state="enrolled",
        management_type="apple_mdm", groups=[], tags=[], attributes={})

    await AppManager(tenant).deploy_app(mac_dev, APP_INFO, connector)
    check("a Mac gets InstallAsManaged, which is what makes flag 1 mean anything",
          connector.last_install["install_as_managed"] is True)
    check("...with ManagementFlags 1, remove-on-unenroll",
          connector.last_install["management_flags"] == 1)
    await AppManager(tenant).deploy_app(ipad_dev, APP_INFO, connector)
    check("an iPad does not, since Apple marks the key macOS-only",
          connector.last_install["install_as_managed"] is False)

    # Apple requires the ManifestURL to begin with https. A device answers anything else with an error, so the install
    # is refused here before it is enqueued.
    before = len(connector.calls)
    os.environ["PUBLIC_API_URL"] = "http://mdm.example.com"
    http_refused = False
    try:
        await AppManager(tenant).deploy_app(mac_dev, APP_INFO, connector)
    except ValueError as exc:
        http_refused = "https" in str(exc)
    finally:
        os.environ["PUBLIC_API_URL"] = "https://mdm.example.com"
    check("a plain-http manifest URL is refused", http_refused)
    check("...and nothing was enqueued for it", len(connector.calls) == before)
    failed_row = await AppDeployment.get(device=mac_dev, app_id="slack")
    check("...and the deployment row says why",
          failed_row.status == "failed" and "https" in (failed_row.last_error or ""))

    # An unset PUBLIC_API_URL builds "None/api/manifests/...", which is not https either and is refused too.
    before = len(connector.calls)
    del os.environ["PUBLIC_API_URL"]
    unset_refused = False
    try:
        await AppManager(tenant).deploy_app(mac_dev, APP_INFO, connector)
    except ValueError as exc:
        unset_refused = "https" in str(exc)
    finally:
        os.environ["PUBLIC_API_URL"] = "https://mdm.example.com"
    check("an unset PUBLIC_API_URL is refused too, not sent as a literal None",
          unset_refused and len(connector.calls) == before)

    # A queued install whose push failed is not a failed install: the row stays installing and carries the reason it may
    # sit there a while.
    class _UnpushedConnector:
        async def install_app(self, udid, manifest_url, management_flags=1,
                              install_as_managed=False):
            return {"command_uuid": "cmd-unpushed", "push_failed": True,
                    "push_errors": {udid: "retrieving push cert: no rows in result set"}}

    await AppManager(tenant).deploy_app(mac_dev, APP_INFO, _UnpushedConnector())
    unpushed_row = await AppDeployment.get(device=mac_dev, app_id="slack")
    check("a queued-but-unpushed install is still installing, not failed",
          unpushed_row.status == "installing")
    check("...and the row says the device applies it at its next check-in",
          "next check-in" in (unpushed_row.last_error or "")
          and "no rows in result set" in (unpushed_row.last_error or ""))

    print("\n10) ClearPasscode is offered again, iOS-only, and needs an UnlockToken")
    from controller.services.command_catalog import (
        RETIRED_COMMANDS, get_command, unsupported_reason,
    )
    from controller.auth import DESTRUCTIVE_COMMANDS

    entry = get_command("clear_passcode")
    check("the catalog lists clear_passcode again",
          entry is not None and "clear_passcode" not in RETIRED_COMMANDS)
    check("it is destructive, so it is admin-gated",
          "clear_passcode" in DESTRUCTIVE_COMMANDS)
    check("and it is scoped to iPhone/iPad, not the Mac",
          "Mac" not in (entry.get("platforms") or []))

    # The connector needs the enrollment's UnlockToken, and refuses to build the command without one.
    token_refused = False
    try:
        await mc.MDMConnector().clear_passcode("UDID-1", b"")
    except ValueError as exc:
        token_refused = "UnlockToken" in str(exc)
    check("the connector refuses to build one without an UnlockToken",
          token_refused)

    # A Mac is refused before any task is created, and the refusal names the platform.
    from controller.services.device_commands import (
        CommandError, dispatch_catalog_command,
    )
    mac_refusal = ""
    try:
        await dispatch_catalog_command(mac_dev, "clear_passcode", {},
                                       user="admin@t", tenant=tenant,
                                       allow_destructive=True)
    except CommandError as exc:
        mac_refusal = str(exc)
    check("sending it to a Mac is refused, naming the platform",
          "Clear passcode" in mac_refusal and "Mac" in mac_refusal)

    # The command was stored and the push failed, so the reason has to be on the task rather than only in the log.
    class _UnpushedCommandConnector:
        async def restart_device(self, udid):
            return {"command_uuid": "cmd-restart-unpushed", "push_failed": True,
                    "push_errors": {udid: "BadDeviceToken"}}

    outcome = await dispatch_catalog_command(
        mac_dev, "restart", {}, user="admin@t", tenant=tenant,
        allow_destructive=True, mdm_connector=_UnpushedCommandConnector())
    restart_task = await Task.get(id=outcome["task_id"])
    check("a queued-but-unpushed command still reports as sent",
          restart_task.status == "running"
          and restart_task.details.get("command_uuid") == "cmd-restart-unpushed")
    check("...and the task carries the push failure and which enrollment it hit",
          restart_task.details.get("push_failed") is True
          and restart_task.details.get("push_errors")
          == {mac_dev.udid: "BadDeviceToken"})
    check("...and the caller is handed the same answer to show the admin",
          outcome["result"].get("push_failed") is True)

    # Apple's platform and supervision blocks, per command. The check only refuses on a fact the device reported:
    # an unknown platform or an unreported IsSupervised passes, which is why every case here names one.
    print("\n11) the catalog matches Apple's per-command blocks")
    GATE_CASES = [
        # (command, platform, is_supervised, refused?)
        ("restart", "iPhone", False, True),  # iOS: supervised
        ("restart", "Mac", False, False),  # macOS: no supervision needed
        ("restart", "Apple TV", False, True),  # tvOS: supervised
        ("shutdown", "iPhone", False, True),  # iOS: supervised
        ("shutdown", "Mac", False, False),  # macOS: no supervision needed
        ("shutdown", "Apple TV", True, True),  # tvOS: n/a
        ("clear_restrictions_password", "iPhone", False, True),  # iOS: supervised
        ("clear_restrictions_password", "Mac", True, True),  # macOS: n/a
        ("unlock_user_account", "Mac", False, False),  # macOS: unsupervised is fine
        ("unlock_user_account", "iPad", True, True),  # iOS: n/a
        ("enable_remote_desktop", "Mac", False, True),  # macOS: supervised
        ("disable_remote_desktop", "Mac", False, True),  # macOS: supervised
        ("user_list", "Mac", False, True),  # macOS: supervised
        ("user_list", "iPad", False, False),  # Shared iPad: unsupervised is fine
        ("user_list", "iPhone", True, True),  # Shared iPad is an iPad
        ("logout_user", "iPad", False, False),  # Shared iPad: unsupervised is fine
        ("logout_user", "Mac", True, True),  # macOS: n/a
        ("delete_user", "Mac", False, True),  # macOS: supervised
        ("delete_user", "iPad", False, False),  # Shared iPad: unsupervised is fine
        ("lock", "Apple TV", True, True),  # tvOS: n/a, and lock is a Quick Action
        ("lock", "iPhone", False, False),  # iOS: no supervision needed
        ("lock", "Mac", False, False),  # macOS: no supervision needed
        ("lock", "Apple Watch", False, False),  # watchOS 10: no supervision needed
        # The two OS-update queries differ on supervision and that is Apple's doing: OSUpdateStatus wants it on the Mac
        # as well, AvailableOSUpdates only off the Mac.
        ("available_os_updates", "Mac", False, False),
        ("available_os_updates", "iPhone", False, True),
        ("available_os_updates", "Apple TV", False, True),
        ("os_update_status", "Mac", False, True),
        ("os_update_status", "Apple Watch", True, True),  # watchOS: n/a
    ]
    wrong = [(c, p, s) for c, p, s, refused in GATE_CASES
             if bool(unsupported_reason(get_command(c), p, s)) is not refused]
    check(f"every documented platform/supervision case is refused where Apple says ({wrong})",
          not wrong)
    check("a device that has not said whether it is supervised is let through",
          unsupported_reason(get_command("restart"), "iPhone", None) is None)
    check("a model we cannot classify is let through",
          unsupported_reason(get_command("logout_user"), "Other", None) is None)
    # Device.attributes holds what the device sent, verbatim. A truthiness test would read the string "false" as a yes
    # and pick the wrong architecture command, so anything that is not already a bool reads as unreported.
    check("an attribute that is not a bool counts as unreported, both ways",
          unsupported_reason(get_command("set_recovery_lock"), "Mac", None, "false")
          is None
          and unsupported_reason(get_command("set_firmware_password"), "Mac",
                                 None, "false") is None)
    check("...while a real bool still refuses",
          unsupported_reason(get_command("set_recovery_lock"), "Mac", None, False)
          is not None
          and unsupported_reason(get_command("set_recovery_lock"), "Mac", None, True)
          is None)

    # Return to Service Wi-Fi profile must join the network: device is already wiped and out of reach if it cannot.
    print("\n12) the Return to Service Wi-Fi payload joins the network it names")
    from controller.services.enrollment import build_wifi_profile

    secured = build_wifi_profile("CorpNet", password="hunter2")["PayloadContent"][0]
    check("a network with a password gets Apple's own default, Any",
          secured["EncryptionType"] == "Any")
    check("...and carries the password and the SSID it was given",
          secured["Password"] == "hunter2" and secured["SSID_STR"] == "CorpNet")
    open_net = build_wifi_profile("GuestNet")["PayloadContent"][0]
    check("a network with no password is still declared open",
          open_net["EncryptionType"] == "None" and "Password" not in open_net)
    check("a caller naming an encryption type is still obeyed",
          build_wifi_profile("CorpNet", password="x", encryption="WPA3")
          ["PayloadContent"][0]["EncryptionType"] == "WPA3")

    # Retirement reason lives in one place: the catalog. Changes propagate everywhere.
    print("\n13) the retirement reason has one home")
    from controller.services import command_catalog as _cc
    from controller.services.command_catalog import retirement_reason

    check("nothing is retired right now", _cc.RETIRED_COMMANDS == {})
    check("a command that was never retired answers with no reason",
          retirement_reason("restart") is None)

    saved = dict(_cc.RETIRED_COMMANDS)
    try:
        _cc.RETIRED_COMMANDS["made_up_command"] = "the lab retired it for this test"
        catalog_reason = retirement_reason("made_up_command")
        check("the catalog answers with the reason for a retired command",
              catalog_reason == "the lab retired it for this test")
        runtime_reason = ""
        try:
            await dispatch_catalog_command(mac_dev, "made_up_command", {},
                                           user="admin@t", tenant=tenant,
                                           allow_destructive=True)
        except CommandError as exc:
            runtime_reason = str(exc)
        check("the refusal quotes the catalog rather than restating it",
              catalog_reason in runtime_reason and "made_up_command" in runtime_reason)
    finally:
        _cc.RETIRED_COMMANDS.clear()
        _cc.RETIRED_COMMANDS.update(saved)

    # NanoMDM enqueue must name either the stored command_uuid or the error: an empty answer means not stored.
    print("\n14) a success that names no command is not a queued command")

    class _EmptyResp(_Resp):
        def __init__(self, status_code):
            super().__init__(status_code, ValueError("no body"))
            self.content = b""

    silent = await enqueue_error(_Resp(200, {"request_type": "DeviceInformation"}))
    check("a 200 carrying neither a command_uuid nor a command_error raises",
          silent is not None and "named no stored command" in str(silent))
    check("...and the reason names the keys the body did carry",
          silent is not None and "request_type" in str(silent))
    empty_doc = await enqueue_error(_Resp(200, {}))
    check("a 200 carrying an empty object raises too",
          empty_doc is not None and "named no stored command" in str(empty_doc))
    no_body = await enqueue_error(_EmptyResp(200))
    check("...and so does a 200 with no body at all",
          no_body is not None and "no body" in str(no_body))

    # The caller's own uuid goes in the message rather than onto a body that never claimed to store anything.
    conn.client = _StubClient(_Resp(200, {"request_type": "DeviceInformation"}))
    named = None
    try:
        await conn.enqueue_command("UDID-1", b"<plist/>", command_uuid="local-77")
    except mc.EnqueueError as exc:
        named = exc
    check("the refusal names the uuid the plist asked for, instead of adopting it",
          named is not None and "local-77" in str(named))

    # An error status whose body says nothing this endpoint defines is still just its status.
    conn.client = _StubClient(_Resp(500, {"error": "bad gateway"}))
    plain_status = None
    try:
        await conn.enqueue_command("UDID-1", b"<plist/>")
    except Exception as exc:
        plain_status = exc
    check("an error status with an unrecognized body still answers with its status",
          plain_status is not None and not isinstance(plain_status, mc.EnqueueError))

    await Tortoise.close_connections()
    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} ({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run

run(main)
