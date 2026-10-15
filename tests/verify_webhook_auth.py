"""Verify webhook authentication: NanoMDM's body HMAC, the refused query secret, and step-ca's SCEP challenge webhook.

Run: PYTHONPATH=. .venv/bin/python tests/verify_webhook_auth.py
https://github.com/micromdm/nanomdm/blob/v0.9.0/service/webhook/service.go
https://github.com/micromdm/nanomdm/blob/v0.9.0/http/hashbody/hashbody.go
https://github.com/micromdm/nanomdm/blob/v0.9.0/cmd/nanomdm/main.go
"""
import asyncio
import base64
import hashlib
import hmac
import os
from pathlib import Path
from urllib.parse import urlencode

from starlette.requests import Request

import controller.api.webhook as wh
from tests._verify_harness import LogCapture, make_check

REPO = Path(__file__).resolve().parents[1]

PASS: list = []
FAIL: list = []

check = make_check(FAIL, PASS)


def sign(key: str, body: bytes) -> str:
    """NanoMDM's X-Hmac-Signature, written out from the source cited above."""
    return base64.b64encode(
        hmac.new(key.encode(), body, hashlib.sha256).digest()
    ).decode()


def make_request(query: dict = None, headers: dict = None) -> Request:
    """A starlette Request with no transport: no Tortoise init, no real database."""
    # latin-1, because that is what an ASGI server hands Starlette and what
    # Starlette decodes back: a header byte 0xe9 arrives as "\xe9", not as "é".
    raw_headers = [
        (k.lower().encode(), v.encode("latin-1", "surrogateescape"))
        for k, v in (headers or {}).items()
    ]
    return Request({
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/webhook/mdm",
        "raw_path": b"/webhook/mdm",
        "query_string": urlencode(query or {}).encode(),
        "headers": raw_headers,
        "client": ("172.18.0.5", 51234),
        "server": ("controller", 8000),
    })


def env(**values):
    """Set exactly these webhook variables, clearing the ones left as None."""
    for key in ("WEBHOOK_SECRET", "WEBHOOK_HMAC_KEY"):
        os.environ.pop(key, None)
    for key, value in values.items():
        if value is not None:
            os.environ[key] = value


# A real-ish NanoMDM event body. The bytes matter and nothing else about it does: the signature is over exactly these.
BODY = (
    b'{"topic":"mdm.Connect","event_id":"7d0b0d9e-1f2a-4c1b-9a55-1f2f4a55c0de",'
    b'"created_at":"2026-08-17T12:00:00Z","acknowledge_event":{"udid":'
    b'"F382B30E-1111-2222-3333-444455556666","status":"Acknowledged"}}'
)


def main():
    print("\n== 1. A body HMAC alone is enough ==")
    env(WEBHOOK_SECRET="query-only-secret", WEBHOOK_HMAC_KEY="hmac-key")
    req = make_request(headers={"X-Hmac-Signature": sign("hmac-key", BODY)})
    check("a valid HMAC with no query secret is accepted",
          wh._authorized(req, BODY) == "body-hmac")

    # When WEBHOOK_HMAC_KEY unset, it falls back to WEBHOOK_SECRET; NanoMDM must do the same or the fleet breaks.
    env(WEBHOOK_SECRET="only-webhook-secret")
    req = make_request(
        headers={"X-Hmac-Signature": sign("only-webhook-secret", BODY)})
    check("with WEBHOOK_HMAC_KEY unset the HMAC key falls back to WEBHOOK_SECRET",
          wh._authorized(req, BODY) == "body-hmac")

    # And the other direction: once WEBHOOK_HMAC_KEY is set, WEBHOOK_SECRET stops being the HMAC key, so the two domains
    # are separate.
    env(WEBHOOK_SECRET="query-only-secret", WEBHOOK_HMAC_KEY="hmac-key")
    req = make_request(
        headers={"X-Hmac-Signature": sign("query-only-secret", BODY)})
    check("...and stops being the HMAC key once WEBHOOK_HMAC_KEY is set",
          wh._authorized(req, BODY) is None)

    print("\n== 2. The query secret is refused ==")
    env(WEBHOOK_SECRET="query-only-secret", WEBHOOK_HMAC_KEY="hmac-key")
    req = make_request(query={"secret": "query-only-secret"})
    check("a valid query secret with no HMAC header is refused",
          wh._authorized(req, BODY) is None)

    req = make_request(headers={"X-Webhook-Secret": "query-only-secret"})
    check("the header form of the same secret is refused",
          wh._authorized(req, BODY) is None)

    req = make_request(query={"secret": "query-only-secret"},
                       headers={"X-Hmac-Signature": sign("wrong-key", BODY)})
    check("a valid query secret does not rescue a wrong HMAC",
          wh._authorized(req, BODY) is None)

    req = make_request(query={"secret": "not-the-secret"},
                       headers={"X-Hmac-Signature": sign("hmac-key", BODY)})
    check("a valid HMAC is accepted alongside a wrong query secret",
          wh._authorized(req, BODY) == "body-hmac")

    env(WEBHOOK_SECRET="query-only-secret")
    req = make_request(query={"secret": "query-only-secret"})
    check("...and the query secret is refused when WEBHOOK_SECRET is also the HMAC key",
          wh._authorized(req, BODY) is None)

    print("\n== 3. Neither, and each one wrong ==")
    env(WEBHOOK_SECRET="query-only-secret", WEBHOOK_HMAC_KEY="hmac-key")
    check("no credential at all is refused",
          wh._authorized(make_request(), BODY) is None)

    req = make_request(headers={"X-Hmac-Signature": sign("wrong-key", BODY)})
    check("a wrong HMAC with no query secret is refused",
          wh._authorized(req, BODY) is None)

    # The signature is over the body, so it cannot be lifted off one call and replayed onto another with different
    # contents.
    req = make_request(headers={"X-Hmac-Signature": sign("hmac-key", BODY)})
    check("a signature over other bytes is refused",
          wh._authorized(req, BODY + b" ") is None)

    req = make_request(query={"secret": "not-the-secret"},
                       headers={"X-Hmac-Signature": sign("wrong-key", BODY)})
    check("both presented and both wrong is refused",
          wh._authorized(req, BODY) is None)

    check("an empty signature header is refused",
          wh._authorized(make_request(headers={"X-Hmac-Signature": ""}), BODY)
          is None)

    # hmac.compare_digest raises TypeError on non-ASCII str; must handle before comparing to avoid 500 responses.
    env(WEBHOOK_SECRET="query-only-secret", WEBHOOK_HMAC_KEY="hmac-key")
    for label, value in (("a latin-1 byte", "\xe9"),
                         ("a non-ASCII character", "éAAA")):
        check(f"a signature header carrying {label} is refused, not raised",
              wh._authorized(
                  make_request(headers={"X-Hmac-Signature": value}), BODY)
              is None)

    # Straight at the comparator with a lone surrogate, which no decode path produces but must not raise either.
    check("the comparator survives a lone surrogate on either side",
          wh.constant_time_eq("\udce9", "abc") is False
          and wh.constant_time_eq("abc", "\udce9") is False)

    # A non-ASCII HMAC key from .env must verify a signature, not only avoid raising.
    env(WEBHOOK_SECRET="sécret", WEBHOOK_HMAC_KEY="kéy")
    check("a non-ASCII configured secret is refused as a query secret",
          wh._authorized(make_request(query={"secret": "sécret"}), BODY)
          is None)
    check("...and a non-ASCII configured HMAC key still verifies",
          wh._authorized(
              make_request(headers={"X-Hmac-Signature": sign("kéy", BODY)}),
              BODY) == "body-hmac")
    env(WEBHOOK_SECRET="sécret")
    check("...and a non-ASCII WEBHOOK_SECRET verifies as the fallback HMAC key",
          wh._authorized(
              make_request(headers={"X-Hmac-Signature": sign("sécret", BODY)}),
              BODY) == "body-hmac")

    print("\n== 4. No key configured fails closed ==")
    env()
    check("with neither variable set, a plausible HMAC is refused",
          wh._authorized(
              make_request(headers={"X-Hmac-Signature": sign("", BODY)}),
              BODY) is None)
    check("verify_body_hmac itself refuses on an empty key",
          wh.verify_body_hmac(BODY, sign("", BODY)) is False)

    # With only the HMAC key set, the HMAC works and a query secret equal to it is refused.
    env(WEBHOOK_HMAC_KEY="hmac-key")
    check("with only WEBHOOK_HMAC_KEY set, the HMAC is accepted",
          wh._authorized(
              make_request(headers={"X-Hmac-Signature": sign("hmac-key", BODY)}),
              BODY) == "body-hmac")
    check("...and no query secret can be presented",
          wh._authorized(make_request(query={"secret": "hmac-key"}), BODY)
          is None)

    print("\n== 5. Read per call, not snapshotted at import ==")
    # controller.api.webhook was imported at the top of this file, before any of these variables existed. If either key
    # were captured then, every check above would be reading a value from module-import time.
    def signed(key):
        return make_request(headers={"X-Hmac-Signature": sign(key, BODY)})

    env(WEBHOOK_SECRET="first-secret")
    before = wh._authorized(signed("first-secret"), BODY)
    env(WEBHOOK_SECRET="second-secret")
    after_old = wh._authorized(signed("first-secret"), BODY)
    after_new = wh._authorized(signed("second-secret"), BODY)
    check("a secret set after import is honoured", before == "body-hmac")
    check("a rotated secret takes effect without a re-import",
          after_old is None and after_new == "body-hmac")

    env(WEBHOOK_SECRET="second-secret", WEBHOOK_HMAC_KEY="rotated-hmac-key")
    check("the HMAC key is read per call too",
          wh._authorized(
              make_request(
                  headers={"X-Hmac-Signature": sign("rotated-hmac-key", BODY)}),
              BODY) == "body-hmac")

    print("\n== 6. The boot line, and what the source has to keep ==")
    src = (REPO / "controller" / "api" / "webhook.py").read_text()
    # Section 5 is a property of the source: a reintroduced snapshot would pass every runtime check above until the
    # module was imported with the variables already set.
    check("no module-level WEBHOOK_SECRET snapshot remains",
          "WEBHOOK_SECRET = os.getenv" not in src)
    check("the handler hands the raw body to the verifier",
          "body = await request.body()" in src
          and "_authorized(request, body)" in src)
    check("the header name matches NanoMDM's",
          wh.HMAC_HEADER == "X-Hmac-Signature")

    # The boot line is where an operator reads which schemes are live. It has to say something in every state, including
    # the one where nothing is configured.
    import logging

    handler = LogCapture()
    wh.logger.addHandler(handler)
    try:
        env(WEBHOOK_SECRET="s", WEBHOOK_HMAC_KEY="k")
        wh.log_auth_modes()
        both = handler.records[-1].getMessage()
        check("with both set, the boot line names the HMAC key and no query secret",
              "body HMAC" in both and "query secret" not in both
              and "WEBHOOK_HMAC_KEY" in both)

        env(WEBHOOK_SECRET="s")
        wh.log_auth_modes()
        fallback = handler.records[-1].getMessage()
        check("with only WEBHOOK_SECRET set, it says the HMAC key came from it",
              "body HMAC" in fallback and "WEBHOOK_SECRET" in fallback)

        env()
        wh.log_auth_modes()
        check("with nothing set, it is an error naming what to set",
              handler.records[-1].levelno == logging.ERROR
              and "WEBHOOK_SECRET" in handler.records[-1].getMessage())
    finally:
        wh.logger.removeHandler(handler)
        env(WEBHOOK_SECRET="s")

    asyncio.run(scep_challenge_section())

    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} "
          f"({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


def scep_request(body: bytes, headers: dict) -> Request:
    """A POST to the step-ca webhook route whose receive hands over body."""
    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request({
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/webhook/scep-challenge",
        "raw_path": b"/webhook/scep-challenge",
        "query_string": b"",
        "headers": [(k.lower().encode(), v.encode("latin-1")) for k, v in headers.items()],
        "client": ("172.18.0.9", 40000),
        "server": ("controller", 8000),
    }, receive)


def scep_sign(secret_b64: str, body: bytes) -> str:
    """step-ca's X-Smallstep-Signature: hex HMAC-SHA256 keyed with the decoded secret."""
    return hmac.new(base64.b64decode(secret_b64), body, hashlib.sha256).hexdigest()


async def scep_challenge_section():
    print("\n== 7. step-ca's SCEP challenge webhook ==")
    import inspect
    import json
    import tempfile

    from controller.services import enrollment_links

    secret = base64.b64encode(b"k" * 32).decode()
    workdir = Path(tempfile.mkdtemp())
    secret_file, id_file = workdir / "scep_webhook_secret", workdir / "scep_webhook_id"
    secret_file.write_text(secret + "\n")
    id_file.write_text("webhook-id-1\n")
    os.environ["SCEP_WEBHOOK_SECRET_FILE"] = str(secret_file)
    os.environ["SCEP_WEBHOOK_ID_FILE"] = str(id_file)

    csr_der = b"\x30\x82csr-bytes"
    body = json.dumps({
        "scepChallenge": "the-challenge",
        "scepTransactionID": "txn-1",
        "provisionerName": "mdm_device_scep",
        "x509CertificateRequest": {"subject": {"commonName": "mm 1234"},
                                   "raw": base64.b64encode(csr_der).decode()},
    }).encode()

    seen = []
    verdict = {"allow": True}

    async def fake_validate(challenge_plaintext, provisioner_name, transaction_id, csr_cn, csr_der):
        seen.append((challenge_plaintext, provisioner_name, transaction_id, csr_cn, csr_der))
        if verdict.get("raise"):
            raise RuntimeError("database down")
        return verdict["allow"], None if verdict["allow"] else "expired", None

    original = enrollment_links.validate_and_consume
    check("the fake takes the real signature",
          list(inspect.signature(original).parameters) == list(inspect.signature(fake_validate).parameters))
    enrollment_links.validate_and_consume = fake_validate

    async def call(payload: bytes, headers: dict):
        response = await wh.scep_challenge_webhook(scep_request(payload, headers))
        return response.status_code, json.loads(response.body)

    def good_headers(payload=body):
        return {"X-Smallstep-Signature": scep_sign(secret, payload), "X-Smallstep-Webhook-ID": "webhook-id-1"}

    try:
        status, answer = await call(body, good_headers())
        check("a valid signature and id is allowed", (status, answer) == (200, {"allow": True}))
        check("...with the body's fields handed to validate_and_consume",
              seen == [("the-challenge", "mdm_device_scep", "txn-1", "mm 1234", csr_der)], str(seen))

        seen.clear()
        status, answer = await call(body, {**good_headers(), "X-Smallstep-Signature": scep_sign(secret, b"x")})
        check("a bad signature is denied with 200", (status, answer) == (200, {"allow": False}))
        check("...before anything is validated", not seen)

        status, answer = await call(body, {**good_headers(), "X-Smallstep-Webhook-ID": "webhook-id-2"})
        check("a wrong webhook id is denied with 200", (status, answer) == (200, {"allow": False}))
        headers = good_headers()
        headers.pop("X-Smallstep-Webhook-ID")
        status, answer = await call(body, headers)
        check("a missing webhook id is denied with 200", (status, answer) == (200, {"allow": False}))

        secret_file.unlink()
        status, answer = await call(body, good_headers())
        check("a missing secret file denies everything", (status, answer) == (200, {"allow": False}))
        secret_file.write_text("")
        status, answer = await call(body, good_headers())
        check("an empty secret file denies everything", (status, answer) == (200, {"allow": False}))
        secret_file.write_text("not base64 at all!")
        status, answer = await call(body, good_headers())
        check("a secret that is not base64 denies everything", (status, answer) == (200, {"allow": False}))
        secret_file.write_text(secret)
        check("no call reached validation while the secret was unusable", not seen)

        for label, payload in (("malformed JSON", b"{not json"),
                               ("a JSON array", b"[]"),
                               ("a body without the CSR", json.dumps({"scepChallenge": "c"}).encode()),
                               ("a CSR that is not base64",
                                json.dumps({"scepChallenge": "c", "scepTransactionID": "t",
                                            "provisionerName": "p",
                                            "x509CertificateRequest": {"subject": {}, "raw": "!!"}}).encode())):
            status, answer = await call(payload, good_headers(payload))
            check(f"{label} is denied with 200", (status, answer) == (200, {"allow": False}))
        check("...and none of them reached validation", not seen)

        verdict["allow"] = False
        status, answer = await call(body, good_headers())
        check("a refused challenge is denied with 200", (status, answer) == (200, {"allow": False}))
        verdict["raise"] = True
        status, answer = await call(body, good_headers())
        check("an exception while validating is denied with 200, not raised",
              (status, answer) == (200, {"allow": False}))

        os.environ["SCEP_WEBHOOK_ID_FILE"] = str(workdir / "absent")
        verdict.update({"allow": True, "raise": False})
        status, answer = await call(body, good_headers())
        check("a missing id file denies everything", (status, answer) == (200, {"allow": False}))
    finally:
        enrollment_links.validate_and_consume = original
        os.environ.pop("SCEP_WEBHOOK_SECRET_FILE", None)
        os.environ.pop("SCEP_WEBHOOK_ID_FILE", None)

    check("the webhook app serves no docs or OpenAPI schema",
          wh.app.docs_url is None and wh.app.redoc_url is None and wh.app.openapi_url is None)


from tests._verify_harness import run  # noqa: E402

run(main)
