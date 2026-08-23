"""Verify NanoMDM webhook authentication: both HMAC and legacy query-secret schemes.

Run: PYTHONPATH=. .venv/bin/python tests/verify_webhook_auth.py
https://github.com/micromdm/nanomdm/blob/v0.9.0/service/webhook/service.go
https://github.com/micromdm/nanomdm/blob/v0.9.0/http/hashbody/hashbody.go
https://github.com/micromdm/nanomdm/blob/v0.9.0/cmd/nanomdm/main.go
"""
import base64
import hashlib
import hmac
import os
from pathlib import Path
from urllib.parse import urlencode

from starlette.requests import Request

import controller.api.webhook as wh

REPO = Path(__file__).resolve().parents[1]

PASS: list = []
FAIL: list = []


def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}: {name}")


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

    # And the other direction: once WEBHOOK_HMAC_KEY is set, WEBHOOK_SECRET is no longer the HMAC key, so the two
    # domains really are separate.
    env(WEBHOOK_SECRET="query-only-secret", WEBHOOK_HMAC_KEY="hmac-key")
    req = make_request(
        headers={"X-Hmac-Signature": sign("query-only-secret", BODY)})
    check("...and stops being the HMAC key once WEBHOOK_HMAC_KEY is set",
          wh._authorized(req, BODY) is None)

    print("\n== 2. The legacy query secret is still accepted ==")
    env(WEBHOOK_SECRET="query-only-secret", WEBHOOK_HMAC_KEY="hmac-key")
    req = make_request(query={"secret": "query-only-secret"})
    check("a valid query secret with no HMAC header is accepted",
          wh._authorized(req, BODY) == "query-secret")

    req = make_request(headers={"X-Webhook-Secret": "query-only-secret"})
    check("the header form of the same secret still works",
          wh._authorized(req, BODY) == "query-secret")

    # Dual accept means either credential, not both: a caller with a wrong HMAC and the right query secret is NanoMDM
    # mid-rollout, and refusing it is the fleet-wide outage this window avoids.
    req = make_request(query={"secret": "query-only-secret"},
                       headers={"X-Hmac-Signature": sign("wrong-key", BODY)})
    check("a wrong HMAC does not veto a valid query secret",
          wh._authorized(req, BODY) == "query-secret")

    # The reverse, which also settles which mode gets logged when only one of the two is right.
    req = make_request(query={"secret": "not-the-secret"},
                       headers={"X-Hmac-Signature": sign("hmac-key", BODY)})
    check("a valid HMAC is accepted alongside a wrong query secret",
          wh._authorized(req, BODY) == "body-hmac")

    print("\n== 3. Neither, and each one wrong ==")
    env(WEBHOOK_SECRET="query-only-secret", WEBHOOK_HMAC_KEY="hmac-key")
    check("no credential at all is refused",
          wh._authorized(make_request(), BODY) is None)

    req = make_request(headers={"X-Hmac-Signature": sign("wrong-key", BODY)})
    check("a wrong HMAC with no query secret is refused",
          wh._authorized(req, BODY) is None)

    req = make_request(query={"secret": "not-the-secret"})
    check("a wrong query secret is refused",
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
    for label, value in (("a non-ASCII character", "é"),
                         ("an emoji", "\U0001f600"),
                         ("a replacement character", "�")):
        check(f"a query secret carrying {label} is refused, not raised",
              wh._authorized(make_request(query={"secret": value}), BODY)
              is None)

    # Straight at the comparator with a lone surrogate, which no decode path produces but must not raise either.
    check("the comparator survives a lone surrogate on either side",
          wh.constant_time_eq("\udce9", "abc") is False
          and wh.constant_time_eq("abc", "\udce9") is False)

    # The configured side reaches the same comparison and nothing validates what an operator puts in .env, so a
    # non-ASCII secret has to work rather than merely not raise.
    env(WEBHOOK_SECRET="sécret", WEBHOOK_HMAC_KEY="kéy")
    check("a non-ASCII configured secret still matches itself",
          wh._authorized(make_request(query={"secret": "sécret"}), BODY)
          == "query-secret")
    check("...and a non-ASCII configured HMAC key still verifies",
          wh._authorized(
              make_request(headers={"X-Hmac-Signature": sign("kéy", BODY)}),
              BODY) == "body-hmac")
    check("...while a neighbouring non-ASCII value is refused",
          wh._authorized(make_request(query={"secret": "sècret"}), BODY)
          is None)

    print("\n== 4. No key configured fails closed ==")
    env()
    check("with neither variable set, a plausible HMAC is refused",
          wh._authorized(
              make_request(headers={"X-Hmac-Signature": sign("", BODY)}),
              BODY) is None)
    check("...and so is an empty query secret matching an empty setting",
          wh._authorized(make_request(query={"secret": ""}), BODY) is None)
    check("verify_body_hmac itself refuses on an empty key",
          wh.verify_body_hmac(BODY, sign("", BODY)) is False)

    # Only the HMAC key set: the HMAC works and the query path has nothing to compare against.
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
    env(WEBHOOK_SECRET="first-secret")
    before = wh._authorized(make_request(query={"secret": "first-secret"}), BODY)
    env(WEBHOOK_SECRET="second-secret")
    after_old = wh._authorized(make_request(query={"secret": "first-secret"}), BODY)
    after_new = wh._authorized(make_request(query={"secret": "second-secret"}), BODY)
    check("a secret set after import is honoured", before == "query-secret")
    check("a rotated secret takes effect without a re-import",
          after_old is None and after_new == "query-secret")

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

    class Capture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records = []

        def emit(self, record):
            self.records.append(record)

    handler = Capture()
    wh.logger.addHandler(handler)
    try:
        env(WEBHOOK_SECRET="s", WEBHOOK_HMAC_KEY="k")
        wh.log_auth_modes()
        both = handler.records[-1].getMessage()
        check("with both set, the boot line names both",
              "body HMAC" in both and "query secret" in both
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

    print(f"\nRESULT: {'PASS' if not FAIL else 'FAIL'} "
          f"({len(PASS)} passed, {len(FAIL)} failed)")
    if FAIL:
        raise SystemExit(1)


from tests._verify_harness import run  # noqa: E402

run(main)
