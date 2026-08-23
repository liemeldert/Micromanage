"""Container healthcheck for the controller image.

The image runs three supervisord programs. supervisord keeps the container up
when one of them has crashed. Specifically, it queries:

  userapi   GET http://127.0.0.1:8001/api/v1/health   (+ DB)
  webhook   GET http://127.0.0.1:8000/health          (+ DB)
  controller  mtime of the heartbeat file it touches every 30 sec

The scheduler's heartbeat also can detect a dead controller process, which is why the heartbeat file is used
Only sends exit 3 on consensus

Used by Dockerfile.controller
"""
import os
import sys
import time
import urllib.request

HEARTBEAT_FILE = os.getenv("MDM_CONTROLLER_HEARTBEAT_FILE", "/tmp/micromanage-controller.heartbeat")
# 4 heartbaet intervals
HEARTBEAT_MAX_AGE = int(os.getenv("MDM_CONTROLLER_HEARTBEAT_SECONDS", "30")) * 4
TIMEOUT = 5


def http_ok(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:  # noqa: BLE001
        print(f"{url}: {exc}", file=sys.stderr)
        return False


def heartbeat_ok(path: str) -> bool:
    try:
        age = time.time() - os.stat(path).st_mtime
    except OSError as exc:
        print(f"{path}: {exc}", file=sys.stderr)
        return False
    if age > HEARTBEAT_MAX_AGE:
        print(f"{path}: last touched {int(age)}s ago", file=sys.stderr)
        return False
    return True


def main() -> int:
    ok = http_ok("http://127.0.0.1:8001/api/v1/health")
    ok = http_ok("http://127.0.0.1:8000/health") and ok
    ok = heartbeat_ok(HEARTBEAT_FILE) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
