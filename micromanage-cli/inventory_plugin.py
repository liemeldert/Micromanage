#!/usr/bin/env python3
"""Ansible dynamic inventory script for Micromanage.

Reads the controller's inventory endpoint with a service token.
Supports --list and --host <host>; hosts are named by serial number.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def main():
    parser = argparse.ArgumentParser(description="Micromanage Ansible Dynamic Inventory")
    parser.add_argument("--list", action="store_true", help="List all hosts")
    parser.add_argument("--host", type=str, help="Get all variables for a host")
    args = parser.parse_args()

    base_url = os.environ.get("MICROMANAGE_URL", "http://localhost:8001").rstrip("/")
    token = os.environ.get("MICROMANAGE_SERVICE_TOKEN")
    if not token:
        print("MICROMANAGE_SERVICE_TOKEN environment variable is required", file=sys.stderr)
        sys.exit(1)

    url = f"{base_url}/api/v1/integrations/ansible/inventory"
    if args.host:
        url = f"{url}?host={urllib.parse.quote(args.host)}"

    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req) as resp:
            data = resp.read()
            parsed = json.loads(data.decode("utf-8"))
            print(json.dumps(parsed, indent=2))
    except urllib.error.HTTPError as exc:
        print(f"HTTP error {exc.code}: {exc.read().decode('utf-8', errors='replace')}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"Error querying inventory: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
