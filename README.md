# MicromanageIAC
***MicromanageIAC*** *is a simple IAC controller layer for Apple MDM.*

## What does MicromanageIAC do?
* Provides a simple YAML interface for defining the state of a device.
* Polls managed devices for their state, and attempts to reconcile the state of the device with the desired state defined in the YAML.
* Provides a CLI, a REST API, and a web UI for managing devices, groups, apps, configuration profiles, and device enrollment (with a QR code).

## What doesn't MicromanageIAC do?
* MicromanageIAC is just the controller layer of Micromanage.
* It relies on NanoMDM for the Apple MDM protocol and step-ca for SCEP/PKI.
* MicromanageIAC is intended to only contain a single tenant
  * Internal mentions to tenants should be thought more as locations, where you want some degree of isolation, but are safe sharing PKI and MDM servers.

## Examples

```yaml
groups:
  - name: "all-devices"
    description: "All enrolled devices"
    conditions:
      - type: "device_model"
        operator: "regex"
        value: ".*"  # Matches any model
  
  - name: "macbooks"
    description: "All MacBook devices"
    conditions:
      - type: "device_model"
        operator: "regex"
        value: "^MacBook.*"
  
  - name: "ipads"
    description: "All iPad devices"
    conditions:
      - type: "device_model"
        operator: "regex"
        value: "^iPad.*"
  
  - name: "engineering"
    description: "Engineering department devices"
    conditions:
      - type: "hostname"
        operator: "regex"
        value: "^eng-.*"
  
  - name: "newer-macos"
    description: "Devices running macOS 13 or newer"
    conditions:
      - type: "device_model"
        operator: "regex"
        value: "^Mac.*"
      - type: "os_version"
        operator: "gte"
        value: "13.0"
  
  - name: "test-devices"
    description: "Specific test devices"
    conditions:
      - type: "serial_number"
        operator: "in"
        value:
          - "C02TEST00001"
          - "C02TEST00002"
          - "C02TEST00003"
```

## Running it

* **Local / dev:** `docker compose -f docker-compose.yml -f docker-compose.dev.yml up` (or `./setup.sh dev`).
* **Server / Portainer (prod):** see [DEPLOY.md](DEPLOY.md) — a fully compose-based stack
  ([`docker-compose.prod.yml`](docker-compose.prod.yml)) that pulls images from GHCR,
  generates its TLS cert, and uploads the APNs push cert from environment variables.

Container images are published to GHCR by [`.github/workflows/build-publish.yml`](.github/workflows/build-publish.yml):
`:dev` on every push to the default branch, and `:stable` / `:latest` / `:<version>` on each GitHub release.
