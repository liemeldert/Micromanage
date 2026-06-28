# MicromanageIAC
***MicromanageIAC*** *is a simple IAC controller layer for Apple MDM.*

## What does MicromanageIAC do?
* Provides a simple YAML interface for defining the state of a device.
* Polls managed devices for their state, and attempts to reconcile the state of the device with the desired state defined in the YAML.
* Provides a simple CLIa and REST API for managing devices.

## What doesn't MicromanageIAC do?
* MicromanageIAC is just the controller layer of Micromanage.
* It does not provide much to help set up Apple MDM.
* It does not provide a user interface, other than a CLI.
* Nor does it currently have a page for enrolling devices at the moment.
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
