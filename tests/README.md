# Micromanage tests

This contains all the tests for Micromanage.

They were written fast, since I really don't want to spend time writing tests.

Please don't use these as examples of my code quality.

## Layout

Suites are grouped by the part of the product they exercise. `_verify_harness.py` and `_seed_attrs.py` are shared and
stay at the top.

- `auth/`: tokens, MFA, sessions, login limiting, webhook authentication, security guards.
- `enrollment/`: enrollment links, profiles, attempts, DEP, per-enrollment identity and its renewal.
- `escrow/`: escrowed secrets (FileVault, activation lock, lock codes), clear passcode, account configuration.
- `flows/`: the flow editor, drafts, runs, permissions, warnings and variable naming.
- `devices/`: device endpoints, commands, DDM, deployment state, scoping, tags, task and webhook handlers.
- `compliance/`: the compliance catalog and the dispatcher.
- `platform/`: audit log, config versioning, readiness, retention, settings, tenant CLI, Ansible inventory.
- `postgres/`: schema checks that run against a real Postgres, with the NanoMDM schema they load.

Run one suite from the repo root with the repo on the Python path:

    PYTHONPATH=. python tests/<folder>/verify_X.py .
