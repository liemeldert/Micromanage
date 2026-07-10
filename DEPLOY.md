# Deploying MicromanageIAC (Portainer / Docker Compose)

A fully compose-based deployment -- no `setup.sh`. The stack pulls prebuilt images
from GHCR and uploads the APNs push cert from environment variables; TLS is
terminated by your reverse proxy (§6). Use [`docker-compose.prod.yml`](docker-compose.prod.yml)
and the variables from [`.env.prod.example`](.env.prod.example).

## 1. Prerequisites

- A DNS record for `MDM_HOSTNAME` pointing at the server.
- These host ports reachable by your devices: `443` (MDM), `8001` (app manifests +
  enrollment download), `9443` (step-ca SCEP). The web UI (`3000`) only needs to be
  reachable by admins. Postgres and the NanoMDM management API are never exposed.
- Images: this repo's GitHub Action publishes `…-controller` and `…-webui` to GHCR.
  If the packages are **private**, add your GHCR registry credentials in Portainer
  (Registries → add `ghcr.io` with a PAT that has `read:packages`), or make the
  packages public in your GitHub repo's package settings.

## 2. Generate secrets

```sh
openssl rand -hex 32   # run once each for DB_PASSWORD, NANOMDM_API_KEY, JWT_SECRET, WEBHOOK_SECRET
```

## 3. Get the APNs push certificate (the one manual Apple step)

Apple requires a push certificate; this can't be fully automated. Get one via
[mdmcert.download](https://mdmcert.download) or
[identity.apple.com/pushcert](https://identity.apple.com/pushcert), then base64 the
PEM files and set them as env vars -- the `apns-init` service uploads them on deploy:

```sh
base64 -w0 MDM_Certificate.pem   # -> PUSH_CERT_PEM_B64
base64 -w0 push.key              # -> PUSH_KEY_PEM_B64
```

Set `MDM_TOPIC` to the topic embedded in that cert (`com.apple.mgmt.External.<uuid>`).
You can leave the APNs vars blank to bring the stack up first and add push later.

## 4. Deploy in Portainer

**Stacks → Add stack**, then either:

- **From this Git repo** -- set the compose path to `docker-compose.prod.yml`, or
- **Web editor** -- paste the contents of `docker-compose.prod.yml` (it uses named
  volumes only, so the editor works without the repo on disk).

Under **Environment variables**, add the values from `.env.prod.example`. At minimum:
`DB_PASSWORD`, `NANOMDM_API_KEY`, `JWT_SECRET`, `WEBHOOK_SECRET`, `MDM_HOSTNAME`,
`PUBLIC_API_URL`, and (recommended for first login) `CONTROLLER_BOOTSTRAP_ADMIN_EMAIL`
+ `CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD`. Set `CONTROLLER_IMAGE` / `WEBUI_IMAGE` if
your GHCR path differs from the defaults.

Deploy the stack. On first boot: step-ca initialises its CA, the controller creates
the bootstrap admin, and `apns-init` uploads the push cert (if provided).

## 5. First login & enrollment

- Open `http://<server>:3000`, sign in with the bootstrap admin. Then create real
  users under **Settings/Users** (or the CLI below) and clear the bootstrap vars and
  redeploy.
- Go to **Enrollment** to view the auto-generated profile, download it, or scan the
  QR to enroll a device. It will flag any missing config (`MDM_TOPIC`,
  `SCEP_CHALLENGE`, …).

Provision users without the bootstrap vars:

```sh
docker compose -f docker-compose.prod.yml exec controller \
  python -m controller.tenant_cli user add default you@example.com --role admin --password '...'
```

## 6. Production topology (TLS + SCEP)

Apple requires **HTTPS** for every device-facing endpoint. Every service here serves
**plain HTTP** (NanoMDM included -- it has no built-in TLS), so put a **TLS-terminating
reverse proxy** (Traefik/Caddy/nginx/NPM) in front and route your public hostname to:

| Public path/host | Internal target |
| --- | --- |
| MDM endpoint (`/mdm`, `/checkin`) | `nanomdm:9000` (plain HTTP -- proxy passes headers through) |
| App manifests + enrollment (`/api/...`) | `controller:8001` |
| SCEP (`/scep/...`) | `step-ca:9000` |
| Admin web UI | `webui:3000` |

No client-cert / mTLS config is needed at the proxy: the enrollment profile sets
`SignMessage=true`, so each device signs its check-ins and NanoMDM reads the identity
cert from the `Mdm-Signature` header, validating it against step-ca's CA (wired via
`-ca`/`-intermediate`). Just forward the request headers (proxies do by default).

Then set `PUBLIC_API_URL`, `MDM_SERVER_URL`, and `SCEP_URL` to those **public HTTPS**
URLs.

**SCEP provisioner:** created automatically on step-ca's first boot from `SCEP_NAME`
/ `SCEP_CHALLENGE` (step-ca also initialises an RSA CA chain, which SCEP requires). No
manual step. To change the challenge later, run:

```sh
docker compose -f docker-compose.prod.yml exec step-ca \
  step ca provisioner update mdm_device_scep --challenge "$NEW_CHALLENGE"
# then restart step-ca, and update SCEP_CHALLENGE in the controller env to match
```

The Enrollment page shows exactly which of these values are still missing.

## Image tags

The GitHub Action publishes:

| Trigger | Tags |
| --- | --- |
| push to default branch | `:dev`, `:sha-<commit>` |
| published release | `:stable`, `:latest`, `:<version>`, `:<major>.<minor>` |

Pin `CONTROLLER_IMAGE` / `WEBUI_IMAGE` to `:stable` for production or `:dev` to track latest.
