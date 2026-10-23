# Deploying Micromanage (Portainer / Docker Compose)

This is for a fully compose-based deployment, which is my preference. The stack pulls prebuilt images from GHCR and
uploads the APNs push cert from environment variables. TLS is handled by your own reverse proxy. You want
[`docker-compose.prod.yml`](docker-compose.prod.yml) and the variables from [`.env.example`](.env.example).

The deployment resulting from `./setup.sh dev` exists mostly for development and testing on my part, so I wouldn't
recommend using that for anything important.

While I have attempted to provide reasonable defaults, you should review the compose file and environments first, and
decide whether they suit your environment. The compose file is intended to be a starting point,
and you should modify it as needed, especially regarding SCEP.

## Quickstart

Micromanage includes a shell script that can get the server up and running quickly.
However, you need two things to enroll. You will need a APNs push certificate from Apple (see section 3), and a domain
publicly trusted TLS in front of port 443 (see section 1). Request the certificate first, as the signing email takes
time.

```sh
git clone https://github.com/liemeldert/Micromanage.git micromanage && cd micromanage
./setup.sh env
```

`setup.sh env` asks for the MDM hostname, the first admin email and a password (press enter to generate one). Then set
`SCEP_URL=https://<hostname>:9443/scep/mdm_device_scep` and uncomment `MDM_EMBED_CA_CERT_PATH=/stepca-certs/root_ca.crt`
in `.env`, and leave `MDM_TOPIC` empty. Put the proxy in front of the stack: `/mdm` goes to `nanomdm-front` and
everything under `PUBLIC_API_URL` goes to the controller on port 8001.

```sh
docker compose -f docker-compose.prod.yml up -d
curl -fsS http://127.0.0.1:8001/api/v1/health
```

The published images are linux/amd64 only, so on an arm64 host set `platform: linux/amd64` on `yaml-init`, `controller`
and `webui` in a `compose.override.yml`. Port 9000 must be free on the host, since NanoMDM publishes 127.0.0.1:9000.
Wait until the services are healthy, then sign in at `http://<server>:3000` as the admin (the tenant is `default`) and
clear `CONTROLLER_BOOTSTRAP_ADMIN_EMAIL` and `CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD` in `.env`. With the certificate files
in `certs/apns/`, upload them and recreate the controller so it reads the new topic:

```sh
./setup.sh push-cert
docker compose -f docker-compose.prod.yml up -d --force-recreate --no-deps controller
```

Until then the Enrollment page lists `MDM_TOPIC` as missing and the profile download returns 503. Once it lists
nothing, create an enrollment link under Enrollment and open it on the device, then install the downloaded profile in
the device's settings. The device appears under Devices after its first check-in.

## 1. Prerequisites

- A DNS record for `MDM_HOSTNAME` pointing at the server.
- These ports reachable by your devices: `443` (MDM), `8001` (app manifests and the enrollment download), `9443`
  (SCEP, through `scep-front`). The web UI is on `3000` by default, but does not *need* to be client-device-accessible.

SCEP is served by `scep-front` on port 9443, not on 443. Set `SCEP_URL=https://MDM_HOSTNAME:9443/scep/SCEP_NAME` in
`.env` (with your values for both names), or have your proxy route `/scep/SCEP_NAME` to `scep-front` and keep the
default. `scep-front` presents a certificate from the stack's private CA, so also set
`MDM_EMBED_CA_CERT_PATH=/stepca-certs/root_ca.crt`, which puts that root in every enrollment profile for devices to
trust. Only a proxy that presents a publicly trusted certificate for SCEP makes this unnecessary.
- APN certificate (Be it through Apple or another means)
- Devices to enroll (of course)
- Patience (A virtue, I hear)

If a TLS proxy sits in front of port `8001`, set `FORWARDED_ALLOW_IPS` to the proxy's address as the controller sees it
(its address on the compose network, for a proxy container). The controller then takes the client address from
`X-Forwarded-For`, so the enrollment rate limits and logs see each device instead of the proxy. Without it every request
appears to come from the proxy and shares one rate limit. The sign-in throttle also keys on the client address, so
behind an unlisted proxy a lock earned by one client holds for every client sharing the proxy.
The proxy in front of the web UI must send `X-Forwarded-Proto`, or the session cookie is set without the Secure flag.

## 2. Generate secrets

```sh
./setup.sh env
```

**OR:**

```sh
openssl rand -hex 32   # run once each for secret needed, then set them in .env
```

Optionally, you can generate secrets for `WEBHOOK_HMAC_KEY` and `DDM_HMAC_SECRET`. They are just `WEBHOOK_SECRET`
by default, but if you want to rotate them independently, generate them too. Setup.sh generates them as well.

## 3. Acquire an APNs push certificate

APNs push certificates require an MDM vendor CSR, which is only issued on request.
However, [MacTechs](http://www.mactechs.com/)
provides a service, [mdmcert.download](https://mdmcert.download) that will issue push certificates to legally recognized
businesses, institutions, and organizations, as stipulated by Apple's terms. I have no affiliation to this project, so
make sure you are authorized to use this service by its terms. Since I too have a vendor CSR, I may eventually provide a
similar service as well.

The implementation of this was pulled from MicroMDM.

First, you must register on [mdmcert.download](https://mdmcert.download), then run these two commands:

```sh
./setup.sh apns request you@example.com
# ...check your email
./setup.sh apns decrypt ~/Downloads/mdm_signed_request.*.plist.b64.p7
```

That provides `certs/apns/push.req`. Upload it at [identity.apple.com/pushcert](https://identity.apple.com/pushcert)
("Create a Certificate"), download the certificate Apple gives back, and save it as `certs/apns/MDM_Certificate.pem`.
Then either run `./setup.sh push-cert` (it uploads to NanoMDM and writes `MDM_TOPIC` into `.env` for you)
or base64 the PEM files and set them as env vars so `apns-init` uploads them on deploy:

```sh
base64 < certs/apns/MDM_Certificate.pem | tr -d '\n'
base64 < certs/apns/push.key             | tr -d '\n'
```

Set `MDM_TOPIC` to the topic embedded in the certificate
(`openssl x509 -in certs/apns/MDM_Certificate.pem -noout -subject` shows it as `UID=com.apple.mgmt.External.<uuid>`).
You can leave the APNs vars blank to get the stack up first and add push later. However, you cannot issue commands to
devices without that certificate. It's also something I haven't tested.

## 4. Deploy stack

- First, review .env.example and your .env file to make sure you didn't miss anything.
- Then, deploy docker-compose.prod.yml
- On first boot, step-ca initialises its CA, the controller creates a bootstrap admin account, and `apns-init`
  uploads the push cert if you gave it one.
- On every boot, step-ca attaches the controller's challenge webhook to the SCEP provisioner, so each enrollment
  profile carries its own one-time challenge. There is no shared SCEP challenge to set.
- step-ca itself publishes no port. `scep-front` serves its TLS on `STEPCA_PORT` (9443) and passes on only
  `/scep/<SCEP_NAME>`; everything else returns 404. Its certificate is issued by step-ca for 397 days. step-ca checks
  it at boot and once a day, and re-issues it when under 30 days remain, when `MDM_HOSTNAME` changes or when it no
  longer chains to the CA's root. `scep-front` reloads nginx every 6 hours to pick up a new certificate; to load it at
  once, run `docker compose -f docker-compose.prod.yml restart scep-front`.
- If the `step_ca_data` volume is lost, step-ca initialises a new CA and enrolled devices no longer chain to it;
  restoring that volume from a backup is how existing devices keep working. After a new CA is initialized, run
  `docker compose -f docker-compose.prod.yml restart scep-front nanomdm` so both load its certificates.

```sh
docker compose -f docker-compose.prod.yml exec controller \
  python -m controller.tenant_cli user add default you@example.com --role admin --password '...'
```

### NanoMDM storage cleanup requirement

NanoMDM must be run with the `delete=1` storage option enabled (command line flag `-storage-options delete=1`, as in
`docker-compose.prod.yml`). When enabled, NanoMDM deletes completed command rows from the `command_results` table once
acknowledged, so raw command responses (which may contain sensitive data such as Activation Lock bypass codes) do not
linger in the database.

At startup the controller queries NanoMDM's database read-only:

```sql
SELECT count(*) FROM command_results WHERE status <> 'NotNow' AND created_at > NOW() - INTERVAL '1 hour'
```

If NanoMDM retained completed command results in the last hour, the controller logs a warning that the `delete=1`
storage option may not be active.

## 5. First login and enrollment

- Open `http://<server>:3000` and sign in as the account from before.
- Then, create the actual users under **Settings/Users**
- Go to **Enrollment** to see the auto-generated enrollment profile
- It also provides warnings if you missed anything.

## 6. Enrollment profile signing

By default, over-the-air enrollment `.mobileconfig` profiles are served unsigned. To have devices show the profile as
verified, import a signing identity whose certificate chains to a root the devices trust, such as a certificate issued
by Apple:

- In Keychain Access, select the certificate together with its private key and choose Export to save a `.p12`.
- Upload the `.p12` and its password on the **Enrollment profile signing** card under **Settings**, adding the
  intermediate `.cer` files for the issuing CA if the `.p12` does not include them. The API equivalent is
  `POST /api/v1/tenant/profile-signing` with `p12_b64`, `password` and `intermediates_b64`. Both are admin only.
- The import is refused when the `.p12` cannot be opened with the password (leave it blank if none was set), holds no
  private key, uses an RSA key under 2048 bits or an EC curve other than P-256, P-384 or P-521, or holds a certificate
  that lacks the digitalSignature key usage, has expired or is not valid yet. An intermediate must be a `.cer` CA
  certificate; a copy of the signing certificate among them is ignored. Each file is limited to 64 KB, with at most
  five intermediates. The password is used to open the file and is not stored.
- The private key is encrypted at rest and bound to the tenant. It is never returned by the API.
- The certificate's expiry is recorded and shown on the card.
- A device shows the profile as verified only when the certificate chains to a root the device trusts.
- If the certificate has expired, or the stored key no longer decrypts, the controller serves the profile unsigned
  and logs it. The settings card shows either condition as Not signing, and warns 30 days before expiry.
- `DELETE /api/v1/tenant/profile-signing`, or **Remove certificate** on the card, returns to unsigned profiles.

## 7. Service tokens and Ansible inventory

For automated fleet tooling such as Ansible:

- Admins generate scoped service tokens via the API (`POST /api/v1/service-tokens`).
- Service tokens always use the prefix `mm_st_` followed by 32 bytes in hex, so secret scanning tools can identify them.
- Plaintext tokens are displayed only once upon creation; only SHA-256 digests are stored in `token_hash`.
- Tokens require an expiration (`expires_at`) and support immediate revocation via `revoked_at`.
- Token usage audit logs (`service_token.used`) are throttled to at most once per 24 hours per token.
- Scopes are validated when a token is created. The only scope today is `inventory:read`.
- The Ansible dynamic inventory endpoint (`/api/v1/integrations/ansible/inventory`) requires a service token with
  scope `inventory:read` and refuses user session tokens.
- The inventory lists enrolled devices only. Each host name is the device serial number, and `ansible_host` carries
  the device hostname or its Tailscale IP. Groups are prefixed `platform_`, `tag_` and `group_`.
- Dynamic inventory can be queried directly via HTTP or by using the CLI plugin `micromanage-cli/inventory_plugin.py`.

## 8. Backups

Back up Postgres and the `step_ca_data` volume together, since enrolled devices chain to the CA in `step_ca_data` and a
new CA means re-enrolling them.

```sh
docker compose -f docker-compose.prod.yml exec -T postgres pg_dumpall -U postgres --clean --if-exists \
  > micromanage-postgres.sql
docker compose -f docker-compose.prod.yml stop step-ca
docker run --rm --volumes-from "$(docker compose -f docker-compose.prod.yml ps -aq step-ca)" -v "$PWD":/backup \
  alpine tar czf /backup/step_ca_data.tgz -C /home/step .
docker compose -f docker-compose.prod.yml start step-ca
```

To restore, load both into fresh volumes. `PROJECT` is the compose project name, which `docker volume ls` shows as the
prefix of the volume names.

```sh
docker compose -f docker-compose.prod.yml down
docker volume rm PROJECT_postgres_data PROJECT_step_ca_data
docker compose -f docker-compose.prod.yml create step-ca
docker run --rm --volumes-from "$(docker compose -f docker-compose.prod.yml ps -aq step-ca)" -v "$PWD":/backup \
  alpine tar xzf /backup/step_ca_data.tgz -C /home/step
docker compose -f docker-compose.prod.yml up -d postgres
```

Wait for `postgres` to report healthy, then load the dump and start the rest of the stack:

```sh
docker compose -f docker-compose.prod.yml exec -T postgres psql -U postgres -d postgres < micromanage-postgres.sql
docker compose -f docker-compose.prod.yml up -d
```
