# Deploying Micromanage (Portainer / Docker Compose)

This is for a fully compose-based deployment, which is my preference. The stack pulls prebuilt images from GHCR and
uploads the APNs push cert from environment variables. TLS is handled by your own reverse proxy. You want
[`docker-compose.prod.yml`](docker-compose.prod.yml) and the variables from [`.env.example`](.env.example).

The deployment resulting from `./setup.sh dev` exists mostly for development and testing on my part, so I wouldn't
recommend using that for anything important.

While I have attempted to provide reasonable defaults, you should review the compose file and environments first, and
decide whether they suit your environment. The compose file is intended to be a starting point,
and you should modify it as needed, especially regarding SCEP.

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

## 8. Upgrading to per-enrollment SCEP challenges

This release replaces the shared `SCEP_CHALLENGE` with a one-time challenge per enrollment profile, checked by the
controller through a step-ca webhook.

Back up first. The step-ca and controller changes below cannot be undone without these backups.

```sh
docker compose -f docker-compose.prod.yml exec -T postgres pg_dumpall -U postgres --clean --if-exists \
  > micromanage-postgres.sql
docker compose -f docker-compose.prod.yml stop step-ca
docker run --rm --volumes-from "$(docker compose -f docker-compose.prod.yml ps -aq step-ca)" -v "$PWD":/backup \
  alpine tar czf /backup/step_ca_data.tgz -C /home/step .
```

Update the checkout (`git pull`), so the new `docker-compose.prod.yml` and `deploy/scep-front.conf.template` are on
disk. Without the template, `scep-front` starts with nothing on 9443 and its healthcheck reports it unhealthy. Then
upgrade:

```sh
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
docker compose -f docker-compose.prod.yml logs -f step-ca | grep 'step-ca:'
```

The admin setup waits for the CA to answer, so give it up to three minutes. Stop following the log once it prints
"webhook verified on <SCEP_NAME>".

What the first boot does:

- Before the CA starts, step-ca mints the `scep-front` certificate and copies the CA certificates into the new
  `stepca_certs` volume, which NanoMDM reads instead of step-ca's own volume.
- step-ca turns on its admin API. This moves the provisioners from `ca.json` into step-ca's database, once, keeping
  `ca.json.pre-admin.bak` next to it, and replaces the SCEP challenge in `ca.json` with a random value. The admin API
  must stay enabled from then on, because `ca.json` no longer holds the CA's provisioners. The controller's first boot
  changes its database one way as well, so going back to an older release means restoring both backups,
  `step_ca_data` and Postgres, as shown below.
- It rotates the old static challenge to a random discarded value, removes every ACME provisioner, installs a
  client-only certificate template on the SCEP provisioner and attaches the webhook. Each step logs a line; a line
  containing `ERROR` names the step that failed. With ACME removed from the CA, any ACME client pointed at step-ca
  stops working.

From then on, anything built before the upgrade fails at SCEP and has to be redone:

- Enrollment profiles downloaded or printed before the upgrade. Download a new one from **Enrollment**.
- Return to Service erases queued before the upgrade. Send them again.
- ADE enrollments that were partway through Setup Assistant. Start them again.

Enrolled devices keep working. The controller moves their identity certificates onto the new scheme in daily batches,
and readiness shows how many are left; after that, each certificate is renewed `IDENTITY_RENEW_DAYS` (30) days before
it expires. ADE profiles need no re-push.

In `.env`:

- Delete `SCEP_CHALLENGE`, `MDM_ALLOW_UNSIGNED_TENANT_CLAIM` and `MDM_REQUIRE_SIGNED_TENANT_CLAIM`. Nothing reads
  them any more.
- Leave `DEP_ADE_REQUIRE_APPLE_SIGNATURE` unset; it defaults to `true`. With it on, a device wiped without checking
  out can re-enroll through ADE; with it off, an admin has to allow that device's re-enrollment first.
- If the check refuses a genuine device over its signer's issuer, which the controller log names, add that issuer to
  `DEP_APPLE_DEVICE_CA_NAMES` rather than turning the check off.

If your own proxy sits in front of port 9443, it now reaches `scep-front` instead of step-ca, and only the SCEP path
answers.

To roll back, check out the previous release, then restore both backups into fresh volumes. `PROJECT` is the compose
project name, which `docker volume ls` shows as the prefix of the volume names.

```sh
docker compose -f docker-compose.prod.yml down
docker volume rm PROJECT_postgres_data PROJECT_step_ca_data
docker compose -f docker-compose.prod.yml create step-ca
docker run --rm --volumes-from "$(docker compose -f docker-compose.prod.yml ps -aq step-ca)" -v "$PWD":/backup \
  alpine tar xzf /backup/step_ca_data.tgz -C /home/step
docker compose -f docker-compose.prod.yml up -d postgres
docker compose -f docker-compose.prod.yml exec -T postgres psql -U postgres -d postgres < micromanage-postgres.sql
docker compose -f docker-compose.prod.yml up -d
```

Wait for `postgres` to report healthy before loading the dump.
