# Deploying Micromanage (Portainer / Docker Compose)

This is for a fully compose-based deployment, which is my preference. The stack pulls prebuilt images from GHCR and
uploads the APNs push cert from environment variables. TLS is handled by your own reverse proxy (see section 6). You
want
[`docker-compose.prod.yml`](docker-compose.prod.yml) and the variables from
[`.env.example`](.env.example).

The deployment resulting from `./setup.sh dev` exists mostly for development and testing on my part, so I wouldn't
recommend using that for anything important.

While I have attempted to provide a reasonable defaults, you should review the compose file and environments first, and
determine if what it is doing is appropriate for your environment. The compose file is intended to be a starting point,
and you should modify it as needed, especially regarding SCEP.

## 1. Prerequisites

- A DNS record for `MDM_HOSTNAME` pointing at the server.
- These ports reachable by your devices: `443` (MDM), `8001` (app manifests and the enrollment download), `9443`
  (step-ca SCEP). The web UI is on `3000` by default, but does not *need* to be client-device-accessible.
- APN certificate (Be it through apple or another means)
- Devices to enroll (of course)
- Patience (A virtue, I hear)

## 2. Generate secrets

```sh
./setup.sh env`
```

**OR:**

```sh
openssl rand -hex 32   # run once each for secret needed, then set them in .env
```

Optionally, you can generate secrets for `WEBHOOK_HMAC_KEY` and `DDM_HMAC_SECRET`. They are just `WEBHOOK_SECRET`
by default, but if you want to rotate them independently, generate them too. Setup.sh generates them as well.

## 3. Acquire an APNs push certificate

APNs push certificates require a MDM vendor CSR, which are only issued on request.
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
("Create a Certificate"), download the certificate Apple gives back, and save it as `certs/apns/MDM_Certificate.pem`
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

- First, before doing anything else, review .env.example and your .env file to make sure you didn't miss anything.
- Then, deploy docker-compose.prod.yml
- On first boot, step-ca initialises its CA, the controller creates a bootstrap admin account, and `apns-init`
  uploads the push cert if you gave it one.
-

```sh
docker compose -f docker-compose.prod.yml exec controller \
  python -m controller.tenant_cli user add default you@example.com --role admin --password '...'
```

## 5. First login and enrollment

- Open `http://<server>:3000` and sign in as the account from before.
- Then, create the actual users under **Settings/Users**
- Go to **Enrollment** to see the auto-generated enrollment profile
- It also provides warnings if you missed anything.
