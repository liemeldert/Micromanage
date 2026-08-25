#!/usr/bin/env bash
# Micromanage setup script
# Usage:
#   ./setup.sh -> interactive full setup (production-ish)
#   ./setup.sh dev -> development setup (no root, HMR, no real devices needed)
#   ./setup.sh env -> generate .env from .env.example
#   ./setup.sh apns request <email> -> generate push key + CSR and send the mdmcert.download request
#   ./setup.sh apns decrypt <.p7> -> decrypt the emailed reply into the request Apple wants
#   ./setup.sh push-cert -> upload Apple's push cert + key to running NanoMDM, set MDM_TOPIC
#   ./setup.sh tenant <id> -> create YAML configs for a new tenant
#   ./setup.sh up -> start all services

set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLU}[INFO]${NC}  $*"; }
ok()    { echo -e "${GRN}[OK]${NC}    $*"; }
warn()  { echo -e "${YEL}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERR]${NC}   $*" >&2; }
die()   { error "$*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

check_deps() {
  local missing=()
  for cmd in docker openssl; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    die "Missing required tools: ${missing[*]}"
  fi
}

_env_set() {
  local key="$1" val="$2"
  local esc; esc=$(printf '%s' "$val" | sed -e 's/[\\&|]/\\&/g')
  if grep -qE "^${key}=" .env; then
    sed -i.bak "s|^${key}=.*|${key}=${esc}|" .env && rm -f .env.bak
  elif grep -qE "^#[[:space:]]*${key}=" .env; then
    sed -i.bak "s|^#[[:space:]]*${key}=.*|${key}=${esc}|" .env && rm -f .env.bak
  else
    if [[ -n "$(tail -c1 .env)" ]]; then
      printf '\n' >> .env
    fi
    printf '%s=%s\n' "$key" "$val" >> .env
  fi
}

_gen_shared_secrets() {
  _env_set DDM_HMAC_SECRET   "$(openssl rand -hex 32)"
  _env_set WEBHOOK_HMAC_KEY  "$(openssl rand -hex 32)"
}

cmd_env() {
  if [[ -f .env ]]; then
    warn ".env already exists, skipping. Delete it first to regenerate."
    return
  fi
  cp .env.example .env

  # Generate random secrets in-place
  local db_pass; db_pass=$(openssl rand -hex 20)
  local api_key; api_key=$(openssl rand -hex 20)
  local jwt_sec; jwt_sec=$(openssl rand -hex 32)
  local wh_sec;  wh_sec=$(openssl rand -hex 32)
  local ca_pass; ca_pass=$(openssl rand -hex 20)
  local scep_ch; scep_ch=$(openssl rand -hex 20)

  sed -i.bak \
    -e "s/changeme_strong_password/${db_pass}/" \
    -e "s/changeme_random_api_key/${api_key}/" \
    -e "s/changeme_long_random_secret/${jwt_sec}/" \
    -e "s/changeme_webhook_secret/${wh_sec}/" \
    -e "s/changeme_stepca_password/${ca_pass}/" \
    -e "s/changeme_scep_challenge/${scep_ch}/" \
    .env && rm -f .env.bak
  _gen_shared_secrets

  echo
  read -rp "Enter your MDM public hostname (e.g. mdm.example.org): " hostname
  [[ -n "$hostname" ]] || die "A hostname is required."
  _env_set MDM_HOSTNAME "$hostname"
  _env_set PUBLIC_API_URL "https://${hostname}"
  sed -i.bak "s/mdm\.example\.com/${hostname}/g" .env && rm -f .env.bak

  local admin_email="" admin_pass=""
  echo
  read -rp "Email for the first admin account (blank to create one later with the CLI): " admin_email
  if [[ -n "$admin_email" ]]; then
    while :; do
      # -s so it is never echoed to the terminal or into scrollback
      read -rsp "Password for ${admin_email} (blank to generate one): " admin_pass; echo
      if [[ -z "$admin_pass" ]]; then
        admin_pass=$(openssl rand -base64 24 | tr -d '/+=')
        info "Generated a password. Read it once from .env (CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD), then delete them after you sign in."
        break
      fi
      if [[ "$admin_pass" == *'$'* ]]; then
        warn "Compose reads \$ in an env file as a variable reference. Choose another, or press enter to have one generated."
        continue
      fi
      break
    done
    _env_set CONTROLLER_BOOTSTRAP_ADMIN_EMAIL "$admin_email"
    _env_set CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD "$admin_pass"
    admin_pass=""
    warn "Clear both CONTROLLER_BOOTSTRAP_ADMIN_* values and redeploy once you have signed in and made real users."
  else
    info "No admin account has been made. Create one after the stack is up with:"
    echo "  docker compose -f docker-compose.prod.yml exec controller \\"
    echo "    python -m controller.tenant_cli user add default you@example.com --role admin"
  fi

  chmod 600 .env

  ok ".env created with random secrets, w/ mode 600"
  echo
  warn "Edit .env now if you need to configure S3 / object store for app packages."
}

MDMCERT_URL="https://mdmcert.download/api/v1/signrequest"
# The public API key MicroMDM and Commandment ship
MDMCERT_API_KEY="f847aea2ba06b41264d587b229e2712c89b1490a1208b7ff1aafab5bb40d47bc"

cmd_apns() {
  local sub="${1:-}"
  case "$sub" in
    request) shift; cmd_apns_request "$@" ;;
    decrypt) shift; cmd_apns_decrypt "$@" ;;
    *)
      echo "Usage:"
      echo "  ./setup.sh apns request <email>          step 1: generate keys + CSR and send the request"
      echo "  ./setup.sh apns decrypt <emailed .p7>    step 2: decrypt what mdmcert.download emailed you"
      echo "  Step 3: upload certs/apns/push.req at https://identity.apple.com/pushcert and save the certificate as certs/apns/MDM_Certificate.pem."
      echo "  ./setup.sh push-cert                     step 4: upload Apple's certificate to NanoMDM"
      echo

      [[ -z "$sub" ]] && exit 0 || die "unknown apns subcommand: $sub"
      ;;
  esac
}

cmd_apns_request() {
  local email="${1:-}"
  [[ -n "$email" ]] || die "usage: ./setup.sh apns request <email>"
  command -v curl &>/dev/null || die "curl is required"
  mkdir -p certs/apns

  for f in certs/apns/push.key certs/apns/push.csr certs/apns/pki.key certs/apns/pki.crt; do
    [[ -f "$f" ]] && die "$f already exists."
  done

  echo
  echo -e "${BLU}  APNs push certificate: request via mdmcert.download${NC}"
  echo

  info "Generating the push key and CSR"
  openssl req -new -newkey rsa:2048 -nodes \
    -keyout certs/apns/push.key -out certs/apns/push.csr \
    -subj "/C=US/CN=mdm-push/emailAddress=${email}" 2>/dev/null
  chmod 600 certs/apns/push.key
  ok "certs/apns/push.key and certs/apns/push.csr"

  # The throwaway PKI pair. mdmcert.download encrypts its reply to this
  # certificate; only its key can open the email you get.
  info "Generating the one-off exchange (pki) certificate the reply is encrypted to"
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout certs/apns/pki.key -out certs/apns/pki.crt \
    -subj "/CN=mdmcert.download" 2>/dev/null
  chmod 600 certs/apns/pki.key
  ok "certs/apns/pki.key and certs/apns/pki.crt"

  local body
  body=$(python3 - "$email" <<'PYJ'
import base64, json, sys
email = sys.argv[1]
csr = base64.b64encode(open("certs/apns/push.csr", "rb").read()).decode()
pki = base64.b64encode(open("certs/apns/pki.crt", "rb").read()).decode()
print(json.dumps({"csr": csr, "email": email,
                  "key": "f847aea2ba06b41264d587b229e2712c89b1490a1208b7ff1aafab5bb40d47bc",
                  "encrypt": pki}))
PYJ
)

  info "Sending the signing request to mdmcert.download"
  local resp
  resp=$(curl -sS -X POST -H "Content-Type: application/json" \
    -H "User-Agent: micromanage/setup" --data "$body" "$MDMCERT_URL") \
    || die "the request to mdmcert.download failed"
  if ! echo "$resp" | grep -q '"result"[[:space:]]*:[[:space:]]*"success"'; then
    die "mdmcert.download did not accept the request: $resp"
  fi
  ok "Request accepted."
  echo
  echo "Check the inbox for ${email}. mdmcert.download emails a file named like"
  echo "  mdm_signed_request.<timestamp>.plist.b64.p7"
  echo "Save it and run:"
  echo "  ./setup.sh apns decrypt ~/Downloads/mdm_signed_request.<timestamp>.plist.b64.p7"
}

cmd_apns_decrypt() {
  local p7="${1:-}"
  [[ -n "$p7" && -f "$p7" ]] || die "usage: ./setup.sh apns decrypt <path to the emailed .p7 file>"
  [[ -f certs/apns/pki.key && -f certs/apns/pki.crt ]] \
    || die "certs/apns/pki.key and pki.crt are missing; run './setup.sh apns request' first"
  [[ -f certs/apns/push.req ]] && die "certs/apns/push.req already exists; move it aside first"

  # The emailed file is hex text of a PKCS7 envelope encrypted to pki.crt.
  info "Decrypting the emailed request with certs/apns/pki.key"
  local tmp; tmp=$(mktemp)
  # `xxd -r -p` turns the hex text back into DER. Falls back to python if xxd is absent.
  if command -v xxd &>/dev/null; then
    tr -d ' \n\r' < "$p7" | xxd -r -p > "$tmp"
  else
    python3 -c "import sys,binascii; sys.stdout.buffer.write(binascii.unhexlify(open(sys.argv[1]).read().strip()))" "$p7" > "$tmp"
  fi
  openssl smime -decrypt -inform DER -in "$tmp" \
    -recip certs/apns/pki.crt -inkey certs/apns/pki.key \
    -out certs/apns/push.req || { rm -f "$tmp"; die "decryption failed. Is this the reply to the request made with the current certs/apns/pki.key?"; }
  rm -f "$tmp"
  ok "Decrypted push certificate request written to certs/apns/push.req"
  echo
  echo "Next, at Apple: sign in at https://identity.apple.com/pushcert, choose"
  echo "'Create a Certificate', upload certs/apns/push.req, and download the"
  echo "certificate Apple returns. Save it as certs/apns/MDM_Certificate.pem"
  echo "(convert if Apple hands you a .der: openssl x509 -inform DER -in MDM_*.der -out certs/apns/MDM_Certificate.pem)."
  echo "Then: ./setup.sh push-cert"
}

cmd_push_cert() {
  local cert_file="${1:-certs/apns/MDM_Certificate.pem}"
  local key_file="${2:-certs/apns/push.key}"

  [[ -f "$cert_file" ]] || die "Certificate not found: $cert_file. Run './setup.sh apns' first."
  [[ -f "$key_file" ]]  || die "Key not found: $key_file"

  # Load NanoMDM API key from .env
  local api_key
  api_key=$(grep -E '^NANOMDM_API_KEY=' .env 2>/dev/null | cut -d= -f2 | tr -d '"' || true)
  [[ -n "$api_key" ]] || die "NANOMDM_API_KEY not found in .env"

  info "Uploading APNs push certificate to NanoMDM..."
  local resp http_code body_file
  body_file=$(mktemp)
  http_code=$(curl -sS -o "$body_file" -w '%{http_code}' -u "nanomdm:${api_key}" \
    -X PUT \
    -H "Content-Type: text/plain" \
    --data-binary "$(cat "$cert_file")
$(cat "$key_file")" \
    http://localhost:9000/v1/pushcert) || { rm -f "$body_file"; die "could not reach NanoMDM on http://localhost:9000"; }
  resp=$(cat "$body_file")
  rm -f "$body_file"
  echo "$resp"

  [[ "$http_code" == 2* ]] || die "NanoMDM refused the push certificate (HTTP ${http_code}): ${resp}"

  echo
  ok "Push certificate uploaded. Check NanoMDM logs: docker compose -f docker-compose.prod.yml logs nanomdm"

  local topic="" not_after=""
  if command -v python3 &>/dev/null; then
    local parsed
    parsed=$(python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get("topic") or "")
    print(d.get("not_after") or "")
except Exception:
    print("")
    print("")
' <<<"$resp" 2>/dev/null || printf "\n\n")
    topic=$(sed -n '1p' <<<"$parsed")
    not_after=$(sed -n '2p' <<<"$parsed")
  fi

  if [[ -z "$topic" ]]; then
    topic=$(openssl x509 -in "$cert_file" -noout -subject -nameopt RFC2253 2>/dev/null \
      | grep -oE 'com\.apple\.mgmt\.[A-Za-z0-9._-]+' | head -1 || true)
    if [[ -z "$topic" ]]; then
      warn "Could not read a com.apple.mgmt.* topic from NanoMDM's response or from $cert_file; is this Apple's push certificate?"
    fi
  fi
  if [[ -z "$not_after" ]]; then
    not_after=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
  fi

  if [[ -n "$topic" ]]; then
    if grep -qE "^MDM_TOPIC=" .env; then
      sed -i.bak "s|^MDM_TOPIC=.*|MDM_TOPIC=${topic}|" .env && rm -f .env.bak
    else
      echo "MDM_TOPIC=${topic}" >> .env
    fi
    ok "MDM_TOPIC=${topic} written to .env"
    warn "Recreate the controller so it picks up the topic (a plain restart keeps old env):"
    echo "  docker compose -f docker-compose.prod.yml up -d --force-recreate --no-deps controller"
    echo "Devices enrolled before this carry no topic in their MDM payload; re-enroll them"
    echo "with a new profile so pushes can reach them."
  fi

  local cert_b64 key_b64
  cert_b64=$(base64 < "$cert_file" | tr -d '\n')
  key_b64=$(base64 < "$key_file" | tr -d '\n')
  if grep -qE "^PUSH_CERT_PEM_B64=" .env; then
    sed -i.bak "s|^PUSH_CERT_PEM_B64=.*|PUSH_CERT_PEM_B64=${cert_b64}|" .env && rm -f .env.bak
  else
    echo "PUSH_CERT_PEM_B64=${cert_b64}" >> .env
  fi
  if grep -qE "^PUSH_KEY_PEM_B64=" .env; then
    sed -i.bak "s|^PUSH_KEY_PEM_B64=.*|PUSH_KEY_PEM_B64=${key_b64}|" .env && rm -f .env.bak
  else
    echo "PUSH_KEY_PEM_B64=${key_b64}" >> .env
  fi

  chmod 600 .env
  ok "PUSH_CERT_PEM_B64/PUSH_KEY_PEM_B64 written to .env (backup copy of the cert material; .env is now chmod 600, since it holds the private key)"

  if [[ -n "$not_after" ]]; then
    echo
    warn "Certificate expires: ${not_after}"
    warn "Apple ties renewal to the Apple Account that created the cert."
  fi
}

cmd_tenant() {
  local tenant_id="${1:-}"
  if [[ -z "$tenant_id" ]]; then
    read -rp "Tenant ID (letters, numbers, hyphens only): " tenant_id
  fi

  [[ "$tenant_id" =~ ^[a-zA-Z0-9_-]+$ ]] || die "Invalid tenant ID: $tenant_id"

  local tenant_dir="yaml-configs/tenants/${tenant_id}"
  if [[ -d "$tenant_dir" ]]; then
    warn "Tenant '${tenant_id}' already exists at ${tenant_dir}"
    return
  fi

  mkdir -p "$tenant_dir"

  read -rp "Tenant display name [${tenant_id}]: " tenant_name
  tenant_name="${tenant_name:-$tenant_id}"

  read -rp "Allowed user email(s) (comma-separated): " emails_raw
  # Build YAML list
  local email_list=""
  IFS=',' read -ra emails <<< "$emails_raw"
  for email in "${emails[@]}"; do
    email=$(echo "$email" | xargs) # trim whitespace
    email_list+="    - \"${email}\"\n"
  done

  cat > "${tenant_dir}/config.yaml" << EOF
tenant:
  id: "${tenant_id}"
  name: "${tenant_name}"
  allowed_users:
$(echo -e "$email_list")
  dep:
    enabled: false
    default_profile: ""
EOF

  cat > "${tenant_dir}/groups.yaml" << 'EOF'
groups:
  - name: "all-devices"
    description: "All enrolled devices"
    conditions:
      - type: "device_model"
        operator: "regex"
        value: ".*"

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
EOF

  cat > "${tenant_dir}/apps.yaml" << 'EOF'
apps: []
# Example:
# apps:
#   - id: "company-app"
#     name: "Company App"
#     bundle_id: "com.example.companyapp"
#     versions:
#       - version: "1.0.0"
#         s3_key: "company-app/company-app-1.0.0.ipa"
#         groups:
#           - "all-devices"
EOF

  cat > "${tenant_dir}/profiles.yaml" << 'EOF'
profiles: []
# Example:
# profiles:
#   - id: "wifi-corporate"
#     name: "Corporate WiFi"
#     description: "Configure corporate WiFi network"
#     groups:
#       - "all-devices"
#     payload:
#       PayloadType: "Configuration"
#       PayloadIdentifier: "com.example.wifi.corporate"
#       PayloadDisplayName: "Corporate WiFi"
#       PayloadContent:
#         - PayloadType: "com.apple.wifi.managed"
#           SSID_STR: "Corporate"
#           EncryptionType: "WPA2"
EOF

  cat > "${tenant_dir}/flows.yaml" << 'EOF'
version: 2
flows:
- id: enrollment
  name: Device enrollment
  description: Runs when a device enrolls. Waits for the device to report itself,
    then releases it from Setup Assistant. Add your profiles, apps and account setup
    between the two.
  enabled: true
  permanent: true
  nodes:
  - id: start-dep
    type: start
    params:
      kind: enroll_dep
      match: {}
    ui:
      x: -260
      y: -80
    next: await-info
  - id: start-ota
    type: start
    params:
      kind: enroll_profile
      match: {}
    ui:
      x: -260
      y: 80
    next: await-info
  - id: await-info
    type: wait_for
    params:
      signal: device_info
      timeout_minutes: 30
    ui:
      x: 0
      y: 0
    next: release
    on_timeout: gate-stuck
  - id: gate-stuck
    type: manual_gate
    params:
      summary: Device has not reported in since it enrolled
      severity: yellow
      options:
      - label: Release it from Setup Assistant
        edge: on_release
      - label: Stop this run
        edge: on_cancel
    ui:
      x: 0
      y: 240
    on_release: release
    on_cancel: done
  - id: release
    type: release_device
    params: {}
    ui:
      x: 280
      y: 0
    next: done
  - id: done
    type: end
    params: {}
    ui:
      x: 520
      y: 0
EOF

  ok "Tenant '${tenant_id}' scaffolded at ${tenant_dir}"
  echo
  info "Next: create the tenant + an admin user in the database via the CLI:"
  echo "  docker compose -f docker-compose.prod.yml exec controller python -m controller.tenant_cli tenant create ${tenant_id} --name \"${tenant_name}\""
  echo "  docker compose -f docker-compose.prod.yml exec controller python -m controller.tenant_cli user add ${tenant_id} you@example.com --role admin"
}

cmd_up() {
  info "Starting all services..."
  docker compose -f docker-compose.prod.yml up -d "$@"
  echo
  ok "Services started."
  echo
  echo -e "  Web UI:     ${GRN}http://localhost:3000${NC}"
  echo -e "  Controller: ${GRN}http://localhost:8001/docs${NC}"
  local mdm_port; mdm_port=$(grep -E '^MDM_PORT=' .env 2>/dev/null | tail -1 | cut -d= -f2)
  echo -e "  MDM front:  ${GRN}http://localhost:${mdm_port:-443}/mdm${NC} (devices; everything else there is 404)"
  echo -e "  NanoMDM:    ${GRN}http://localhost:9000${NC} (loopback only: /mdm, /v1/ and /version)"
  echo -e "  step-ca:    ${GRN}https://localhost:9443${NC}"
}

# -- full interactive setup -----------------------------------------------------
cmd_interactive() {
  echo
  echo -e "${BLU}Micromanage First-time Setup!${NC}"
  echo

  check_deps

  info "Step 1/4: Environment configuration"
  cmd_env
  echo

  info "Step 2/4: Create the default tenant"
  cmd_tenant "default"
  echo

  info "Step 3/4: Starting services..."
  cmd_up
  echo

  info "Step 4/4: Apple Push Notification certificate"
  echo "  APNs setup requires access to Apple's developer portal."
  echo "  Run this after you have an Apple Developer account:"
  echo
  echo -e "  ${YEL}./setup.sh apns${NC}"
  echo
  ok "Setup complete! Open http://localhost:3000 to get started. Thank you for trying out Micromanage!"
}

_scaffold_dev_tenant() {
  local dir="yaml-configs/tenants/default"
  local template="${SCRIPT_DIR}/deploy/tenant-template/default"

  [[ -d "$template" ]] || die "Missing ${template}; cannot create the example tenant."

  mkdir -p "$dir"
  cp "${template}"/*.yaml "$dir"/

  ok "Created example yaml-configs/tenants/default/"
  echo -e "  Login with: tenant ${GRN}default${NC} / email ${GRN}admin@localhost.dev${NC}"
  echo -e "  The controller will create the DB row on first sync."
}

# -- dev ----------------------------------------------------------------------
cmd_dev() {
  echo
  echo -e "${BLU}Micromanage testing/developement setup${NC}"
  echo

  warn "Running in development mode! Do not use this for actual devices!"

  check_deps

  # Generate .env using localhost
  if [[ ! -f .env ]]; then
    info "Generating .env for localhost..."
    cp .env.example .env
    local db_pass; db_pass=$(openssl rand -hex 20)
    local api_key; api_key=$(openssl rand -hex 20)
    local jwt_sec; jwt_sec=$(openssl rand -hex 32)
    local wh_sec;  wh_sec=$(openssl rand -hex 32)
    local ca_pass; ca_pass=$(openssl rand -hex 20)
    local scep_ch; scep_ch=$(openssl rand -hex 20)
    sed -i.bak \
      -e "s/changeme_strong_password/${db_pass}/" \
      -e "s/changeme_random_api_key/${api_key}/" \
      -e "s/changeme_long_random_secret/${jwt_sec}/" \
      -e "s/changeme_webhook_secret/${wh_sec}/" \
      -e "s/changeme_stepca_password/${ca_pass}/" \
      -e "s/changeme_scep_challenge/${scep_ch}/" \
      .env && rm -f .env.bak
    _gen_shared_secrets
    ok ".env created"
  else
    ok ".env already exists, skipping"
  fi
  grep -qE '^MDM_HOSTNAME=.' .env   || _env_set MDM_HOSTNAME "mdm.example.com"
  grep -qE '^PUBLIC_API_URL=.' .env || _env_set PUBLIC_API_URL "https://mdm.example.com"
  grep -q '^MDM_PORT=' .env || echo "MDM_PORT=8443" >> .env
  echo

  # Ensure yaml-configs is user-writable (Docker may have created it as root)
  if [[ -d yaml-configs && ! -w yaml-configs ]]; then
    warn "yaml-configs/ is not writable, fixing ownership with docker..."
    docker compose -f docker-compose.prod.yml -f docker-compose.dev.yml run --rm -u root controller \
      chown -R mdm:mdm /app/yaml-configs 2>/dev/null || true
    # Also try host-side fix if running as same UID
    chmod -R u+w yaml-configs 2>/dev/null || true
  fi

  # Create default tenant if missing
  if [[ ! -d yaml-configs/tenants/default ]]; then
    info "Creating the default tenant (id: default, user: admin@localhost.dev)..."
    _scaffold_dev_tenant
  else
    ok "Default tenant already exists"
  fi
  echo

  # Start infrastructure services (step-ca issues the device certs NanoMDM validates)
  info "Starting infrastructure services (postgres, step-ca, nanomdm, nanomdm-front, controller)..."
  info "Devices reach NanoMDM at http://localhost:8443/mdm"
  docker compose \
    -f docker-compose.prod.yml \
    -f docker-compose.dev.yml \
    up -d postgres step-ca nanomdm nanomdm-front controller
  echo
  ok "Infrastructure is up!"
  echo

  echo -e "${YEL}Next, start the web UI:${NC}"
  echo
  echo "  cd webui && yarn dev"
  echo
  echo -e "  Then open ${GRN}http://localhost:3000${NC}"
  echo -e "  Controller API: ${GRN}http://localhost:8001/docs${NC}"
  echo -e "  NanoMDM (devices): ${GRN}http://localhost:8443/mdm${NC}"
  echo -e "  NanoMDM API:    ${GRN}http://localhost:9000${NC} (only /mdm, /v1/ and /version)"
  echo

  echo -e "${YEL}To test with real Apple devices, expose the controller via a tunnel:${NC}"
  echo
  echo "  ngrok http 8001 --host-header rewrite"
  echo "  # or: tailscale funnel 8001"
  echo
  echo "  Then set DEV_TUNNEL_URL in .env and restart the controller:"
  echo "  docker compose -f docker-compose.prod.yml -f docker-compose.dev.yml restart controller"
  echo
  warn "You still need an APNs push certificate for push. Run './setup.sh apns' to set that up."
}

case "${1:-}" in
  dev)        cmd_dev ;;
  env)        cmd_env ;;
  apns)       cmd_apns "${2:-}" "${3:-}" ;;
  push-cert)  cmd_push_cert "${2:-}" "${3:-}" ;;
  tenant)     cmd_tenant "${2:-}" ;;
  up)         shift; cmd_up "$@" ;;
  "")         cmd_interactive ;;
  *)          echo "Unknown command: $1"; echo "Usage: $0 [dev|env|apns|push-cert|tenant|up]"; exit 1 ;;
esac
