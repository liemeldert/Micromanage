#!/usr/bin/env bash
# MicromanageIAC — one-shot setup helper
# Usage:
#   ./setup.sh               → interactive full setup (production)
#   ./setup.sh dev           → laptop/dev setup (no root, HMR, no real devices needed)
#   ./setup.sh env           → generate .env from .env.example
#   ./setup.sh certs         → generate self-signed TLS certs for NanoMDM
#   ./setup.sh apns          → guided Apple Push Notification cert setup
#   ./setup.sh push-cert     → upload APNs cert to running NanoMDM
#   ./setup.sh tenant <id>   → scaffold YAML configs for a new tenant
#   ./setup.sh up            → start all services (production compose)

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

# ── env ──────────────────────────────────────────────────────────────────────
cmd_env() {
  if [[ -f .env ]]; then
    warn ".env already exists — skipping (delete it first to regenerate)"
    return
  fi
  cp .env.example .env

  # Generate random secrets in-place
  local db_pass; db_pass=$(openssl rand -hex 20)
  local api_key; api_key=$(openssl rand -hex 20)
  local jwt_sec; jwt_sec=$(openssl rand -hex 32)
  local wh_sec;  wh_sec=$(openssl rand -hex 32)

  sed -i "s/changeme_strong_password/${db_pass}/" .env
  sed -i "s/changeme_random_api_key/${api_key}/" .env
  sed -i "s/changeme_long_random_secret/${jwt_sec}/" .env
  sed -i "s/changeme_webhook_secret/${wh_sec}/" .env

  echo
  read -rp "Enter your MDM public hostname (e.g. mdm.example.com): " hostname
  sed -i "s/mdm.example.com/${hostname}/g" .env
  sed -i "s|https://mdm.example.com|https://${hostname}|g" .env

  ok ".env created with random secrets"
  echo
  warn "Edit .env now if you need to configure S3 / object store for app packages."
}

# ── certs ─────────────────────────────────────────────────────────────────────
cmd_certs() {
  mkdir -p certs

  if [[ -f certs/server.crt && -f certs/server.key ]]; then
    warn "certs/server.crt already exists — skipping (delete to regenerate)"
    return
  fi

  # Read hostname from .env if available
  local hostname="mdm.example.com"
  if [[ -f .env ]]; then
    hostname=$(grep -E '^MDM_HOSTNAME=' .env | cut -d= -f2 | tr -d '"' || echo "mdm.example.com")
  fi

  info "Generating self-signed TLS certificate for: ${hostname}"
  info "(For production, replace with a real cert from Let's Encrypt or your CA)"

  openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
    -nodes \
    -keyout certs/server.key \
    -out certs/server.crt \
    -subj "/CN=${hostname}" \
    -addext "subjectAltName=DNS:${hostname},DNS:localhost,IP:127.0.0.1"

  chmod 600 certs/server.key
  ok "TLS certificate written to certs/server.{crt,key}"
  echo
  warn "This is self-signed. For production, replace with a real certificate."
  warn "Apple requires the MDM endpoint to use a publicly-trusted TLS cert."
}

# ── apns ─────────────────────────────────────────────────────────────────────
cmd_apns() {
  mkdir -p certs/apns

  echo
  echo -e "${BLU}═══════════════════════════════════════════════════════${NC}"
  echo -e "${BLU}  Apple Push Notification Certificate Setup${NC}"
  echo -e "${BLU}═══════════════════════════════════════════════════════${NC}"
  echo
  echo "Apple MDM requires a push certificate issued by Apple. This is a"
  echo "one-time setup per Apple Developer account."
  echo
  echo -e "${YEL}Step 1: Generate a certificate signing request (CSR)${NC}"

  if [[ ! -f certs/apns/push.csr ]]; then
    openssl req -new -newkey rsa:2048 -nodes \
      -keyout certs/apns/push.key \
      -out certs/apns/push.csr \
      -subj "/CN=MicromanageIAC MDM Push Certificate"
    ok "CSR generated: certs/apns/push.csr"
  else
    ok "CSR already exists: certs/apns/push.csr"
  fi

  echo
  echo -e "${YEL}Step 2: Get the vendor-signed CSR from MicroMDM's push cert portal${NC}"
  echo
  echo "  Option A (mdmcert.download — easiest):"
  echo "    1. Go to https://mdmcert.download"
  echo "    2. Enter your Apple Developer email"
  echo "    3. Upload: certs/apns/push.csr"
  echo "    4. Download the returned .plist file → save as certs/apns/push.plist"
  echo
  echo "  Option B (Apple Push Certificates Portal directly):"
  echo "    1. Log in to https://identity.apple.com/pushcert"
  echo "    2. Upload your MDM vendor-signed CSR"
  echo "    3. Download the certificate → save as certs/apns/MDM_Certificate.pem"
  echo "    4. Skip to Step 4 below"
  echo
  read -rp "Press Enter once you have downloaded the certificate file..."
  echo

  echo -e "${YEL}Step 3: Decrypt the downloaded .plist (skip if you used Option B)${NC}"
  if [[ -f certs/apns/push.plist ]]; then
    openssl smime -decrypt \
      -in certs/apns/push.plist \
      -inform DER \
      -inkey certs/apns/push.key \
      -out certs/apns/push_signed.plist 2>/dev/null || true

    # Extract the Base64 certificate from the plist
    python3 -c "
import plistlib, base64, sys
with open('certs/apns/push_signed.plist', 'rb') as f:
    data = plistlib.load(f)
cert = data.get('PushCertificateChain') or data.get('Certificate', b'')
if isinstance(cert, bytes):
    sys.stdout.buffer.write(cert)
" > certs/apns/push_cert.der 2>/dev/null || \
    cp certs/apns/push_signed.plist certs/apns/push_cert.der

    openssl x509 -inform DER -in certs/apns/push_cert.der \
      -out certs/apns/MDM_Certificate.pem 2>/dev/null || \
    cp certs/apns/push_signed.plist certs/apns/MDM_Certificate.pem
    ok "Certificate written to certs/apns/MDM_Certificate.pem"
  fi

  if [[ -f certs/apns/MDM_Certificate.pem ]]; then
    echo
    echo -e "${YEL}Step 4: Upload the push certificate to NanoMDM${NC}"
    echo
    echo "Run this after 'docker compose up -d':"
    echo
    echo "  ./setup.sh push-cert"
    echo
    ok "APNs certificate is ready in certs/apns/"
  else
    warn "No certificate found in certs/apns/. Complete the steps above first."
  fi
}

# ── push-cert ─────────────────────────────────────────────────────────────────
cmd_push_cert() {
  local cert_file="${1:-certs/apns/MDM_Certificate.pem}"
  local key_file="${2:-certs/apns/push.key}"

  [[ -f "$cert_file" ]] || die "Certificate not found: $cert_file — run './setup.sh apns' first"
  [[ -f "$key_file" ]]  || die "Key not found: $key_file"

  # Load NanoMDM API key from .env
  local api_key
  api_key=$(grep -E '^NANOMDM_API_KEY=' .env 2>/dev/null | cut -d= -f2 | tr -d '"' || true)
  [[ -n "$api_key" ]] || die "NANOMDM_API_KEY not found in .env"

  info "Uploading APNs push certificate to NanoMDM..."
  curl -s -u "nanomdm:${api_key}" \
    -X PUT \
    -H "Content-Type: text/plain" \
    --data-binary "$(cat "$cert_file")
$(cat "$key_file")" \
    http://localhost:9000/v1/pushcert | cat

  echo
  ok "Push certificate uploaded. Check NanoMDM logs: docker compose logs nanomdm"
}

# ── tenant ────────────────────────────────────────────────────────────────────
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

  ok "Tenant '${tenant_id}' scaffolded at ${tenant_dir}"
  echo
  info "Next: create the tenant + an admin user in the database via the CLI:"
  echo "  docker compose exec controller python -m controller.tenant_cli tenant create ${tenant_id} --name \"${tenant_name}\""
  echo "  docker compose exec controller python -m controller.tenant_cli user add ${tenant_id} you@example.com --role admin"
}

# ── up ────────────────────────────────────────────────────────────────────────
cmd_up() {
  info "Starting all services..."
  docker compose up -d "$@"
  echo
  ok "Services started."
  echo
  echo -e "  Web UI:     ${GRN}http://localhost:3000${NC}"
  echo -e "  Controller: ${GRN}http://localhost:8001/docs${NC}"
  echo -e "  NanoMDM:    ${GRN}http://localhost:9000${NC}"
  echo -e "  step-ca:    ${GRN}https://localhost:9443${NC}"
}

# ── full interactive setup ─────────────────────────────────────────────────────
cmd_interactive() {
  echo
  echo -e "${BLU}╔═══════════════════════════════════════════════╗${NC}"
  echo -e "${BLU}║       MicromanageIAC — First-time Setup       ║${NC}"
  echo -e "${BLU}╚═══════════════════════════════════════════════╝${NC}"
  echo

  check_deps

  info "Step 1/5: Environment configuration"
  cmd_env
  echo

  info "Step 2/5: TLS certificates for NanoMDM"
  cmd_certs
  echo

  info "Step 3/5: Scaffold default tenant"
  cmd_tenant "default"
  echo

  info "Step 4/5: Starting services"
  cmd_up
  echo

  info "Step 5/5: Apple Push Notification certificate"
  echo "  APNs setup requires interaction with Apple's developer portal."
  echo "  Run this after you have an Apple Developer account:"
  echo
  echo -e "  ${YEL}./setup.sh apns${NC}"
  echo
  ok "Setup complete! Open http://localhost:3000 to get started."
}

# ── helpers ───────────────────────────────────────────────────────────────────
_scaffold_dev_tenant() {
  # Non-interactive version of cmd_tenant for the dev path.
  # Creates yaml-configs/tenants/default/ with a known test account.
  local dir="yaml-configs/tenants/default"
  mkdir -p "$dir"

  cat > "${dir}/config.yaml" << 'EOF'
tenant:
  id: "default"
  name: "Default (dev)"
  allowed_users:
    - "admin@localhost.dev"
  dep:
    enabled: false
    default_profile: ""
EOF

  cat > "${dir}/groups.yaml" << 'EOF'
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

  cat > "${dir}/apps.yaml"     << 'EOF'
apps: []
EOF
  cat > "${dir}/profiles.yaml" << 'EOF'
profiles: []
EOF

  ok "Scaffolded yaml-configs/tenants/default/"
  echo -e "  Login with: tenant ${GRN}default${NC} / email ${GRN}admin@localhost.dev${NC}"
  echo -e "  The controller will create the DB row on first sync."
}

# ── dev ──────────────────────────────────────────────────────────────────────
cmd_dev() {
  echo
  echo -e "${BLU}╔═══════════════════════════════════════════════╗${NC}"
  echo -e "${BLU}║     MicromanageIAC — Dev / Laptop Setup       ║${NC}"
  echo -e "${BLU}╚═══════════════════════════════════════════════╝${NC}"
  echo
  check_deps

  # 1. Generate .env using localhost defaults (skip domain prompt)
  if [[ ! -f .env ]]; then
    info "Generating .env with localhost defaults..."
    cp .env.example .env
    local db_pass; db_pass=$(openssl rand -hex 20)
    local api_key; api_key=$(openssl rand -hex 20)
    local jwt_sec; jwt_sec=$(openssl rand -hex 32)
    local wh_sec;  wh_sec=$(openssl rand -hex 32)
    sed -i "s/changeme_strong_password/${db_pass}/"  .env
    sed -i "s/changeme_random_api_key/${api_key}/"   .env
    sed -i "s/changeme_long_random_secret/${jwt_sec}/" .env
    sed -i "s/changeme_webhook_secret/${wh_sec}/"    .env
    # Leave hostname as-is for now; NanoMDM still needs a cert
    ok ".env created"
  else
    ok ".env already exists — skipping"
  fi
  echo

  # 2. TLS cert for NanoMDM (self-signed, localhost)
  if [[ ! -f certs/server.crt ]]; then
    info "Generating self-signed TLS cert for NanoMDM (localhost)..."
    mkdir -p certs
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
      -keyout certs/server.key -out certs/server.crt \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost,DNS:nanomdm,IP:127.0.0.1" 2>/dev/null
    chmod 600 certs/server.key
    ok "TLS cert written to certs/"
  else
    ok "TLS cert already exists — skipping"
  fi
  echo

  # 3. Ensure yaml-configs is user-writable (Docker may have created it as root)
  if [[ -d yaml-configs && ! -w yaml-configs ]]; then
    warn "yaml-configs/ is not writable — fixing ownership with docker..."
    docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm -u root controller \
      chown -R mdm:mdm /app/yaml-configs 2>/dev/null || true
    # Also try host-side fix if running as same UID
    chmod -R u+w yaml-configs 2>/dev/null || true
  fi

  # 4. Scaffold default tenant if missing
  if [[ ! -d yaml-configs/tenants/default ]]; then
    info "Scaffolding default tenant (id: default, user: admin@localhost.dev)..."
    _scaffold_dev_tenant
  else
    ok "Default tenant already exists"
  fi
  echo

  # 4. Start infrastructure services (skip step-ca and webui-docker)
  info "Starting infrastructure services (postgres, nanomdm, controller)..."
  info "NanoMDM will be on https://localhost:8443 (no root required)"
  docker compose \
    -f docker-compose.yml \
    -f docker-compose.dev.yml \
    up -d postgres nanomdm controller
  echo
  ok "Infrastructure is up."
  echo

  # 5. Webui dev instructions
  echo -e "${YEL}Next step — start the web UI with HMR:${NC}"
  echo
  echo "  cd webui && yarn dev"
  echo
  echo -e "  Then open ${GRN}http://localhost:3000${NC}"
  echo -e "  Controller API: ${GRN}http://localhost:8001/docs${NC}"
  echo -e "  NanoMDM API:    ${GRN}https://localhost:9000${NC} (self-signed cert)"
  echo

  # 6. Tunnel hint
  echo -e "${YEL}To test with real Apple devices, expose the controller via a tunnel:${NC}"
  echo
  echo "  ngrok http 8001 --host-header rewrite"
  echo "  # or: tailscale funnel 8001"
  echo
  echo "  Then set DEV_TUNNEL_URL in .env and restart the controller:"
  echo "  docker compose -f docker-compose.yml -f docker-compose.dev.yml restart controller"
  echo
  warn "APNs push certificate is still required for real device push — run './setup.sh apns' when ready."
}

# ── dispatch ──────────────────────────────────────────────────────────────────
case "${1:-}" in
  dev)        cmd_dev ;;
  env)        cmd_env ;;
  certs)      cmd_certs ;;
  apns)       cmd_apns ;;
  push-cert)  cmd_push_cert "${2:-}" "${3:-}" ;;
  tenant)     cmd_tenant "${2:-}" ;;
  up)         shift; cmd_up "$@" ;;
  "")         cmd_interactive ;;
  *)          echo "Unknown command: $1"; echo "Usage: $0 [dev|env|certs|apns|push-cert|tenant|up]"; exit 1 ;;
esac
