#!/usr/bin/env bash
set -euo pipefail

DB_PATH="${CYRENE_DATABASE_PATH:-/data/exchange.sqlite3}"
HOST="${CYRENE_HOST:-0.0.0.0}"
PORT="${CYRENE_PORT:-8000}"
PROVIDER_URL="${CYRENE_PROVIDER_URL:-http://127.0.0.1:11434}"
PROVIDER_BINDING="${CYRENE_PROVIDER_BINDING:-binding:default}"
DEFAULT_GATEWAY_NAME="${CYRENE_GATEWAY_NAME:-Default Production Gateway}"
PUBLIC_BASE_URL="${CYRENE_PUBLIC_BASE_URL:-http://${HOST}:${PORT}}"

# Ensure data directory exists
mkdir -p "$(dirname "$DB_PATH")"

# Seed default gateway endpoint if database does not have an active endpoint
python3 - "$DB_PATH" "$DEFAULT_GATEWAY_NAME" "$PUBLIC_BASE_URL" <<'PY'
import sys
from pathlib import Path
from uuid import uuid4
from cyrene_exchange_product.store import ExchangeStore
from cyrene_exchange_product.service import ExchangeProductService
from cyrene_exchange_product.domain import CreateEndpointRequest, EndpointState

db_file = Path(sys.argv[1])
store = ExchangeStore(db_file)
try:
    active = [ep for ep in store.list_endpoints() if ep.state is EndpointState.ACTIVE]
    if not active:
        service = ExchangeProductService(store)
        ep = service.create_endpoint(
            CreateEndpointRequest(
                name=sys.argv[2],
                public_base_url=sys.argv[3],
                auth_policy_ref="policy://default",
            ),
            idempotency_key="auto-init-default-gateway",
        )
        print(f"[Init] Initialized active gateway endpoint: id={ep.id}, name={ep.name}")
    else:
        print(f"[Init] Existing active gateway endpoint found: id={active[0].id}")
finally:
    store.close()
PY

EXTRA_ARGS=()
if [[ -n "${CYRENE_CONTROL_TOKEN:-}" ]]; then
  EXTRA_ARGS+=(--control-token "$CYRENE_CONTROL_TOKEN")
fi

echo "[Exchange] Starting Cyrene Exchange Gateway on ${HOST}:${PORT} with DB ${DB_PATH}..."
exec cyrene-exchange --database "$DB_PATH" serve \
  --host "$HOST" \
  --port "$PORT" \
  --provider "${PROVIDER_BINDING}=${PROVIDER_URL}" \
  "${EXTRA_ARGS[@]}" "$@"
