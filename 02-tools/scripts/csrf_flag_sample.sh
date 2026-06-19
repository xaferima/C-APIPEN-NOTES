#!/bin/bash

echo "[*] Extrayendo tokens de auth..."

AUTH_RESPONSE=$(curl --path-as-is -s -k -i -X POST \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    --data-binary '{"email": "john4@healthcare.app","password": "john@1234"}' \
    'https://hackapi.secops.group/api/v1/auth' 2>/dev/null)

CSRF_TOKEN=$(printf '%s' "$AUTH_RESPONSE" | tr -d '\r' | grep -im1 '^x-csrf-token:' | cut -d':' -f2- | tr -d '[:space:]')
JWT_TOKEN=$(printf '%s' "$AUTH_RESPONSE" | tail -1 | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

echo "[+] CSRF: $CSRF_TOKEN"
echo "[+] JWT: ${JWT_TOKEN:0:50}..."

echo -e "\n[*] Enviando 10 appointment requests para ver respuestas...\n"

for i in {1..10}; do
    RESPONSE=$(curl --path-as-is -s -k -i -X POST \
        -H "X-CSRF-Token: $CSRF_TOKEN" \
        -H 'Content-Type: application/json' \
        -H 'Accept: application/json' \
        -H "Authorization: $JWT_TOKEN" \
        --data-binary '{"slot": "2024-12-15T10:00:00","notes": "Test"}' \
        'https://hackapi.secops.group/api/v1/appointment' 2>/dev/null)
    
    HTTP_CODE=$(printf '%s' "$RESPONSE" | head -1 | grep -oE '[0-9]{3}')
    BODY=$(printf '%s' "$RESPONSE" | tail -1)
    
    echo "[$i] HTTP $HTTP_CODE | Body: $BODY"
done
