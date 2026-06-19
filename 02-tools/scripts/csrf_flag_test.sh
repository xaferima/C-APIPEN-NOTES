#!/bin/bash

# Colores para output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuración
MAX_ATTEMPTS=5
FLAGFILE="flag_found.txt"
LOGFILE="bruteforce.log"

# Limpiar archivos anteriores
> "$LOGFILE"

echo -e "${BLUE}[*] CSRF Token Bruteforce - Test (5 intentos)${NC}\n"

# Step 0: autenticar una sola vez
echo -e "${BLUE}[*] Autenticando con /api/v1/auth...${NC}"

AUTH_RESPONSE=$(curl --path-as-is -s -k -i -X POST \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    --data-binary '{"email": "john4@healthcare.app","password": "john@1234"}' \
    'https://hackapi.secops.group/api/v1/auth' 2>/dev/null)

CSRF_TOKEN=$(printf '%s' "$AUTH_RESPONSE" | tr -d '\r' | grep -im1 '^x-csrf-token:' | cut -d':' -f2- | tr -d '[:space:]')
JWT_TOKEN=$(printf '%s' "$AUTH_RESPONSE" | tail -1 | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$CSRF_TOKEN" ] || [ -z "$JWT_TOKEN" ]; then
    echo -e "${RED}[!] Error extrayendo tokens${NC}"
    echo "CSRF: $CSRF_TOKEN / JWT: ${JWT_TOKEN:0:30}..."
    exit 1
fi

echo -e "${GREEN}[+] X-CSRF-Token: $CSRF_TOKEN${NC}"
echo -e "${GREEN}[+] JWT Token: ${JWT_TOKEN:0:50}...${NC}\n"

# Test 1 appointment request
echo -e "${BLUE}[*] Enviando primer appointment...${NC}"

APPOINTMENT=$(curl --path-as-is -s -k -i -X POST \
    -H "X-CSRF-Token: $CSRF_TOKEN" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -H "Authorization: $JWT_TOKEN" \
    --data-binary '{"slot": "2024-12-15T10:00:00","notes": "Test"}' \
    'https://hackapi.secops.group/api/v1/appointment' 2>/dev/null)

echo "$APPOINTMENT" | head -20
echo -e "\n${BLUE}[*] Test completado${NC}"
