#!/bin/bash
# set-target.sh - Cambiar TARGET_HOST dinámicamente
# Uso: ./set-target.sh <host:port>
# Ej:  ./set-target.sh target.com:9000

if [ -z "$1" ]; then
    echo "❌ Uso: set-target.sh <host:port>"
    echo ""
    echo "Ejemplos:"
    echo "  ./set-target.sh mock.hackme.secops.group:9000"
    echo "  ./set-target.sh exam-target.internal:8080"
    echo "  ./set-target.sh localhost:3000"
    exit 1
fi

CAPIPEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$CAPIPEN_DIR/.env"

if [ ! -f "$ENV_FILE" ]; then
    echo "❌ Archivo .env no encontrado en $CAPIPEN_DIR"
    exit 1
fi

TARGET_HOST="$1"

# Actualizar .env (funciona en macOS y Linux)
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' "s/^TARGET_HOST=.*/TARGET_HOST=\"$TARGET_HOST\"/" "$ENV_FILE"
else
    # Linux
    sed -i "s/^TARGET_HOST=.*/TARGET_HOST=\"$TARGET_HOST\"/" "$ENV_FILE"
fi

# Recargar variables
source ~/.zshrc 2>/dev/null || source ~/.bashrc 2>/dev/null

echo "✅ TARGET_HOST actualizado a: $TARGET_HOST"
echo "✅ Variable exportada globalmente"
echo ""
echo "Verificar:"
echo "  echo \$TARGET_HOST"
