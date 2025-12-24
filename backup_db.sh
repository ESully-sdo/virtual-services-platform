#!/bin/bash

# --- CONFIGURACIÓN ---
BACKUP_DIR="/home/ubuntu/backups"
CONTAINER_NAME="virtual_db"
DB_NAME="negocio_db"
DB_USER="root"
# ⚠️ CONTRASEÑA REAL ACTUALIZADA (CORRECTA)
DB_PASS="gZ.jULs5gFQe,_zEgYAS." 
DATE=$(date +%Y-%m-%d_%H-%M-%S)
FILENAME="backup_$DATE.sql"

# 1. Crear carpeta si no existe
mkdir -p "$BACKUP_DIR"

# 2. Generar el respaldo (Dump)
echo "🔄 Generando respaldo de la base de datos..."

# Ejecutamos el comando y verificamos si tuvo éxito
# Nota: La contraseña va pegada al -p sin espacios
if sudo docker exec "$CONTAINER_NAME" mysqldump -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" > "$BACKUP_DIR/$FILENAME"; then
    
    # Verificamos que el archivo NO esté vacío (mayor a 0 bytes)
    if [ -s "$BACKUP_DIR/$FILENAME" ]; then
        echo "✅ Respaldo exitoso: $FILENAME"
        
        # Comprimir para ahorrar espacio
        gzip "$BACKUP_DIR/$FILENAME"
        echo "📦 Comprimido a: $FILENAME.gz"
        
        # 4. Limpieza (Borrar respaldos de más de 7 días)
        echo "🧹 Limpiando respaldos viejos (+7 días)..."
        find "$BACKUP_DIR" -type f -name "*.gz" -mtime +7 -delete
    else
        echo "⚠️ Error: El archivo de respaldo se creó vacío. Verifica que la base de datos tenga datos."
        rm "$BACKUP_DIR/$FILENAME"
        exit 1
    fi

else
    echo "❌ ERROR CRÍTICO: Acceso denegado a la base de datos."
    echo "💡 Solución: Verifica que la contraseña en DB_PASS sea correcta."
    # Borrar el archivo fallido
    rm -f "$BACKUP_DIR/$FILENAME"
    exit 1
fi

echo "--- Proceso Terminado ---"