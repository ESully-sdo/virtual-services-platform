import mysql.connector
import os

print("--> Intentando conectar a la Base de Datos...")

# Configuración manual (la misma que en tu docker-compose)
config = {
    'user': 'user_fila',
    'password': 'userpassword',
    'host': 'db', # Nombre del servicio en Docker
    'database': 'negocio_db',
    'port': 3306
}

try:
    conn = mysql.connector.connect(**config)
    cursor = conn.cursor()
    
    print("--> Conexión exitosa. Creando tablas...")
    
    # 1. Tabla de Fila Virtual
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS clientes_fila (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nombre VARCHAR(100),
            telefono VARCHAR(20),
            status ENUM('espera', 'notificado', 'atendido', 'cancelado') DEFAULT 'espera',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("   [OK] Tabla 'clientes_fila' lista.")

    # 2. Tabla de Reparaciones
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reparaciones (
            id INT AUTO_INCREMENT PRIMARY KEY,
            cliente_nombre VARCHAR(100),
            telefono VARCHAR(20),
            dispositivo VARCHAR(100),
            falla VARCHAR(255),
            estatus ENUM('Recibido', 'En Revisión', 'En Reparación', 'Listo', 'Entregado') DEFAULT 'Recibido',
            costo DECIMAL(10,2) DEFAULT 0.00,
            notas TEXT,
            fecha_ingreso TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("   [OK] Tabla 'reparaciones' lista.")
    
    conn.commit()
    conn.close()
    print("\n--> ¡ÉXITO! Las tablas ya existen. Ahora sí puedes registrarte.")

except Exception as e:
    print(f"\n--> ERROR: {e}")
