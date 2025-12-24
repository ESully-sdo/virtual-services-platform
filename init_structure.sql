-- Este script crea todas las tablas maestras (multi-cliente) necesarias

-- 1. Tabla Maestra de Negocios (Clientes SaaS)
CREATE TABLE IF NOT EXISTS negocios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL,
    whatsapp_token VARCHAR(255), 
    twilio_sid VARCHAR(100),     
    telefono_admin VARCHAR(20),  
    password_hash VARCHAR(255),  
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Tabla de Configuración (Donde se guarda Dirección, Horarios, etc.)
CREATE TABLE IF NOT EXISTS configuracion (
    negocio_id INT PRIMARY KEY,
    direccion VARCHAR(255),
    horarios VARCHAR(255),
    precio_antivirus VARCHAR(255),
    precio_mantenimiento VARCHAR(255),
    FOREIGN KEY (negocio_id) REFERENCES negocios(id) ON DELETE CASCADE
);

-- 3. Tabla de Clientes en Fila (Añade la clave foránea negocio_id)
CREATE TABLE IF NOT EXISTS clientes_fila (
    id INT AUTO_INCREMENT PRIMARY KEY,
    negocio_id INT NOT NULL,
    nombre VARCHAR(100),
    telefono VARCHAR(20),
    status ENUM('espera', 'notificado', 'atendido', 'cancelado') DEFAULT 'espera',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (negocio_id) REFERENCES negocios(id) ON DELETE CASCADE
);

-- 4. Tabla de Reparaciones (Añade la clave foránea negocio_id)
CREATE TABLE IF NOT EXISTS reparaciones (
    id INT AUTO_INCREMENT PRIMARY KEY,
    negocio_id INT NOT NULL,
    cliente_nombre VARCHAR(100),
    telefono VARCHAR(20),
    dispositivo VARCHAR(100),
    falla VARCHAR(255),
    estatus ENUM('Recibido', 'En Revisión', 'En Reparación', 'Listo', 'Entregado') DEFAULT 'Recibido',
    costo DECIMAL(10,2) DEFAULT 0.00,
    notas TEXT,
    fecha_ingreso TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (negocio_id) REFERENCES negocios(id) ON DELETE CASCADE
);
