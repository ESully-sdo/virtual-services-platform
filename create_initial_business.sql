-- Usamos la base de datos
USE negocio_db;

-- Insertar el negocio principal "Virtual Services"
INSERT INTO negocios (nombre, telefono_admin, password_hash)
VALUES ('Virtual Services', '5545834212', 'virtual2025');

-- Obtener el ID del negocio que acabamos de crear
SET @negocio_id = LAST_INSERT_ID();

-- Insertar la configuración inicial del bot para este nuevo negocio
INSERT INTO configuracion (negocio_id, direccion, horarios, precio_antivirus, precio_mantenimiento)
VALUES (
    @negocio_id, 
    'DEMOSTRACION: Cita previa.', 
    'DEMOSTRACION: 9am a 6pm', 
    'DEMOSTRACION: Precio por consulta', 
    'DEMOSTRACION: Costo base'
);
