-- 1. Seleccionamos la base de datos
USE negocio_db;

-- 2. Obtenemos el ID del negocio Demo (basado en el teléfono que configuramos)
-- Guardamos el ID en una variable @demo_id
SELECT @demo_id := id FROM negocios WHERE telefono_admin = '5500000000' LIMIT 1;

-- Si no existe el demo, lo creamos rápido (Seguridad)
INSERT INTO negocios (nombre, slug, telefono_admin, password_hash) 
SELECT 'Negocio Demo', 'demo-negocio', '5500000000', 'demo'
WHERE @demo_id IS NULL;

-- Volvemos a leer el ID por si se acaba de crear
SELECT @demo_id := id FROM negocios WHERE telefono_admin = '5500000000' LIMIT 1;

-- 3. Limpiamos datos viejos del demo para no duplicar (Opcional)
DELETE FROM clientes_fila WHERE negocio_id = @demo_id;
DELETE FROM reparaciones WHERE negocio_id = @demo_id;
DELETE FROM ventas WHERE negocio_id = @demo_id;

-- 4. INSERTAR DATOS: FILA VIRTUAL
INSERT INTO clientes_fila (negocio_id, nombre, telefono, status, created_at) VALUES 
(@demo_id, 'Sofía Ramírez', '5511223344', 'espera', NOW()),
(@demo_id, 'Carlos Méndez', '5522334455', 'espera', DATE_SUB(NOW(), INTERVAL 15 MINUTE)),
(@demo_id, 'Ana López', '5533445566', 'notificado', DATE_SUB(NOW(), INTERVAL 30 MINUTE)),
(@demo_id, 'Jorge Trejo', '5544556677', 'atendido', DATE_SUB(NOW(), INTERVAL 1 HOUR)),
(@demo_id, 'Lucía Fernández', '5555667788', 'cancelado', DATE_SUB(NOW(), INTERVAL 2 HOUR));

-- 5. INSERTAR DATOS: TALLER DE REPARACIONES
INSERT INTO reparaciones (negocio_id, cliente_nombre, telefono, dispositivo, falla, estatus, costo, fecha_ingreso) VALUES
(@demo_id, 'Pedro Pascal', '5566778899', 'iPhone 13', 'Pantalla rota', 'En Reparación', 2500.00, DATE_SUB(NOW(), INTERVAL 2 DAY)),
(@demo_id, 'Maria Felix', '5577889900', 'Samsung S21', 'No carga', 'Recibido', 800.00, NOW()),
(@demo_id, 'Juan Gabriel', '5588990011', 'Laptop HP', 'Lenta, limpieza', 'Listo', 500.00, DATE_SUB(NOW(), INTERVAL 1 DAY)),
(@demo_id, 'Luis Miguel', '5599001122', 'iPad Air', 'Cambio de batería', 'Entregado', 1200.00, DATE_SUB(NOW(), INTERVAL 5 DAY));

-- 6. INSERTAR DATOS: VENTAS
INSERT INTO ventas (negocio_id, cliente_nombre, telefono, concepto, monto, metodo_pago, estatus, fecha_venta) VALUES
(@demo_id, 'Cliente Casual', '5500001111', 'Corte de Cabello + Barba', 350.00, 'Efectivo', 'Entregado', NOW()),
(@demo_id, 'Roberto Gómez', '5500002222', 'Gel y Cera', 150.00, 'Tarjeta', 'Entregado', DATE_SUB(NOW(), INTERVAL 2 HOUR)),
(@demo_id, 'Florinda Meza', '5500003333', 'Tinte completo', 1200.00, 'Transferencia', 'En Proceso', NOW()),
(@demo_id, 'Rubén Aguirre', '5500004444', 'Masaje Capilar', 450.00, 'Efectivo', 'Cancelado', DATE_SUB(NOW(), INTERVAL 1 DAY)),
(@demo_id, 'Ramón Valdés', '5500005555', 'Afeitado clásico', 200.00, 'Efectivo', 'Entregado', DATE_SUB(NOW(), INTERVAL 3 DAY));