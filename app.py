import os
import sys
import mysql.connector
import requests
import hmac
import hashlib
from flask import Flask, render_template, request, redirect, session, jsonify, url_for, flash, make_response
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
from werkzeug.security import generate_password_hash, check_password_hash
from requests.auth import HTTPBasicAuth

app = Flask(__name__)

# --- 1. CONFIGURACIÓN ---
app.secret_key = os.environ.get('SECRET_KEY', 'super_secret_key_default')
PASSWORD_ADMIN = os.environ.get('PASSWORD_ADMIN', 'admin123')
VERIFY_TOKEN = os.environ.get('VERIFY_TOKEN', 'mi_token_seguro')
WHATSAPP_SECRET = os.environ.get('WHATSAPP_SECRET', '')

# Corrección de IP real (necesario tras Nginx)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Cookies Seguras
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# Inicializar Extensiones
csrf = CSRFProtect(app)

# Rate Limiter (Anti-Fuerza Bruta)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri="memory://"
)

# Manejador de Bloqueo (Redirige al login con timer)
@app.errorhandler(RateLimitExceeded)
def ratelimit_handler(e):
    flash("TOO_MANY_ATTEMPTS") 
    return redirect(url_for('login'))

# Headers de Seguridad y No-Caché
@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response

# --- 2. BASE DE DATOS ---
db_config = {
    'host': os.environ.get('DB_HOST', 'virtual_db'),
    'user': os.environ.get('DB_USER', 'root'),
    'password': os.environ.get('DB_PASSWORD', 'root_password'),
    'database': os.environ.get('DB_NAME', 'negocio_db')
}

def get_db_connection():
    try:
        return mysql.connector.connect(**db_config)
    except mysql.connector.Error as err:
        print(f"Error DB: {err}", file=sys.stderr)
        return None

# Inicialización de tablas
def inicializar_base_datos():
    conn = get_db_connection()
    if not conn: return
    try:
        cursor = conn.cursor()
        
        cursor.execute("""CREATE TABLE IF NOT EXISTS negocios (
            id INT AUTO_INCREMENT PRIMARY KEY, nombre VARCHAR(100), telefono_admin VARCHAR(20), password_hash VARCHAR(255),
            whatsapp_token TEXT, whatsapp_id VARCHAR(100), whatsapp_publico VARCHAR(50),
            twilio_sid VARCHAR(100), twilio_token VARCHAR(100), twilio_from VARCHAR(50), 
            slug VARCHAR(100) UNIQUE, fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        
        cursor.execute("""CREATE TABLE IF NOT EXISTS configuracion (
            negocio_id INT PRIMARY KEY, direccion VARCHAR(255), horarios VARCHAR(255), fila_titulo VARCHAR(255), fila_descripcion TEXT,
            modulo_taller TINYINT(1) DEFAULT 0, modulo_ventas TINYINT(1) DEFAULT 0, url_encuesta VARCHAR(255),
            FOREIGN KEY (negocio_id) REFERENCES negocios(id) ON DELETE CASCADE)""")

        cursor.execute("""CREATE TABLE IF NOT EXISTS servicios (
            id INT AUTO_INCREMENT PRIMARY KEY, negocio_id INT NOT NULL, nombre VARCHAR(100) NOT NULL, precio VARCHAR(50), descripcion VARCHAR(255),
            FOREIGN KEY (negocio_id) REFERENCES negocios(id) ON DELETE CASCADE)""")

        cursor.execute("""CREATE TABLE IF NOT EXISTS clientes_fila (
            id INT AUTO_INCREMENT PRIMARY KEY, negocio_id INT, nombre VARCHAR(100), telefono VARCHAR(20),
            status ENUM('espera', 'notificado', 'atendido', 'cancelado') DEFAULT 'espera', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (negocio_id) REFERENCES negocios(id) ON DELETE CASCADE)""")
        
        cursor.execute("""CREATE TABLE IF NOT EXISTS ventas (
            id INT AUTO_INCREMENT PRIMARY KEY, negocio_id INT, cliente_nombre VARCHAR(100), telefono VARCHAR(20), correo VARCHAR(100),
            producto_id VARCHAR(50), concepto VARCHAR(255) NOT NULL, monto DECIMAL(10,2) NOT NULL, metodo_pago VARCHAR(50) DEFAULT 'Efectivo', 
            comentario TEXT, estatus VARCHAR(20) DEFAULT 'En Proceso', fecha_venta TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (negocio_id) REFERENCES negocios(id) ON DELETE CASCADE)""")

        cursor.execute("""CREATE TABLE IF NOT EXISTS reparaciones (
            id INT AUTO_INCREMENT PRIMARY KEY, negocio_id INT, cliente_nombre VARCHAR(100), telefono VARCHAR(20), dispositivo VARCHAR(100),
            falla VARCHAR(255), estatus VARCHAR(50) DEFAULT 'Recibido', costo DECIMAL(10,2), fecha_ingreso TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (negocio_id) REFERENCES negocios(id) ON DELETE CASCADE)""")
        
        conn.commit()
    except Exception as e: print(f"Error Init DB: {e}")
    finally: conn.close()

inicializar_base_datos()

# Helper Credenciales
def get_negocio_credenciales(identificador):
    conn = get_db_connection()
    if not conn: return {'negocio': None, 'config': None}
    cur = conn.cursor(dictionary=True)
    if str(identificador).isdigit():
        cur.execute("SELECT * FROM negocios WHERE id=%s", (identificador,))
    else:
        cur.execute("SELECT * FROM negocios WHERE slug=%s", (identificador,))
    n = cur.fetchone()
    c = None
    if n:
        cur.execute("SELECT * FROM configuracion WHERE negocio_id=%s", (n['id'],))
        c = cur.fetchone()
    conn.close()
    return {'negocio': n, 'config': c}

# --- 3. RUTAS PÚBLICAS (KIOSCO) ---
@app.route('/')
def home():
    # Si ya inició sesión, que vaya al admin. Si no, a la Landing.
    if 'user_id' in session:
        return redirect('/admin')
    return render_template('landing.html')

@app.route('/ayuda')
def ayuda():
    return render_template('ayuda.html')

@app.route('/b/<nid>')
def kiosco_negocio(nid):
    d = get_negocio_credenciales(nid)
    if not d['negocio']: return "Negocio no encontrado", 404
    real_id = d['negocio']['id']
    return render_template('inicio.html', negocio=d['negocio'], config=d['config'], nid=real_id)

@app.route('/b/<nid>/registro')
def registro_negocio(nid):
    d = get_negocio_credenciales(nid)
    if not d['negocio']: return "Negocio no encontrado", 404
    real_id = d['negocio']['id']
    return render_template('registro.html', nid=real_id, config=d['config'], negocio=d['negocio'])

@app.route('/b/<nid>/rastreo', methods=['GET', 'POST'])
@csrf.exempt 
def rastreo_negocio(nid):
    d = get_negocio_credenciales(nid)
    if not d['negocio']: return "No existe", 404
    real_id = d['negocio']['id']
    ticket = None; error = None
    if request.method == 'POST':
        tid = request.form.get('ticket_id')
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM reparaciones WHERE id=%s AND negocio_id=%s", (tid, real_id))
        ticket = cur.fetchone(); conn.close()
        if not ticket: error = "No se encontró el ticket"
    return render_template('rastreo.html', ticket=ticket, error=error, nid=real_id, config=d['config'], negocio=d['negocio'])

@app.route('/b/<nid>/exito')
def exito_negocio(nid):
    return render_template('exito.html', nombre=request.args.get('nombre'), turno=request.args.get('turno'), nid=nid)

@app.route('/api/b/<nid>/registrar', methods=['POST'])
@csrf.exempt
def registrar_publico(nid):
    d = get_negocio_credenciales(nid)
    if not d['negocio']: return "Error", 404
    real_id = d['negocio']['id']
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("INSERT INTO clientes_fila (negocio_id, nombre, telefono) VALUES (%s, %s, %s)", (real_id, request.form['nombre'], request.form['telefono']))
    new_id = cur.lastrowid
    conn.commit(); conn.close()
    return redirect(url_for('exito_negocio', nid=nid, nombre=request.form['nombre'], turno=new_id))

# --- 4. RUTAS ADMIN ---

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        tel = request.form.get('telefono')
        pwd = request.form.get('password')
        if tel == "admin" and pwd == PASSWORD_ADMIN:
            session['super_admin'] = True; return redirect(url_for('superadmin'))
        
        conn = get_db_connection(); cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM negocios WHERE telefono_admin=%s", (tel,))
        n = cur.fetchone()
        
        login_success = False
        if n:
            try:
                if check_password_hash(n['password_hash'], pwd): login_success = True
            except: pass
            if not login_success and n['password_hash'] == pwd:
                new_hash = generate_password_hash(pwd)
                cur.execute("UPDATE negocios SET password_hash=%s WHERE id=%s", (new_hash, n['id']))
                conn.commit(); login_success = True
        conn.close()
        
        if login_success:
            session['user_id'] = n['id']; session['negocio_nombre'] = n['nombre']
            return redirect('/admin')
        flash('Datos incorrectos')
    return render_template('login.html')

@app.route('/logout')
def logout(): session.clear(); return redirect('/login')

@app.route('/admin')
def admin():
    if 'user_id' not in session: return redirect('/login')
    nid = session['user_id']; conn = get_db_connection(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM configuracion WHERE negocio_id=%s", (nid,)); config = cur.fetchone()
    cur.execute("SELECT nombre FROM negocios WHERE id=%s", (nid,)); negocio = cur.fetchone()
    cur.execute("SELECT * FROM clientes_fila WHERE negocio_id=%s AND status IN ('espera','notificado')", (nid,)); fila = cur.fetchall()
    cur.execute("SELECT * FROM reparaciones WHERE negocio_id=%s AND estatus != 'Entregado'", (nid,)); reparaciones = cur.fetchall()
    cur.execute("SELECT * FROM ventas WHERE negocio_id=%s AND estatus NOT IN ('entregado', 'Entregado', 'Cancelado') ORDER BY fecha_venta DESC", (nid,)); ventas = cur.fetchall()
    cur.execute("SELECT SUM(monto) as total FROM ventas WHERE negocio_id=%s", (nid,)); res_total = cur.fetchone(); total = res_total['total'] or 0
    conn.close()
    return render_template('admin.html', negocio_nombre=negocio['nombre'], fila=fila, reparaciones=reparaciones, ventas=ventas, config=config, total_ventas=total)

@app.route('/admin/historial_ventas')
def historial_ventas():
    if 'user_id' not in session: return redirect('/login')
    nid = session['user_id']; conn = get_db_connection(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM configuracion WHERE negocio_id=%s", (nid,)); config = cur.fetchone()
    cur.execute("SELECT nombre FROM negocios WHERE id=%s", (nid,)); negocio = cur.fetchone()
    cur.execute("SELECT * FROM ventas WHERE negocio_id=%s AND estatus IN ('entregado', 'Entregado') ORDER BY fecha_venta DESC", (nid,)); ventas = cur.fetchall(); conn.close()
    return render_template('historial_ventas.html', ventas=ventas, config=config, negocio_nombre=negocio['nombre'])

@app.route('/admin/historial_fila')
def historial_fila():
    if 'user_id' not in session: return redirect('/login')
    nid = session['user_id']; conn = get_db_connection(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM configuracion WHERE negocio_id=%s", (nid,)); config = cur.fetchone()
    cur.execute("SELECT nombre FROM negocios WHERE id=%s", (nid,)); negocio = cur.fetchone()
    cur.execute("SELECT * FROM clientes_fila WHERE negocio_id=%s ORDER BY created_at DESC LIMIT 100", (nid,)); historial = cur.fetchall(); conn.close()
    return render_template('historial.html', historial=historial, config=config, negocio_nombre=negocio['nombre'])

@app.route('/admin/historial_taller')
def historial_taller():
    if 'user_id' not in session: return redirect('/login')
    nid = session['user_id']; conn = get_db_connection(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM configuracion WHERE negocio_id=%s", (nid,)); config = cur.fetchone()
    cur.execute("SELECT nombre FROM negocios WHERE id=%s", (nid,)); negocio = cur.fetchone()
    cur.execute("SELECT * FROM reparaciones WHERE negocio_id=%s ORDER BY fecha_ingreso DESC", (nid,)); reparaciones = cur.fetchall(); conn.close()
    return render_template('historial_taller.html', reparaciones=reparaciones, config=config, negocio_nombre=negocio['nombre'])

@app.route('/configuracion')
def configuracion():
    if 'user_id' not in session: return redirect('/login')
    nid = session['user_id']; conn = get_db_connection(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM negocios WHERE id=%s", (nid,)); n = cur.fetchone()
    cur.execute("SELECT * FROM configuracion WHERE negocio_id=%s", (nid,)); c = cur.fetchone()
    cur.execute("SELECT * FROM servicios WHERE negocio_id=%s", (nid,)); s = cur.fetchall()
    conn.close()
    identificador = n.get('slug') if n.get('slug') else nid
    kiosco_url = f"{request.host_url}b/{identificador}"
    return render_template('configuracion.html', negocio=n, config=c, servicios=s, kiosco_url=kiosco_url)

@app.route('/superadmin', methods=['GET', 'POST'])
def superadmin():
    if not session.get('super_admin'): return redirect('/login')
    conn = get_db_connection(); cur = conn.cursor(dictionary=True)
    if request.method == 'POST':
        slug = request.form['nombre'].lower().replace(' ', '-')
        hashed_pw = generate_password_hash(request.form['password'])
        cur.execute("INSERT INTO negocios (nombre, slug, telefono_admin, password_hash) VALUES (%s, %s, %s, %s)", 
                    (request.form['nombre'], slug, request.form['telefono'], hashed_pw))
        nid = cur.lastrowid
        cur.execute("INSERT INTO configuracion (negocio_id, direccion, horarios, fila_titulo, fila_descripcion, modulo_taller, modulo_ventas) VALUES (%s, 'Pendiente', '9am-6pm', 'Únete', 'Regístrate', 0, 0)", (nid,))
        conn.commit(); flash(f'ID: {nid}')
    cur.execute("SELECT * FROM negocios"); ns = cur.fetchall(); conn.close()
    return render_template('superadmin.html', negocios=ns)

# --- 5. APIs (ACCIONES) ---

@app.route('/api/guardar_config', methods=['POST'])
def guardar_configuracion():
    if 'user_id' not in session: return redirect('/login')
    nid = session['user_id']; f = request.form; conn = get_db_connection(); cur = conn.cursor()
    slug = f.get('nombre').lower().replace(' ', '-') if f.get('nombre') else None
    
    cur.execute("""UPDATE negocios SET nombre=%s, slug=%s, whatsapp_token=%s, whatsapp_id=%s, whatsapp_publico=%s, twilio_sid=%s, twilio_token=%s, twilio_from=%s WHERE id=%s""", 
        (f['nombre'], slug, f.get('whatsapp_token'), f.get('whatsapp_id'), f.get('whatsapp_publico'), f.get('twilio_sid'), f.get('twilio_token'), f.get('twilio_from'), nid))
    
    taller = 1 if 'modulo_taller' in f else 0; ventas = 1 if 'modulo_ventas' in f else 0
    cur.execute("SELECT negocio_id FROM configuracion WHERE negocio_id=%s", (nid,))
    if cur.fetchone():
        cur.execute("""UPDATE configuracion SET direccion=%s, horarios=%s, fila_titulo=%s, fila_descripcion=%s, modulo_taller=%s, modulo_ventas=%s, url_encuesta=%s WHERE negocio_id=%s""", 
            (f.get('direccion'), f.get('horarios'), f.get('fila_titulo'), f.get('fila_descripcion'), taller, ventas, f.get('url_encuesta'), nid))
    conn.commit(); conn.close(); return redirect('/configuracion')

@app.route('/api/nueva_venta', methods=['POST'])
def nueva_venta():
    if 'user_id' not in session: return redirect('/login')
    nid = session['user_id']; f = request.form; conn = get_db_connection(); cur = conn.cursor()
    pid = f.get('producto_id'); pid = pid if pid and pid.isdigit() else 0
    cur.execute("""INSERT INTO ventas (negocio_id, cliente_nombre, telefono, correo, producto_id, concepto, monto, metodo_pago, comentario, estatus) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'En Proceso')""", 
        (nid, f['cliente_nombre'], f['telefono'], f.get('correo'), pid, f['concepto'], f['monto'], f['metodo_pago'], f.get('comentario')))
    conn.commit(); conn.close(); return redirect('/admin')

@app.route('/api/actualizar_estado/<int:id>', methods=['POST'])
@app.route('/api/actualizar_venta/<int:id>', methods=['POST'])
def actualizar_venta(id):
    if 'user_id' not in session: return jsonify({'status': 'error'}), 403
    data = request.get_json() if request.is_json else request.form
    estatus = data.get('estatus'); encuesta = data.get('notificar_encuesta')
    should_send = encuesta in [True, 'true', 'on', 1]
    nid = session['user_id']; conn = get_db_connection(); cur = conn.cursor(dictionary=True)
    cur.execute("UPDATE ventas SET estatus=%s WHERE id=%s AND negocio_id=%s", (estatus, id, nid))
    conn.commit()
    if estatus in ['entregado', 'Entregado'] and should_send:
        cur.execute("SELECT v.cliente_nombre, v.telefono, n.whatsapp_token, n.whatsapp_id, c.url_encuesta FROM ventas v JOIN negocios n ON v.negocio_id=n.id JOIN configuracion c ON c.negocio_id=n.id WHERE v.id=%s", (id,))
        info = cur.fetchone()
        if info and info['telefono'] and info['whatsapp_token']:
            enviar_plantilla_aviso(info['whatsapp_token'], info['whatsapp_id'], info['telefono'], info['cliente_nombre'])
    conn.close()
    if request.is_json: return jsonify({'status': 'ok'})
    return redirect('/admin')

@app.route('/api/enviar_encuesta/<int:id>', methods=['POST'])
def enviar_encuesta_manual(id):
    if 'user_id' not in session: return jsonify({'status': 'error'}), 403
    nid = session['user_id']; conn = get_db_connection(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT v.cliente_nombre, v.telefono, n.whatsapp_token, n.whatsapp_id, c.url_encuesta FROM ventas v JOIN negocios n ON v.negocio_id=n.id JOIN configuracion c ON c.negocio_id=n.id WHERE v.id=%s AND v.negocio_id=%s", (id, nid))
    info = cur.fetchone(); conn.close()
    
    if info and info['telefono'] and info['whatsapp_token']:
        enviar_plantilla_aviso(info['whatsapp_token'], info['whatsapp_id'], info['telefono'], info['cliente_nombre'])
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'error', 'msg': 'Faltan datos'})

@app.route('/api/nueva_reparacion', methods=['POST'])
def nueva_reparacion():
    if 'user_id' not in session: return redirect('/login')
    f = request.form; nid = session['user_id']; conn = get_db_connection(); cur = conn.cursor()
    cur.execute("INSERT INTO reparaciones (negocio_id, cliente_nombre, telefono, dispositivo, falla, costo) VALUES (%s, %s, %s, %s, %s, %s)", (nid, f['nombre'], f['telefono'], f['dispositivo'], f['falla'], f['costo']))
    conn.commit(); conn.close(); return redirect('/admin')

@app.route('/api/actualizar_reparacion/<int:id>', methods=['POST'])
def actualizar_reparacion(id):
    if 'user_id' not in session: return jsonify({'status': 'error'}), 403
    data = request.json; conn = get_db_connection(); cur = conn.cursor()
    cur.execute("UPDATE reparaciones SET estatus=%s WHERE id=%s AND negocio_id=%s", (data['estatus'], id, session['user_id']))
    conn.commit(); conn.close(); return jsonify({'status': 'ok'})

@app.route('/api/notificar/<int:id>', methods=['POST'])
def notificar_fila(id):
    if 'user_id' not in session: return jsonify({'status': 'error'}), 403
    nid = session['user_id']; conn = get_db_connection(); cur = conn.cursor(dictionary=True)
    cur.execute("SELECT c.*, n.whatsapp_token, n.whatsapp_id, n.twilio_sid, n.twilio_token, n.twilio_from FROM clientes_fila c JOIN negocios n ON c.negocio_id = n.id WHERE c.id=%s AND c.negocio_id=%s", (id, nid))
    data = cur.fetchone()
    
    if data:
        # LOGS DE DEPURACIÓN (TE DIRÁN EXACTAMENTE QUÉ PASA)
        print(f"--- INTENTANDO AVISAR A {data['nombre']} ({data['telefono']}) ---", file=sys.stderr)
        
        # Prioridad WhatsApp (Plantilla)
        if data.get('whatsapp_token') and data.get('whatsapp_id'):
            print("--- ENVIANDO WHATSAPP... ---", file=sys.stderr)
            enviar_plantilla_aviso(data['whatsapp_token'], data['whatsapp_id'], data['telefono'], data['nombre'])
        
        # Respaldo SMS (Solo si no hay whats, o si quieres ambos, quita el elif y pon if)
        elif data.get('twilio_sid'):
            print("--- ENVIANDO SMS TWILIO... ---", file=sys.stderr)
            msg = f"Hola {data['nombre']}, tu turno en {session.get('negocio_nombre','el negocio')} está listo."
            enviar_sms(data['telefono'], msg, {'negocio': data})
        else:
            print("--- NO SE ENCONTRARON CREDENCIALES (NI WA NI SMS) ---", file=sys.stderr)
        
        cur.execute("UPDATE clientes_fila SET status='notificado' WHERE id=%s", (id,))
        conn.commit()
    
    conn.close()
    return jsonify({'status': 'ok'})

@app.route('/api/atender/<int:id>', methods=['POST'])
def atender_fila(id):
    if 'user_id' not in session: return jsonify({'status': 'error'}), 403
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("UPDATE clientes_fila SET status='atendido' WHERE id=%s AND negocio_id=%s", (id, session['user_id']))
    conn.commit(); conn.close(); return jsonify({'status': 'ok'})

@app.route('/api/servicios/agregar', methods=['POST'])
def agregar_servicio():
    if 'user_id' not in session: return jsonify({"error": "403"}), 403
    nid = session['user_id']; conn = get_db_connection(); cur = conn.cursor()
    cur.execute("INSERT INTO servicios (negocio_id, nombre, precio) VALUES (%s, %s, %s)", (nid, request.form.get('nombre_servicio'), request.form.get('precio_servicio')))
    conn.commit(); conn.close(); return redirect('/configuracion')

@app.route('/api/servicios/eliminar/<int:sid>', methods=['POST'])
def eliminar_servicio(sid):
    if 'user_id' not in session: return jsonify({"error": "403"}), 403
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("DELETE FROM servicios WHERE id=%s AND negocio_id=%s", (sid, session['user_id']))
    conn.commit(); conn.close(); return redirect('/configuracion')

@app.route('/api/cambiar_password', methods=['POST'])
def cambiar_password():
    if 'user_id' not in session: return jsonify({"error": "403"}), 403
    nid = session['user_id']
    
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    
    # 1. VERIFICACIÓN DE SEGURIDAD: ¿Es el usuario Demo?
    cur.execute("SELECT telefono_admin FROM negocios WHERE id=%s", (nid,))
    user = cur.fetchone()
    
    # Si es el teléfono del demo, bloqueamos la acción
    if user and user['telefono_admin'] == '5500000000':
        conn.close()
        flash('🚫 ERROR: Por seguridad, no se puede cambiar la contraseña de la cuenta Demo.')
        return redirect('/configuracion')

    # 2. Si no es demo, procedemos normalmente
    n = request.form.get('nueva_pass')
    if not n or n != request.form.get('confirm_pass'): 
        conn.close()
        flash('Error: Las contraseñas no coinciden')
        return redirect('/configuracion')
    
    hashed_pw = generate_password_hash(n)
    cur.execute("UPDATE negocios SET password_hash=%s WHERE id=%s", (hashed_pw, nid))
    conn.commit(); conn.close(); flash('Contraseña cambiada'); return redirect('/logout')

@app.route('/webhook', methods=['GET', 'POST'])
@csrf.exempt
def webhook():
    if request.method == 'GET':
        return request.args.get('hub.challenge') if request.args.get('hub.verify_token') == VERIFY_TOKEN else ('Error', 403)
    if request.method == 'POST':
        if WHATSAPP_SECRET:
            signature = request.headers.get('X-Hub-Signature-256')
            if not signature: return 'Signature missing', 403
            elements = signature.split('='); sig_hash = elements[1]
            expected_hash = hmac.new(WHATSAPP_SECRET.encode('utf-8'), request.get_data(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig_hash, expected_hash): return 'Invalid signature', 403
        
        # Chatbot básico
        data = request.json
        try:
            entry = data['entry'][0]['changes'][0]['value']
            if 'messages' in entry:
                msg = entry['messages'][0]; tel = msg['from']; waba = entry['metadata']['phone_number_id']
                if tel.startswith("521") and len(tel) == 13: tel = tel.replace("521", "52", 1)
                
                if 'text' in msg:
                    txt = msg['text']['body'].lower().strip()
                    conn = get_db_connection()
                    if conn:
                        cur = conn.cursor(dictionary=True)
                        cur.execute("SELECT n.id, n.nombre, c.*, n.whatsapp_token, n.whatsapp_id FROM negocios n LEFT JOIN configuracion c ON n.id = c.negocio_id WHERE n.whatsapp_id=%s", (waba,))
                        ndata = cur.fetchone()
                        if ndata:
                            token = ndata['whatsapp_token']; phone_id = ndata['whatsapp_id']
                            respuesta = ""
                            if "hola" in txt or "menu" in txt:
                                respuesta = f"👋 Hola, soy {ndata['nombre']}.\n1️⃣ Ubicación\n2️⃣ Servicios"
                                if ndata.get('modulo_taller'): respuesta += "\n🎫 Ver estado de ticket (Envía tu número)"
                            elif txt == "1": respuesta = f"📍 {ndata['direccion']}\n⏰ {ndata['horarios']}"
                            elif txt == "2": respuesta = "Consulta nuestros servicios en tienda."
                            elif ndata.get('modulo_taller') and txt.isdigit():
                                cur.execute("SELECT * FROM reparaciones WHERE id=%s AND negocio_id=%s", (txt, ndata['id']))
                                t = cur.fetchone()
                                if t: respuesta = f"🎫 Ticket #{t['id']}\n📱 {t['dispositivo']}\nEstado: {t['estatus']}\nCosto: ${t['costo']}"
                                else: respuesta = "No encontré ese ticket."
                            if respuesta: enviar_mensaje_chat(token, phone_id, tel, respuesta)
                        conn.close()
        except Exception as e: print(f"Webhook Error: {e}")
        return 'EVENT_RECEIVED', 200

# --- HELPERS ---

def enviar_plantilla_aviso(token, phone_id, to, nombre_cliente):
    url = f"https://graph.facebook.com/v17.0/{phone_id}/messages"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    to = ''.join(filter(str.isdigit, to))
    if len(to) == 10: to = '52' + to
    
    # ----------------------------------------------------
    # AQUÍ ESTÁ EL CAMBIO: PLANTILLA "hello_world"
    # ----------------------------------------------------
    # Meta siempre permite 'hello_world' para pruebas.
    # Si esta funciona, significa que 'aviso_turno' no está aprobada o creada.
    payload = {
        "messaging_product": "whatsapp",
        "to": to,
        "type": "template",
        "template": {
            "name": "hello_world", # CAMBIADO PARA PRUEBAS (Deberías cambiarlo a 'aviso_turno' después)
            "language": {"code": "en_US"} # hello_world suele ser en_US
        }
    }
    
    try: 
        r = requests.post(url, json=payload, headers=headers)
        # ESTO ES LO QUE DEBES BUSCAR EN LOS LOGS SI FALLA
        print(f"--- WA TEMPLATE {to}: {r.status_code} ---", file=sys.stderr)
        if r.status_code != 200: 
            print(f"WA Error Body: {r.text}", file=sys.stderr)
    except Exception as e: 
        print(f"WA EXCEPTION: {e}", file=sys.stderr)

def enviar_mensaje_chat(token, phone_id, to, texto):
    url = f"https://graph.facebook.com/v17.0/{phone_id}/messages"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    to = ''.join(filter(str.isdigit, to))
    if len(to) == 10: to = '52' + to
    payload = {"messaging_product": "whatsapp", "to": to, "type": "text", "text": {"body": texto}}
    try: 
        r = requests.post(url, json=payload, headers=headers)
        if r.status_code != 200: print(f"WA Chat Error: {r.text}", file=sys.stderr)
    except: pass

def enviar_sms(tel, msg, creds):
    if not creds or not creds.get('negocio'): return False, "No config"
    sid = creds['negocio'].get('twilio_sid'); tok = creds['negocio'].get('twilio_token'); frm = creds['negocio'].get('twilio_from')
    if not sid or not tok or not frm: return False, "Faltan credenciales"
    tel_digits = ''.join(filter(str.isdigit, tel))
    if len(tel_digits) == 10: num = "+52" + tel_digits
    else: num = "+" + tel_digits if not tel.startswith('+') else tel
    try:
        url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
        data = {"To": num, "From": frm, "Body": msg}
        r = requests.post(url, data=data, auth=(sid, tok))
        print(f"--- TWILIO: {r.status_code} {r.text} ---", file=sys.stderr)
        return (True, "Enviado") if r.status_code in [200, 201] else (False, f"Error Twilio: {r.text}")
    except Exception as e: return False, str(e)


# --- RUTAS LEGALES (AGREGAR ESTO AL FINAL DE APP.PY) ---
@app.route('/legal/<tipo>')
def pagina_legal(tipo):
    contenido = ""
    titulo = ""
    fecha = "18 de Diciembre, 2025"
    
    if tipo == "terminos":
        titulo = "Términos y Condiciones"
        contenido = """
        <h3 class="text-xl font-bold mt-6 mb-2">1. Aceptación</h3>
        <p class="mb-4">Al utilizar Virtual Services, aceptas estos términos. El servicio se ofrece "tal cual" para la gestión de negocios.</p>
        <h3 class="text-xl font-bold mt-6 mb-2">2. Responsabilidad</h3>
        <p class="mb-4">No nos hacemos responsables por pérdidas de datos o interrupciones del servicio ajenas a nuestro control.</p>
        """
    elif tipo == "privacidad":
        titulo = "Aviso de Privacidad"
        contenido = """
        <h3 class="text-xl font-bold mt-6 mb-2">Datos Personales</h3>
        <p class="mb-4">Recopilamos teléfono y nombre solo para el funcionamiento del sistema (notificaciones y citas).</p>
        <h3 class="text-xl font-bold mt-6 mb-2">No compartimos datos</h3>
        <p class="mb-4">Tus datos y los de tus clientes son privados y no se venden a terceros.</p>
        """
    elif tipo == "reembolsos":
        titulo = "Política de Reembolsos"
        contenido = """
        <h3 class="text-xl font-bold mt-6 mb-2">Suscripciones</h3>
        <p class="mb-4">Puedes cancelar en cualquier momento. No ofrecemos reembolsos por meses parciales ya pagados.</p>
        """
    else:
        return "Página no encontrada", 404
        
    return render_template('legal.html', titulo=titulo, contenido=contenido, fecha=fecha)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
