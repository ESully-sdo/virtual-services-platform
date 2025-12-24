# Usamos una versión ligera de Python
FROM python:3.9-slim

# Evita que Python genere archivos .pyc y buffer de salida
# Esto es crucial para ver logs en tiempo real
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Directorio de trabajo dentro del contenedor
WORKDIR /app

# Instalar dependencias del sistema y curl
RUN apt-get update && apt-get install -y \
    pkg-config \
    default-libmysqlclient-dev \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Descargar wait-for-it.sh
RUN curl -sS https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh -o /usr/bin/wait-for-it.sh \
    && chmod +x /usr/bin/wait-for-it.sh

# Copiamos y cargamos las librerías de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiamos todo el código del proyecto
COPY . .

# Exponemos el puerto 5000
EXPOSE 5000

# COMANDO MODIFICADO PARA LOGS VISIBLES:
# --access-logfile - : Manda logs de acceso a la pantalla
# --error-logfile -  : Manda logs de error a la pantalla
# --log-level debug  : Muestra TODO, hasta lo más mínimo
ENTRYPOINT ["/usr/bin/wait-for-it.sh", "db:3306", "--", "gunicorn", "--bind", "0.0.0.0:5000", "--timeout", "120", "--workers", "1", "--threads", "4", "--access-logfile", "-", "--error-logfile", "-", "--log-level", "info", "app:app"]
