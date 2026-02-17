"""
Flask Terminal Demo - VersiÃ³n Segura + Lista para Railway
=========================================================
Mejoras de seguridad:
  1. Lista BLANCA de comandos (no lista negra)
  2. Sin shell=True - el input nunca toca la shell
  3. Rate limiting por IP para evitar abuso
  4. ValidaciÃ³n estricta del input (tipo, longitud)
  5. Manejo de errores que no revela informaciÃ³n sensible
  6. Headers de seguridad en todas las respuestas
  7. Logging estructurado

Fix para Railway:
  - host="0.0.0.0"
  - Puerto leÃ­do desde variable de entorno PORT
"""

from flask import Flask, render_template, request, jsonify
from functools import wraps
import subprocess
import logging
import secrets
import time
import os

# â”€â”€ ConfiguraciÃ³n â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
log = logging.getLogger(__name__)

# â”€â”€ Rate Limiting (en memoria) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

RATE_LIMIT_WINDOW = 60      # segundos
RATE_LIMIT_MAX    = 15      # peticiones por ventana por IP

_rate_store: dict[str, list[float]] = {}

def is_rate_limited(ip: str) -> bool:
    now          = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    timestamps   = [t for t in _rate_store.get(ip, []) if t > window_start]
    _rate_store[ip] = timestamps
    if len(timestamps) >= RATE_LIMIT_MAX:
        return True
    _rate_store[ip].append(now)
    return False

# â”€â”€ Lista BLANCA de comandos â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# El usuario solo elige una CLAVE â€” nunca escribe el binario real.

ALLOWED_COMMANDS: dict[str, dict] = {
    "date":     {"cmd": ["date"],            "desc": "Fecha y hora del sistema",      "timeout": 3},
    "uptime":   {"cmd": ["uptime"],          "desc": "Tiempo encendido y carga",      "timeout": 3},
    "whoami":   {"cmd": ["whoami"],          "desc": "Usuario actual",                "timeout": 3},
    "hostname": {"cmd": ["hostname"],        "desc": "Nombre del host",               "timeout": 3},
    "uname":    {"cmd": ["uname", "-a"],     "desc": "InformaciÃ³n del kernel",        "timeout": 3},
    "df":       {"cmd": ["df", "-h"],        "desc": "Uso del disco",                 "timeout": 5},
    "free":     {"cmd": ["free", "-h"],      "desc": "Uso de la memoria RAM",         "timeout": 3},
    "ps":       {"cmd": ["ps", "aux"],       "desc": "Procesos activos",              "timeout": 5},
    "env":      {"cmd": ["env"],             "desc": "Variables de entorno",          "timeout": 3},
    "ls":       {"cmd": ["ls", "-lh", "/"],  "desc": "Archivos en raÃ­z del sistema",  "timeout": 3},
    "netstat":  {"cmd": ["ss", "-tuln"],     "desc": "Puertos en escucha",            "timeout": 5},
    "id":       {"cmd": ["id"],              "desc": "UID, GID y grupos del usuario", "timeout": 3},
}

# â”€â”€ Headers de seguridad â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-XSS-Protection"]       = "1; mode=block"
    response.headers["Cache-Control"]          = "no-store"
    return response

# â”€â”€ Decorador rate limit â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def rate_limit(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr or "unknown"
        if is_rate_limited(ip):
            log.warning(f"Rate limit alcanzado | ip={ip}")
            return jsonify({
                "ok":  False,
                "out": "Demasiadas peticiones. Espera un momento."
            }), 429
        return f(*args, **kwargs)
    return wrapper

# â”€â”€ Rutas â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/commands", methods=["GET"])
def list_commands():
    """Devuelve la lista de comandos disponibles sin revelar los binarios reales."""
    cmds = {key: val["desc"] for key, val in ALLOWED_COMMANDS.items()}
    return jsonify({"commands": cmds})


@app.route("/cmd", methods=["POST"])
@rate_limit
def cmd():
    ip = request.remote_addr or "unknown"

    # 1. Validar que el body es JSON
    if not request.is_json:
        return jsonify({"ok": False, "out": "Se esperaba JSON."}), 400

    data = request.get_json(silent=True) or {}
    key  = data.get("cmd", "")

    # 2. Validar tipo y longitud
    if not isinstance(key, str) or len(key) > 32:
        log.warning(f"Input invalido | ip={ip} | key={repr(key)[:50]}")
        return jsonify({"ok": False, "out": "Input invalido."}), 400

    # 3. Verificar lista blanca
    if key not in ALLOWED_COMMANDS:
        log.warning(f"Comando no permitido | ip={ip} | key={key!r}")
        return jsonify({"ok": False, "out": f"Comando '{key}' no permitido."}), 403

    entry   = ALLOWED_COMMANDS[key]
    timeout = entry["timeout"]

    log.info(f"Ejecutando | ip={ip} | key={key} | cmd={entry['cmd']}")

    # 4. Ejecutar SIN shell=True â€” proteccion real contra injection
    try:
        result = subprocess.run(
            entry["cmd"],
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout or result.stderr or "(sin salida)"
        return jsonify({"ok": True, "out": output, "code": result.returncode})

    except subprocess.TimeoutExpired:
        log.error(f"Timeout | ip={ip} | key={key}")
        return jsonify({"ok": False, "out": f"Timeout ({timeout}s) alcanzado."}), 200

    except FileNotFoundError:
        log.error(f"Binario no encontrado | key={key} | cmd={entry['cmd']}")
        return jsonify({"ok": False, "out": "Comando no disponible en este sistema."}), 200

    except Exception:
        log.exception(f"Error inesperado | ip={ip} | key={key}")
        return jsonify({"ok": False, "out": "Error interno del servidor."}), 500


# â”€â”€ Arranque compatible con Railway â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))  # Railway inyecta PORT automaticamente
    app.run(
        host="0.0.0.0",  # Obligatorio en Railway
        port=port,
        debug=False,
               )
