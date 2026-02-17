from flask import Flask, render_template, request, jsonify, abort
from functools import wraps
import subprocess
import logging
import time
import os

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  ConfiguraciÃ³n
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "cambia-esto-en-produccion")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  Lista BLANCA de comandos permitidos
#  Formato: "clave_ui": (["binario", "args..."], "descripciÃ³n")
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
COMANDOS_PERMITIDOS: dict[str, tuple[list[str], str]] = {
    "fecha":     (["date"],               "Fecha y hora del sistema"),
    "uptime":    (["uptime"],             "Tiempo activo del servidor"),
    "espacio":   (["df", "-h"],           "Uso del disco"),
    "memoria":   (["free", "-h"],         "Uso de la memoria RAM"),
    "procesos":  (["ps", "aux", "--sort=-pcpu", "--no-headers", "-o", "pid,pcpu,pmem,comm"],
                                          "Top procesos por CPU"),
    "red":       (["ss", "-tuln"],        "Puertos y conexiones activas"),
    "kernel":    (["uname", "-a"],        "InformaciÃ³n del kernel"),
    "cpu":       (["lscpu"],              "InformaciÃ³n de la CPU"),
    "whoami":    (["whoami"],             "Usuario actual"),
    "env":       (["env"],                "Variables de entorno"),
}

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  Rate limiting simple en memoria
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_rate_store: dict[str, list[float]] = {}
RATE_LIMIT = 10        # peticiones
RATE_WINDOW = 60       # segundos


def rate_limited(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr or "unknown"
        now = time.time()
        hits = _rate_store.get(ip, [])
        hits = [t for t in hits if now - t < RATE_WINDOW]
        if len(hits) >= RATE_LIMIT:
            logger.warning("Rate limit excedido para IP %s", ip)
            return jsonify({"error": "Demasiadas peticiones. Espera un momento."}), 429
        hits.append(now)
        _rate_store[ip] = hits
        return f(*args, **kwargs)
    return wrapper


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  Rutas
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.route("/")
def home():
    return render_template("index.html", comandos=COMANDOS_PERMITIDOS)


@app.route("/cmd", methods=["POST"])
@rate_limited
def cmd():
    if not request.is_json:
        abort(400)

    clave = request.json.get("cmd", "").strip()

    if clave not in COMANDOS_PERMITIDOS:
        logger.warning("Intento de comando no permitido: %r desde %s", clave, request.remote_addr)
        return jsonify({"error": "Comando no permitido."}), 403

    binario, descripcion = COMANDOS_PERMITIDOS[clave]

    logger.info("Ejecutando '%s' solicitado por %s", clave, request.remote_addr)

    try:
        resultado = subprocess.run(
            binario,
            shell=False,          # â† NUNCA shell=True con input de usuario
            capture_output=True,
            text=True,
            timeout=8,
        )
        salida = resultado.stdout or resultado.stderr or "(sin salida)"
    except subprocess.TimeoutExpired:
        salida = "El comando tardÃ³ demasiado y fue cancelado."
    except FileNotFoundError:
        salida = f"El comando '{binario[0]}' no estÃ¡ disponible en este sistema."
    except Exception:
        logger.exception("Error inesperado ejecutando '%s'", clave)
        salida = "Error interno. Revisa los logs del servidor."

    return jsonify({"out": salida, "cmd": clave, "desc": descripcion})


@app.route("/cmds", methods=["GET"])
def listar_comandos():
    """Devuelve la lista de comandos disponibles (sin exponer los binarios reales)."""
    return jsonify({
        k: desc for k, (_, desc) in COMANDOS_PERMITIDOS.items()
    })


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  Arranque
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
if __name__ == "__main__":
    # En producciÃ³n usar Gunicorn: gunicorn -w 4 app:app
    app.run(host="127.0.0.1", port=8080, debug=False)
