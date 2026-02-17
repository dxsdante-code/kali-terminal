from flask import Flask, render_template, request, jsonify
import subprocess

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/cmd", methods=["POST"])
def cmd():
    command = request.json["cmd"]

    # 🔒 BLOQUEAR comandos peligrosos (básico)
    blocked = ["rm", "shutdown", "reboot", "mkfs", ":(){", "dd"]
    for b in blocked:
        if b in command:
            return jsonify({"out": "BLOCKED COMMAND"})

    try:
        output = subprocess.check_output(command, shell=True, text=True, timeout=5)
    except Exception as e:
        output = str(e)

    return jsonify({"out": output})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
