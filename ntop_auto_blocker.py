import os
import time
import requests
import schedule
from dotenv import load_dotenv
from subprocess import call

# Chargement des variables d'environnement
load_dotenv()

NTOPNG_URL = os.getenv("NTOPNG_URL")
API_KEY = os.getenv("NTOPNG_API_KEY")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", 30))
BLOCK_SCRIPT = os.getenv("BLOCK_SCRIPT", "/app/block_ip.sh")

HEADERS = {
    "Authorization": f"Bearer {API_KEY}"
}

# Historique des IP déjà bloquées
blocked_ips = set()

def fetch_suspicious_hosts():
    try:
        url = f"{NTOPNG_URL}/lua/rest/v2/get/alerts/active"
        response = requests.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()
        alerts = response.json().get("alerts", [])
        
        for alert in alerts:
            ip = alert.get("host")
            if ip and ip not in blocked_ips:
                print(f"[!] IP suspecte détectée : {ip}")
                block_ip(ip)
                blocked_ips.add(ip)

    except Exception as e:
        print(f"[Erreur] Impossible de récupérer les alertes : {e}")

def block_ip(ip):
    try:
        print(f"[>] Blocage de l'IP {ip}")
        result = call([BLOCK_SCRIPT, ip])
        if result == 0:
            print(f"[✓] IP {ip} bloquée avec succès")
            blocked_ips.add(ip)
            send_webhook(ip)
        else:
            print(f"[x] Échec du blocage de l'IP {ip}")
    except Exception as e:
        print(f"[Erreur] Échec du blocage : {e}")

def send_webhook(ip):
    webhook_url = os.getenv("WEBHOOK_URL")
    if webhook_url:
        try:
            payload = {
                "ip": ip,
                "event": "IP_BLOCKED",
                "timestamp": int(time.time())
            }
            requests.post(webhook_url, json=payload, timeout=5)
            print(f"[→] Webhook envoyé pour l’IP {ip}")
        except Exception as e:
            print(f"[!] Échec de l’envoi du webhook : {e}")


# Planification du job
schedule.every(POLL_INTERVAL).seconds.do(fetch_suspicious_hosts)

print(f"🚦 Agent de blocage lancé (intervalle : {POLL_INTERVAL}s)")
while True:
    schedule.run_pending()
    time.sleep(1)

from flask import Flask, request, jsonify
import threading

app = Flask(__name__)

@app.route("/ban", methods=["POST"])
def manual_ban():
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP manquante"}), 400

    if ip in blocked_ips:
        return jsonify({"message": f"{ip} est déjà bloquée"}), 200

    block_ip(ip)
    return jsonify({"message": f"{ip} a été bloquée"}), 200

# Lancer le serveur Flask dans un thread à part
def start_api():
    app.run(host="0.0.0.0", port=5000)

threading.Thread(target=start_api).start()

@app.route("/unban", methods=["POST"])
def manual_unban():
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP manquante"}), 400

    if ip not in blocked_ips:
        return jsonify({"message": f"{ip} n'est pas dans la liste des IP bloquées"}), 200

    result = call(["/app/unblock_ip.sh", ip])
    if result == 0:
        blocked_ips.remove(ip)
        print(f"[✓] IP {ip} débloquée avec succès")
        return jsonify({"message": f"{ip} a été débloquée"}), 200
    else:
        print(f"[x] Échec du déblocage de l'IP {ip}")
        return jsonify({"error": f"Impossible de débloquer l'IP {ip}"}), 500


