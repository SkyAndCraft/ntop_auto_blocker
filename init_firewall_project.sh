#!/bin/bash
set -e

mkdir -p scripts

echo "[+] Création de block_ip.sh"
cat > scripts/block_ip.sh <<'EOF'
#!/bin/bash
IP=$1
iptables -A INPUT -s $IP -j DROP
echo "IP $IP bloquée"
EOF

echo "[+] Création de unblock_ip.sh"
cat > scripts/unblock_ip.sh <<'EOF'
#!/bin/bash
IP=$1
iptables -D INPUT -s $IP -j DROP
echo "IP $IP débloquée"
EOF

chmod +x scripts/*.sh

echo "[+] Création du requirements.txt"
cat > requirements.txt <<EOF
requests
schedule
python-dotenv
flask
EOF

echo "[+] Création du .env.example"
cat > .env.example <<EOF
NTOPNG_URL=http://192.168.1.42:3000
NTOPNG_API_KEY=<ta_clé_api>
POLL_INTERVAL=30
BLOCK_SCRIPT=/app/scripts/block_ip.sh
UNBLOCK_SCRIPT=/app/scripts/unblock_ip.sh
WEBHOOK_URL=https://ton.webhook.com/ban
EOF

echo "[+] Création du Dockerfile"
cat > Dockerfile <<EOF
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "ntop_auto_blocker.py"]
EOF

echo "[+] Création du docker-compose.yml"
cat > docker-compose.yml <<EOF
version: "3.9"
services:
  ntop_blocker:
    build: .
    container_name: ntop_blocker
    restart: unless-stopped
    ports:
      - "5000:5000"
    env_file:
      - .env
    volumes:
      - ./scripts:/app/scripts
    cap_add:
      - NET_ADMIN
EOF

echo "[+] Création de ntop_auto_blocker.py"
cat > ntop_auto_blocker.py <<'EOF'
import os
import time
import requests
import schedule
from dotenv import load_dotenv
from subprocess import call
from flask import Flask, request, jsonify
import threading

# Load .env variables
load_dotenv()

NTOPNG_URL = os.getenv("NTOPNG_URL")
API_KEY = os.getenv("NTOPNG_API_KEY")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", 30))
BLOCK_SCRIPT = os.getenv("BLOCK_SCRIPT", "/app/scripts/block_ip.sh")
UNBLOCK_SCRIPT = os.getenv("UNBLOCK_SCRIPT", "/app/scripts/unblock_ip.sh")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")

HEADERS = {"Authorization": f"Bearer {API_KEY}"}
blocked_ips = set()

# Webhook notifier
def send_webhook(ip, event):
    if not WEBHOOK_URL:
        return
    payload = {
        "ip": ip,
        "event": event,
        "timestamp": int(time.time())
    }
    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=5)
        print(f"[→] Webhook envoyé : {event} {ip}")
    except Exception as e:
        print(f"[!] Webhook échec : {e}")

# Blocage d'une IP
def block_ip(ip):
    if ip in blocked_ips:
        return
    print(f"[>] Blocage de l'IP {ip}")
    result = call([BLOCK_SCRIPT, ip])
    if result == 0:
        blocked_ips.add(ip)
        print(f"[✓] IP {ip} bloquée")
        send_webhook(ip, "IP_BLOCKED")
    else:
        print(f"[x] Échec du blocage de l'IP {ip}")

# Déblocage d'une IP
def unblock_ip(ip):
    if ip not in blocked_ips:
        return False
    print(f"[>] Déblocage de l'IP {ip}")
    result = call([UNBLOCK_SCRIPT, ip])
    if result == 0:
        blocked_ips.remove(ip)
        print(f"[✓] IP {ip} débloquée")
        send_webhook(ip, "IP_UNBLOCKED")
        return True
    else:
        print(f"[x] Échec du déblocage")
        return False

# Requête à l'API ntopng
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
    except Exception as e:
        print(f"[Erreur API] {e}")

# Planification
schedule.every(POLL_INTERVAL).seconds.do(fetch_suspicious_hosts)

# Flask REST API
app = Flask(__name__)

@app.route("/ban", methods=["POST"])
def api_ban():
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP manquante"}), 400
    block_ip(ip)
    return jsonify({"message": f"{ip} bloquée"}), 200

@app.route("/unban", methods=["POST"])
def api_unban():
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP manquante"}), 400
    success = unblock_ip(ip)
    if success:
        return jsonify({"message": f"{ip} débloquée"}), 200
    else:
        return jsonify({"error": f"{ip} non débloquée"}), 500

@app.route("/ban-list", methods=["GET"])
def api_ban_list():
    return jsonify({
        "banned_ips": list(blocked_ips),
        "total": len(blocked_ips)
    })

def start_flask():
    app.run(host="0.0.0.0", port=5000)

# Démarrage
if __name__ == "__main__":
    print("🚀 Script ntop_auto_blocker.py lancé")
    threading.Thread(target=start_flask).start()
    while True:
        schedule.run_pending()
        time.sleep(1)
EOF

echo "[+] Création du service systemd skyfirewall"

sudo tee /etc/systemd/system/skyfirewall.service > /dev/null <<EOF
[Unit]
Description=Pare-feu ntop_auto_blocker via Docker Compose
After=network.target docker.service

[Service]
Type=oneshot
WorkingDirectory=/opt/skyfirewall
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF

echo "[+] Activation du service systemd"
sudo systemctl daemon-reexec
sudo systemctl enable skyfirewall.service
echo "[✓] Service activé. Il démarrera automatiquement au prochain reboot ! 🔒"
sudo systemctl start skyfirewall

echo "[✓] Firewall installé et prêt à l'emploie 🎉"
