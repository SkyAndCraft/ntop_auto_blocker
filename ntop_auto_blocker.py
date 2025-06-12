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
    webhook_url = os.getenv("https://discord.com/api/webhooks/1382689016721440839/mphXketY97H4VuPkSqlzzyRJnzXkxMx8sYrYhDqI5TnwRLWdHwAaqCT67M-9er62UTnt")
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
