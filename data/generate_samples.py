"""
generate_samples.py — Crea logs de muestra realistas (con ataques embebidos)
para poder probar LogHawk sin necesidad de logs reales.

Genera:
  data/sample_auth.log     (SSH: tráfico normal + fuerza bruta + un compromiso)
  data/sample_access.log   (HTTP: tráfico normal + escaneo + herramientas ofensivas)
"""

import os
import random
from datetime import datetime, timedelta

random.seed(42)
HERE = os.path.dirname(os.path.abspath(__file__))
BASE = datetime(2026, 6, 24, 9, 0, 0)

NORMAL_USERS = ["alejo", "deploy", "ana", "carlos"]
BENIGN_IPS = ["192.168.1.10", "192.168.1.11", "10.0.0.5"]
ATTACKER_SSH = "203.0.113.66"
COMPROMISE_IP = "198.51.100.23"
SCANNER_IP = "203.0.113.99"
TOOL_IP = "203.0.113.45"


def auth_line(ts, host, pid, msg):
    return f"{ts.strftime('%b %d %H:%M:%S')} {host} sshd[{pid}]: {msg}"


def build_auth():
    lines, t = [], BASE
    host = "web-prod-01"
    # Tráfico normal
    for _ in range(15):
        t += timedelta(seconds=random.randint(20, 120))
        u, ip = random.choice(NORMAL_USERS), random.choice(BENIGN_IPS)
        lines.append(auth_line(t, host, random.randint(1000, 9999),
                               f"Accepted password for {u} from {ip} port {random.randint(40000,60000)} ssh2"))
    # Ataque de fuerza bruta (sin éxito) desde ATTACKER_SSH
    t += timedelta(minutes=5)
    for _ in range(18):
        t += timedelta(seconds=random.randint(1, 6))
        u = random.choice(["root", "admin", "test", "oracle", "postgres"])
        lines.append(auth_line(t, host, random.randint(1000, 9999),
                               f"Failed password for invalid user {u} from {ATTACKER_SSH} port {random.randint(40000,60000)} ssh2"))
    # Compromiso: muchos fallos y luego un acceso EXITOSO desde COMPROMISE_IP
    t += timedelta(minutes=3)
    for _ in range(9):
        t += timedelta(seconds=random.randint(1, 8))
        lines.append(auth_line(t, host, random.randint(1000, 9999),
                               f"Failed password for deploy from {COMPROMISE_IP} port {random.randint(40000,60000)} ssh2"))
    t += timedelta(seconds=5)
    lines.append(auth_line(t, host, random.randint(1000, 9999),
                           f"Accepted password for deploy from {COMPROMISE_IP} port {random.randint(40000,60000)} ssh2"))
    return lines


def access_line(ip, ts, method, path, status, ua):
    return (f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"{method} {path} HTTP/1.1" {status} {random.randint(120,4000)} "-" "{ua}"')


def build_access():
    lines, t = [], BASE
    BROWSER = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    normal_paths = ["/", "/index.html", "/about", "/products", "/css/main.css", "/api/items"]
    # Tráfico normal
    for _ in range(25):
        t += timedelta(seconds=random.randint(5, 40))
        lines.append(access_line(random.choice(BENIGN_IPS), t, "GET",
                                 random.choice(normal_paths), random.choice([200, 200, 200, 304]), BROWSER))
    # Enumeración / escaneo: muchas 404 desde SCANNER_IP
    t += timedelta(minutes=2)
    for i in range(16):
        t += timedelta(seconds=random.randint(1, 3))
        lines.append(access_line(SCANNER_IP, t, "GET", f"/old/page{i}.php", 404, BROWSER))
    # Acceso a rutas sensibles
    for p in ["/admin", "/.env", "/wp-login.php", "/.git/config"]:
        t += timedelta(seconds=random.randint(1, 4))
        lines.append(access_line(SCANNER_IP, t, "GET", p, random.choice([403, 404]), BROWSER))
    # Herramienta ofensiva (User-Agent sqlmap)
    t += timedelta(minutes=1)
    for _ in range(6):
        t += timedelta(seconds=random.randint(1, 3))
        lines.append(access_line(TOOL_IP, t, "GET", "/api/items?id=1'", random.choice([200, 500]),
                                 "sqlmap/1.7.2#stable (http://sqlmap.org)"))
    return lines


def main():
    auth_path = os.path.join(HERE, "sample_auth.log")
    access_path = os.path.join(HERE, "sample_access.log")
    with open(auth_path, "w") as f:
        f.write("\n".join(build_auth()) + "\n")
    with open(access_path, "w") as f:
        f.write("\n".join(build_access()) + "\n")
    print(f"Generado: {auth_path}")
    print(f"Generado: {access_path}")


if __name__ == "__main__":
    main()
