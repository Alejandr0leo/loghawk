"""
detections.py — Reglas de detección. Cada función recibe DataFrames de eventos
y devuelve una lista de alertas (dicts) con: ts, rule, severity, src_ip, detail, count.

Severidades: CRITICAL > HIGH > MEDIUM > LOW
"""

import pandas as pd

# Configuración de umbrales (ajustable)
BRUTE_FORCE_FAILS = 5          # nº de fallos SSH...
BRUTE_FORCE_WINDOW_S = 120     # ...dentro de esta ventana (segundos)
WEB_ENUM_4XX = 10              # nº de respuestas 4xx para marcar enumeración
WEB_ENUM_WINDOW_S = 60

SENSITIVE_PATHS = (
    "/admin", "/.env", "/wp-login.php", "/.git", "/phpmyadmin",
    "/config", "/.aws", "/server-status", "/actuator",
)
MALICIOUS_UA = (
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster",
    "hydra", "gobuster", "wpscan", "fuzz",
)


def _window_breaches(df: pd.DataFrame, threshold: int, window_s: int):
    """Para un df de una sola IP ordenado por ts, ¿hay >=threshold eventos en window_s?
    Devuelve (max_en_ventana, ts_del_primer_evento_del_pico)."""
    times = df["ts"].sort_values().tolist()
    best, best_ts = 0, None
    i = 0
    for j in range(len(times)):
        while (times[j] - times[i]).total_seconds() > window_s:
            i += 1
        span = j - i + 1
        if span > best:
            best, best_ts = span, times[i]
    return best, best_ts


def detect_ssh_bruteforce(auth: pd.DataFrame) -> list[dict]:
    alerts = []
    if auth.empty:
        return alerts
    failed = auth[auth["outcome"] == "failed"]
    for ip, grp in failed.groupby("ip"):
        peak, peak_ts = _window_breaches(grp, BRUTE_FORCE_FAILS, BRUTE_FORCE_WINDOW_S)
        if peak >= BRUTE_FORCE_FAILS:
            alerts.append(dict(
                ts=peak_ts, rule="SSH brute force", severity="HIGH", src_ip=ip,
                detail=f"{peak} intentos fallidos en <= {BRUTE_FORCE_WINDOW_S}s "
                       f"contra usuarios: {', '.join(sorted(grp['user'].unique())[:5])}",
                count=int(peak),
            ))
    return alerts


def detect_bruteforce_then_success(auth: pd.DataFrame) -> list[dict]:
    """IP con muchos fallos que luego logra un acceso aceptado => posible compromiso."""
    alerts = []
    if auth.empty:
        return alerts
    for ip, grp in auth.groupby("ip"):
        fails = grp[grp["outcome"] == "failed"]
        succ = grp[grp["outcome"] == "accepted"]
        if len(fails) >= BRUTE_FORCE_FAILS and not succ.empty:
            first_success = succ["ts"].min()
            fails_before = fails[fails["ts"] <= first_success]
            if len(fails_before) >= BRUTE_FORCE_FAILS:
                user = succ.sort_values("ts").iloc[0]["user"]
                alerts.append(dict(
                    ts=first_success, rule="Posible compromiso (fuerza bruta + acceso)",
                    severity="CRITICAL", src_ip=ip,
                    detail=f"{len(fails_before)} fallos seguidos de acceso EXITOSO "
                           f"como '{user}'. Revisar de inmediato.",
                    count=int(len(fails_before)),
                ))
    return alerts


def detect_web_enumeration(access: pd.DataFrame) -> list[dict]:
    alerts = []
    if access.empty:
        return alerts
    errs = access[access["status"].between(400, 499)]
    for ip, grp in errs.groupby("ip"):
        peak, peak_ts = _window_breaches(grp, WEB_ENUM_4XX, WEB_ENUM_WINDOW_S)
        if peak >= WEB_ENUM_4XX:
            alerts.append(dict(
                ts=peak_ts, rule="Enumeracion / escaneo web", severity="MEDIUM", src_ip=ip,
                detail=f"{peak} respuestas 4xx en <= {WEB_ENUM_WINDOW_S}s "
                       f"({grp['path'].nunique()} rutas distintas)",
                count=int(peak),
            ))
    return alerts


def detect_sensitive_paths(access: pd.DataFrame) -> list[dict]:
    alerts = []
    if access.empty:
        return alerts
    mask = access["path"].str.lower().str.startswith(SENSITIVE_PATHS)
    hits = access[mask]
    for ip, grp in hits.groupby("ip"):
        paths = sorted(grp["path"].unique())[:6]
        alerts.append(dict(
            ts=grp["ts"].min(), rule="Acceso a rutas sensibles", severity="MEDIUM",
            src_ip=ip, detail=f"Solicito: {', '.join(paths)}", count=int(len(grp)),
        ))
    return alerts


def detect_malicious_user_agents(access: pd.DataFrame) -> list[dict]:
    alerts = []
    if access.empty:
        return alerts
    ua = access["ua"].str.lower()
    mask = ua.apply(lambda s: any(tool in s for tool in MALICIOUS_UA))
    hits = access[mask]
    for ip, grp in hits.groupby("ip"):
        tools = sorted({t for s in grp["ua"].str.lower() for t in MALICIOUS_UA if t in s})
        alerts.append(dict(
            ts=grp["ts"].min(), rule="Herramienta ofensiva detectada (User-Agent)",
            severity="HIGH", src_ip=ip,
            detail=f"User-Agent asociado a: {', '.join(tools)}", count=int(len(grp)),
        ))
    return alerts


ALL_RULES = [
    ("auth", detect_ssh_bruteforce),
    ("auth", detect_bruteforce_then_success),
    ("access", detect_web_enumeration),
    ("access", detect_sensitive_paths),
    ("access", detect_malicious_user_agents),
]
