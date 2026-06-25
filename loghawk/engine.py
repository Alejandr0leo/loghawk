"""
engine.py — Orquesta el parseo de logs y la ejecución de todas las reglas.
"""

import pandas as pd

from .parsers import parse_auth_log, parse_access_log
from . import detections

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def run(auth_path: str | None = None, access_path: str | None = None) -> dict:
    """Ejecuta LogHawk sobre los logs disponibles.

    Devuelve un dict con:
      - 'auth'   : DataFrame de eventos SSH
      - 'access' : DataFrame de eventos HTTP
      - 'alerts' : DataFrame de alertas ordenadas por severidad y hora
    """
    auth = parse_auth_log(auth_path) if auth_path else pd.DataFrame()
    access = parse_access_log(access_path) if access_path else pd.DataFrame()

    sources = {"auth": auth, "access": access}
    alerts: list[dict] = []
    for source, rule in detections.ALL_RULES:
        df = sources.get(source)
        if df is not None and not df.empty:
            alerts.extend(rule(df))

    alerts_df = pd.DataFrame(
        alerts, columns=["ts", "rule", "severity", "src_ip", "detail", "count"]
    )
    if not alerts_df.empty:
        alerts_df["_sev"] = alerts_df["severity"].map(_SEV_ORDER)
        alerts_df = (alerts_df.sort_values(["_sev", "ts"])
                              .drop(columns="_sev")
                              .reset_index(drop=True))
    return {"auth": auth, "access": access, "alerts": alerts_df}
