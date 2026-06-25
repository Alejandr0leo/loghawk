"""
cli.py — Ejecuta LogHawk desde la terminal y muestra un resumen de alertas.

Uso:
    python cli.py --auth data/sample_auth.log --access data/sample_access.log
    python cli.py --auth data/sample_auth.log --json alerts/alerts.json
"""

import argparse
import json
import os

from loghawk import run

_COLORS = {"CRITICAL": "\033[95m", "HIGH": "\033[91m",
           "MEDIUM": "\033[93m", "LOW": "\033[94m"}
_RESET = "\033[0m"


def main():
    ap = argparse.ArgumentParser(description="LogHawk — mini-SIEM en Python")
    ap.add_argument("--auth", help="ruta a auth.log (SSH)")
    ap.add_argument("--access", help="ruta a access.log (Apache/Nginx)")
    ap.add_argument("--json", help="guardar alertas en este archivo JSON")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    if not args.auth and not args.access:
        ap.error("Indica al menos --auth o --access")

    result = run(auth_path=args.auth, access_path=args.access)
    auth, access, alerts = result["auth"], result["access"], result["alerts"]

    print("=" * 64)
    print("  LogHawk — resumen de análisis")
    print("=" * 64)
    print(f"  Eventos SSH analizados   : {len(auth)}")
    print(f"  Eventos HTTP analizados  : {len(access)}")
    print(f"  Alertas generadas        : {len(alerts)}")
    print("-" * 64)

    if alerts.empty:
        print("  Sin alertas. Todo limpio.")
    else:
        for _, a in alerts.iterrows():
            sev = a["severity"]
            color = "" if args.no_color else _COLORS.get(sev, "")
            reset = "" if args.no_color else _RESET
            print(f"  {color}[{sev:8}]{reset} {a['ts']}  {a['src_ip']:15}  {a['rule']}")
            print(f"             ↳ {a['detail']}")
    print("=" * 64)

    if args.json:
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        records = alerts.copy()
        if not records.empty:
            records["ts"] = records["ts"].astype(str)
        with open(args.json, "w") as f:
            json.dump(records.to_dict(orient="records"), f, indent=2, ensure_ascii=False)
        print(f"  Alertas guardadas en: {args.json}")


if __name__ == "__main__":
    main()
