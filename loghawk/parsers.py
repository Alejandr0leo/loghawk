"""
parsers.py — Convierte líneas de log crudas en eventos estructurados (DataFrames).

Soporta dos formatos comunes:
  - auth.log de Linux (eventos SSH: Failed / Accepted password)
  - access.log de Apache/Nginx en formato "combined"
"""

import re
from datetime import datetime
import pandas as pd

# ---------------------------------------------------------------------------
# SSH / auth.log
# ---------------------------------------------------------------------------
_AUTH_LINE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
_AUTH_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
)
_AUTH_ACCEPTED = re.compile(
    r"Accepted password for (?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)"
)


def parse_auth_log(path: str, year: int | None = None) -> pd.DataFrame:
    """Devuelve un DataFrame con eventos SSH: ts, host, user, ip, port, outcome."""
    year = year or datetime.now().year
    rows = []
    with open(path, "r", errors="ignore") as fh:
        for line in fh:
            m = _AUTH_LINE.match(line.strip())
            if not m:
                continue
            msg = m.group("msg")
            outcome = user = ip = port = None
            if (fm := _AUTH_FAILED.search(msg)):
                outcome, user, ip, port = "failed", fm["user"], fm["ip"], fm["port"]
            elif (am := _AUTH_ACCEPTED.search(msg)):
                outcome, user, ip, port = "accepted", am["user"], am["ip"], am["port"]
            else:
                continue
            ts = datetime.strptime(
                f"{m['month']} {int(m['day']):02d} {m['time']} {year}",
                "%b %d %H:%M:%S %Y",
            )
            rows.append(dict(ts=ts, host=m["host"], user=user,
                             ip=ip, port=int(port), outcome=outcome))
    return pd.DataFrame(rows, columns=["ts", "host", "user", "ip", "port", "outcome"])


# ---------------------------------------------------------------------------
# Apache / Nginx access.log (combined)
# ---------------------------------------------------------------------------
_ACCESS_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)


def parse_access_log(path: str) -> pd.DataFrame:
    """Devuelve un DataFrame con eventos HTTP: ts, ip, method, path, status, ua."""
    rows = []
    with open(path, "r", errors="ignore") as fh:
        for line in fh:
            m = _ACCESS_LINE.match(line.strip())
            if not m:
                continue
            try:
                ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                continue
            rows.append(dict(
                ts=ts.replace(tzinfo=None), ip=m["ip"], method=m["method"],
                path=m["path"], status=int(m["status"]), ua=m["ua"],
            ))
    return pd.DataFrame(rows, columns=["ts", "ip", "method", "path", "status", "ua"])
