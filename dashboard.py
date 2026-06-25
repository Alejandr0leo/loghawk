"""
dashboard.py — Dashboard visual de LogHawk (Streamlit).

Uso:
    streamlit run dashboard.py

Permite subir tus propios logs o usar los de muestra, y muestra alertas,
severidades, IPs más activas y una línea de tiempo de eventos.
"""

import os
import pandas as pd
import streamlit as st

from loghawk import run

st.set_page_config(page_title="LogHawk — mini-SIEM", page_icon="🦅", layout="wide")

SEV_COLOR = {"CRITICAL": "#8e44ad", "HIGH": "#e74c3c",
             "MEDIUM": "#f39c12", "LOW": "#3498db"}
HERE = os.path.dirname(os.path.abspath(__file__))

st.title("🦅 LogHawk — mini-SIEM")
st.caption("Detección de actividad sospechosa en logs de SSH y servidores web.")

# ---- Fuente de datos -------------------------------------------------------
with st.sidebar:
    st.header("Fuente de logs")
    mode = st.radio("Usar:", ["Logs de muestra", "Subir mis logs"])
    auth_path = access_path = None

    if mode == "Logs de muestra":
        auth_path = os.path.join(HERE, "data", "sample_auth.log")
        access_path = os.path.join(HERE, "data", "sample_access.log")
        if not os.path.exists(auth_path):
            st.warning("Genera los datos: `python data/generate_samples.py`")
    else:
        up_auth = st.file_uploader("auth.log (SSH)", type=["log", "txt"])
        up_access = st.file_uploader("access.log (web)", type=["log", "txt"])
        os.makedirs("/tmp/loghawk", exist_ok=True)
        if up_auth:
            auth_path = "/tmp/loghawk/auth.log"
            open(auth_path, "wb").write(up_auth.read())
        if up_access:
            access_path = "/tmp/loghawk/access.log"
            open(access_path, "wb").write(up_access.read())

if not auth_path and not access_path:
    st.info("Selecciona los logs de muestra o sube tus propios archivos en la barra lateral.")
    st.stop()

result = run(auth_path=auth_path, access_path=access_path)
auth, access, alerts = result["auth"], result["access"], result["alerts"]

# ---- Métricas --------------------------------------------------------------
c1, c2, c3, c4 = st.columns(4)
c1.metric("Eventos SSH", len(auth))
c2.metric("Eventos HTTP", len(access))
c3.metric("Alertas", len(alerts))
crit = 0 if alerts.empty else int((alerts["severity"] == "CRITICAL").sum())
c4.metric("Críticas", crit)

st.divider()

if alerts.empty:
    st.success("Sin alertas: no se detectó actividad sospechosa.")
    st.stop()

# ---- Alertas por severidad -------------------------------------------------
left, right = st.columns([2, 1])
with left:
    st.subheader("Alertas")
    for _, a in alerts.iterrows():
        color = SEV_COLOR.get(a["severity"], "#888")
        st.markdown(
            f"<div style='border-left:5px solid {color};padding:8px 12px;"
            f"margin-bottom:8px;background:#00000008;border-radius:4px'>"
            f"<b style='color:{color}'>{a['severity']}</b> · "
            f"<code>{a['src_ip']}</code> · <b>{a['rule']}</b><br>"
            f"<small>{a['ts']} — {a['detail']}</small></div>",
            unsafe_allow_html=True,
        )

with right:
    st.subheader("Por severidad")
    sev_counts = alerts["severity"].value_counts()
    st.bar_chart(sev_counts)

    st.subheader("IPs más señaladas")
    top_ips = alerts.groupby("src_ip")["count"].sum().sort_values(ascending=False)
    st.bar_chart(top_ips)

# ---- Línea de tiempo -------------------------------------------------------
st.divider()
st.subheader("Línea de tiempo de eventos")
frames = []
if not auth.empty:
    a = auth[["ts", "ip", "outcome"]].copy()
    a["tipo"] = "SSH " + a["outcome"]
    frames.append(a[["ts", "ip", "tipo"]])
if not access.empty:
    h = access[["ts", "ip", "status"]].copy()
    h["tipo"] = "HTTP " + h["status"].astype(str)
    frames.append(h[["ts", "ip", "tipo"]])
if frames:
    timeline = pd.concat(frames).set_index("ts").sort_index()
    per_min = timeline.resample("1min").size().rename("eventos")
    st.line_chart(per_min)

st.caption("LogHawk v0.1 · proyecto de portafolio — github.com/Alejandr0leo")
