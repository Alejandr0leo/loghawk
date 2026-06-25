# 🦅 LogHawk — mini-SIEM en Python

Detección de actividad sospechosa en logs de **SSH** y **servidores web** (Apache/Nginx).
LogHawk parsea logs crudos, aplica un motor de reglas de detección al estilo SOC y
genera alertas priorizadas por severidad, tanto en terminal como en un dashboard visual.

> Proyecto de portafolio orientado a roles de **Analista SOC / Blue Team / Threat Detection**.

---

## ✨ ¿Qué hace?

- **Parsea** logs reales: `auth.log` (SSH) y `access.log` de Apache/Nginx (formato *combined*).
- **Detecta** patrones de ataque con un motor de reglas configurable.
- **Prioriza** alertas por severidad: `CRITICAL` > `HIGH` > `MEDIUM` > `LOW`.
- **Visualiza** todo en un dashboard interactivo (Streamlit): alertas, severidades, IPs más activas y línea de tiempo.
- **Funciona sin logs reales**: incluye un generador de datos de muestra con ataques embebidos.

---

## 🛡️ Reglas de detección

| Regla | Severidad | Qué busca |
|---|---|---|
| Fuerza bruta SSH | HIGH | Muchos intentos fallidos desde una misma IP en una ventana corta. |
| Posible compromiso | CRITICAL | Fuerza bruta seguida de un acceso SSH **exitoso**. |
| Enumeración / escaneo web | MEDIUM | Ráfaga de respuestas 4xx (rutas inexistentes) desde una IP. |
| Acceso a rutas sensibles | MEDIUM | Solicitudes a `/admin`, `/.env`, `/.git`, `/wp-login.php`, etc. |
| Herramienta ofensiva | HIGH | User-Agent de `sqlmap`, `nikto`, `nmap`, `hydra`, `gobuster`… |

Los umbrales (nº de intentos, tamaño de ventana, rutas, herramientas) se ajustan en
`loghawk/detections.py`.

---

## 🚀 Uso rápido

```bash
# 1. Instalar dependencias
pip install -r requirements.txt

# 2. Generar logs de muestra (con ataques embebidos)
python data/generate_samples.py

# 3a. Correr en terminal
python cli.py --auth data/sample_auth.log --access data/sample_access.log

# 3b. O abrir el dashboard
streamlit run dashboard.py
```

### Ejemplo de salida (terminal)

```
================================================================
  LogHawk — resumen de análisis
================================================================
  Eventos SSH analizados   : 43
  Eventos HTTP analizados  : 51
  Alertas generadas        : 6
----------------------------------------------------------------
  [CRITICAL] 198.51.100.23   Posible compromiso (fuerza bruta + acceso)
             ↳ 9 fallos seguidos de acceso EXITOSO como 'deploy'.
  [HIGH    ] 203.0.113.66    SSH brute force
             ↳ 18 intentos fallidos en <= 120s contra root, admin, oracle…
  [MEDIUM  ] 203.0.113.99    Enumeracion / escaneo web
             ↳ 20 respuestas 4xx en <= 60s (20 rutas distintas)
================================================================
```

Para analizar **tus propios logs**, apunta `--auth` y `--access` a tus archivos,
o súbelos desde la barra lateral del dashboard.

---

## 🧱 Arquitectura

```
loghawk/
├── loghawk/
│   ├── parsers.py      # Logs crudos → eventos estructurados (DataFrames)
│   ├── detections.py   # Motor de reglas de detección
│   └── engine.py       # Orquesta parseo + reglas → alertas
├── data/
│   └── generate_samples.py   # Genera logs de muestra con ataques
├── cli.py              # Ejecución por terminal
├── dashboard.py        # Dashboard visual (Streamlit)
└── requirements.txt
```

**Stack:** Python · pandas · Streamlit · regex.

---

## 🗺️ Roadmap

- [ ] Soporte para más fuentes (firewall, Windows Event Logs).
- [ ] Enriquecimiento de IPs con Threat Intelligence (geolocalización + reputación).
- [ ] Reglas en formato YAML para añadirlas sin tocar código.
- [ ] Exportación de alertas a formato compatible con SIEM (CEF/JSON).

---

## 👤 Autor

**Nikolay Alejandro León Duarte** — Estudiante de Ingeniería de Sistemas (ciberseguridad, redes, Python)
GitHub: [github.com/Alejandr0leo](https://github.com/Alejandr0leo)

---

*Proyecto educativo / de portafolio. Úsalo únicamente sobre logs de sistemas propios o con autorización.*
