import streamlit as st
import pandas as pd
import plotly.express as px

# =========================
# CONFIG
# =========================

st.set_page_config(
    page_title="Windows SOC Dashboard",
    layout="wide"
)


# =========================
# ESTILO
# =========================

st.markdown("""
<style>

.stApp {
    background-color: #0e1117;
    color: white;
}

h1,h2,h3 {
    color: #ff6b00;
}

[data-testid="stMetricValue"] {
    color: #00ff88;
}

</style>
""", unsafe_allow_html=True)

# =========================
# CARGAR DATOS
# =========================

df = pd.read_csv("events.csv")

df["TimeCreated"] = pd.to_datetime(df["TimeCreated"])

# =========================
# ANONIMIZAR DATOS
# =========================

df["Computer"] = "HOST-" + (
    df["Computer"]
    .astype("category")
    .cat.codes
    .astype(str)
)

df["TargetUserName"] = "USER-" + (
    df["TargetUserName"]
    .fillna("Unknown")
    .astype("category")
    .cat.codes
    .astype(str)
)

st.title("🛡 Windows SOC Dashboard")

# =========================
# KPIs
# =========================

total_events = len(df)

critical_events = len(
    df[df["EventID"].isin(
        [4720,4732,4740,4697,4104]
    )]
)

success_logons = len(
    df[df["EventID"] == 4624]
)

failed_logons = len(
    df[df["EventID"] == 4625]
)

hosts = df["Computer"].nunique()

last_update = df["TimeCreated"].max()

c1,c2,c3,c4,c5,c6 = st.columns(6)

c1.metric(
    "Eventos Totales",
    total_events
)

c2.metric(
    "Eventos Críticos",
    critical_events
)

c3.metric(
    "Logons Exitosos",
    success_logons
)

c4.metric(
    "Logons Fallidos",
    failed_logons
)

c5.metric(
    "Hosts",
    hosts
)

c6.metric(
    "Última Actualización",
    str(last_update)[:10]
)

st.divider()

# =========================
# EVENTOS MAS FRECUENTES
# =========================

st.subheader("📊 Top Event IDs")

event_counts = (
    df["EventID"]
    .value_counts()
    .head(15)
    .reset_index()
)

event_counts.columns = [
    "EventID",
    "Cantidad"
]

fig = px.bar(
    event_counts,
    x="EventID",
    y="Cantidad",
    template="plotly_dark"
)

st.plotly_chart(
    fig,
    use_container_width=True
)

# =========================
# TIMELINE
# =========================

st.subheader("📈 Actividad Temporal")

timeline = (
    df.groupby(
        df["TimeCreated"].dt.date
    )
    .size()
    .reset_index(name="Eventos")
)

fig2 = px.line(
    timeline,
    x="TimeCreated",
    y="Eventos",
    template="plotly_dark"
)

st.plotly_chart(
    fig2,
    use_container_width=True
)

# =========================
# TOP USUARIOS
# =========================

st.subheader("👤 Top Usuarios")

top_users = (
    df["TargetUserName"]
    .value_counts()
    .head(10)
    .reset_index()
)

top_users.columns = [
    "Usuario",
    "Eventos"
]

fig_users = px.bar(
    top_users,
    x="Usuario",
    y="Eventos",
    template="plotly_dark"
)

st.plotly_chart(
    fig_users,
    use_container_width=True
)

# =========================
# TOP IPS
# =========================

st.subheader("🌐 Top IPs")

ips = df[
    (df["IpAddress"].notna())
    & (df["IpAddress"] != "-")
]

if len(ips) > 0:

    top_ips = (
        ips["IpAddress"]
        .value_counts()
        .head(10)
        .reset_index()
    )

    top_ips.columns = [
        "IP",
        "Eventos"
    ]

    fig_ips = px.bar(
        top_ips,
        x="IP",
        y="Eventos",
        template="plotly_dark"
    )

    st.plotly_chart(
        fig_ips,
        use_container_width=True
    )

# =========================
# BRUTE FORCE DETECTION
# =========================

st.subheader("🔥 Brute Force Detection")

failed = df[df["EventID"] == 4625].copy()

if len(failed) > 0:

    failed["TimeCreated"] = pd.to_datetime(
        failed["TimeCreated"]
    )

    alerts = []

    for user in failed["TargetUserName"].unique():

        user_events = failed[
            failed["TargetUserName"] == user
        ].sort_values("TimeCreated")

        times = list(user_events["TimeCreated"])

        for i in range(len(times)):

            count = 1

            for j in range(i + 1, len(times)):

                delta = (
                    times[j] - times[i]
                ).total_seconds()

                if delta <= 600:
                    count += 1
                else:
                    break

            if count >= 5:

                alerts.append({
                    "User": user,
                    "Attempts": count,
                    "Start": times[i]
                })

                break

    if alerts:

        for alert in alerts:

            st.error(
                f"🚨 {alert['User']} realizó "
                f"{alert['Attempts']} logons fallidos "
                f"en menos de 10 minutos."
            )

    else:

        st.success(
            "No se detectaron ataques de fuerza bruta."
        )

# =========================
# EVENTOS CRITICOS
# =========================

st.subheader("🚨 Eventos Críticos")

critical_map = {
    4720: "Nuevo Usuario",
    4732: "Agregado a Administradores",
    4740: "Cuenta Bloqueada",
    4697: "Servicio Instalado",
    4104: "PowerShell"
}

for event_id, desc in critical_map.items():

    count = len(
        df[df["EventID"] == event_id]
    )

    if count > 0:

        st.error(
            f"{desc}: {count} eventos"
        )

# =========================
# MITRE ATTACK
# =========================

st.subheader("🎯 MITRE ATT&CK")

mitre = pd.DataFrame({

    "EventID":[
        4625,
        4720,
        4732,
        4697,
        4104
    ],

    "MITRE":[
        "T1110",
        "T1136",
        "T1098",
        "T1543",
        "T1059.001"
    ],

    "Technique":[
        "Brute Force",
        "Create Account",
        "Account Manipulation",
        "Service Creation",
        "PowerShell"
    ]
})

st.dataframe(
    mitre,
    use_container_width=True
)

# =========================
# SEVERIDAD DE EVENTOS
# =========================

st.subheader("⚠️ Event Severity Matrix")

severity = pd.DataFrame({

    "EventID":[
        4624,
        4625,
        4720,
        4732,
        4740,
        4697,
        4104
    ],

    "Description":[
        "Successful Logon",
        "Failed Logon",
        "User Created",
        "Added to Administrators",
        "Account Locked",
        "Service Installed",
        "PowerShell Execution"
    ],

    "Severity":[
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
        "HIGH",
        "CRITICAL",
        "CRITICAL"
    ]
})

st.dataframe(
    severity,
    use_container_width=True
)

# =========================
# RECOMENDACIONES
# =========================

st.subheader("🛡 Threat Response Recommendations")

if len(df[df["EventID"] == 4740]) > 0:
    st.warning(
        "Investigar cuentas bloqueadas."
    )

if len(df[df["EventID"] == 4720]) > 0:
    st.warning(
        "Verificar nuevas cuentas creadas."
    )

if len(df[df["EventID"] == 4732]) > 0:
    st.warning(
        "Revisar cambios en grupos privilegiados."
    )

if len(df[df["EventID"] == 4104]) > 0:
    st.warning(
        "Investigar actividad PowerShell."
    )

# =========================
# TABLA FINAL
# =========================

# =========================
# INCIDENT TIMELINE
# =========================

st.subheader("🕒 Incident Timeline")

timeline_df = df[
    df["EventID"].isin(
        [4625,4624,4720,4732,4740,4697,4104]
    )
]

timeline_df = timeline_df.sort_values(
    "TimeCreated",
    ascending=False
)

st.dataframe(
    timeline_df[
        [
            "TimeCreated",
            "EventID",
            "TargetUserName",
            "Computer"
        ]
    ].head(50),
    use_container_width=True
)

st.subheader("📄 Últimos Eventos")

st.dataframe(
    df.sort_values(
        "TimeCreated",
        ascending=False
    ).head(100),
    use_container_width=True
)

