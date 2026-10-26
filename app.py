
import streamlit as st
import sqlite3
from datetime import datetime, timedelta

DB = "login_activity.db"

st.set_page_config(
    page_title="Suspicious Login Detection",
    page_icon="🔐",
    layout="wide"
)

# Demo accounts only — not for production use
ACCOUNTS = {
    "admin": {"password": "admin123", "role": "Admin"},
    "user": {"password": "user123", "role": "User"}
}

# Initialize database
def init_db():
    with sqlite3.connect(DB) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                ip_address TEXT,
                event_time TEXT,
                success INTEGER,
                alert TEXT,
                severity TEXT
            )
        """)

init_db()

def analyze_login(username, ip, success):
    """Apply simple demo detection rules."""
    now = datetime.now()
    alert = "Normal login activity"
    severity = "Low"

    with sqlite3.connect(DB) as conn:
        # Count failed attempts for this username and IP
        since = (now - timedelta(minutes=10)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        failures = conn.execute("""
            SELECT COUNT(*) FROM login_logs
            WHERE username = ? AND ip_address = ?
              AND success = 0 AND event_time >= ?
        """, (username, ip, since)).fetchone()[0]

        if not success and failures >= 2:
            alert = "Repeated failed login attempts"
            severity = "High"

        elif success and ip not in ("192.0.2.10", "127.0.0.1"):
            alert = "Successful login from an unrecognized demo IP"
            severity = "Medium"

        elif not success:
            alert = "Failed login attempt"
            severity = "Medium"

        conn.execute("""
            INSERT INTO login_logs
            (username, ip_address, event_time, success, alert, severity)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            username,
            ip,
            now.strftime("%Y-%m-%d %H:%M:%S"),
            int(success),
            alert,
            severity
        ))

    return alert, severity


# Session state
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "role" not in st.session_state:
    st.session_state.role = ""

st.sidebar.title("🔐 Login Security")
st.sidebar.caption("Suspicious Login Activity Detection")

# Login page
if not st.session_state.authenticated:
    st.title("🔐 Suspicious Login Activity Detection System")
    st.write(
        "Monitor login attempts and identify suspicious patterns."
    )

    st.info(
        "Demo accounts: admin / admin123 or user / user123"
    )

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        ip = st.text_input(
            "Demo IP address",
            value="192.0.2.10",
            help="Simulation only. This is not your actual network IP."
        )
        submit = st.form_submit_button("Sign In", type="primary")

    if submit:
        if not username.strip() or not ip.strip():
            st.error("Enter a username and demo IP address.")
        else:
            valid = (
                username in ACCOUNTS
                and ACCOUNTS[username]["password"] == password
            )

            alert, severity = analyze_login(
                username.strip(), ip.strip(), valid
            )

            if valid:
                st.session_state.authenticated = True
                st.session_state.username = username
                st.session_state.role = ACCOUNTS[username]["role"]
                st.rerun()
            else:
                st.error("Login failed. Check your credentials.")
                if severity == "High":
                    st.warning(
                        "Security alert: repeated failed login attempts detected."
                    )
                st.caption(f"Detection result: {alert}")

    st.stop()

# Logged-in sidebar
st.sidebar.success(
    f"Signed in: {st.session_state.username}"
)
st.sidebar.write(f"Role: {st.session_state.role}")

if st.sidebar.button("Log Out"):
    st.session_state.authenticated = False
    st.session_state.username = ""
    st.session_state.role = ""
    st.rerun()

# User page
if st.session_state.role == "User":
    st.title("👤 User Portal")
    st.subheader("Login Activity")
    st.write(
        "Your demo account is signed in. Suspicious login events "
        "are recorded for the administrator to review."
    )

    with sqlite3.connect(DB) as conn:
        rows = conn.execute("""
            SELECT event_time, ip_address, success, alert, severity
            FROM login_logs
            WHERE username = ?
            ORDER BY id DESC LIMIT 20
        """, (st.session_state.username,)).fetchall()

    if rows:
        st.dataframe(
            [{
                "Time": r[0],
                "Demo IP": r[1],
                "Result": "Success" if r[2] else "Failed",
                "Detection": r[3],
                "Severity": r[4]
            } for r in rows],
            use_container_width=True
        )
    else:
        st.info("No login events available.")

# Admin dashboard
else:
    st.title("📊 Security Monitoring Dashboard")
    st.write("Review login activity and investigate security alerts.")

    with sqlite3.connect(DB) as conn:
        logs = conn.execute("""
            SELECT id, username, ip_address, event_time,
                   success, alert, severity
            FROM login_logs
            ORDER BY id DESC
        """).fetchall()

    total = len(logs)
    failed = sum(1 for r in logs if r[4] == 0)
    suspicious = sum(
        1 for r in logs
        if r[5] != "Normal login activity"
    )
    high = sum(1 for r in logs if r[6] == "High")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Attempts", total)
    c2.metric("Failed Logins", failed)
    c3.metric("Flagged Events", suspicious)
    c4.metric("High Severity", high)

    st.divider()
    st.subheader("🚨 Login Activity and Alerts")

    search = st.text_input(
        "Search username or demo IP"
    )
    severity_filter = st.selectbox(
        "Filter by severity",
        ["All", "Low", "Medium", "High"]
    )

    filtered = []
    for r in logs:
        if search.lower() not in (
            r[1] + " " + r[2]
        ).lower():
            continue
        if severity_filter != "All" and r[6] != severity_filter:
            continue
        filtered.append(r)

    if filtered:
        st.dataframe(
            [{
                "ID": r[0],
                "Username": r[1],
                "Demo IP": r[2],
                "Time": r[3],
                "Result": "Success" if r[4] else "Failed",
                "Alert": r[5],
                "Severity": r[6]
            } for r in filtered],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No matching login events.")

    st.caption(
        "Educational prototype: detection rules are illustrative. "
        "IP addresses are entered for simulation and are not verified "
        "against real network traffic."
    )
