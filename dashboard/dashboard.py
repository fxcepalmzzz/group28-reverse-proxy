
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import psutil
import re
import subprocess
from datetime import datetime, timedelta
from streamlit_autorefresh import st_autorefresh
from logparser import parse_logs  # Must include ModSecurity + access.log
from llm_assistant import ask_llm

# Auto-refresh every 30 seconds
if st.session_state.get("selected_tab", " Overview") != " SOC Assistant":
    st_autorefresh(interval=30 * 1000, key="datarefresh")


st.set_page_config(page_title="SOC Dashboard", layout="wide")

st.markdown("""
    <style>
        .block-container { padding-top: 2rem !important; }
        h1 { font-size: 2.5rem !important; }
        .tab-button {
            display: block;
            background-color: #2c2f33;
            color: white;
            padding: 0.75rem 1.5rem;
            margin: 0.3rem 0;
            border: none;
            border-radius: 5px;
            width: 100%;
            text-align: left;
            cursor: pointer;
            font-size: 1rem;
        }
        .tab-button:hover { background-color: #40444b; }
        .tab-button.selected {
            background-color: #5865f2;
            font-weight: bold;
        }
    </style>
""", unsafe_allow_html=True)

st.markdown("<h1 style='text-align: center; color: white;'> Security Operations Dashboard</h1>", unsafe_allow_html=True)

# Manual refresh button (optional)
if st.sidebar.button(" Manual Refresh Logs"):
    st.rerun()

# Always load latest logs
df = parse_logs()
if df.empty:
    st.warning("No logs parsed from access.log or modsec_audit.log.")
    st.stop()

# Confirm freshness
st.sidebar.markdown(" Logs reloaded fresh every 30s (auto) or manually")

# Drop timezone for compatibility
df["Timestamp"] = df["Timestamp"].dt.tz_localize(None)
df.sort_values("Timestamp", inplace=True)
# Sidebar navigation
st.sidebar.markdown("##  Navigation")

tabs = {
    " Overview": "overview",
    " Threat Trends": "trends",
    " Raw Logs": "logs",
    " Live Alerts": "alerts",
    " Remediation Support": "remediation",
    " Threat Hunting": "threat_hunting",
    " SOC Assistant": "assistant"
}

for tab_name in tabs:
    if st.sidebar.button(tab_name, key=tab_name, use_container_width=True):
        st.session_state["selected_tab"] = tab_name

if "selected_tab" not in st.session_state:
    st.session_state["selected_tab"] = list(tabs.keys())[0]

selected_tab = st.session_state["selected_tab"]

# Sidebar filters
ip_filter = port_filter = protocol_filter = severity_filter = date1 = date2 = None
if tabs[selected_tab] == "logs":
    st.sidebar.markdown("---")
    st.sidebar.header("🔍 Filters")
    date1 = pd.to_datetime(st.sidebar.date_input("Start Date", df["Timestamp"].min()))
    date2 = pd.to_datetime(st.sidebar.date_input("End Date", df["Timestamp"].max()))
    ip_filter = st.sidebar.multiselect("Source IP", df["SourceIP"].unique())
    port_filter = st.sidebar.multiselect("Destination Port", df["DestPort"].unique())
    protocol_filter = st.sidebar.multiselect("Protocol", df["Protocol"].unique())
    severity_filter = st.sidebar.multiselect("Severity", df["Severity"].unique())

# Overview tab
if tabs[selected_tab] == "overview":
    top1, top2 = st.columns([1, 2])
    with top1:
        st.subheader("Top Source IPs")
        st.dataframe(df["SourceIP"].value_counts().head(5))

    with top2:
        chart_type = st.radio("Select Chart Type", ["Pie Chart", "Bar Chart"], horizontal=True)

        if chart_type == "Bar Chart":
            st.subheader(" Event Type Breakdown (Bar Chart)")
            event_counts = df["EventType"].value_counts().reset_index()
            event_counts.columns = ["EventType", "Count"]
            fig = px.bar(event_counts, x="EventType", y="Count", color="EventType", text_auto=True)
            fig.update_layout(xaxis_title="Event Type", yaxis_title="Number of Events")
            st.plotly_chart(fig, use_container_width=True)

        elif chart_type == "Pie Chart":
            st.subheader(" Event Type Breakdown (Pie Chart)")
            fig = px.pie(df, names="EventType", hole=0.4)
            st.plotly_chart(fig, use_container_width=True)


    def ping_status(ip):
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '1', ip],
                                    stdout=subprocess.DEVNULL)
            return "🟢 Active" if result.returncode == 0 else "🔴 Inactive"
        except Exception:
            return "🔴 Inactive"

    servers = [
        {"name": "HTTP Server1", "ip": "192.168.100.20"},
        {"name": "HTTP Server2", "ip": "192.168.100.30"},
        {"name": "Windows Server", "ip": "192.168.100.40"},
    ]

    status_list = [ping_status(server["ip"]) for server in servers]

    server_table = pd.DataFrame({
        "Server": [s["name"] for s in servers],
        "Status": status_list
    })

    st.subheader("Server Health Table")
    st.table(server_table.set_index("Server"))

# Trends tab
elif tabs[selected_tab] == "trends":
    st.subheader(" Threat Activity Over Time")
    df["Hour"] = df["Timestamp"].dt.strftime("%Y-%m-%d %H")
    timeline = df.groupby(["Hour", "EventType"]).size().reset_index(name="Count")
    fig = px.line(timeline, x="Hour", y="Count", color="EventType")
    st.plotly_chart(fig, use_container_width=True)

    b1, b2, b3 = st.columns(3)
    with b1:
        st.subheader("Zone Distribution")
        fig = px.bar(df, x="Zone", color="Severity")
        st.plotly_chart(fig, use_container_width=True)
    with b2:
        st.subheader("Destination Ports")
        fig = px.bar(df, x="DestPort", color="EventType")
        st.plotly_chart(fig, use_container_width=True)
    with b3:
        st.subheader("Protocol Usage")
        fig = px.bar(df, x="Protocol", color="EventType")
        st.plotly_chart(fig, use_container_width=True)

# Logs tab (raw viewer)
elif tabs[selected_tab] == "logs":
    end_datetime = date2 + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)
    df_filtered = df[(df["Timestamp"] >= date1) & (df["Timestamp"] <= end_datetime)].copy()
    if ip_filter:
        df_filtered = df_filtered[df_filtered["SourceIP"].isin(ip_filter)]
    if port_filter:
        df_filtered = df_filtered[df_filtered["DestPort"].isin(port_filter)]
    if protocol_filter:
        df_filtered = df_filtered[df_filtered["Protocol"].isin(protocol_filter)]
    if severity_filter:
        df_filtered = df_filtered[df_filtered["Severity"].isin(severity_filter)]

    st.subheader(f" Raw Log Viewer ({len(df_filtered)} logs)")
    st.dataframe(df_filtered)  # No limit, no style
    csv = df_filtered.to_csv(index=False).encode('utf-8')
    st.download_button("Download Filtered Logs", data=csv, file_name="filtered_logs.csv", mime="text/csv")

elif tabs[selected_tab] == "alerts":
    st.subheader(" Live Alerts / Incident Queue")

    recent_alerts = df[df["Severity"].isin(["High", "Critical"])]
    recent_alerts = recent_alerts.sort_values("Timestamp", ascending=False).head(50)

    st.sidebar.markdown("---")
    st.sidebar.header(" Alert Filters")
    alert_statuses = ["Open", "Investigating", "Resolved"]

    alert_data = recent_alerts.copy()
    statuses = (["Open", "Investigating", "Resolved"] * ((len(alert_data) // 3) + 1))[:len(alert_data)]
    alert_data["Status"] = statuses

    status_filter = st.sidebar.multiselect("Status", alert_statuses)
    if status_filter:
        alert_data = alert_data[alert_data["Status"].isin(status_filter)]

    # Color rows by severity
    severity_color = {
        "High": "tomato",
        "Critical": "red",
        "Medium": "orange",
        "Low": "#ffffcc"
    }

    def color_row(row):
        return [f'background-color: {severity_color.get(row.Severity, "white")}' for _ in row]

    st.dataframe(
        alert_data[[
            "Timestamp", "Severity", "EventType", "SourceIP", "Status"
        ]].rename(columns={"Timestamp": "Time Detected"}).style.apply(color_row, axis=1)
    )


elif tabs[selected_tab] == "remediation":
    st.subheader(" Remediation Support")

    st.markdown("""
    This section auto-detects the most severe recent attack and provides suggested remediation steps.
    You can also manually search for other attack types below.
    """)

    # Define remediation steps dictionary
    remediation_steps = {
    "SQLi": [
        "- [ ] Validate input sanitization on vulnerable endpoints",
        "- [ ] Block offending IP via firewall or WAF",
        "- [ ] Review database logs for unauthorized access",
        "- [ ] Deploy WAF rules to detect common SQLi patterns"
    ],
    "XSS": [
        "- [ ] Escape or encode all user input on output",
        "- [ ] Review affected endpoints and sanitize inputs",
        "- [ ] Deploy Content Security Policy (CSP) headers",
        "- [ ] Clear browser caches for any vulnerable sessions"
    ],
    "Port Scan": [
        "- [ ] Run internal Nmap to verify exposed ports",
        "- [ ] Block scanner IP or apply rate limiting rules",
        "- [ ] Audit exposed services for unnecessary exposure",
        "- [ ] Notify affected asset owners"
    ],
    "Malicious Bot": [
        "- [ ] Identify bot's user-agent and block at web server",
        "- [ ] Apply CAPTCHA or rate-limiting on affected endpoints",
        "- [ ] Check if bot accessed sensitive paths"
    ],
    "Recon Tool": [
        "- [ ] Monitor for enumeration patterns (e.g., /admin, /login)",
        "- [ ] Enforce stricter rate limits",
        "- [ ] Review for path discovery vulnerabilities"
    ],
    "Brute Force": [
        "- [ ] Lock accounts after failed attempts",
        "- [ ] Enforce strong password policies",
        "- [ ] Enable CAPTCHA on login forms",
        "- [ ] Monitor and block repeated login attempts"
    ],
    "LFI": [
        "- [ ] Sanitize file path inputs",
        "- [ ] Use allowlists for file access",
        "- [ ] Disable unnecessary includes or file access functions",
        "- [ ] Harden web server configuration"
    ],
    "RFI": [
        "- [ ] Disable URL-based file includes in server configs",
        "- [ ] Sanitize and validate external URLs",
        "- [ ] Block known malicious remote URLs/domains",
        "- [ ] Use application-level firewalls for dynamic includes"
    ],
    "Command Injection": [
        "- [ ] Never pass user input to OS/system commands directly",
        "- [ ] Use secure APIs instead of shell execution",
        "- [ ] Employ input allowlists",
        "- [ ] Monitor logs for suspicious command execution patterns"
    ],
    "Path Traversal": [
        "- [ ] Restrict input to known safe directories/files",
        "- [ ] Normalize and sanitize path inputs",
        "- [ ] Disable symbolic link following where not needed",
        "- [ ] Log and alert on abnormal path patterns (e.g., '../')"
    ],
    "DoS": [
        "- [ ] Enable rate-limiting on exposed endpoints",
        "- [ ] Deploy DDoS mitigation services (e.g., Cloudflare, WAF)",
        "- [ ] Monitor bandwidth and traffic spikes",
        "- [ ] Set automatic rules for IP blacklisting based on abuse"
    ],
    "Insecure Headers": [
        "- [ ] Add security headers (CSP, X-Frame-Options, HSTS)",
        "- [ ] Scan headers using tools like securityheaders.com",
        "- [ ] Validate header configuration in NGINX/Apache"
    ],
    "Credential Stuffing": [
        "- [ ] Monitor for login attempts using breached credentials",
        "- [ ] Enforce MFA (multi-factor authentication)",
        "- [ ] Integrate with Have I Been Pwned API for known leaks",
        "- [ ] Add login anomaly detection"
    ],
    "Directory Listing": [
        "- [ ] Disable directory listing in the web server config",
        "- [ ] Add index.html to prevent default listings",
        "- [ ] Limit permissions on publicly exposed directories"
    ],
    "Broken Auth": [
        "- [ ] Implement secure session management",
        "- [ ] Rotate session tokens after login",
        "- [ ] Enforce MFA and strict session timeout",
        "- [ ] Validate authorization server-side for every action"
    ],
        "R.U.D.Y. Attack Attempt": [
        "- [ ] Detect slow POST connections using rate/time thresholds",
        "- [ ] Deploy timeout rules in WAF or web server config",
        "- [ ] Use traffic profiling to identify abnormally long requests"
    ],
    "Sensitive Path Access": [
        "- [ ] Monitor and restrict access to sensitive directories (e.g., /admin, /.git)",
        "- [ ] Implement authentication and role-based access control",
        "- [ ] Obfuscate sensitive paths where appropriate"
    ],
    "Possible Slowloris (TLS Exhaustion)": [
        "- [ ] Limit number of concurrent connections per IP",
        "- [ ] Use `keepalive_timeout` and `client_body_timeout` settings in NGINX",
        "- [ ] Deploy reverse proxies or CDNs that can mitigate Slowloris attacks"
    ],
    "Code Injection": [
        "- [ ] Sanitize and validate all user inputs",
        "- [ ] Avoid dynamic code execution from untrusted sources",
        "- [ ] Implement secure coding practices and perform code reviews"
    ],
    "Uncommon HTTP Method": [
        "- [ ] Only allow necessary HTTP methods (e.g., GET, POST)",
        "- [ ] Block unused or risky methods (e.g., TRACE, CONNECT)",
        "- [ ] Monitor for suspicious methods in logs"
    ],
    "Malicious Upload": [
        "- [ ] Validate file types and restrict executable uploads",
        "- [ ] Use antivirus scanning on all uploaded files",
        "- [ ] Store uploads outside the web root"
    ],
    "Open Redirect": [
        "- [ ] Avoid using user-controlled input in redirect URLs",
        "- [ ] Implement redirect allowlists",
        "- [ ] Validate target URLs against internal safe domains"
    ]

}


    # Get most severe attack by priority of severity
    severity_levels = ["Critical", "High", "Medium", "Low"]
    top_attacks = []

    for severity in severity_levels:
        top_severity = df[df["Severity"] == severity]
        if not top_severity.empty:
            top_attacks = top_severity["EventType"].value_counts().index.tolist()
            break

    # Show auto-detected top attack
    if top_attacks:
        st.markdown(f"###  Auto-Detected Most Severe Attacks")
        for attack in top_attacks:
            if attack in remediation_steps:
                with st.expander(f" Remediation Steps for {attack}", expanded=False):
                    for step in remediation_steps[attack]:
                        st.markdown(step)
            else:
                st.info(f"No remediation steps available for **{attack}**.")
    else:
        st.info("No high severity attacks found or no remediation steps available.")

    # Manual search dropdown
    st.markdown("---")
    st.markdown("###  Search Remediation for Other Attacks")
    selected_attack = st.selectbox("Choose an attack type", list(remediation_steps.keys()))

    if selected_attack:
        with st.expander(f" Remediation Steps for {selected_attack}", expanded=False):
            for step in remediation_steps[selected_attack]:
                st.markdown(step)

elif tabs[selected_tab] == "threat_hunting":
    st.subheader(" Threat Hunting Workspace")

    st.markdown("""
    Use this section to explore logs with flexible filters, keyword/regex search, and anomaly detection tools.
    """)

    # Sidebar filters
    st.sidebar.markdown("---")
    st.sidebar.header(" Threat Hunting Filters")

    date1 = pd.to_datetime(st.sidebar.date_input("Start Date", df["Timestamp"].min()))
    date2 = pd.to_datetime(st.sidebar.date_input("End Date", df["Timestamp"].max()))

    event_filter = st.sidebar.multiselect("Event Type", df["EventType"].unique())
    ip_filter = st.sidebar.multiselect("Source IP", df["SourceIP"].unique())
    severity_filter = st.sidebar.multiselect("Severity", df["Severity"].unique())
    protocol_filter = st.sidebar.multiselect("Protocol", df["Protocol"].unique())

    st.sidebar.markdown("####  Keyword/Pattern Search")
    search_keyword = st.sidebar.text_input("Enter keyword or regex (e.g., /admin, union, bot)")

    # Filter the DataFrame
    # Filter the DataFrame
    end_datetime = date2 + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)
    df_filtered = df[(df["Timestamp"] >= date1) & (df["Timestamp"] <= end_datetime)].copy()


    if event_filter:
        df_filtered = df_filtered[df_filtered["EventType"].isin(event_filter)]
    if ip_filter:
        df_filtered = df_filtered[df_filtered["SourceIP"].isin(ip_filter)]
    if severity_filter:
        df_filtered = df_filtered[df_filtered["Severity"].isin(severity_filter)]
    if protocol_filter:
        df_filtered = df_filtered[df_filtered["Protocol"].isin(protocol_filter)]

    if search_keyword:
        try:
            pattern = re.compile(search_keyword, re.IGNORECASE)
            df_filtered = df_filtered[df_filtered.apply(lambda row: bool(pattern.search(str(row))), axis=1)]
        except re.error:
            st.warning("Invalid regex pattern.")
        
    # Display filtered results

    from anomalydetector import detect_ml_anomalies

    st.markdown("### Machine Learning-Based Anomalies")
    ml_anomalies_df = detect_ml_anomalies(df_filtered)

    # Prevent ML error if filtered logs are empty
    if df_filtered.empty:
        ml_anomalies_df = pd.DataFrame()
        st.info("No logs matched your filters or keyword search.")
    else:
        ml_anomalies_df = detect_ml_anomalies(df_filtered)

    with st.expander("Understanding Machine Learning-Based Anomaly Detection"):
        st.markdown("""
        This system uses the **Isolation Forest** algorithm to identify unusual behavior in web traffic logs.

        **Features Used:**
        - Hour of the request
        - Whether the access occurred during standard work hours (08:00–18:00)
        - Whether the request happened on a weekend
        - Whether the IP is being seen for the first time

        **Configuration:**
        - The model is trained automatically using all log entries
        - It is configured to label approximately **5% of entries as anomalies**, based on behavioral patterns (via `contamination=0.05`)
        - Data is normalized before training using `MinMaxScaler`

        **Anomaly Score:**
        - Each entry receives a **score** (`ML_AnomalyScore`) based on how different it is from typical patterns
        - Scores **closer to 0** represent normal behavior
        - **More negative scores** (e.g., `-0.15`) indicate stronger anomalies
        - Entries in the lowest 5% of scores are flagged as outliers (`ML_AnomalyFlag = -1`)

        **Interpretability Fields:**
        - `IsWorkHours`: True if the request occurred between 08:00 and 18:00
        - `IsWeekend`: True if the request occurred on a Saturday or Sunday
        - `IsFirstSeenIP`: True if the IP address is accessing the site for the first time

        These indicators help explain why a specific log was flagged as anomalous and support faster investigation.
        """)


    # Filter controls
    st.markdown("#### Anomaly Filters")
    col1, _ = st.columns(2)
    with col1:
        filter_non_workhours_weekends = st.checkbox("Remove Non-Work Hour & Weekend Access", value=False)

    filtered_ml_df = ml_anomalies_df.copy()

    # Always remove known attacks
    known_attacks = [
        "SQLi", "XSS", "Path Traversal", "Open Redirect",
        "Sensitive Path Access", "Malicious Bot", "Malicious Upload", "Code Injection",
        "Possible Slowloris (TLS Exhaustion)", "Uncommon HTTP Method",
        "R.U.D.Y. Attack Attempt"
    ]
    if "EventType" in filtered_ml_df.columns:
        filtered_ml_df = filtered_ml_df[~filtered_ml_df["EventType"].isin(known_attacks)]


    if filter_non_workhours_weekends:
        filtered_ml_df = filtered_ml_df[
            (filtered_ml_df["IsWorkHours"] == True) & (filtered_ml_df["IsWeekend"] == False)
        ]


    # Show ML anomalies
    if not filtered_ml_df.empty:
        st.success(f"{len(filtered_ml_df)} ML anomalies shown based on current filters.")
        st.dataframe(filtered_ml_df[[
            "Timestamp", "EventType", "SourceIP", "Action",
            "Protocol", "ML_AnomalyScore","IsWorkHours", "IsWeekend", "AnomalyReason"
        ]])
        csv = filtered_ml_df.to_csv(index=False).encode("utf-8")
        st.download_button("Download Filtered Anomalies", data=csv, file_name="filtered_ml_anomalies.csv", mime="text/csv")
    else:
        st.info("No ML anomalies matched current filters.")

    #  RAW LOG VIEWER (always shown below ML)
    st.markdown(f"### Raw Log Viewer ({len(df_filtered)} entries)")
    st.dataframe(df_filtered)

    csv = df_filtered.to_csv(index=False).encode("utf-8")
    st.download_button(" Download Raw Logs", data=csv, file_name="threat_hunting_logs.csv", mime="text/csv")


    # Top Event Types 
    st.markdown("###  Most Common Event Types")
    top_events = df_filtered["EventType"].value_counts().reset_index()
    top_events.columns = ["EventType", "Count"]
    fig_event = px.bar(top_events, x="EventType", y="Count", title="Top Event Types", text="Count")
    fig_event.update_layout(xaxis_tickangle=0)  # horizontal labels
    fig_event.update_traces(textposition='outside')
    fig_event.update_layout(
    xaxis_tickangle=0,
    margin=dict(t=60) )
    st.plotly_chart(fig_event, use_container_width=True)

elif tabs[selected_tab] == "assistant":
    st.subheader(" SOC Assistant Chatbot (LLM-Powered)")

    st.markdown("""
    Ask anything about cybersecurity, logs, incident response, NGINX, WAF, attacks, etc.

    Examples:
    - *How do I block an IP in ModSecurity?*
    - *What is SQL injection and how do I prevent it?*
    - *Where are NGINX logs stored?*
    """)

    query = st.text_input("💬 Ask a question:")
    if query:
        with st.spinner("Thinking..."):
            answer = ask_llm(query)
        st.markdown(f"**💡 Assistant:**\n\n{answer}")

