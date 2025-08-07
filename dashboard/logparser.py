import re
import json
import pandas as pd
from datetime import datetime, timedelta

def parse_nginx_access_logs():
    log_path = "/var/log/nginx/access.log"
    data = []

    with open(log_path, "r") as f:
        for line in f:
            parts = re.match(r'(\S+) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+) ".*?" "(.*?)"', line)
            if not parts:
                continue

            ip = parts.group(1)
            timestamp_str = parts.group(2)
            request = parts.group(3)
            status = parts.group(4)
            user_agent = parts.group(6)

            try:
                timestamp = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z") 
            except Exception:
                continue

            # Default values
            action = "Allowed"
            protocol = "HTTPS"  # will adjust later if needed

            # Detect malformed TLS-style Slowloris connections (binary gibberish)
            if request.startswith(r"\x16\x03") or "\\x16\\x03" in request or re.match(r'\\x[0-9a-fA-F]{2}', request):
                event_type = "Possible Slowloris (TLS Exhaustion)"
                severity = "High"
                protocol = "TLS"
                action = "Blocked"
                data.append({
                    "Timestamp": timestamp,
                    "Severity": severity,
                    "EventType": event_type,
                    "Action": action,
                    "SourceIP": ip,
                    "DestPort": "443",
                    "Protocol": protocol,
                    "Zone": "Reverse Proxy"
                })
                continue

            try:
                method, path, proto = request.split()
                protocol = proto.replace("/", "")
            except ValueError:
                continue  # skip malformed

            ua = user_agent.lower()
            path_lower = path.lower()
            event_type = "Normal"
            severity = "Low"

            # Expanded detection logic
            if any(bot in ua for bot in ["evilbot", "scrapy", "python-requests", "curl", "wget", "go-http-client"]):
                event_type = "Malicious Bot"
                severity = "High"
            elif method in ["DELETE", "PUT"] or (method == "POST" and "/delete" in path_lower):
                event_type = "Uncommon HTTP Method"
                severity = "High"
            elif re.search(r"(upload|submit).(php|jsp|aspx)", path_lower) and re.search(r"\.(php|jsp|exe|sh)\.jpg", path_lower):
                event_type = "Malicious Upload"
                severity = "Critical"
            elif re.search(r"(?:\.\./){2,}|%2e%2e%2f|%2e%2e/", path_lower) and any(p in path_lower for p in ["passwd", "shadow", "boot.ini", "win.ini"]):
                event_type = "Path Traversal"
                severity = "Critical"
            elif re.search(r"[\|\;\&\`]", path_lower) and any(k in path_lower for k in ["ping", "curl", "wget", "nc", "host=", "cmd=", "exec="]):
                event_type = "Code Injection"
                severity = "Critical"
            elif re.search(r"(<script|alert%28|%3cscript|onerror=|svg/on)", path_lower, re.IGNORECASE):
                event_type = "XSS"
                severity = "Critical"
            elif re.search(r"(redirect|url|next|target)=https?%3a%2f%2f|=http[s]?:\/\/(?!mrproxy\.test)", path_lower):
                event_type = "Open Redirect"
                severity = "High"
            elif any(sens in path_lower for sens in ["/admin", "/config", "/env", "/backup", "/.git", "/.env"]):
                event_type = "Sensitive Path Access"
                severity = "Critical"
            elif re.search(r"(id|user)=('|%27)?[^ ]*?(or|%6f%72|%4f%52).*?(=|like|>|<)", path_lower) or "union select" in path_lower:
                event_type = "SQLi"
                severity = "Critical"
            elif status == "400" and "go-http-client" in ua:
                event_type = "R.U.D.Y. Attack Attempt"
                severity = "High"

            # Decide action based on status
            if status.startswith("4") or status.startswith("5"):
                action = "Blocked"
                if event_type == "Normal":
                    event_type = "Blocked"
                    severity = "Medium"

            data.append({
                "Timestamp": timestamp,
                "Severity": severity,
                "EventType": event_type,
                "Action": action,
                "SourceIP": ip,
                "DestPort": "443",
                "Protocol": protocol,
                "Zone": "Reverse Proxy"
            })

    return pd.DataFrame(data)


def parse_modsec_logs():
    log_path = "/var/log/modsec_audit.log"
    data = []
    entry = ""
    collecting = False

    with open(log_path, "r") as f:
        for line in f:
            if line.startswith('---') and 'H--' in line:
                collecting = True
                entry = ""
            elif line.startswith('---') and 'Z--' in line:
                collecting = False
                timestamp = None
                ip = "-"
                uri = "/"

                try:
                    time_match = re.search(r'Date: (.+)', entry)
                    if time_match:
                        gmt_time = datetime.strptime(time_match.group(1).strip(), "%a, %d %b %Y %H:%M:%S GMT")
                        timestamp = gmt_time + timedelta(hours=8)

                    ip_match = re.search(r'\[hostname "([^"]+)"\]', entry)
                    ip = ip_match.group(1) if ip_match else "-"

                    uri_match = re.search(r'\[uri "([^"]+)"\]', entry)
                    uri = uri_match.group(1) if uri_match else "/"

                    messages = re.findall(r'ModSecurity: (.*?)\[severity "(\d)"\].*?\[msg "([^"]+)"\]', entry)
                    for raw_msg, sev_code, msg in messages:
                        severity_map = {
                            "0": "Critical",
                            "1": "High",
                            "2": "Medium",
                            "3": "Low"
                        }
                        data.append({
                            "Timestamp": timestamp,
                            "Severity": severity_map.get(sev_code, "Low"),
                            "EventType": msg,
                            "Action": "Blocked",
                            "SourceIP": ip,
                            "DestPort": "443",
                            "Protocol": "HTTPS",
                            "Zone": "WAF (ModSecurity)"
                        })
                except Exception:
                    continue
            elif collecting:
                entry += line

    return pd.DataFrame(data)

def parse_logs():
    df1 = parse_nginx_access_logs()
    df2 = parse_modsec_logs()
    df = pd.concat([df1, df2], ignore_index=True)
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    return df
