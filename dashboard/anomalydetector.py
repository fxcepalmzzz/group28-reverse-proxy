import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler

def detect_ml_anomalies(df):
    if df.empty:
        return pd.DataFrame()

    df = df.copy()


    # Feature Engineering
    df["Hour"] = df["Timestamp"].dt.hour
    df["IsWeekend"] = df["Timestamp"].dt.dayofweek >= 5
    df["IsWorkHours"] = df["Hour"].between(8, 18)

    # Determine First-Seen IPs
    first_seen_ips = df.sort_values("Timestamp").drop_duplicates("SourceIP", keep="first")
    df["IsFirstSeenIP"] = df["SourceIP"].isin(first_seen_ips["SourceIP"])

    # Select numerical features for ML
    feature_df = df[["Hour", "IsWeekend", "IsWorkHours", "IsFirstSeenIP"]].astype(float)

    # Normalize features
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(feature_df)

    # Fit Isolation Forest model
    model = IsolationForest(contamination=0.05, random_state=42)
    preds = model.fit_predict(X_scaled)

    df["ML_AnomalyScore"] = model.decision_function(X_scaled)
    df["ML_AnomalyFlag"] = preds

    # Filter anomalies
    anomalies = df[df["ML_AnomalyFlag"] == -1].copy()

    # Generate more specific AnomalyReason
    reasons = []
    for idx, row in anomalies.iterrows():
        reason_parts = []
        if not row["IsWorkHours"]:
            reason_parts.append("Access outside work hours")
        if row["IsWeekend"]:
            reason_parts.append("Weekend access")
        if row["Hour"] < 4 or row["Hour"] > 22:
            reason_parts.append(f"Suspicious hour ({row['Hour']}:00)")
        if row["IsFirstSeenIP"]:
            reason_parts.append("First-time IP access")
        if not reason_parts:
            reason_parts.append("Anomalous behavior detected by ML")
        reasons.append(", ".join(reason_parts))

    anomalies["AnomalyReason"] = reasons

    return anomalies[[
        "Timestamp", "EventType", "SourceIP", "Severity", "Action",
        "Protocol", "Zone", "ML_AnomalyScore", "AnomalyReason",
        "IsWorkHours", "IsWeekend", "IsFirstSeenIP"
    ]]

