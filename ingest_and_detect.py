import os
import random
from datetime import datetime, timedelta
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

def generate_sample_logs(n=1500, start_time=None, out_csv='sample_logs.csv'):
    """Generate synthetic sample logs and write to out_csv"""
    if start_time is None:
        start_time = datetime.now() - timedelta(days=1)
    users = ['alice', 'bob', 'carol', 'dave', 'admin', 'svc_backup', 'svc_sync']
    ips = [f'10.0.0.{i}' for i in range(2,50)]
    event_types = ['login_success', 'login_failed', 'file_access', 'privilege_escalation',
                   'config_change', 'sap_transaction', 'file_download', 'file_copied',
                   'email_sent', 'external_transfer', 'usb_insert', 'port_scan', 'brute_force']
    logs = []
    ts = start_time
    for i in range(n):
        ts += timedelta(seconds=random.randint(10,300))
        user = random.choices(users, weights=[15,15,12,10,4,3,3])[0]
        ip = random.choice(ips)
        # occasional focused attack cluster
        if i % 230 in (0,1,2,3,4,5):
            event = random.choice(['login_failed', 'brute_force'])
            ip = '203.0.113.55'
            user = 'admin' if random.random() < 0.8 else user
        else:
            event = random.choices(event_types, weights=[40,10,10,2,5,5,3,2,3,2,1,1,1])[0]
        # occasional privilege escalation
        if i % 400 == 0:
            event = 'privilege_escalation'
        details = f"auto_generated_detail_{i}"
        logs.append({
            'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S'),
            'user': user,
            'source_ip': ip,
            'event': event,
            'details': details
        })
    df = pd.DataFrame(logs)
    df.to_csv(out_csv, index=False)
    print(f"Generated logs -> {out_csv}")
    return df

def is_private_ip(ip):
    """Simple RFC1918-like check"""
    if not isinstance(ip, str):
        return False
    return ip.startswith('10.') or ip.startswith('172.') or ip.startswith('192.168')

def detect_incident_type(event_text):
    """Map event+details text to an incident type and base severity"""
    if not isinstance(event_text, str):
        return None, None
    e = event_text.lower()
    # mapping rules (expandable)
    if any(k in e for k in ["login_failed", "failed login", "login failure", "invalid password"]):
        return "Authentication Failure", 5
    if any(k in e for k in ["brute_force", "brute force", "repeated login"]):
        return "Brute Force / Authentication Attack", 7
    if any(k in e for k in ["phish", "acme-phish", "suspicious domain", "email_sent"]):
        return "Phishing / Email Abuse", 6
    if any(k in e for k in ["external_transfer", "upload to ftp", "uploaded file", "external upload", "uploaded"]):
        return "Data Exfiltration", 9
    if any(k in e for k in ["usb", "removable media", "usb_insert", "removable"]):
        return "Insider / Removable Media", 8
    if any(k in e for k in ["privilege_escalation", "privilege escalation", "added to sudoers", "sudoers"]):
        return "Privilege Escalation", 10
    if any(k in e for k in ["firewall_breach", "firewall", "unusual outbound", "port_scan", "port scan", "recon"]):
        return "Network Intrusion / Reconnaissance", 8
    if any(k in e for k in ["file_deleted", "deleted backup", "deleted"]):
        return "Potential Sabotage / Data Deletion", 9
    if any(k in e for k in ["file_copied", "file_download", "file_accessed", "file_access"]):
        return "Suspicious File Activity", 7
    if any(k in e for k in ["config_change", "modified firewall", "config modified"]):
        return "Unauthorized Configuration Change", 8
    if any(k in e for k in ["malware", "virus", "ransomware"]):
        return "Malware Infection", 9
    return None, None

def run_detection(log_csv='sample_logs.csv', out_incidents='detected_incidents.csv', kb_dir='knowledge_articles', contamination=0.05):
    """
    Run detection on log_csv, write out_incidents and generate KB markdown files into kb_dir.
    Returns: incidents DataFrame
    """
    os.makedirs(kb_dir, exist_ok=True)
    if not os.path.exists(log_csv):
        raise FileNotFoundError(f"{log_csv} not found")

    df = pd.read_csv(log_csv, parse_dates=['timestamp'])
    # normalize columns if needed: ensure lower-case event/details strings
    df['event'] = df['event'].astype(str)
    df['details'] = df['details'].astype(str)
    df = df.sort_values('timestamp').reset_index(drop=True)

    # basic feature flags
    df['is_failed_login'] = df['event'].str.contains('failed|invalid|brute_force', case=False, na=False).astype(int)
    df['is_priv_esc'] = df['event'].str.contains('privilege_escalation|privilege escalation|sudoers', case=False, na=False).astype(int)
    df['is_sap'] = df['event'].str.contains('sap', case=False, na=False).astype(int)

    # rolling counts - naive O(n^2) approach acceptable for prototype (small logs)
    df['user_failed_count_30m'] = 0
    df['ip_failed_count_30m'] = 0
    for idx, row in df.iterrows():
        t = row['timestamp']
        window_start = t - pd.Timedelta(minutes=30)
        user_mask = (df['user'] == row['user']) & (df['timestamp'] >= window_start) & (df['timestamp'] <= t)
        ip_mask = (df['source_ip'] == row['source_ip']) & (df['timestamp'] >= window_start) & (df['timestamp'] <= t)
        df.at[idx, 'user_failed_count_30m'] = int(df.loc[user_mask, 'is_failed_login'].sum())
        df.at[idx, 'ip_failed_count_30m'] = int(df.loc[ip_mask, 'is_failed_login'].sum())

    # rule-based detection using detect_incident_type + extra heuristics
    incidents = []
    iid = 1

    for idx, row in df.iterrows():
        text = f"{row.get('event','')} {row.get('details','')}"
        itype, base_sev = detect_incident_type(text)
        # heuristics: if many failed attempts within 30 mins -> brute_force
        if row['ip_failed_count_30m'] >= 5:
            itype = itype or "Brute Force / Authentication Attack"
            base_sev = max(base_sev or 0, 7)
        # suspicious if user failed many times
        if row['user_failed_count_30m'] >= 5:
            itype = itype or "Authentication Abnormality"
            base_sev = max(base_sev or 0, 6)

        # if we found an incident type, add it
        if itype:
            incidents.append({
                'incident_id': f'INC{iid:04d}',
                'timestamp': row['timestamp'],
                'type': itype,
                'user': row.get('user', ''),
                'source_ip': row.get('source_ip', ''),
                'evidence': text,
                'severity_score': int(base_sev or 5)
            })
            iid += 1

    # ML-Lite anomaly detection on user-level aggregates
    agg = df.groupby(['user']).agg({
        'is_failed_login': 'sum',
        'is_priv_esc': 'sum',
        'is_sap': 'sum',
        'user_failed_count_30m': 'max'
    }).reset_index()

    # Only run if we have enough data
    try:
        X = agg[['is_failed_login', 'is_priv_esc', 'is_sap', 'user_failed_count_30m']].fillna(0).values
    except Exception:
        X = None

    if X is not None and len(X) >= 5:
        iso = IsolationForest(contamination=contamination, random_state=42)
        preds = iso.fit_predict(X)
        agg['anomaly'] = (preds == -1).astype(int)
        for _, r in agg[agg['anomaly']==1].iterrows():
            # create an ML-based incident for that user
            last_ts = df[df['user'] == r['user']]['timestamp'].max()
            incidents.append({
                'incident_id': f'INC{iid:04d}',
                'timestamp': last_ts,
                'type': 'Anomalous User Behavior (ML)',
                'user': r['user'],
                'source_ip': df[df['user'] == r['user']]['source_ip'].iloc[-1] if not df[df['user'] == r['user']].empty else '',
                'evidence': f'user-level aggregates: failed_logins={r["is_failed_login"]}, priv_esc={r["is_priv_esc"]}',
                'severity_score': 6
            })
            iid += 1

    # Post-processing: severity adjustments and dedupe (by type+user+timestamp window)
    # mark external IPs and bump severity
    for inc in incidents:
        inc['is_external'] = not is_private_ip(inc.get('source_ip',''))
        if inc['is_external']:
            inc['severity_score'] = min(10, inc['severity_score'] + 2)
        # bump if recent (within 1 hour)
        try:
            if (datetime.now() - pd.to_datetime(inc['timestamp'])).total_seconds() < 3600:
                inc['severity_score'] = min(10, inc['severity_score'] + 1)
        except Exception:
            pass

    inc_df = pd.DataFrame(incidents)
    if inc_df.empty:
        # return empty but well-formed DF
        inc_df = pd.DataFrame(columns=['incident_id','timestamp','type','user','source_ip','evidence','severity_score','is_external'])

    # Simple dedupe: if same user+type within 5 minutes, keep highest severity
    if not inc_df.empty:
        inc_df['timestamp'] = pd.to_datetime(inc_df['timestamp'])
        inc_df = inc_df.sort_values('timestamp').reset_index(drop=True)
        deduped = []
        used = [False]*len(inc_df)
        for i, r in inc_df.iterrows():
            if used[i]:
                continue
            dup_group = [i]
            for j in range(i+1, len(inc_df)):
                if used[j]:
                    continue
                if (inc_df.loc[i, 'user'] == inc_df.loc[j, 'user']
                    and inc_df.loc[i, 'type'] == inc_df.loc[j, 'type']
                    and abs((inc_df.loc[i,'timestamp'] - inc_df.loc[j,'timestamp']).total_seconds()) <= 300):
                    dup_group.append(j)
                    used[j] = True
            # select highest severity among group
            group_rows = inc_df.loc[dup_group]
            best_idx = group_rows['severity_score'].idxmax()
            deduped.append(inc_df.loc[best_idx].to_dict())
        inc_df = pd.DataFrame(deduped)

    # Generate KB markdowns
    def generate_kb_article(incident_row):
        iid = incident_row['incident_id']
        title = f"{iid} - {incident_row['type']} - {incident_row['user']}"
        ts = pd.to_datetime(incident_row['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
        external = 'Yes' if incident_row.get('is_external') else 'No'
        severity = int(incident_row.get('severity_score', 5))
        evidence = incident_row.get('evidence','')
        remediation = "Investigate source IP, lock/monitor accounts, preserve logs, and follow incident response playbook."
        if 'Privilege' in incident_row['type']:
            remediation = "Isolate affected account, revoke escalated privileges, and run forensic analysis."
        if 'Exfil' in incident_row['type'] or 'Removable' in incident_row['type']:
            remediation = "Preserve evidence, disconnect suspect endpoints from network, and perform data leak analysis."
        content = f"""---
title: "{title}"
date: {ts}
severity: {severity}
external: {external}
---

## Summary
**Incident ID:** {iid}  
**Type:** {incident_row['type']}  
**User:** {incident_row.get('user','')}  
**Source IP:** {incident_row.get('source_ip','')}  
**Timestamp:** {ts}  

## Evidence
{evidence}

## Root Cause (Hypothesis)
Describe likely root cause here.

## Impact
Describe potential impact (unauthorised access, data exfiltration risk, service disruption).

## Remediation / Recommended Next Steps
{remediation}

## Learning Points
- Add account lockout after repeated failures.
- Add geo-IP / unusual IP detection for critical accounts.
- Monitor removable media & outbound transfers.

"""
        fname = os.path.join(kb_dir, f"{iid}.md")
        with open(fname, 'w') as f:
            f.write(content)
        return fname

    if not inc_df.empty:
        inc_df['kb_path'] = inc_df.apply(generate_kb_article, axis=1)
        inc_df = inc_df.sort_values('severity_score', ascending=False).reset_index(drop=True)

    # save incidents CSV
    inc_df.to_csv(out_incidents, index=False)
    print(f"Detected incidents saved -> {out_incidents}")
    print(f"Knowledge articles -> {kb_dir}")
    return inc_df

# If run directly, regenerate sample logs and run detection (demo)
if __name__ == '__main__':
    random.seed(42)
    np.random.seed(42)
    sample = generate_sample_logs()
    run_detection(log_csv='sample_logs.csv', out_incidents='detected_incidents.csv', kb_dir='knowledge_articles', contamination=0.05)
