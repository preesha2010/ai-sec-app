import os
import requests

def history_loader_node(state):
    """
    Loads all previous scans for this application from the dashboard
    and computes historical metrics that will be used by the Supervisor
    agent throughout the pipeline.
    """

    app_name = os.getenv("APP_NAME", "unknown")
    dashboard_url = os.getenv("DASHBOARD_URL", "")

    history = []

    if dashboard_url:
        try:
            response = requests.get(
                f"{dashboard_url}/api/history/{app_name}",
                timeout=15
            )

            if response.status_code == 200:
                history = response.json()

        except Exception as e:
            print(f"[History Loader] {e}")

    state["history"] = history
    state["historical_metrics"] = compute_historical_metrics(history)

    print(f"[History Loader] Loaded {len(history)} previous scans.")

    return state


def compute_historical_metrics(history):
    """
    Generates summary statistics from previous scans.
    These metrics are consumed later by the Supervisor agent.
    """

    if not history:
        return {
            "total_scans": 0,
            "avg_finding_count": 0,
            "risk_distribution": {},
            "most_common_vulnerabilities": [],
            "consecutive_critical_scans": 0,
            "finding_counts": [],
        }

    risk_distribution = {}
    finding_counts = []
    vulnerability_counts = {}
    consecutive_critical = 0

    for scan in history:
        # -----------------------------
        # Risk distribution
        # -----------------------------
        risk = scan.get("risk_level", "UNKNOWN")
        risk_distribution[risk] = risk_distribution.get(risk, 0) + 1
        report = scan.get("report", "")
        findings_this_scan = 0

        for line in report.splitlines():
            line = line.strip()
            if not line.startswith("|"):
                continue
            if "---" in line:
                continue
            columns = [c.strip() for c in line.strip("|").split("|")]
            if len(columns) < 2:
                continue
            if columns[0].lower() == "vulnerability":
                continue
            findings_this_scan += 1
            vuln = columns[0]
            vulnerability_counts[vuln] = (
                vulnerability_counts.get(vuln, 0) + 1
            )

        finding_counts.append(findings_this_scan)

    # -----------------------------------
    # Average findings
    # -----------------------------------

    avg_finding_count = (
        round(sum(finding_counts) / len(finding_counts), 2)
        if finding_counts
        else 0
    )

    # -----------------------------------
    # Most common vulnerabilities
    # -----------------------------------

    most_common = sorted(
        vulnerability_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]

    # -----------------------------------
    # Consecutive critical scans
    # -----------------------------------

    for scan in history:
        if scan.get("risk_level") == "CRITICAL":
            consecutive_critical += 1
        else:
            break

    return {
        "total_scans": len(history),
        "avg_finding_count": avg_finding_count,
        "risk_distribution": risk_distribution,
        "most_common_vulnerabilities": [
            {
                "name": name,
                "count": count
            }
            for name, count in most_common
        ],
        "consecutive_critical_scans": consecutive_critical,
        "finding_counts": finding_counts,
    }