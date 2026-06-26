import os
import requests
from langchain_groq import ChatGroq

API_KEY = os.getenv("GROQ_API_KEY")
llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0, api_key=API_KEY)

def feedback_node(state):
    app_name = os.getenv("APP_NAME", "unknown")
    dashboard_url = os.getenv("DASHBOARD_URL","")

    # fetching past scan history from dashboard
    history_text = "No previous scan history available"
    if dashboard_url:
        try:
            response = requests.get(
                f"{dashboard_url}/api/history/{app_name}",
                timeout=10
            )
            if response.status_code == 200:
                scans = response.json()
                if scans:
                    history_text = f"Previous {len(scans)} scan(s) found:\n"
                    for i, scan in enumerate(scans, 1):
                        history_text += f"\nScan {i} ({scan['scan_time']}) — {scan['risk_level']}:\n{scan['report'][:800]}\n"
                else:
                    history_text = "No previous scans found for this app."

        except Exception as e:
            history_text = f"Could not retrieve history: {e}"

    prompt = f"""
You are a feedback analyst in a security scanning pipeline. Your job is to compare current verified findings against this app's historical scan data and annotate each finding with a confidence level.

CURRENT VERIFIED FINDINGS:
{state['verified_vulnerabilities']}

HISTORICAL SCAN DATA FOR THIS APP:
{history_text}

You must do two things:

TASK 1 — FILTER (remove false positives):
A finding is likely a false positive if:
- It appeared in only one previous scan and never again across multiple scans
- It is not present in any previous scan history at all AND is a very unlikely vulnerability given the code context described

TASK 2 — ESCALATE (increase severity of recurring unresolved issues):
A finding should be escalated if:
- It has appeared in 2 or more previous scans
- It is still present in the current scan
- This means it has not been fixed despite being flagged before

For escalated findings, increase their severity by one level:
LOW → MEDIUM
MEDIUM → HIGH
HIGH → CRITICAL

STRICT RULES:
1. If there is no history, pass all findings through unchanged - you cannot filter or escalate without evidence.
2. Do not invent new findings.
3. Do not add findings that were not in CURRENT VERIFIED FINDINGS.
4. Base all decisions strictly on what the historical data actually shows.
5. Do not suggest mitigations — that is the next agent's job.

Output each finding in this exact format:

Vulnerability: <name>
Severity: <level - escalated if applicable>
Likelihood: <level from verified findings>
Location: <location from verified findings>
Risk: <risk from verified findings>
Feedback Action: <PASSED THROUGH / ESCALATED from X to Y / REMOVED as likely false positive>
Reason: <one sentence explaining the decision based on history>

At the end list any removed findings under: 
Removed Findings: <name> - <reason>

"""
    response = llm.invoke(prompt)
    state["feedback"] = response.content
    return state