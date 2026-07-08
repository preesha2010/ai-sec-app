import os
from langchain_groq import ChatGroq

API_KEY = os.getenv("GROQ_API_KEY")
llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0, api_key=API_KEY)

def feedback_node(state):

    history = state.get("history", [])

    if history:
        history_text = f"Previous {len(history)} scan(s) found:\n"

        for i, scan in enumerate(history, 1):
            history_text += (
                f"\nScan {i} "
                f"({scan.get('scan_time')}) "
                f"— {scan.get('risk_level')}:\n"
                f"{scan.get('report','')[:800]}\n"
            )
    else:
        history_text = "No previous scan history available."

    prompt = f"""
You are a feedback analyst in a security scanning pipeline. Your job is to compare current verified findings against this app's historical scan data and improve the quality of the current scan by identifying trends and unresolved vulnerabilities. 

CURRENT VERIFIED FINDINGS:
{state['verified_vulnerabilities']}

HISTORICAL SCAN DATA FOR THIS APP:
{history_text}

TASK 1 — HISTORY ANALYSIS:
For every current verified finding, classify it as one of the following:

• NEW - no matching mention found in any historical scan above. Pass through unchanged.

• RECURRING - matches a finding in exactly one historical scan and is still present.

• PERSISTENT
  - The vulnerability has appeared in two or more previous scans and is still unresolved.
  - Persistent vulnerabilities indicate that previous remediation attempts were unsuccessful or the issue has been ignored.

TASK 2 — PRIORITY ESCALATION:
Escalate ONLY persistent vulnerabilities. 

Increase their severity by one level:
LOW → MEDIUM
MEDIUM → HIGH
HIGH → CRITICAL

Do NOT escalate CRITICAL vulnerabilities. 

Do NOT change severity of NEW or RECURRING findings. 

Do NOT remove findings simply because they do not exist in historical scans.

A vulnerability appearing for the first time should be classified as NEW and passed through unchanged.

Only modify the Severity field when a finding qualifies for escalation.

STRICT RULES:
1. If no historical scan data exists, classify every finding as NEW.
2. Never invent new vulnerabilities.
3. Never delete or ignore verified findings.
4. Never change file paths, vulnerability names, likelihood, risk descriptions, or locations.
5. Only modify Severity when escalation rules apply.
6. Do not suggest mitigations.
7. Base every decision strictly on the historical scan data provided.

For every finding output exactly:
Vulnerability: <copy exactly from verified vulnerabilities>
Severity: <original severity OR escalated severity>
Likelihood: <level from verified vulnerabilities>
Location: <location from verified vulnerabilities>
Risk: <risk from verified vulnerabilities>
History Status: <NEW / RECURRING / PERSISTENT>
Feedback Action: <PASSED THROUGH / ESCALATED from X to Y>
Reason: <One brief sentence explaining the decision using the historical scan data.>

Finally output:

Summary
New Findings: <number>
Recurring Findings: <number>
Persistent Findings: <number>
Escalated Findings: <number>
"""
    response = llm.invoke(prompt)
    state["feedback"] = response.content
    return state