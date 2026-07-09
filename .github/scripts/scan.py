import os
import sys
import subprocess
import requests
from datetime import datetime, timedelta, timezone
from agents.graph import buildGraph

IST = timezone(timedelta(hours=5, minutes=30))

def changed_files():
    # returns list of files changed in the last commit
    try: 
        result = subprocess.run(["git", "diff", "--name-only", "HEAD~1", "HEAD"], capture_output=True, text=True) 
        files = result.stdout.strip().splitlines()
        
        files = [
            f for f in files    
            if f and f.endswith((".py", ".js", ".ts", ".html", ".yml", ".yaml")) and os.path.exists(f)  # files with relevant extensions and those that exist
        ]

        if not files:   # if files list is empty 
            print("No files changed in the last commit.")
            return ["app.py"] if os.path.exists("app.py") else [] # default to app.py if no files changed   
        return files
    
    except Exception as e:
        print(f"Error getting changed files: {e}")
        return ["app.py"] if os.path.exists("app.py") else [] # default to app.py if error occurs
    
def read_code(files):
    # reads contents of the files and returns as a string
    code_dump = ""
    for path in files:
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            code_dump += f"\n\n# File: {path}\n{content}"  # adding file name as comment before its content
            print(f"Read file: {path}")
        except Exception as e:
            print(f"Error reading file {path}: {e}")
    return code_dump

files = changed_files()

if not files: 
    print("No relevant files to scan.")
    sys.exit(0)

print(f"Files to be scanned: {files}")
code = read_code(files)

#   connecting graph.py to scan.py

graph = buildGraph()

initial_state = {
    # input
    "code": code,
    "files_scanned": files,

    # history
    "history": [],
    "historical_metrics": {},

    # agent outputs
    "vulnerabilities": "",
    "scanner_metrics": {},
    "scanner_prompt": "",
    "verified_vulnerabilities": "",
    "verifier_metrics": {},
    "verifier_prompt": "",
    "mitigator_prompt": "",
    "mitigator_metrics": {},
    "feedback": "",
    "final_report": "",

    # supervisor
    "supervisor_notes": {},
}

# LangGraph takes the initial state and sends it to the entry point, waits for the function to return updated state then passes updated state to next function cause of the edge that was defined
result = graph.invoke(initial_state)

report = result["final_report"]

with open("security_report.md", "w") as file:
    file.write(report)      # saving report to md file 

print(report)

print("\n[AGENT 1 — SCANNER]")
print("Job: Find candidate vulnerabilities")
print(result["vulnerabilities"])

print("\n[SUPERVISOR CHECKPOINT 1 — after Scanner]")
scanner_notes = result.get("supervisor_notes", {}).get("scanner", {})
print(f"Status: {scanner_notes.get('status', 'N/A')}")
for obs in scanner_notes.get("observations", []):
    print(f"  — {obs}")

print("\n[AGENT 2 — VERIFIER]")
print("Job: Cross-check findings against actual code")
print(result["verified_vulnerabilities"])

print("\n[SUPERVISOR CHECKPOINT 2 — after Verifier]")
verifier_notes = result.get("supervisor_notes", {}).get("verifier", {})
print(f"Status: {verifier_notes.get('status', 'N/A')}")
for obs in verifier_notes.get("observations", []):
    print(f"  — {obs}")

print("\n[AGENT 3 — FEEDBACK]")
print("Job: Filter false positives, escalate recurring issues")
print(result["feedback"])

print("\n[AGENT 4 — MITIGATOR]")
print("Job: Write mitigations for processed findings")
print(result["final_report"])

print("\n[SUPERVISOR CHECKPOINT 3 — after Mitigator]")
mitigator_notes = result.get("supervisor_notes", {}).get("mitigator", {})
print(f"Status: {mitigator_notes.get('status', 'N/A')}")
for obs in mitigator_notes.get("observations", []):
    print(f"  — {obs}")

# sending results to dashboard
def send_to_dashboard(risk_level, files_scanned, report):
    try:
        payload = {
            "app_name": os.getenv("APP_NAME", "unknown"),
            "repo": os.getenv("GITHUB_REPOSITORY", "unknown"),
            "push_time": datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S"),
            "risk_level": risk_level,
            "files_scanned": ", ".join(files_scanned),
            "report": report
        } # data being sent to the dashboard
        
        dashboard_url = os.getenv("DASHBOARD_URL")

        if not dashboard_url:
            print("No DASHBOARD_URL set.")
            return
            
        # POST request to send report to dashboard with payload as JSON and a timeout of 10 seconds
        response = requests.post(f"{dashboard_url}/api/report", json=payload, timeout=60)
        
        if response.status_code == 201:
            print("Results sent to dashboard.")
        else:
            print({response.status_code})
        
    except Exception as e:
        print(f"Error sending to dashboard: {e}")

risk_level = "NONE"
for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
    if f"RESULT: {level}" in report:
        risk_level = level
        break

send_to_dashboard(risk_level, files, report)

# Fail the pipeline if serious issues found
if "RESULT: CRITICAL" in report or "RESULT: HIGH" in report:
    print("High severity issues found. Pipeline failed.")
    sys.exit(1)
else:
    print("Scan complete.")
    sys.exit(0)

# testing scan.py