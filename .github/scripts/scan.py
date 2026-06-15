import os
import sys
from groq import Groq
import subprocess
import requests
from datetime import datetime, timedelta, timezone

API_KEY = os.getenv("GROQ_API_KEY")
client = Groq(api_key=API_KEY)

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

prompt = f"""
You are a security analyst reviewing code for vulnerabilities for a Flask web application. You will receive one or more code files.  

CODE TO REVIEW: 
{code}

Your job is to find concrete security vulnerabilities in this code and explain exactly how to fix them.

Focus on:

OWASP Top 10
- Broken Access Control
- Security Misconfiguration
- Software Supply Chain Failures
- Cryptographic Failures
- Injection
- Insecure Design 
- Authentication Failures
- Software and Data Integrity Failures
- Security Logging and Alerting Failures
- Mishandling of Exceptional Conditions

Also look for
- Hardcoded passwords
- SQL injection
- Plaintext password storage
- Missing authentication
- Cross site scripting (XSS)

Do not give generic advice not tied to the code.

For each vulnerability, respond in the exact markdown format as below:

| Vulnerability | Severity | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| <name> | <Critical/High/Medium/Low> | <High/Medium/Low> | <what happens if exploited> | <specific fix> |

Use this criteria to assign severity (how serious is the risk if exploited):
- CRITICAL: At least one easily exploitable issue that can lead to full compromise with little or no authentication (e.g., unauthenticated admin access, remote code execution, SQL injection on login, etc.).
- HIGH: Serious issues that can expose sensitive data or escalate privileges, but require some access/conditions (e.g., hardcoded admin credentials, plaintext or weakly hashed passwords, direct DB dumps).
- MEDIUM: Issues that weaken security but are harder to exploit or have partial impact (e.g., using SHA-256 without salt for passwords, missing CSRF protection, missing logging on auth paths).
- LOW: Primarily OWASP best-practice or defense-in-depth issues (e.g., missing security headers, overly verbose error messages, minor validation gaps).

Use this criteria to assign likelihood (how easy is the risk to exploit):
- HIGH: trivial to exploit, no special access needed
- MEDIUM: requires some knowledge or specific conditions
- LOW: requires significant effort or insider access

After the table add a brief summary paragraph.

At the end give an overall risk rating for the code based on highest severity found:
RESULT: CRITICAL or
RESULT: HIGH or
RESULT: MEDIUM or
RESULT: LOW or
RESULT: NONE
"""

response = client.chat.completions.create(
    model="llama-3.3-70b-versatile",
    messages=[
        {
            "role": "user",
            "content": prompt
        }
    ],
    temperature=0,
    max_tokens=1024
)

report =  response.choices[0].message.content

with open("security_report.md", "w") as file:
    file.write(report)      # saving report to md file 

print(report)

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