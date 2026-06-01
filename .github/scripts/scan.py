import os
import sys
from groq import Groq

API_KEY = os.getenv("GROQ_API_KEY")
client = Groq(api_key=API_KEY)

# read app.py
with open("app.py", "r") as file:
    code = file.read()      # scanning only app.py

prompt = f"""
Analyse this Flask application for the following security vulnerabilities:

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

Code:
{code}

Respond in the following format for each vulnerabilty found:
Vulnerability: <name of vulnerability>
- Risk: <explanation of the risk>
- Mitigation: <suggested fix>

At the end write exactly one of these lines:
RESULT: CRITICAL
RESULT: HIGH
RESULT: MEDIUM
RESULT: LOW
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

# Fail the pipeline if serious issues found
if "RESULT: CRITICAL" in report or "RESULT: HIGH" in report:
    print("High severity issues found. Pipeline failed.")
    sys.exit(1)
else:
    print("Scan complete.")
    sys.exit(0)
