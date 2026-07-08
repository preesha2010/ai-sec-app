import os
from langchain_groq import ChatGroq

API_KEY = os.getenv("GROQ_API_KEY")
llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0, api_key=API_KEY)

SCANNER_PROMPT_TEMPLATE = """
You are a security analyst reviewing code for vulnerabilities for a web application. You will receive one or more code files. Your job is to find concrete security vulnerabilities in this code.  

CODE TO REVIEW: 
{code}

A vulnerability can come from two kinds of evidence:
PRESENCE - a specific line or pattern of code that directly causes the issue (e.g. string-concatenated SQL queries, a plaintext password comparison).
ABSENCE - a required protection that is missing across the relevant code (e.g. no input validation on a form handler, no rate limiting on a login route, no CSRF protection anywhere forms are processed). For absence-based findings, you must specify exactly what you checked for and where, not just assert the codebase "lacks security."

PROCESS:
1. Read through the entire code and identify either specific risky code, or specific missing protections, using the two evidence types above.
2. For PRESENCE findings, note the exact code responsible.
3. For ABSENCE findings, name the specific function(s) or code path(s) where the missing protection would be expected, and confirm you checked and it is not there.
4. Do not search for a vulnerability in every category below just to have something to report. Many categories may genuinely not apply to this code - that is a normal and expected outcome, not a failure.

Focus on:

OWASP Top 10 vulnerabilities
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

Do not flag a vulnerability type for functionality the code doesn't have. For example, do not flag SQL injection if there is no database query in the code, and do not flag XSS if there is no HTML rendering or web output, and do not flag missing CSRF protection if there are no forms or state-changing web requests at all.
Standard secure practices are not vulnerabilities. Reading secrets via environment variables, using parameterized queries, or using well-known libraries in their default secure configuration should NOT be flagged.

Do not give mitigations or fixes. That is not your job. It is a separate step later. 
Do not give generic advice not tied to the code.
"""

def extract_scanner_metrics(output_text):
    vulnerabilities = []
    current = {}
    for line in output_text.splitlines():
        line = line.strip()
        if line.startswith("Vulnerability:"):
            if current:
                vulnerabilities.append(current)
            current = {"name": line.replace("Vulnerability:", "").strip()}
        elif line.startswith("Evidence Type:") and current:
            current["evidence_type"] = line.replace("Evidence Type:", "").strip()
        elif line.startswith("Location:") and current:
            current["location"] = line.replace("Location:", "").strip()
    if current:
        vulnerabilities.append(current)

    return {
        "candidate_count": len(vulnerabilities),
        "presence_count": sum(1 for v in vulnerabilities if v.get("evidence_type", "").lower() == "presence"),
        "absence_count": sum(1 for v in vulnerabilities if v.get("evidence_type", "").lower() == "absence"),
        "vulnerability_names": [v.get("name", "") for v in vulnerabilities],
    }

def scanner_node(state):
    prompt = SCANNER_PROMPT_TEMPLATE.format(code=state["code"])
    response = llm.invoke(prompt)
    output = response.content

    print("\n========== RAW SCANNER OUTPUT ==========\n")
    print(output)
    print("\n========================================\n")

    metrics = extract_scanner_metrics(output)

    state["vulnerabilities"] = output
    state["scanner_metrics"] = metrics
    state["scanner_prompt"] = SCANNER_PROMPT_TEMPLATE  # store prompt version so that Supervisor can later evaluate prompt quality

    print(f"Scanner found {metrics['candidate_count']} candidate vulnerabilities")

    return state