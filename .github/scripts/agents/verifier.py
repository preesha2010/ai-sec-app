import os
from langchain_groq import ChatGroq

API_KEY = os.getenv("GROQ_API_KEY")
llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0, api_key=API_KEY)

def verifier_node(state):
    prompt = f"""
You are a senior security reviewer. A junior analyst found the following potential vulnerabilities in this code. 

Original code:
{state['code']}

Your ONLY JOB is to check the following reported vulnerabilities against the code.

Reported vulnerabilities:
{state['vulnerabilities']}

STRICT RULES:
1. You may ONLY confirm vulnerabilities that were already listed above. Do NOT introduce any new vulnerability that wasn't in the reported list.
2. For each reported vulnerability, you MUST copy-paste the EXACT line(s) of code from ORIGINAL CODE that prove it is real, word for word, inside the Evidence field. If you cannot copy an exact snippet, you cannot confirm it.
3. Before confirming anything, re-read ORIGINAL CODE one more time and ask: "does this exact pattern appear, character for character, in the code above?" If the answer is no, discard it.
4. Do NOT use phrases like "throughout the codebase" or "in general" — every confirmed item must point to one specific snippet you can quote.
5. Reading an environment variable (os.getenv) is NOT a hardcoded secret. Do not flag os.getenv calls as hardcoded credentials.
6. Do not invent SQL injection, XSS, or missing security headers unless you can quote the exact code that handles SQL, HTML rendering, or HTTP responses.

For each reported vulnerability, check it against the actual code:
If it is a real confirmed issue, keep it and assign severity and likelihood.
If it is not actually present in the code or is a false positive, remove it and briefly note why it was discarded. 

Use this criteria to assign severity (how serious is the risk if exploited):
- CRITICAL: At least one easily exploitable issue that can lead to full compromise with little or no authentication (e.g., unauthenticated admin access, remote code execution, SQL injection on login, etc.).
- HIGH: Serious issues that can expose sensitive data or escalate privileges, but require some access/conditions (e.g., hardcoded admin credentials, plaintext or weakly hashed passwords, direct DB dumps).
- MEDIUM: Issues that weaken security but are harder to exploit or have partial impact (e.g., using SHA-256 without salt for passwords, missing CSRF protection, missing logging on auth paths).
- LOW: Primarily OWASP best-practice or defense-in-depth issues (e.g., missing security headers, overly verbose error messages, minor validation gaps).

Use this criteria to assign likelihood (how easy is the risk to exploit):
- HIGH: trivial to exploit, no special access needed
- MEDIUM: requires some knowledge or specific conditions
- LOW: requires significant effort or insider access

Output only confirmed vulnerabilites with their severity and likelihood in the following format:

Vulnerability: <name>
Severity: <level>
Likelihood: <level>
Location: <where in code>
Risk: <why this matters>

If any vulnerabilites were discarded, list them out in the end.

Do not give mitigations or fixes. That is not your job. There is a separate step for that. 
"""
    response = llm.invoke(prompt)
    state["verified_vulnerabilities"] = response.content
    return state