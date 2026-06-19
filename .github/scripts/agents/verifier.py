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

PROCESS — follow these steps in order for EACH reported vulnerability:
STEP 1 — Locate: Find the exact line(s) in ORIGINAL CODE that the analyst is referring to. Copy that exact snippet.
STEP 2 — Verify: Does the snippet you copied actually demonstrate the claimed vulnerability, or did the analyst misread/assume something not actually present?
STEP 3 — Decide: 
   - CONFIRM only if you copied a real snippet in Step 1 AND it genuinely demonstrates the vulnerability in Step 2.
   - DISCARD if you cannot find a matching snippet, or the snippet doesn't actually prove the claim, or the analyst is describing a vulnerability type that doesn't apply to what this code actually does (e.g. flagging a database-only vulnerability in code with no database, or a web-rendering vulnerability in code with no HTML output).

HARD CONSTRAINTS:
- You may only evaluate vulnerabilities that appear in the REPORTED VULNERABILITIES list above. Do not add anything new.
- Standard security practices (using parameterized queries, reading secrets from environment variables, using HTTPS libraries by default) are NOT vulnerabilities. Only flag the ABSENCE or MISUSE of these practices, not their use.

EVIDENCE TYPES (use whichever applies):
- LINE-LEVEL: copy the exact line(s) of code that directly demonstrate the issue.
- ABSENCE/PATTERN-LEVEL: if the vulnerability is the absence of a protection (e.g. no input validation, no rate limiting, no CSRF protection) or spans multiple locations, instead describe specifically what you searched for and confirm it does not appear anywhere in CODE TO REVIEW, and name the relevant function(s) or file(s) where you'd expect to find it.

Do not confirm a vulnerability using vague language like "the codebase lacks security" — even an absence-based finding must be specific about what is missing and where you checked.

Use this criteria to assign severity (how serious is the risk if exploited):
- CRITICAL: Easily exploitable, leads to full compromise, little or no authentication (e.g., unauthenticated admin access, remote code execution, SQL injection on login, etc.).
- HIGH: Serious issues that can expose sensitive data or escalate privileges, but require some access/conditions (e.g., hardcoded admin credentials, plaintext or weakly hashed passwords, direct DB dumps).
- MEDIUM: Issues that weaken security but are harder to exploit or have partial impact (e.g., using SHA-256 without salt for passwords, missing CSRF protection, missing logging on auth paths).
- LOW: Primarily OWASP best-practice or defense-in-depth gaps (e.g., missing security headers, overly verbose error messages, minor validation gaps).

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

At the end, list discarded vulnerabilities under 'DISCARDED (false positives)' with a one-liner reason each, referencing the step they failed at. 

Do not give mitigations or fixes. That is a separate step later. 
"""
    response = llm.invoke(prompt)
    state["verified_vulnerabilities"] = response.content
    return state