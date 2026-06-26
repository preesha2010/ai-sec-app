import os
from langchain_groq import ChatGroq

API_KEY = os.getenv("GROQ_API_KEY")
llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0, api_key=API_KEY)

def mitigator_node(state):
    prompt = f"""
You are a security engineer. Below are confirmed vulnerbailities, already verified against the code. For each one, provide a specific and actionable mitigation. 

Findings after feedback processing:
{state['feedback']}


These findings are the result of a multi-agent pipeline:
- A scanner identified candidate vulnerabilities
- A verifier confirmed them against the actual code
- A feedback agent filtered false positives and escalated recurring issues

For each vulnerability, respond in the exact markdown format as below:

| Vulnerability | Severity | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| <name> | <Critical/High/Medium/Low> | <High/Medium/Low> | <what happens if exploited> | <specific fix> |

After the table, add a brief summary. If any findings were escalated due to being recurring and unresolved, explicitly call them out as requiring urgent attention since they have persisted across multiple scans.

At the end give an overall risk rating for the code based on highest severity found:
RESULT: CRITICAL or
RESULT: HIGH or
RESULT: MEDIUM or
RESULT: LOW or
RESULT: NONE
"""
    response = llm.invoke(prompt)
    state["final_report"] = response.content
    return state