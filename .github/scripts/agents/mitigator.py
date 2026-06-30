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
- A feedback agent compared them against this app's scan history, classified each as NEW, RECURRING, or PERSISTENT, and escalated severity for PERSISTENT findings that remain unresolved

For each vulnerability, respond in the exact markdown format as below:

| Vulnerability | Severity | Likelihood | History | Impact | Mitigation |
|---|---|---|---|---|---|
| <name> | <Critical/High/Medium/Low> | <High/Medium/Low> | <NEW/RECURRING/PERSISTENT> | <what happens if exploited> | <specific fix> |

After the table, add a brief summary. If any findings are marked PERSISTENT, explicitly call them out by name in a separate short paragraph titled "Unresolved Issues Requiring Urgent Attention" — note that these have remained unfixed across multiple scans and previous mitigation guidance has not been acted on.

At the end give an overall risk rating for the code based on the highest severity found in the table above:
RESULT: CRITICAL or
RESULT: HIGH or
RESULT: MEDIUM or
RESULT: LOW or
RESULT: NONE
"""
    response = llm.invoke(prompt)
    state["final_report"] = response.content
    return state