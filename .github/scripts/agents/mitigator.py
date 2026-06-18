import os
from langchain_groq import ChatGroq

API_KEY = os.getenv("GROQ_API_KEY")
llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0, api_key=API_KEY)

def mitigator_node(state):
    prompt = f"""
You are a security engineer. Below are confirmed vulnerbailities, already verified against the code. For each one, provide a specific and actionable mitigation. 

Vulnerabilities found :
{state['verified_vulnerabilities']}

For each vulnerability, respond in the exact markdown format as below:

| Vulnerability | Severity | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| <name> | <Critical/High/Medium/Low> | <High/Medium/Low> | <what happens if exploited> | <specific fix> |

After the end of the table add a brief summary paragraph.

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