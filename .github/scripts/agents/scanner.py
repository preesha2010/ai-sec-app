import os
from langchain_groq import ChatGroq

API_KEY = os.getenv("GROQ_API_KEY")
llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0, api_key=API_KEY)

def scanner_node(state):
    prompt = f"""
You are a security analyst reviewing code for vulnerabilities for a Flask web application. You will receive one or more code files.  

CODE TO REVIEW: 
{state['code']}

Your job is to find concrete security vulnerabilities in this code.

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

Do not give mitigations or fixes. That is not your job. It is a separate step later. 
Do not give generic advice not tied to the code.
"""
    response = llm.invoke(prompt)
    state["vulnerabilities"] = response.content
    return state

