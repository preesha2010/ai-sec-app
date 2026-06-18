from langgraph.graph import StateGraph, END
from agents.state import ScanState
from agents.scanner import scanner_node
from agents.verifier import verifier_node
from agents.mitigator import mitigator_node

def buildGraph():
    workflow = StateGraph(ScanState)    # creates an empty graph

    # adding nodes
    workflow.add_node("scanner", scanner_node)
    workflow.add_node("verifier", verifier_node)
    workflow.add_node("mitigator", mitigator_node)

    # adding edges
    workflow.set_entry_point("scanner")
    workflow.add_edge("scanner", "verifier")
    workflow.add_edge("verifier", "mitigator")
    workflow.add_edge("mitigator", END)

    # compile workflow
    return workflow.compile()
