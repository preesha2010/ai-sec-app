from langgraph.graph import StateGraph, END
from agents.state import ScanState
from agents.scanner import scanner_node
from agents.verifier import verifier_node
from agents.feedback import feedback_node
from agents.mitigator import mitigator_node
from agents.history_loader import history_loader_node
from agents.supervisor import supervisor_node

def scanner_supervisor_node(state):
    return supervisor_node(state, "scanner")

def verifier_supervisor_node(state):
    return supervisor_node(state, "verifier")

def mitigator_supervisor_node(state):
    return supervisor_node(state, "mitigator")

def buildGraph():
    workflow = StateGraph(ScanState)    # creates an empty graph

    # adding nodes
    workflow.add_node("history_loader", history_loader_node)
    workflow.add_node("scanner", scanner_node)
    workflow.add_node("scanner_supervisor", scanner_supervisor_node)
    workflow.add_node("verifier", verifier_node)
    workflow.add_node("verifier_supervisor", verifier_supervisor_node)
    workflow.add_node("feedback", feedback_node)
    workflow.add_node("mitigator", mitigator_node)
    workflow.add_node("mitigator_supervisor", mitigator_supervisor_node)

    # adding edges
    workflow.set_entry_point("history_loader")
    workflow.add_edge("history_loader", "scanner")
    workflow.add_edge("scanner", "scanner_supervisor")
    workflow.add_edge("scanner_supervisor", "verifier")
    workflow.add_edge("verifier", "verifier_supervisor")
    workflow.add_edge("verifier_supervisor", "feedback")
    workflow.add_edge("feedback", "mitigator")
    workflow.add_edge("mitigator", "mitigator_supervisor")
    workflow.add_edge("mitigator_supervisor", END)

    # compile workflow
    return workflow.compile()