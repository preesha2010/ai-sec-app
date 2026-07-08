from typing import TypedDict

class ScanState(TypedDict):
    # input
    code: str
    files_scanned: list

    # history (loaded once at start)
    history: list                    # all past scans raw
    historical_metrics: dict         # averages, counts, trends

    # agent outputs
    vulnerabilities: str             # Scanner
    scanner_metrics: dict            # count, severity breakdown
    scanner_prompt: str             # Scanner
    verified_vulnerabilities: str    # Verifier
    verifier_metrics: dict           # confirmed count, discarded count
    verifier_prompt: str             # Verifier
    mitigator_metrics: dict          # count, severity breakdown
    mitigator_prompt: str            # Mitigator
    feedback: str 
    final_report: str                # Mitigator

    # supervisor observations (accumulates across 3 checkpoints)
    supervisor_notes: dict           # list of observations added at each checkpoint