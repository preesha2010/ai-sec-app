from typing import TypedDict

class ScanState(TypedDict):
    code: str
    files_scanned: list
    vulnerabilities: str   # findigns from scanner
    verified_vulnerabilities: str     # findings confirmed after verification
    feedback: str
    final_report: str    # mitigations + report format 