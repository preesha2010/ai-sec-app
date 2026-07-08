def supervisor_node(state, stage):
    """
    Observes the pipeline at different checkpoints.
    Never modifies agent outputs.
    Only records observations about pipeline health.
    """

    notes = state.get("supervisor_notes", {})

    if stage == "scanner":
        notes["scanner"] = scanner_supervision(state)

    elif stage == "verifier":
        notes["verifier"] = verifier_supervision(state)

    elif stage == "mitigator":
        notes["mitigator"] = mitigator_supervision(state)

    state["supervisor_notes"] = notes
    return state

def scanner_supervision(state):

    metrics = state.get("scanner_metrics", {})
    history = state.get("historical_metrics", {})

    candidate_count = metrics.get("candidate_count", 0)
    historical_average = history.get("avg_finding_count", 0)

    observations = []

    status = "OK"

    if historical_average > 0:

        if candidate_count < historical_average * 0.5:
            status = "WARNING"
            observations.append(
                f"Scanner found only {candidate_count} candidate vulnerabilities "
                f"(historical average: {historical_average:.1f}). Coverage appears unusually low."
            )

        elif candidate_count > historical_average * 2:
            status = "WARNING"
            observations.append(
                f"Scanner found {candidate_count} candidate vulnerabilities "
                f"(historical average: {historical_average:.1f}). Possible spike in findings."
            )

        else:
            observations.append(
                f"Candidate vulnerability count ({candidate_count}) is consistent with historical scans."
            )

    else:
        observations.append(
            "No historical data available. Baseline will be established from this scan."
        )

    return {
        "status": status,
        "observations": observations
    }

def verifier_supervision(state):
    """
    Evaluates the health of the verifier agent.
    Monitors whether the verifier is unusually strict or lenient
    compared to expected behaviour and historical trends.
    """
    metrics = state.get("verifier_metrics", {})
    historical_metrics = state.get("historical_metrics", {})

    verification_rate = metrics.get("verification_rate", 0)
    confirmed = metrics.get("confirmed_count", 0)
    discarded = metrics.get("discarded_count", 0)
    severity_distribution = metrics.get("severity_distribution", {})

    observations = []
    status = "OK"
    total = confirmed + discarded

    if total == 0:
        observations.append(
            "No vulnerabilities were available for verification."
        )
    else:
        # very low acceptance rate
        if verification_rate < 0.30:
            status = "WARNING"
            observations.append(
                f"Verifier confirmed only {confirmed} of {total} findings "
                f"({verification_rate:.0%} verification rate). "
                "The verifier may be overly strict or the scanner may be generating excessive false positives."
            )
        # very high acceptance rate
        elif verification_rate > 0.95 and confirmed >= 3:
            status = "WARNING"
            observations.append(
                f"Verifier confirmed {confirmed} of {total} findings "
                f"({verification_rate:.0%} verification rate). "
                "Very few findings were rejected. The verifier may not be filtering false positives effectively."
            )
        else:
            observations.append(
                f"Verification rate ({verification_rate:.0%}) is within the expected range."
            )

    # severity distribution observation
    observations.append(
        "Confirmed severity distribution: "
        f"Critical={severity_distribution.get('CRITICAL', 0)}, "
        f"High={severity_distribution.get('HIGH', 0)}, "
        f"Medium={severity_distribution.get('MEDIUM', 0)}, "
        f"Low={severity_distribution.get('LOW', 0)}."
    )

    # compare against historical average if available
    # historical_metrics doesn't store avg verification rate yet
    # but we can flag if confirmed count is very different from avg findings
    avg_findings = historical_metrics.get("avg_finding_count", 0)
    if avg_findings > 0:
        deviation = abs(confirmed - avg_findings) / max(avg_findings, 1)
        if deviation > 0.6:
            status = "WARNING"
            observations.append(
                f"Confirmed finding count ({confirmed}) deviates significantly "
                f"from historical average ({avg_findings:.1f}). "
                "This indicates an unusual change in the pipeline output and may warrant review."
            )

    return {
        "status": status,
        "observations": observations
    }


def mitigator_supervision(state):
    """
    Evaluates the quality of the mitigator agent's output.
    Does NOT judge the application's security posture —
    only evaluates whether the mitigator did its job properly.
    """
    report = state.get("final_report", "")
    feedback = state.get("feedback", "")
    history = state.get("historical_metrics", {})

    observations = []
    status = "OK"

    # --------------------------------------------------
    # Count vulnerabilities entering vs mitigations produced
    # --------------------------------------------------
    expected_count = feedback.count("Vulnerability:")
    mitigation_count = 0
    for line in report.splitlines():
        stripped = line.strip()
        if (
            stripped.startswith("|")
            and "---" not in stripped
            and "Vulnerability" not in stripped
        ):
            mitigation_count += 1

    if expected_count > 0 and mitigation_count != expected_count:
        status = "WARNING"
        observations.append(
            f"Mitigator produced {mitigation_count} mitigation(s) for "
            f"{expected_count} verified vulnerability(ies). "
            "Some findings may be missing mitigations."
        )
    else:
        observations.append(
            f"Every verified vulnerability ({mitigation_count}) received a mitigation."
        )

    # --------------------------------------------------
    # Check overall RESULT line exists
    # --------------------------------------------------
    if "RESULT:" not in report:
        status = "WARNING"
        observations.append(
            "Overall risk rating (RESULT) is missing from the report. "
            "Pipeline pass/fail logic may not work correctly."
        )
    else:
        observations.append("Overall risk rating (RESULT) is present.")

    # --------------------------------------------------
    # Check persistent findings are highlighted
    # --------------------------------------------------
    persistent_exists = "History Status: PERSISTENT" in feedback or "PERSISTENT" in feedback
    if persistent_exists:
        if "Unresolved Issues Requiring Urgent Attention" not in report:
            status = "WARNING"
            observations.append(
                "Persistent vulnerabilities exist in the feedback but are not "
                "explicitly highlighted in the final report."
            )
        else:
            observations.append(
                "Persistent vulnerabilities are clearly highlighted in the report."
            )

    # --------------------------------------------------
    # Detect overly generic mitigations
    # --------------------------------------------------
    generic_phrases = [
        "implement proper authentication",
        "follow best practices",
        "improve security",
        "use secure coding practices",
        "validate input",
        "sanitize input",
        "ensure security",
        "implement security measures",
    ]
    generic_count = 0
    report_lower = report.lower()
    for phrase in generic_phrases:
        generic_count += report_lower.count(phrase)

    if generic_count > 2:
        status = "WARNING"
        observations.append(
            f"Found {generic_count} generic mitigation phrase(s). "
            "Several mitigations appear non-specific and may not be actionable."
        )
    else:
        observations.append("Mitigations appear sufficiently specific.")

    return {
        "status": status,
        "observations": observations,
    }