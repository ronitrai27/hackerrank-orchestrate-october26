"""Critic and Guardrail Validation Subagent.

Verifies generated audit decisions and step sequences against the exact rules
and constraints from problem_statement.md, deletion_rules.csv, and sample_output.csv.
"""

from typing import List, Tuple
from code.src.guardrails.schemas import (
    AuditStep,
    CaseOutputRow,
    CaseState,
    DeletionStatus,
    Phase,
    StepOperation,
    StepState,
    OPERATION_PHASE_MAP,
    OPERATION_STATE_MAP,
)


class CriticVerifier:
    """Verifies output invariant compliance with 0 hallucination."""

    def verify_case(self, state: CaseState) -> Tuple[bool, List[str]]:
        """Verify the case output for contract compliance."""
        issues: List[str] = []

        # 1. NOT_APPLICABLE verification
        if state.deletion_status == DeletionStatus.NOT_APPLICABLE:
            if len(state.steps) > 0:
                issues.append("NOT_APPLICABLE cases must have an empty steps array.")
            return (len(issues) == 0, issues)

        if not state.steps:
            issues.append(f"Case {state.case_id} marked {state.deletion_status.value} but has no steps.")
            return (False, issues)

        # 2. Step numbering: 1-indexed, consecutive
        for idx, step in enumerate(state.steps, start=1):
            if step.step_no != idx:
                issues.append(
                    f"Step numbering gap or mismatch: expected {idx}, got {step.step_no}."
                )

        # 3. Phase sequence verification: FINDING -> REMEDIATION -> VERIFICATION
        current_phase_idx = 0
        phase_order = {Phase.FINDING: 0, Phase.REMEDIATION: 1, Phase.VERIFICATION: 2}
        for step in state.steps:
            p_idx = phase_order.get(step.phase, 99)
            if p_idx < current_phase_idx:
                issues.append(
                    f"Phase ordering violated: found {step.phase.value} after earlier later-phase step."
                )
            current_phase_idx = max(current_phase_idx, p_idx)

        # 4. Operation and State validation
        for step in state.steps:
            expected_phase = OPERATION_PHASE_MAP.get(step.operation)
            if expected_phase != step.phase:
                issues.append(
                    f"Step {step.step_no}: operation {step.operation.value} cannot be in phase {step.phase.value}."
                )
            expected_state = OPERATION_STATE_MAP.get(step.operation)
            if expected_state != step.state:
                issues.append(
                    f"Step {step.step_no}: operation {step.operation.value} requires state {expected_state.value}, got {step.state.value}."
                )

        # 5. Evidence citation rules
        if state.deletion_status == DeletionStatus.COMPLETE:
            for step in state.steps:
                if step.phase != Phase.VERIFICATION:
                    issues.append(
                        f"COMPLETE case contains non-verification step {step.step_no} ({step.phase.value})."
                    )
                if not step.evidence_id:
                    issues.append(
                        f"COMPLETE verification step {step.step_no} must cite a valid evidence_id."
                    )
        elif state.deletion_status == DeletionStatus.INCOMPLETE:
            for step in state.steps:
                if step.phase == Phase.FINDING and not step.evidence_id:
                    issues.append(
                        f"INCOMPLETE finding step {step.step_no} must cite a valid evidence_id."
                    )
                elif step.phase in (Phase.REMEDIATION, Phase.VERIFICATION) and step.evidence_id:
                    issues.append(
                        f"INCOMPLETE future step {step.step_no} ({step.phase.value}) must have empty evidence_id, got '{step.evidence_id}'."
                    )

        return (len(issues) == 0, issues)


critic_verifier = CriticVerifier()
