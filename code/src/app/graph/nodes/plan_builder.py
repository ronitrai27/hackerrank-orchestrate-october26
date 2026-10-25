"""Plan Builder Node.

Constructs the final audit steps and assigns deletion_status based on evidence findings.
"""

from typing import List
from code.src.guardrails.schemas import AuditStep, CaseState, DeletionStatus, Phase, StepOperation, StepState
from code.src.lib.evidence_engine import evidence_engine


def build_audit_plan(state: CaseState) -> CaseState:
    """Audit evidence and construct ordered AuditStep list."""
    # 1. If not a deletion request, return NOT_APPLICABLE
    if state.authorizes_deletion is False:
        state.deletion_status = DeletionStatus.NOT_APPLICABLE
        state.steps = []
        return state

    # 2. Resolve current and historical identities
    identity = evidence_engine.resolve_identity(state.email)
    state.user_id = identity.get("user_id")
    state.all_emails = identity.get("all_emails", [state.email])
    state.names = identity.get("names", [])
    state.phones = identity.get("phones", [])
    state.email_hashes = identity.get("email_hashes", [])

    # 3. Scan evidence files, SQL replicas, and system activity up to audit_at
    steps = evidence_engine.scan_evidence_for_case(
        case_id=state.case_id,
        identity=identity,
        audit_at=state.audit_at,
    )

    # 4. Determine status based on presence of findings
    has_findings = any(s.phase == Phase.FINDING for s in steps)

    if has_findings:
        state.deletion_status = DeletionStatus.INCOMPLETE
        state.steps = steps
    else:
        state.deletion_status = DeletionStatus.COMPLETE
        state.steps = steps

    return state
