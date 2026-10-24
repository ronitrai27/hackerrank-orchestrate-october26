"""Data models, enums, and guardrails for Ghost Data Still Exists.

Conforms strictly to the problem statement, deletion_rules.csv, and sample_output.csv.
"""

from enum import Enum
import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


class DeletionStatus(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Phase(str, Enum):
    FINDING = "FINDING"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"


class StepOperation(str, Enum):
    # --- FINDING phase operations ---
    REPORT_REMAINING_RECORD = "REPORT_REMAINING_RECORD"
    REPORT_EXPOSED_PII = "REPORT_EXPOSED_PII"
    REPORT_ACTIVE_DATA_FLOW = "REPORT_ACTIVE_DATA_FLOW"
    REPORT_RESTORE_RISK = "REPORT_RESTORE_RISK"

    # --- REMEDIATION phase operations ---
    DISABLE_DATA_FLOW = "DISABLE_DATA_FLOW"
    BLOCK_RESTORE = "BLOCK_RESTORE"
    DELETE_RECORD = "DELETE_RECORD"
    REDACT_RECORD = "REDACT_RECORD"
    ANONYMIZE_RECORD = "ANONYMIZE_RECORD"

    # --- VERIFICATION phase operations ---
    VERIFY_RECORD_ABSENT = "VERIFY_RECORD_ABSENT"
    VERIFY_RECORD_PRESENT = "VERIFY_RECORD_PRESENT"
    VERIFY_RECORD_REDACTED = "VERIFY_RECORD_REDACTED"
    VERIFY_RECORD_ANONYMIZED = "VERIFY_RECORD_ANONYMIZED"
    VERIFY_DATA_FLOW_DISABLED = "VERIFY_DATA_FLOW_DISABLED"
    VERIFY_RESTORE_BLOCKED = "VERIFY_RESTORE_BLOCKED"


class StepState(str, Enum):
    PRESENT = "PRESENT"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    BLOCKED = "BLOCKED"
    ABSENT = "ABSENT"
    REDACTED = "REDACTED"
    ANONYMIZED = "ANONYMIZED"


# Operation to allowed Phase mapping
OPERATION_PHASE_MAP: Dict[StepOperation, Phase] = {
    StepOperation.REPORT_REMAINING_RECORD: Phase.FINDING,
    StepOperation.REPORT_EXPOSED_PII: Phase.FINDING,
    StepOperation.REPORT_ACTIVE_DATA_FLOW: Phase.FINDING,
    StepOperation.REPORT_RESTORE_RISK: Phase.FINDING,
    StepOperation.DISABLE_DATA_FLOW: Phase.REMEDIATION,
    StepOperation.BLOCK_RESTORE: Phase.REMEDIATION,
    StepOperation.DELETE_RECORD: Phase.REMEDIATION,
    StepOperation.REDACT_RECORD: Phase.REMEDIATION,
    StepOperation.ANONYMIZE_RECORD: Phase.REMEDIATION,
    StepOperation.VERIFY_RECORD_ABSENT: Phase.VERIFICATION,
    StepOperation.VERIFY_RECORD_PRESENT: Phase.VERIFICATION,
    StepOperation.VERIFY_RECORD_REDACTED: Phase.VERIFICATION,
    StepOperation.VERIFY_RECORD_ANONYMIZED: Phase.VERIFICATION,
    StepOperation.VERIFY_DATA_FLOW_DISABLED: Phase.VERIFICATION,
    StepOperation.VERIFY_RESTORE_BLOCKED: Phase.VERIFICATION,
}

# Operation to allowed State mapping
OPERATION_STATE_MAP: Dict[StepOperation, StepState] = {
    StepOperation.REPORT_REMAINING_RECORD: StepState.PRESENT,
    StepOperation.REPORT_EXPOSED_PII: StepState.PRESENT,
    StepOperation.REPORT_ACTIVE_DATA_FLOW: StepState.ACTIVE,
    StepOperation.REPORT_RESTORE_RISK: StepState.ACTIVE,
    StepOperation.DISABLE_DATA_FLOW: StepState.DISABLED,
    StepOperation.BLOCK_RESTORE: StepState.BLOCKED,
    StepOperation.DELETE_RECORD: StepState.ABSENT,
    StepOperation.REDACT_RECORD: StepState.REDACTED,
    StepOperation.ANONYMIZE_RECORD: StepState.ANONYMIZED,
    StepOperation.VERIFY_RECORD_ABSENT: StepState.ABSENT,
    StepOperation.VERIFY_RECORD_PRESENT: StepState.PRESENT,
    StepOperation.VERIFY_RECORD_REDACTED: StepState.REDACTED,
    StepOperation.VERIFY_RECORD_ANONYMIZED: StepState.ANONYMIZED,
    StepOperation.VERIFY_DATA_FLOW_DISABLED: StepState.DISABLED,
    StepOperation.VERIFY_RESTORE_BLOCKED: StepState.BLOCKED,
}

# Strict operation ordering priority within each phase
OPERATION_ORDER: Dict[StepOperation, int] = {
    # FINDING
    StepOperation.REPORT_REMAINING_RECORD: 10,
    StepOperation.REPORT_EXPOSED_PII: 11,
    StepOperation.REPORT_ACTIVE_DATA_FLOW: 12,
    StepOperation.REPORT_RESTORE_RISK: 13,
    # REMEDIATION
    StepOperation.DISABLE_DATA_FLOW: 20,
    StepOperation.BLOCK_RESTORE: 21,
    StepOperation.DELETE_RECORD: 22,
    StepOperation.REDACT_RECORD: 23,
    StepOperation.ANONYMIZE_RECORD: 24,
    # VERIFICATION
    StepOperation.VERIFY_RECORD_ABSENT: 30,
    StepOperation.VERIFY_RECORD_PRESENT: 31,
    StepOperation.VERIFY_RECORD_REDACTED: 32,
    StepOperation.VERIFY_RECORD_ANONYMIZED: 33,
    StepOperation.VERIFY_DATA_FLOW_DISABLED: 34,
    StepOperation.VERIFY_RESTORE_BLOCKED: 35,
}


class AuditStep(BaseModel):
    """Single step in steps_json."""

    step_no: int = Field(..., description="1-indexed consecutive integer")
    phase: Phase = Field(..., description="FINDING, REMEDIATION, or VERIFICATION")
    system_id: str = Field(..., description="Service or system identifier")
    resource_id: str = Field(..., description="Resource or record identifier")
    operation: StepOperation = Field(..., description="Allowed operation")
    state: StepState = Field(..., description="Allowed state matching operation")
    evidence_id: str = Field(
        default="",
        description="Evidence citation for findings and complete verifications; empty for remediation & future verification",
    )

    @model_validator(mode="after")
    def validate_phase_and_state(self) -> "AuditStep":
        # Check operation matches phase
        expected_phase = OPERATION_PHASE_MAP.get(self.operation)
        if expected_phase and self.phase != expected_phase:
            raise ValueError(
                f"Operation '{self.operation.value}' belongs to phase '{expected_phase.value}', but found '{self.phase.value}'."
            )
        # Check operation matches state
        expected_state = OPERATION_STATE_MAP.get(self.operation)
        if expected_state and self.state != expected_state:
            raise ValueError(
                f"Operation '{self.operation.value}' requires state '{expected_state.value}', but found '{self.state.value}'."
            )
        return self


class CaseOutputRow(BaseModel):
    """Complete output record for a single case in output.csv."""

    case_id: str
    deletion_status: DeletionStatus
    steps: List[AuditStep] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_contract(self) -> "CaseOutputRow":
        # If NOT_APPLICABLE, steps must be empty
        if self.deletion_status == DeletionStatus.NOT_APPLICABLE:
            if len(self.steps) > 0:
                raise ValueError("NOT_APPLICABLE cases must have an empty steps list.")
            return self

        # Steps must have consecutive numbering starting at 1
        for idx, step in enumerate(self.steps, start=1):
            if step.step_no != idx:
                raise ValueError(
                    f"Step numbering must be strictly consecutive starting at 1. Expected {idx}, got {step.step_no}."
                )

        # In COMPLETE cases, only VERIFICATION phase is allowed, and all must cite evidence_id
        if self.deletion_status == DeletionStatus.COMPLETE:
            for step in self.steps:
                if step.phase != Phase.VERIFICATION:
                    raise ValueError(
                        f"COMPLETE cases must only have VERIFICATION steps, found '{step.phase.value}'."
                    )
                if not step.evidence_id:
                    raise ValueError(
                        f"COMPLETE verification step {step.step_no} must cite a valid evidence_id."
                    )

        # In INCOMPLETE cases:
        # Remediation and future verification steps MUST have empty evidence_id
        # Findings MUST have non-empty evidence_id
        if self.deletion_status == DeletionStatus.INCOMPLETE:
            for step in self.steps:
                if step.phase == Phase.FINDING and not step.evidence_id:
                    raise ValueError(
                        f"INCOMPLETE finding step {step.step_no} must cite a valid evidence_id."
                    )
                elif step.phase in (Phase.REMEDIATION, Phase.VERIFICATION) and step.evidence_id:
                    raise ValueError(
                        f"INCOMPLETE future step {step.step_no} ({step.phase.value}) must have empty evidence_id, got '{step.evidence_id}'."
                    )

        return self

    def to_csv_dict(self) -> Dict[str, str]:
        """Convert to row dictionary for output.csv."""
        if self.deletion_status == DeletionStatus.NOT_APPLICABLE:
            steps_str = "[]"
        else:
            steps_list = [step.model_dump(mode="json") for step in self.steps]
            # Output compact JSON without redundant spaces to match sample_output.csv
            steps_str = json.dumps(steps_list, separators=(",", ":"))
        return {
            "case_id": self.case_id,
            "deletion_status": self.deletion_status.value,
            "steps_json": steps_str,
        }


class CaseState(BaseModel):
    """Complete LangGraph execution state for one case."""

    # Input request fields from deletion_requests.csv
    case_id: str
    email: str
    requested_at: str
    reported_status: str
    reported_at: str
    audit_at: str
    request_text: str

    # Intent analysis (via JEV Choice)
    authorizes_deletion: Optional[bool] = None
    intent_reason: Optional[str] = None

    # Resolved identity bundle
    user_id: Optional[str] = None
    all_emails: List[str] = Field(default_factory=list)
    names: List[str] = Field(default_factory=list)
    phones: List[str] = Field(default_factory=list)
    email_hashes: List[str] = Field(default_factory=list)

    # Discovered evidence records filtered to <= audit_at
    remaining_records: List[Dict[str, Any]] = Field(default_factory=list)
    exposed_pii_records: List[Dict[str, Any]] = Field(default_factory=list)
    active_data_flows: List[Dict[str, Any]] = Field(default_factory=list)
    restore_risks: List[Dict[str, Any]] = Field(default_factory=list)
    retained_records: List[Dict[str, Any]] = Field(default_factory=list)

    # Verified clean records (for COMPLETE cases)
    verified_absent_records: List[Dict[str, Any]] = Field(default_factory=list)

    # Generated steps and status
    deletion_status: Optional[DeletionStatus] = None
    steps: List[AuditStep] = Field(default_factory=list)

    # Critic verification status
    critic_passed: bool = False
    critic_feedback: List[str] = Field(default_factory=list)
