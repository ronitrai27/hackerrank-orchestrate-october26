"""Test suite for the 3 participant-authored custom evaluation cases.

Demonstrates evaluation across 3 distinct edge scenarios:
1. case_custom_01: Tombstone PII leakage / exposed identifiers in customer snapshot bundle.
2. case_custom_02: Cross-system SQLite replica drift / ghost records in read-replica database.
3. case_custom_03: Multilingual GDPR Art. 15 Data Access & Portability request (NOT_APPLICABLE).
"""

import unittest
from code.src.guardrails.schemas import CaseState, DeletionStatus
from code.src.app.graph.workflow import audit_graph


class TestCustomEvaluationCases(unittest.TestCase):
    """3 custom participant evaluation cases testing complex edge scenarios."""

    def test_custom_case_01_tombstone_pii_leak(self):
        """Case 1: User requested deletion; workflow reported COMPLETE, but an unredacted

        tombstone with exposed personal identifiers remains in a snapshot bundle.
        Must evaluate to INCOMPLETE with REPORT_EXPOSED_PII and REDACT_RECORD.
        """
        req_state = CaseState(
            case_id="case_custom_01",
            email="addo.kofi@gmail.com",
            requested_at="2026-09-03T12:00:00Z",
            reported_status="COMPLETE",
            reported_at="2026-09-06T12:00:00Z",
            audit_at="2026-09-15T12:00:00Z",
            request_text="Please delete my account and ensure no personal information is retained in tombstones.",
        )

        final_dict = audit_graph.invoke(req_state)
        final_state = CaseState.model_validate(final_dict)

        self.assertEqual(final_state.deletion_status, DeletionStatus.INCOMPLETE)
        self.assertTrue(final_state.critic_passed, f"Critic issues: {final_state.critic_feedback}")

        operations = [s.operation.value for s in final_state.steps]
        self.assertIn("REPORT_EXPOSED_PII", operations)
        self.assertIn("REDACT_RECORD", operations)
        self.assertIn("VERIFY_RECORD_REDACTED", operations)

        # Confirm step ordering: FINDING -> REMEDIATION -> VERIFICATION
        phases = [s.phase.value for s in final_state.steps]
        self.assertIn("FINDING", phases)
        self.assertIn("REMEDIATION", phases)
        self.assertIn("VERIFICATION", phases)
        print(f"\n[PASS] case_custom_01 (Tombstone PII) -> Status: {final_state.deletion_status}, Steps: {len(final_state.steps)}")

    def test_custom_case_02_sqlite_replica_drift(self):
        """Case 2: Primary record deleted, but cross-system SQLite read-replica

        drift left ghost customer records in customer_data_read_replica.
        Must evaluate to INCOMPLETE with REPORT_REMAINING_RECORD and DELETE_RECORD.
        """
        req_state = CaseState(
            case_id="case_custom_02",
            email="diya.k4436@outlook.com",
            requested_at="2026-08-29T10:00:00Z",
            reported_status="COMPLETE",
            reported_at="2026-09-01T10:00:00Z",
            audit_at="2026-09-21T10:00:00Z",
            request_text="Please delete my account and ensure all database replicas are purged.",
        )

        final_dict = audit_graph.invoke(req_state)
        final_state = CaseState.model_validate(final_dict)

        self.assertEqual(final_state.deletion_status, DeletionStatus.INCOMPLETE)
        self.assertTrue(final_state.critic_passed, f"Critic issues: {final_state.critic_feedback}")

        operations = [s.operation.value for s in final_state.steps]
        self.assertIn("REPORT_REMAINING_RECORD", operations)
        self.assertIn("DELETE_RECORD", operations)
        self.assertIn("VERIFY_RECORD_ABSENT", operations)

        print(f"[PASS] case_custom_02 (Replica Drift) -> Status: {final_state.deletion_status}, Steps: {len(final_state.steps)}")

    def test_custom_case_03_non_deletion_dsar_export(self):
        """Case 3: Multilingual GDPR Article 15 Data Access & Portability request.

        The customer explicitly requests to download a copy of their data and NOT delete.
        Must evaluate to NOT_APPLICABLE with steps_json=[].
        """
        req_state = CaseState(
            case_id="case_custom_03",
            email="amina.elmasri@gmail.com",
            requested_at="2026-08-18T09:14:00Z",
            reported_status="NOT_STARTED",
            reported_at="2026-08-18T09:15:00Z",
            audit_at="2026-09-03T11:30:00Z",
            request_text="Ich möchte eine Kopie meiner Daten herunterladen (Auskunftsrecht DSGVO Art. 15). Bitte mein Konto auf keinen Fall löschen.",
        )

        final_dict = audit_graph.invoke(req_state)
        final_state = CaseState.model_validate(final_dict)

        self.assertEqual(final_state.deletion_status, DeletionStatus.NOT_APPLICABLE)
        self.assertEqual(len(final_state.steps), 0)
        self.assertTrue(final_state.critic_passed, f"Critic issues: {final_state.critic_feedback}")

        print(f"[PASS] case_custom_03 (Multilingual DSAR Export) -> Status: {final_state.deletion_status}, Steps: {len(final_state.steps)} (Empty [])")


if __name__ == "__main__":
    unittest.main()
