"""Test suite for calibrating against dataset/sample_deletion_requests.csv.

Runs the LangGraph deletion audit agent on the 32 sample requests and
compares the output against dataset/sample_output.csv.
"""

import csv
import json
import unittest
from pathlib import Path

from code.src.config.settings import settings
from code.src.guardrails.schemas import CaseOutputRow, CaseState, DeletionStatus
from code.src.app.graph.workflow import audit_graph


class TestSampleCases(unittest.TestCase):
    """Test cases against official sample ground truth."""

    @classmethod
    def setUpClass(cls):
        # Load sample ground truth
        cls.sample_output_path = settings.dataset_dir / "sample_output.csv"
        cls.ground_truth = {}
        if cls.sample_output_path.exists():
            with open(cls.sample_output_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    cls.ground_truth[row["case_id"]] = {
                        "deletion_status": row["deletion_status"],
                        "steps_json": json.loads(row["steps_json"]),
                    }

        # Load sample requests
        cls.sample_requests_path = settings.dataset_dir / "sample_deletion_requests.csv"
        cls.sample_requests = []
        if cls.sample_requests_path.exists():
            with open(cls.sample_requests_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                cls.sample_requests = list(reader)

    def test_run_all_32_samples(self):
        """Run all 32 sample cases through the compiled LangGraph agent and report accuracy."""
        self.assertGreater(len(self.sample_requests), 0, "No sample requests loaded.")

        correct_status = 0
        total = len(self.sample_requests)

        for req in self.sample_requests:
            case_id = req["case_id"]
            init_state = CaseState(
                case_id=case_id,
                email=req["email"],
                requested_at=req["requested_at"],
                reported_status=req["reported_status"],
                reported_at=req["reported_at"],
                audit_at=req["audit_at"],
                request_text=req["request_text"],
            )

            final_state_dict = audit_graph.invoke(init_state)
            final_state = CaseState.model_validate(final_state_dict)

            row = CaseOutputRow(
                case_id=final_state.case_id,
                deletion_status=final_state.deletion_status,
                steps=final_state.steps,
            )
            csv_dict = row.to_csv_dict()
            pred_status = csv_dict["deletion_status"]

            if case_id in self.ground_truth:
                gt_status = self.ground_truth[case_id]["deletion_status"]
                is_match = (pred_status == gt_status)
                if is_match:
                    correct_status += 1
                status_icon = "MATCH" if is_match else "MISMATCH"
                print(f"{case_id}: Pred={pred_status} | GT={gt_status} | Steps={len(final_state.steps)} [{status_icon}]")

        accuracy = (correct_status / total) * 100
        print(f"\n==========================================")
        print(f"SAMPLE SET ACCURACY: {correct_status}/{total} ({accuracy:.1f}%)")
        print(f"==========================================")
        self.assertGreaterEqual(accuracy, 75.0)


if __name__ == "__main__":
    unittest.main()
