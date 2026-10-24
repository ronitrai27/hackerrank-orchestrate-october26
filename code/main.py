"""Ghost Data Still Exists - Main Entry Point.

Executes the deletion audit agent across dataset/deletion_requests.csv (518 cases)
and writes the final validated predictions directly to output.csv at the repository root.
"""

import argparse
import csv
import sys
import time
from pathlib import Path
from typing import Optional

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from code.src.config.settings import settings
from code.src.guardrails.schemas import CaseOutputRow, CaseState
from code.src.app.graph.workflow import audit_graph


def run_pipeline(
    requests_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
    limit: Optional[int] = None,
) -> None:
    """Run deletion audit agent across all cases and write output.csv."""
    req_file = requests_path or (settings.dataset_dir / "deletion_requests.csv")
    out_file = output_path or settings.output_csv_path

    if not req_file.exists():
        print(f"Error: Requests file not found at {req_file}")
        sys.exit(1)

    print(f"==================================================")
    print(f"GHOST DATA STILL EXISTS: DELETION AUDIT AGENT")
    print(f"Reading requests from: {req_file}")
    print(f"Writing output to:     {out_file}")
    print(f"==================================================")

    with open(req_file, "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))

    if limit:
        reader = reader[:limit]

    total_cases = len(reader)
    print(f"Processing {total_cases} cases...")

    start_time = time.time()
    results = []

    for idx, row in enumerate(reader, start=1):
        case_id = row["case_id"]
        init_state = CaseState(
            case_id=case_id,
            email=row["email"],
            requested_at=row["requested_at"],
            reported_status=row["reported_status"],
            reported_at=row["reported_at"],
            audit_at=row["audit_at"],
            request_text=row["request_text"],
        )

        try:
            final_state_dict = audit_graph.invoke(init_state)
            final_state = CaseState.model_validate(final_state_dict)

            output_row = CaseOutputRow(
                case_id=final_state.case_id,
                deletion_status=final_state.deletion_status,
                steps=final_state.steps,
            )
            csv_dict = output_row.to_csv_dict()
            results.append(csv_dict)

            if idx % 25 == 0 or idx == total_cases:
                elapsed = time.time() - start_time
                print(f"Progress: [{idx}/{total_cases}] (Elapsed: {elapsed:.1f}s)")
        except Exception as e:
            print(f"Error processing {case_id}: {e}")
            # Safe fallback to NOT_APPLICABLE on unrecoverable failure
            results.append({
                "case_id": case_id,
                "deletion_status": "NOT_APPLICABLE",
                "steps_json": "[]",
            })

    # Sort results strictly by case_id as required by the challenge
    results.sort(key=lambda r: r["case_id"])

    # Write output.csv with exact header
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["case_id", "deletion_status", "steps_json"],
            quoting=csv.QUOTE_MINIMAL,
        )
        writer.writeheader()
        for r in results:
            writer.writerow(r)

    total_time = time.time() - start_time
    print(f"==================================================")
    print(f"COMPLETED: Wrote {len(results)} rows to {out_file}")
    print(f"Total time: {total_time:.1f}s ({total_time / total_cases:.2f}s per case)")
    print(f"==================================================")


def main():
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists Runner")
    parser.add_argument("--requests", type=Path, default=None, help="Path to input deletion requests CSV")
    parser.add_argument("--output", type=Path, default=None, help="Path to target output CSV")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of cases (for testing)")
    args = parser.parse_args()

    run_pipeline(
        requests_path=args.requests,
        output_path=args.output,
        limit=args.limit,
    )


if __name__ == "__main__":
    main()
