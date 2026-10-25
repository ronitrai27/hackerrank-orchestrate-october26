# Ghost Data Still Exists: AI Deletion Audit Agent

An enterprise-grade, deterministic AI-powered deletion-audit agent built for **HackerRank Orchestrate (October 2026)**.

The agent investigates data deletion requests across multi-system commerce platforms to determine whether a subject's personal data was truly deleted, whether it persists in databases, logs, replicas, attachments, or backups, and what ordered remediation and verification steps are necessary to achieve complete compliance.

---

## 1. System Overview & Core Approach

Traditional deletion workflows frequently report `COMPLETE` prematurely while user PII persists across read replicas, debug logs, backup snapshots, or customer support bundles. Active synchronization and failover pipelines may also recreate data that was previously erased.

Our agent abandons naive, hallucination-prone end-to-end LLM prompting in favor of a **deterministic LangGraph StateGraph** orchestrated with strict schema guardrails, dynamic multi-hop identity resolution, and deep evidence inspection.

```
+--------------------------------------------------------------------------------------------------+
|                                    DELETION AUDIT WORKFLOW                                       |
+--------------------------------------------------------------------------------------------------+
                                                 |
                                     1. INGESTION & TEMPORAL CUTOFF
                                     - Enforces strict audit_at barrier
                                     - Discards post-audit evidence/claims
                                                 |
                                                 v
                                       2. INTENT CLASSIFICATION
                                     - Authorizes deletion vs GDPR Art 15 / Access / Export / Opt-out
                                     - Returns NOT_APPLICABLE with steps_json=[] on non-deletion
                                                 |
                                                 v
                                  3. MULTI-HOP CRYPTOGRAPHIC IDENTITY GRAPH
                                     - Resolves user_identities.csv snapshot (user_id, names, emails, phones)
                                     - Scans user_audit_log.csv for historical emails/phones
                                     - Derives full SHA-256 hash sets for correlation key matching
                                                 |
                                                 v
                                    4. MULTI-SOURCE EVIDENCE ENGINE
                                     - SQLite primary, replica & reporting drift (evaluates record_json columns)
                                     - JSON customer snapshot bundles & account tombstone PII leakage
                                     - Word-boundary token-exact service log scanning (prevents substring collision)
                                     - system_activity.csv failed deletion tracing & active sync risks
                                     - Multimodal OCR / PDF attachment inspection
                                                 |
                                                 v
                                    5. POLICY & INVARIANT PLAN BUILDER
                                     - Evaluates findings against deletion_rules.csv
                                     - Generates ordered steps: FINDING -> REMEDIATION -> VERIFICATION
                                     - Emits evidence-backed verification for COMPLETE cases
                                                 |
                                                 v
                                   6. TWO-TIER DETERMINISTIC CRITIC VERIFIER
                                     - Validates Pydantic invariants, step numbering & field states
                                     - Ensures zero hallucinations & strict evidence_id grounding
                                                 |
                                                 v
                                        Validated output.csv Row
```

### Key Pillars of the Approach

1. **Temporal Cutoff Barrier (`audit_at`)**:
   The agent reconstructs the ground-truth state strictly as of the case's `audit_at` timestamp. Any system activity, snapshots, or evidence logged after this threshold are discarded. Reported claims (`reported_status`) are treated purely as assertions, never as proof.

2. **Intent Classification & Scope Guard**:
   Distinguishes genuine deletion/erasure requests (GDPR Art. 17 / CCPA) from data access, rectification, portability, or marketing opt-out inquiries (e.g., GDPR Art. 15). Non-deletion requests correctly yield `NOT_APPLICABLE` with an empty step sequence (`[]`).

3. **Multi-Hop Cryptographic Identity Graph**:
   Merges current identity records from `user_identities.csv` with historical mutations in `user_audit_log.csv`. Computes SHA-256 digests across all past and present email variants, enabling the agent to match anonymized correlation keys in background logs (such as `analytics_service` traces).

4. **Deep Evidence Introspection**:
   - **SQLite Snapshot Execution**: Dynamically executes and queries primary, regional, reporting, and failover SQL replicas. Recursively parses dynamic JSON fields (`record_json`) to catch un-purged user records.
   - **Tombstone PII Inspection**: Inspects account tombstones to ensure direct identifiers (name, email, phone) are completely redacted while preserving the stable `user_id`.
   - **Token-Exact Word-Boundary Matching**: Uses word-boundary matching (`\b`) to eliminate false-positive substring collisions (e.g., preventing `user_43` from falsely triggering on `user_437`).
   - **Failure & Recreation Traces**: Detects `FAILED` deletion events and active background synchronizations in `system_activity.csv`.
   - **Cached Multimodal OCR**: Scans support ticket attachments and customer handover documents.

5. **Deterministic Policy & Invariant Plan Builder**:
   Maps evidence findings directly to rules in `deletion_rules.csv`. Enforces the required 3-phase sequence: `FINDING` &rarr; `REMEDIATION` &rarr; `VERIFICATION`. Remediation orders process-disabling before dependent record modifications. `COMPLETE` cases cite evidence proving compliance at `audit_at`, while future remediation actions cite `""`.

6. **Two-Tier Critic & Schema Guardrails**:
   A deterministic Pydantic validator guarantees schema compliance, 1-indexed contiguous step numbers, valid operation-state pairings, and valid evidence citations before emitting final rows.

---

## 2. Directory Structure

```text
code/
├── README.md                      # This comprehensive architecture and usage guide
├── __init__.py                    # Python package declaration
├── main.py                        # Primary CLI entry point to run audit across 518 cases
├── Docs/
│   └── Decision.md                # Detailed technical architecture & decision rationale
├── evaluation/
│   ├── main.py                    # Evaluation suite CLI runner (32 samples + 3 custom cases)
│   ├── evaluation_report.md       # Full evaluation report (100% accuracy, metrics, edge cases)
│   └── usage_report.md            # Token usage, model execution counts, and cost metrics
└── src/
    ├── __init__.py
    ├── app/
    │   ├── __init__.py
    │   └── graph/
    │       ├── __init__.py
    │       ├── workflow.py        # LangGraph StateGraph pipeline definition
    │       └── nodes/
    │           ├── __init__.py
    │           ├── intent_classifier.py  # Intent categorization & cutoff enforcement
    │           └── plan_builder.py       # Policy mapping & remediation plan generator
    ├── config/
    │   ├── __init__.py
    │   └── settings.py            # Centralized settings & path configuration
    ├── guardrails/
    │   ├── __init__.py
    │   ├── schemas.py             # Pydantic v2 data models & validation invariants
    │   └── critic.py              # Two-tier deterministic schema & evidence verifier
    ├── lib/
    │   ├── __init__.py
    │   ├── evidence_engine.py     # SQLite, log, snapshot & activity audit engine
    │   └── ocr_extractor.py       # Multimodal OCR engine for images and PDFs
    └── tests/
        ├── __init__.py
        ├── test_samples.py        # Calibration test suite over 32 official sample cases
        └── test_custom_cases.py   # Participant-authored custom evaluation test cases
```

---

## 3. Setup and Installation

### Prerequisites

- **Python**: Version 3.10, 3.11, 3.12, or 3.13
- **Virtual Environment Tool**: `uv` (recommended) or standard `venv` / `pip`

### Step 1: Clone Repository & Create Virtual Environment

From the repository root:

```bash
# Using uv (fastest)
uv venv
source .venv/bin/activate       # macOS / Linux
# or
.venv\Scripts\Activate.ps1      # Windows PowerShell

# Or using standard python venv
python3 -m venv .venv
source .venv/bin/activate       # macOS / Linux
# or
.venv\Scripts\Activate.ps1      # Windows PowerShell
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
# or via uv:
uv pip install -r requirements.txt
```

Core dependencies installed:
- `pydantic>=2.7.0` (Type-safe schemas and validation invariants)
- `langgraph>=0.0.30` & `langchain-core>=0.1.30` (Deterministic state machine orchestration)
- `python-dotenv>=1.0.0` (Environment variable management)
- `pillow>=10.2.0`, `pypdf>=4.1.0`, `pdfplumber>=0.10.0` (Multimodal and document parsing)

### Step 3: Environment Configuration

Create a `.env` file at the repository root to configure the necessary API keys:

```bash
# TypeSafe JEV Decisions API (via OpenRouter Alpha Decisions endpoint)
# Powers the IntentClassifier node (model: typesafe/jev-1.14) for multilingual deletion authorization
OPENROUTER_JEV=your_openrouter_api_key_here
# or: TYPESAFE_API_KEY=your_typesafe_key_here

# Optional: Google Gemini API (used during multimodal OCR extraction for images/PDFs)
# Note: OCR extracts are already pre-cached in dataset/evidence/ocr_cache/
GEMINI_API_KEY=your_gemini_api_key_here

# Optional: OpenAI API key (if using external LLM fallback)
OPENAI_API_KEY=your_openai_api_key_here
```

*(Note: The pipeline includes defensive caching and heuristics so execution can proceed smoothly even if offline, but `OPENROUTER_JEV` powers live TypeSafe JEV 1.14 decisions via the Decisions API).*

---

## 4. How to Run

### Run Full 518-Case Deletion Audit Pipeline

To process all 518 cases from `dataset/deletion_requests.csv` and generate the official root `output.csv`:

```bash
# From repository root:
python code/main.py
```

Options:
- `--requests <path>`: Custom input CSV path (default: `dataset/deletion_requests.csv`)
- `--output <path>`: Custom output CSV path (default: `output.csv`)
- `--limit <int>`: Limit processing to first N cases (ideal for smoke testing)

Example:
```bash
python code/main.py --limit 10
```

### Run Evaluation & Calibration Test Suite

Run the full evaluation runner across the 32 official benchmark cases and the 3 custom edge cases:

```bash
python code/evaluation/main.py
```

Or run via `unittest` directly:

```bash
# Run sample cases calibration (32 cases)
python -m unittest code.src.tests.test_samples

# Run participant custom edge cases (3 cases)
python -m unittest code.src.tests.test_custom_cases
```

---

## 5. Benchmark & Accuracy Metrics

| Benchmark Suite | Total Cases | Target Metric | Result | Accuracy |
|---|---|---|---|---|
| **Official Sample Calibration** | 32 cases | Status, Steps, Operation Parity | **32 / 32 Passed** | **100.0%** |
| **Participant Custom Edge Cases** | 3 cases | Complex Leakage & GDPR Art 15 | **3 / 3 Passed** | **100.0%** |
| **Official 518 Evaluation Dataset** | 518 cases | Execution & Schema Validity | **518 / 518 Valid** | **100.0%** |

Full metrics, field-level breakdowns, and token expenditure are documented in:
- [`code/evaluation/evaluation_report.md`](file:///R:/hackerrank/code/evaluation/evaluation_report.md)
- [`code/evaluation/usage_report.md`](file:///R:/hackerrank/code/evaluation/usage_report.md)

---

## 6. Output Contract Conformance

The output generated at `output.csv` conforms strictly to challenge requirements:
- Columns: `case_id,deletion_status,steps_json`
- Sorted ascending by `case_id`
- JSON array encoding with consecutive 1-based step numbering
- Strict phase sequencing: `FINDING` &rarr; `REMEDIATION` &rarr; `VERIFICATION`
- Valid operation and state mappings according to §6.4 of `AGENTS.md`
