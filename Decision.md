📁 Submission Checklist
Artifact	Where
output.csv	Repo root — 518 rows
code.zip	Contains code/, README.md, code/evaluation/evaluation_report.md, code/evaluation/usage_report.md
chat_transcript	Upload log.txt from repo root
Agent trace zip	Your Antigravity IDE brain folder (see agent_trace_instructions.md)
⚡ Key Gotchas
Do NOT trust reported_status — it's a claim. Cases marked COMPLETE may have ghost data everywhere.
Historical emails matter — a request may use an old email; user_audit_log.csv resolves it.
audit_at is the cutoff — evidence timestamped AFTER audit_at must be ignored for that case.
Evidence files have no case label — you must connect them by matching identifiers in the file contents.
SQL evidence = SQLite snapshots — may include regional replicas with different data (replication drift).
Account tombstones — user_id stays, but name/email/phone/hash must be redacted (rule_15).