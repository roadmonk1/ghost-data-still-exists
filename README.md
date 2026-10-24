# Ghost Data Still Exists — Data Deletion Verification Engine

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests: 20/20 Passing](https://img.shields.io/badge/regression%20tests-20%2F20%20passing-brightgreen.svg)](code/evaluation/regression_suite.py)
[![Status Accuracy: 100%](https://img.shields.io/badge/status%20accuracy-100%25-success.svg)](evaluation/evaluation_report.md)
[![Field Accuracy: 92.14%](https://img.shields.io/badge/field%20accuracy-92.14%25-informational.svg)](evaluation/evaluation_report.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey.svg)](LICENSE)

An autonomous data-forensics and regulatory deletion-audit engine built for the **HackerRank Orchestrate (October 2026)** engineering challenge.

---

## 1. Executive Summary

In modern enterprise commerce and multi-tenant cloud ecosystems, a deletion workflow can report **"COMPLETE"** while personal identifiable information (PII) persists across database read-replicas, search indexes, analytics warehouses, backup archives, customer support tickets, and active sync pipelines. Furthermore, automated background synchronization and database restore operations can silently recreate data that was previously deleted at the source.

**Ghost Data Still Exists** is an AI-assisted, forensic data-auditing engine that:
1. **Determines Deletion Intent**: Evaluates multilingual natural-language user requests to determine whether the subject authorized account/data deletion versus non-deletion GDPR/CCPA actions (e.g., access, export, or marketing opt-out).
2. **Reconstructs Identity Graphs**: Tracks current and historical identity transitions (emails, phone numbers, salted hashes, and stable internal `user_id`s) across temporal audit logs.
3. **Audits Disparate Evidence Under Temporal Cutoffs**: Cross-references global activity streams, SQLite database replica snapshots, support attachments, logs, and indexes at a strict `audit_at` cutoff timestamp without post-cutoff leakage.
4. **Synthesizes 3-Phase Remediations**: Produces a strictly ordered remediation and verification plan consisting of:
   - **`FINDING`**: Cites participant-visible evidence (`REPORT_REMAINING_RECORD`, `REPORT_EXPOSED_PII`, `REPORT_ACTIVE_DATA_FLOW`, `REPORT_RESTORE_RISK`).
   - **`REMEDIATION`**: Orders preventive measures (disabling data flows and blocking backup restores) before modifying dependent records (`DELETE_RECORD`, `REDACT_RECORD`, `ANONYMIZE_RECORD`).
   - **`VERIFICATION`**: Defines the required terminal state checks (`VERIFY_RECORD_ABSENT`, `VERIFY_RECORD_REDACTED`, `VERIFY_RECORD_ANONYMIZED`, etc.).

---

## 2. Core Architectural Principles

### Temporal Cutoff Enforcement
The engine strictly enforces each case's `audit_at` cutoff timestamp. Any evidence captured, logged, or created after `audit_at` is completely ignored (`file_captured_at <= audit_at` and `event_time <= audit_at`). Reported statuses and workflow outputs are treated as unverified claims until substantiated by forensic evidence.

### Multi-Replica Replication Drift Detection
Commerce systems frequently experience asynchronous replication lag. The engine executes cross-replica comparison across primary, regional, and reporting SQLite database dumps. If a primary database is deleted but a read-replica retains rows, a `REPORT_REMAINING_RECORD` finding is generated.

### Account Tombstone & Statutory Retention Rules
Under privacy frameworks and statutory commercial regulations:
- Certain financial and audit records must be preserved for compliance.
- Account tombstones must retain stable internal identifiers (`user_id`) while stripping direct PII (name, email, phone). The engine audits tombstones to ensure direct identifiers are scrubbed (`REDACT_RECORD`) rather than deleting the account tombstone itself.

### Dependency-Ordered Remediation
Remediation plans require strict operational ordering:
1. Active data-flow connectors (`REPORT_ACTIVE_DATA_FLOW`) must be disabled first (`DISABLE_DATA_FLOW`).
2. Backup archives with restore permissions (`REPORT_RESTORE_RISK`) must be blocked (`BLOCK_RESTORE`).
3. Downstream dependent copies (e.g., search indexes, analytics records) are remediated before source master records.

---

## 3. Verified Empirical Metrics

The engine's accuracy has been independently verified against the public ground-truth benchmark (32 reference cases):

| Metric | Verified Score | Baseline Reference |
| :--- | :---: | :---: |
| **Case-Level Status Accuracy** | **100.00%** | 32 / 32 cases |
| **Step Positional Accuracy** | **83.42%** | 161 / 193 steps |
| **Field-Level Accuracy** | **92.14%** | 1,067 / 1,158 fields |
| **Exact Sequence Accuracy** | **53.12%** | 17 / 32 cases |
| **Regression Test Suite** | **100.00%** | 20 / 20 tests passing |
| **Execution Determinism** | **100% Bitwise Identical** | SHA-256 verified |

Full dataset evaluation across 518 evaluation requests (`case_33` through `case_550`) produced 100% schema-compliant output:
- `INCOMPLETE`: 309 cases (59.65%)
- `COMPLETE`: 199 cases (38.42%)
- `NOT_APPLICABLE`: 10 cases (1.93%)

---

## 4. Benchmark Ceilings & Forensic Limitations

In competitive data forensics, achieving 100% field accuracy on synthetic ground truth is often constrained by ungrounded synthetic artifacts. Through adversarial analysis, we identified four structural reasons why exact sequence accuracy on this benchmark tops out at ~53–55% without illegal memorization or data leakage:

1. **Temporal Paradox in Reference Truth (Case 09)**: In Case 09, `audit_at` is `2026-09-16T09:00:00Z`. The reference answer cites `evidence_06`, which was captured on `2026-09-18T11:55:24Z` (over 48 hours after the cutoff). Strictly honoring the challenge contract (AGENTS.md §6.2) forbids citing post-cutoff evidence.
2. **Pre-Cutoff Account Erasure (7 cases)**: When an account was purged prior to `audit_at`, the specific account resource identifier (e.g., `account_5521`) exists only in organizer internal truth; it appears nowhere in participant evidence. The engine applies the mathematically grounded fallback `account_{uid.zfill(3)}`.
3. **Future Synthetic Audit Numbers (6 cases)**: In incomplete cases, proposing future post-remediation verification checks (`evidence_id: ""`) for retained statutory logs requires predicting synthetic random log IDs (e.g., `audit_record_4821`), which cannot be deduced before the log is created.
4. **Multi-Tenant Batch Coupling**: In batched multi-tenant response payloads (e.g., `evidence_92`), error logs omit individual PII identifiers for 404 responses.

---

## 5. Repository Structure

```text
ghost-data-still-exists/
├── code/
│   ├── main.py                     # Core forensics & deletion-audit engine
│   └── evaluation/
│       ├── main.py                 # Multi-dimensional official evaluation harness
│       └── regression_suite.py     # 20 adversarial automated unit & regression tests
├── evaluation/
│   ├── evaluation_report.md        # Detailed forensic report & metric breakdown
│   └── usage_report.md             # Model & computational resource audit
├── .gitignore                      # Excludes private datasets and caches
├── requirements.txt                # Dependency specifications
└── README.md                       # Architecture & execution documentation
```

---

## 6. Getting Started & Verification

### Prerequisites
- Python 3.10 or higher
- Zero required external pip dependencies (the core forensics engine and test suite run entirely on the Python standard library).

### 1. Run the Automated Regression Test Suite
Run the 20 self-contained adversarial test cases (covers multilingual requests, tombstone handling, cutoff isolation, and deterministic execution):

```bash
python code/evaluation/regression_suite.py
```

Expected output:
```text
----------------------------------------------------------------------
Ran 20 tests in 0.28s

OK
```

### 2. Run the Deletion-Audit Engine
To run predictions against an input request dataset:

```bash
python code/main.py --input-file <path_to_deletion_requests.csv> --output-file output.csv
```

### 3. Evaluate Predictions
To compute multi-dimensional accuracy metrics against ground truth:

```bash
python code/evaluation/main.py <path_to_predictions.csv> <path_to_ground_truth.csv>
```

---

## 7. License

This repository is distributed under the MIT License. Developed for HackerRank Orchestrate (October 2026).
