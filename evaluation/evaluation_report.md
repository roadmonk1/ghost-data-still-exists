# Evaluation Report: Ghost Data Still Exists Deletion-Audit Agent

**Challenge**: HackerRank Orchestrate (October 2026) — Ghost Data Still Exists  
**Solution**: Deterministic Evidence-Grounded Deletion-Audit Engine (`code/main.py`)  
**Evaluated Against**: Public Baseline (`dataset/sample_deletion_requests.csv` & `dataset/sample_output.csv`) + 518 Evaluation Cases (`dataset/deletion_requests.csv`)

---

## 1. Measured Evaluation Metrics

All metrics reported below are calculated directly from empirical runs against the official ground truth in `dataset/sample_output.csv` using the enhanced evaluator in `code/evaluation/main.py`.

| Evaluation Metric | Initial Baseline | Phase 1 Verified | Phase 2 Final | Passed / Total | Description |
|---|---|---|---|---|---|
| **Case-Level Status Accuracy** | 100.00% (32/32) | 100.00% (32/32) | **100.00%** | **32 / 32** | Perfect classification across `COMPLETE`, `INCOMPLETE`, `NOT_APPLICABLE` |
| **Field-Level Accuracy** | 84.37% (977/1158) | 85.41% (989/1158) | **92.14%** | **1,067 / 1,158** | Exact match across `phase`, `system_id`, `resource_id`, `operation`, `state`, `evidence_id` |
| **Step-Level Positional Match** | 75.65% (146/193) | 76.68% (148/193) | **83.42%** | **161 / 193** | Exact positional alignment across all step tuple definitions |
| **Exact Sequence Accuracy** | 40.62% (13/32) | 43.75% (14/32) | **53.12%** | **17 / 32** | Complete, identical JSON array match including step ordering and numbering |

### Field-Level Accuracy Breakdown

| Field | Errors | Accuracy | Notes |
|---|---|---|---|
| `phase` | 3 | **98.4%** | Finding -> Remediation -> Verification ordering strictly enforced |
| `evidence_id` | 8 | **95.9%** | Grounded evidence citations for present and redacted resources |
| `system_id` | 16 | **91.7%** | Canonical system normalization across all services |
| `operation` | 16 | **91.7%** | Strict policy action mapping per data category |
| `state` | 16 | **91.7%** | Grounded resource states at cutoff time |
| `resource_id` | 32 | **83.4%** | Grounded resource identifier matching across evidence sources |

### Full Dataset Execution Summary (518 Cases)
- **Total Requests Evaluated**: 518 cases (`case_33` through `case_550`)
- **INCOMPLETE Decisions**: 309 cases (59.65%) — remaining replicas, active data flows, or unredacted PII identified
- **COMPLETE Decisions**: 199 cases (38.42%) — fully verified compliant states across all copies
- **NOT_APPLICABLE Decisions**: 10 cases (1.93%) — non-destructive intent classified (e.g., promo opt-out, account access, correction)
- **Determinism Check**: Two consecutive full runs yielded identical SHA-256 hashes (`d769ded4ce5490f5d457e243458aee8729d35bbb6a3cb1c27eea94cc4de9deb0`), verifying 100% bitwise determinism.

---

## 2. Failures Identified & Engineering Improvements

During systematic forensic audit and adversarial evaluation across Phase 1 and Phase 2, critical failure classes were diagnosed and resolved without hardcoded labels:

### Failure 1: Multi-Line JSON Trace Extraction in Observability Logs
- **Symptom**: In structured JSON log streams (`structured_service_events_eu_west_20260918.log`), audit records such as `audit_record_4902` and `account_3960` in Case 09 were completely omitted from predictions.
- **Root Cause**: The trace dictionary builder parsed `key=value` pairs with a regular expression that only matched unquoted shell-style pairs, skipping JSON-encoded log payloads and leaving trace metadata empty.
- **Improvement**: Updated `parse_log()` to merge deserialized JSON payloads into the trace key-value store, successfully binding initiation queries with completion entries across asynchronous spans.

### Failure 2: User Identifier Attribution in Central Audit Logs
- **Symptom**: In central observability logs (`service_events_ap_south_20260915.log`), security audit records (`audit_record_2945` in Case 12, `audit_record_1797` in Case 17) were not matched to target users.
- **Root Cause**: Keys like `correlation_key` or `lookup_key` contained stable user IDs (`user_12`, `user_17`) rather than emails. The parser stored them in `email`, which never matched the user's primary or historical email address.
- **Improvement**: Added type detection in `parse_log()`: if `lookup_key` or `correlation_key` matches the `user_` prefix, it is mapped to `user_id`, immediately restoring grounded attribution.

### Failure 3: Evidence File Archive Capture Time vs Snapshot Cutoff Boundary
- **Symptom**: Cases 26, 27, and 28 falsely classified as `INCOMPLETE` due to snapshot records from `evidence_02` (`customer_data_snapshot_bundle_20260917.json`).
- **Root Cause**: While individual snapshot timestamps inside the file carried `2026-09-09` or `2026-09-15T12:00:00Z`, the bundle file itself was created on `2026-09-17`, which was after the cases' `audit_at` cutoff (`2026-09-15T12:00:00Z`). Incomplete snapshots from the future leaked into the audit, overwriting completed compliant states from `evidence_92`.
- **Improvement**: Strictly enforced dual-timestamp filtering: `obs.get('file_captured_at', obs['captured_at']) <= audit_at and obs['captured_at'] <= audit_at`. Evidence captured after `audit_at` is completely isolated from consideration.

### Failure 4: Attribution of Anonymized Analytics Records
- **Symptom**: Compliant cases (e.g., Case 03, Case 04, Case 21, Case 25, Case 26, Case 27, Case 28) lacked verification steps for `analytics_platform`.
- **Root Cause**: When an analytics profile is properly anonymized per policy, all direct PII fields (`email`, `phone`, `user_id`, `email_hash`) are set to `None`. Standard identifier resolution cannot directly link the unidentifiable record.
- **Improvement**: Correlated anonymized analytics records with `system_activity.csv`. When `deletion_worker` reports `ANONYMIZE_RECORD` on `analytics_platform` in that user's deletion workflow, and the resulting record exists in an evidence export captured at or before `audit_at`, the record is correctly grounded and verified.

### Failure 5: Schema Precedence in SQLite Snapshot Exports
- **Symptom**: In SQLite snapshots (`customer_data_inventory_20260916.sql`), rows in `customer_analytics_profiles` were misclassified as `account_service` with category `USER_PROFILE` and status `PRESENT`.
- **Root Cause**: Schema table name matching checked `'profile' in table` before `'analytics' in table`, assigning `customer_analytics_profiles` to `account_service` and generating spurious findings.
- **Improvement**: Reordered table prefix matching to prioritize `'analytics'` before `'profile'`, correctly classifying records under `analytics_platform` with `ANONYMIZED` status when identifiers are null.

### Failure 6: Multilingual Intent Disambiguation
- **Symptom**: Non-deletion requests written in French, German, or Spanish were sometimes misclassified as destructive deletion requests.
- **Root Cause**: Keyword lists were English-only.
- **Improvement**: Expanded `is_deletion_authorized()` with multilingual negative indicators (`ne supprimez pas`, `demande d'accès`, `nicht löschen`, `no borrar`, `solicitud de acceso`).

---

## 3. Regression & Adversarial Test Suite

A dedicated regression test suite (`code/evaluation/regression_suite.py`) containing 20 automated test cases was verified (100% pass rate in <0.3s):

1. `test_sample_status_accuracy_100_percent`: All 32 sample cases achieve 100% status accuracy.
2. `test_output_schema_and_vocabulary`: All 15 permitted operations, 7 states, and 3 phases strictly validated.
3. `test_adv_01_multilingual_access_request_is_not_applicable`: French GDPR access request classified `NOT_APPLICABLE`.
4. `test_adv_02_marketing_opt_out_is_not_applicable`: Marketing newsletter opt-out classified `NOT_APPLICABLE`.
5. `test_adv_03_export_only_request_is_not_applicable`: Data export without deletion intent classified `NOT_APPLICABLE`.
6. `test_adv_04_historical_email_resolution`: Email alias from `user_audit_log.csv` correctly resolves to primary user.
7. `test_adv_05_strictly_ignore_evidence_after_audit_cutoff`: Future events after `audit_at` excluded from findings.
8. `test_adv_06_account_tombstone_exposed_pii_handling`: Tombstone with direct PII triggers `REPORT_EXPOSED_PII` and `REDACT_RECORD`.
9. `test_adv_07_account_tombstone_clean_is_compliant`: Compliant tombstone verified as `REDACTED`.
10. `test_adv_08_shared_support_ticket_redaction_rule`: Multi-party support ticket remediated via `REDACT_RECORD`.
11. `test_adv_09_active_data_flow_generates_disable_remediation`: Active connector triggers `REPORT_ACTIVE_DATA_FLOW` and `DISABLE_DATA_FLOW`.
12. `test_adv_10_restore_risk_generates_block_restore`: Active backup archive triggers `REPORT_RESTORE_RISK` and `BLOCK_RESTORE`.
13. `test_adv_11_security_audit_records_retained_never_deleted`: Statutory retention audit logs preserved with `VERIFY_RECORD_PRESENT`.
14. `test_adv_12_audit_execution_is_100_percent_deterministic`: Identical inputs produce bitwise identical outputs.
15. `test_adv_13_decoy_and_unrelated_evidence_isolation`: Decoys belonging to other users are strictly isolated.
16. `test_adv_14_archive_file_captured_at_cutoff`: Evidence files captured after `audit_at` are strictly excluded from citation.
17. `test_adv_15_anonymized_analytics_matching_via_system_activity`: Anonymized analytics records link via `system_activity.csv`.
18. `test_adv_16_multitable_sqlite_analytics_isolation`: SQLite analytics tables correctly map to `analytics_platform`.
19. `test_adv_17_interleaved_batch_isolation`: Multi-tenant users processed within the same batch window maintain strict cross-contamination boundaries.
20. `test_adv_18_valid_case_range_preservation`: Exactly 518 evaluation requests spanning `case_33` through `case_550` map 1-to-1 without dropping or renaming.

---


## 4. Custom Evaluation Cases

### Custom Case 1: Ambiguous GDPR Request (Access/Opt-Out vs Deletion)
- **Input**: `custom_case_01`, `elena.vasquez@gmail.com`
- **Request**: *"Please remove my email from all marketing promotional newsletters. I need to keep my account active for warranty claims."*
- **Audit Decision**: `NOT_APPLICABLE` with `steps_json: []`
- **Grounded Verification**: Confirms that non-destructive requests never generate destructive remediation plans or false positive findings.

### Custom Case 2: Multi-System Replication Drift & Active Connector Risk
- **Input**: `custom_case_02`, `mateo.rossi@outlook.com`
- **Audit Decision**: `INCOMPLETE`
- **Grounded Remediation Sequence**:
  1. `REPORT_ACTIVE_DATA_FLOW` on `integration_service` (`data_flow_8812`) -> `DISABLE_DATA_FLOW`
  2. `REPORT_RESTORE_RISK` on `backup_service` (`backup_1409`) -> `BLOCK_RESTORE`
  3. `REPORT_REMAINING_RECORD` on `account_service` (regional replica lag) -> `DELETE_RECORD`
  4. Post-remediation verification checks for all three systems with empty evidence.

### Custom Case 3: Compliant Tombstone & Statutory Audit Retention
- **Input**: `custom_case_03`, `fatima.zahra@yahoo.com`
- **Audit Decision**: `COMPLETE`
- **Grounded Verification**:
  1. `VERIFY_RECORD_ABSENT` on `account_service` (primary database)
  2. `VERIFY_RECORD_REDACTED` on `identity_service` (`tombstone_7734`, preserving only `user_id`)
  3. `VERIFY_RECORD_PRESENT` on `security_service` (`audit_record_2210`, statutory retention preserved)
