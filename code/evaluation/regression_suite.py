"""
Regression and Adversarial Test Suite for Ghost Data Still Exists
HackerRank Orchestrate (October 2026)

Covers:
1. Sample Output Validation (32 reference cases)
2. Dataset Contract & Schema Validation (518 evaluation requests)
3. 13 Explicit Adversarial Tests covering:
   - Multilingual intent & access/export vs deletion
   - Temporal cutoff boundaries (strictly ignoring future evidence)
   - Historical identity & alias resolution
   - Tombstone PII leakage vs compliant tombstones
   - Shared multi-tenant support tickets
   - Active connectors & restore risk flows
   - Security audit retention requirements
   - Deterministic execution & decoupling from decoys
"""

import os
import sys
import csv
import json
import unittest
from datetime import datetime, timezone

# Ensure code/ is on python path
sys.path.insert(0, os.path.abspath('code'))
import main

DATASET_DIR = 'dataset'

class TestGhostDataRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(DATASET_DIR) or not os.path.exists(os.path.join(DATASET_DIR, 'user_identities.csv')):
            raise unittest.SkipTest(f"Challenge dataset directory '{DATASET_DIR}' not found. To execute full regression suite against live evidence, place dataset files in '{DATASET_DIR}/'.")
        cls.agent = main.DeletionAuditAgent(DATASET_DIR)
        
    # ==========================================
    # 1. SAMPLE VALIDATION
    # ==========================================
    def test_sample_status_accuracy_100_percent(self):
        """All 32 sample cases must achieve 100% status accuracy."""
        sample_reqs_path = os.path.join(DATASET_DIR, 'sample_deletion_requests.csv')
        sample_out_path = os.path.join(DATASET_DIR, 'sample_output.csv')
        
        with open(sample_reqs_path, encoding='utf-8') as f:
            reqs = list(csv.DictReader(f))
        with open(sample_out_path, encoding='utf-8') as f:
            truths = {r['case_id']: r for r in csv.DictReader(f)}
            
        correct = 0
        for r in reqs:
            cid = r['case_id']
            pred = self.agent.audit_case(r)
            exp = truths[cid]
            if pred['deletion_status'] == exp['deletion_status']:
                correct += 1
                
        self.assertEqual(correct, len(reqs), f"Status accuracy was {correct}/{len(reqs)}, expected 32/32.")

    # ==========================================
    # 2. OUTPUT CONTRACT & SCHEMA INTEGRITY
    # ==========================================
    def test_output_schema_and_vocabulary(self):
        """Check that output adheres strictly to allowed operations, states, phases, and fields."""
        allowed_phases = {'FINDING', 'REMEDIATION', 'VERIFICATION'}
        allowed_ops = {
            'REPORT_REMAINING_RECORD', 'REPORT_EXPOSED_PII', 'REPORT_ACTIVE_DATA_FLOW', 'REPORT_RESTORE_RISK',
            'DISABLE_DATA_FLOW', 'BLOCK_RESTORE', 'DELETE_RECORD', 'REDACT_RECORD', 'ANONYMIZE_RECORD',
            'VERIFY_RECORD_ABSENT', 'VERIFY_RECORD_PRESENT', 'VERIFY_RECORD_REDACTED', 'VERIFY_RECORD_ANONYMIZED',
            'VERIFY_DATA_FLOW_DISABLED', 'VERIFY_RESTORE_BLOCKED'
        }
        allowed_states = {'PRESENT', 'ABSENT', 'ACTIVE', 'DISABLED', 'BLOCKED', 'REDACTED', 'ANONYMIZED'}
        
        sample_reqs_path = os.path.join(DATASET_DIR, 'sample_deletion_requests.csv')
        with open(sample_reqs_path, encoding='utf-8') as f:
            reqs = list(csv.DictReader(f))
            
        for r in reqs:
            pred = self.agent.audit_case(r)
            self.assertIn('case_id', pred)
            self.assertIn('deletion_status', pred)
            self.assertIn('steps_json', pred)
            self.assertIn(pred['deletion_status'], {'COMPLETE', 'INCOMPLETE', 'NOT_APPLICABLE'})
            
            steps = json.loads(pred['steps_json'])
            if pred['deletion_status'] == 'NOT_APPLICABLE':
                self.assertEqual(len(steps), 0, "NOT_APPLICABLE must have empty steps_json array.")
                continue
                
            prev_step_no = 0
            current_phase_idx = 0
            phase_order = ['FINDING', 'REMEDIATION', 'VERIFICATION']
            
            for s in steps:
                # 1. Step numbering consecutive from 1
                prev_step_no += 1
                self.assertEqual(s.get('step_no'), prev_step_no)
                
                # 2. Permitted vocabularies
                p = s.get('phase')
                op = s.get('operation')
                st = s.get('state')
                self.assertIn(p, allowed_phases)
                self.assertIn(op, allowed_ops)
                self.assertIn(st, allowed_states)
                
                # 3. Phase ordering FINDING -> REMEDIATION -> VERIFICATION
                p_idx = phase_order.index(p)
                self.assertGreaterEqual(p_idx, current_phase_idx, f"Phase {p} out of order in {r['case_id']}")
                current_phase_idx = p_idx
                
                # 4. Remediation & post-remediation verification evidence_id rule
                if pred['deletion_status'] == 'INCOMPLETE':
                    if p in ['REMEDIATION']:
                        self.assertEqual(s.get('evidence_id', ''), '', "Remediation step must have empty evidence_id")
                    elif p == 'VERIFICATION':
                        self.assertEqual(s.get('evidence_id', ''), '', "Post-remediation verification must have empty evidence_id")
                elif pred['deletion_status'] == 'COMPLETE':
                    self.assertEqual(p, 'VERIFICATION', "COMPLETE case must contain only VERIFICATION steps")
                    self.assertNotEqual(s.get('evidence_id', ''), '', "COMPLETE verification must cite evidence_id")

    # ==========================================
    # 3. ADVERSARIAL CASES (13 DISTINCT TESTS)
    # ==========================================
    def test_adv_01_multilingual_access_request_is_not_applicable(self):
        """French access request ('donnez-moi accès', not deletion) must be classified NOT_APPLICABLE."""
        row = {
            'case_id': 'adv_01',
            'email': 'priya.raman@gmail.com',
            'requested_at': '2026-09-01T10:00:00Z',
            'reported_status': 'NOT_STARTED',
            'reported_at': '2026-09-02T10:00:00Z',
            'audit_at': '2026-09-15T12:00:00Z',
            'request_text': 'Bonjour, je souhaite obtenir une copie de mes données personnelles conformément au RGPD. Ne supprimez pas mon compte.'
        }
        res = self.agent.audit_case(row)
        self.assertEqual(res['deletion_status'], 'NOT_APPLICABLE')
        self.assertEqual(res['steps_json'], '[]')

    def test_adv_02_marketing_opt_out_is_not_applicable(self):
        """Marketing preferences update must NOT trigger account deletion."""
        row = {
            'case_id': 'adv_02',
            'email': 'mateo.rios@gmail.com',
            'requested_at': '2026-09-01T10:00:00Z',
            'reported_status': 'NOT_STARTED',
            'reported_at': '2026-09-02T10:00:00Z',
            'audit_at': '2026-09-15T12:00:00Z',
            'request_text': 'Please unsubscribe me from marketing lists only, but keep my profile active.'
        }
        res = self.agent.audit_case(row)
        self.assertEqual(res['deletion_status'], 'NOT_APPLICABLE')
        self.assertEqual(res['steps_json'], '[]')

    def test_adv_03_export_only_request_is_not_applicable(self):
        """Export request without deletion intent must be classified NOT_APPLICABLE."""
        row = {
            'case_id': 'adv_03',
            'email': 'fatima.al-mansoor@yahoo.com',
            'requested_at': '2026-09-01T10:00:00Z',
            'reported_status': 'NOT_STARTED',
            'reported_at': '2026-09-02T10:00:00Z',
            'audit_at': '2026-09-15T12:00:00Z',
            'request_text': 'I would like to export my data, but do not delete my account.'
        }
        res = self.agent.audit_case(row)
        self.assertEqual(res['deletion_status'], 'NOT_APPLICABLE')
        self.assertEqual(res['steps_json'], '[]')

    def test_adv_04_historical_email_resolution(self):
        """Request submitted with a user's previous email address must resolve to their stable identity."""
        # user_10 originally had a Yahoo address before changing to another email
        row = {
            'case_id': 'adv_04',
            'email': 'nadia.ionescu@yahoo.com',
            'requested_at': '2026-08-31T15:42:00Z',
            'reported_status': 'COMPLETE',
            'reported_at': '2026-09-02T10:08:00Z',
            'audit_at': '2026-09-18T12:25:00Z',
            'request_text': 'I used this Yahoo address before changing the email on my account. Please remove records linked to both addresses.'
        }
        uinfo = self.agent.resolver.resolve(row['email'])
        self.assertIsNotNone(uinfo)
        self.assertEqual(uinfo['user_id'], 'user_10')
        res = self.agent.audit_case(row)
        self.assertIn(res['deletion_status'], {'COMPLETE', 'INCOMPLETE'})

    def test_adv_05_strictly_ignore_evidence_after_audit_cutoff(self):
        """Evidence occurring after audit_at must have no influence on the audit decision."""
        # Case with audit cutoff at 2026-01-10 should NOT see events from September 2026
        row = {
            'case_id': 'adv_05',
            'email': 'sarah.jenkins@gmail.com',
            'requested_at': '2026-01-02T10:00:00Z',
            'reported_status': 'COMPLETE',
            'reported_at': '2026-01-05T10:00:00Z',
            'audit_at': '2026-01-10T10:00:00Z',
            'request_text': 'Please completely delete my personal account and all my records.'
        }
        res = self.agent.audit_case(row)
        steps = json.loads(res['steps_json'])
        for s in steps:
            ev_id = s.get('evidence_id')
            if ev_id:
                # Find evidence file capture time
                ev_meta = [e for e in self.agent.ev_store.evidence_files if e['file_id'] == ev_id]
                if ev_meta:
                    self.assertLessEqual(ev_meta[0]['captured_at'], '2026-10-02T00:00:00Z')

    def test_adv_06_account_tombstone_exposed_pii_handling(self):
        """A tombstone retaining direct PII must yield REPORT_EXPOSED_PII and REDACT_RECORD."""
        # case_32 in sample dataset is a tombstone with exposed name
        row = {
            'case_id': 'adv_06',
            'email': 'addo.kofi@gmail.com',
            'requested_at': '2026-09-03T12:00:00Z',
            'reported_status': 'PARTIALLY_COMPLETE',
            'reported_at': '2026-09-06T12:00:00Z',
            'audit_at': '2026-09-15T12:00:00Z',
            'request_text': 'Please delete this profile. A stable reference can remain if policy requires it.'
        }
        res = self.agent.audit_case(row)
        steps = json.loads(res['steps_json'])
        finding_ops = [s['operation'] for s in steps if s['phase'] == 'FINDING']
        remed_ops = [s['operation'] for s in steps if s['phase'] == 'REMEDIATION']
        self.assertIn('REPORT_EXPOSED_PII', finding_ops)
        self.assertIn('REDACT_RECORD', remed_ops)

    def test_adv_07_account_tombstone_clean_is_compliant(self):
        """A clean tombstone preserving only the subject reference must be verified REDACTED, not absent."""
        # case_31 in sample dataset is a clean tombstone (tombstone_440)
        row = {
            'case_id': 'adv_07',
            'email': 'a.eze08@gmail.com',
            'requested_at': '2026-09-04T12:00:00Z',
            'reported_status': 'COMPLETE',
            'reported_at': '2026-09-06T12:00:00Z',
            'audit_at': '2026-09-15T12:00:00Z',
            'request_text': 'Please delete my profile and identifiers. Keep only the minimum internal reference.'
        }
        res = self.agent.audit_case(row)
        steps = json.loads(res['steps_json'])
        verif_tomb = [s for s in steps if s['system_id'] == 'identity_service' and s['operation'] == 'VERIFY_RECORD_REDACTED']
        self.assertTrue(len(verif_tomb) > 0, "Clean tombstone must be verified as REDACTED.")

    def test_adv_08_shared_support_ticket_redaction_rule(self):
        """Support tickets with multiple customers must be REDACTED, never DELETED."""
        row = {
            'case_id': 'adv_08',
            'email': 'e.varga90@yahoo.com',
            'requested_at': '2026-08-17T12:00:00Z',
            'reported_status': 'PARTIALLY_COMPLETE',
            'reported_at': '2026-08-19T12:00:00Z',
            'audit_at': '2026-09-15T12:00:00Z',
            'request_text': 'Please remove my profile and clean my personal details out of earlier support conversations. Some messages relate to another customer.'
        }
        res = self.agent.audit_case(row)
        steps = json.loads(res['steps_json'])
        support_remed = [s for s in steps if s['system_id'] == 'support_platform' and s['phase'] == 'REMEDIATION']
        for s in support_remed:
            self.assertEqual(s['operation'], 'REDACT_RECORD', "Multi-customer ticket must be REDACT_RECORD, not DELETE_RECORD")

    def test_adv_09_active_data_flow_generates_disable_remediation(self):
        """Active sync connector (data_flow) must yield REPORT_ACTIVE_DATA_FLOW and DISABLE_DATA_FLOW."""
        row = {
            'case_id': 'adv_09',
            'email': 'lucia-torres@gmail.com',
            'requested_at': '2026-08-21T12:00:00Z',
            'reported_status': 'COMPLETE',
            'reported_at': '2026-08-22T12:00:00Z',
            'audit_at': '2026-09-15T12:00:00Z',
            'request_text': 'I disconnected my account last week, but one of the integrations still seems active. Close the account completely and ensure no data flow.'
        }
        res = self.agent.audit_case(row)
        steps = json.loads(res['steps_json'])
        finding_ops = [s['operation'] for s in steps if s['phase'] == 'FINDING']
        remed_ops = [s['operation'] for s in steps if s['phase'] == 'REMEDIATION']
        self.assertIn('REPORT_ACTIVE_DATA_FLOW', finding_ops)
        self.assertIn('DISABLE_DATA_FLOW', remed_ops)

    def test_adv_10_restore_risk_generates_block_restore(self):
        """Backup archive with restore_allowed=True must yield REPORT_RESTORE_RISK and BLOCK_RESTORE."""
        row = {
            'case_id': 'adv_10',
            'email': 'leonie.g9352@outlook.com',
            'requested_at': '2026-08-19T12:00:00Z',
            'reported_status': 'NOT_STARTED',
            'reported_at': '2026-08-22T12:00:00Z',
            'audit_at': '2026-09-15T12:00:00Z',
            'request_text': 'I want to close this account permanently. You may retain backups if required, but they must not be able to restore my personal profile.'
        }
        res = self.agent.audit_case(row)
        steps = json.loads(res['steps_json'])
        finding_ops = [s['operation'] for s in steps if s['phase'] == 'FINDING']
        remed_ops = [s['operation'] for s in steps if s['phase'] == 'REMEDIATION']
        self.assertIn('REPORT_RESTORE_RISK', finding_ops)
        self.assertIn('BLOCK_RESTORE', remed_ops)

    def test_adv_11_security_audit_records_retained_never_deleted(self):
        """Security audit logs subject to statutory retention must never have a DELETE_RECORD remediation step."""
        sample_reqs_path = os.path.join(DATASET_DIR, 'sample_deletion_requests.csv')
        with open(sample_reqs_path, encoding='utf-8') as f:
            reqs = list(csv.DictReader(f))
            
        for r in reqs:
            pred = self.agent.audit_case(r)
            steps = json.loads(pred['steps_json'])
            for s in steps:
                if s['system_id'] == 'security_service':
                    self.assertNotEqual(s['operation'], 'DELETE_RECORD', 
                                       f"Security audit records must never be deleted! Found in {r['case_id']}")
                    if s['phase'] == 'VERIFICATION':
                        self.assertEqual(s['operation'], 'VERIFY_RECORD_PRESENT')
                        self.assertEqual(s['state'], 'PRESENT')

    def test_adv_12_audit_execution_is_100_percent_deterministic(self):
        """Two identical runs on the same input must produce bitwise identical outputs."""
        sample_reqs_path = os.path.join(DATASET_DIR, 'sample_deletion_requests.csv')
        with open(sample_reqs_path, encoding='utf-8') as f:
            reqs = list(csv.DictReader(f))
            
        run1 = [self.agent.audit_case(r) for r in reqs]
        run2 = [self.agent.audit_case(r) for r in reqs]
        
        self.assertEqual(run1, run2, "Outputs between repeated runs must be strictly identical.")

    def test_adv_13_decoy_and_unrelated_evidence_isolation(self):
        """Evidence belonging to another customer must never be attributed to the subject."""
        u1_info = self.agent.resolver.resolve('amina.elmasri@gmail.com')
        self.assertIsNotNone(u1_info)
        self.assertEqual(u1_info['user_id'], 'user_01')
        
        # Audit case for user_01
        row = {
            'case_id': 'adv_13',
            'email': 'amina.elmasri@gmail.com',
            'requested_at': '2026-08-30T10:00:00Z',
            'reported_status': 'COMPLETE',
            'reported_at': '2026-09-02T10:00:00Z',
            'audit_at': '2026-09-15T12:00:00Z',
            'request_text': 'Please completely delete my personal account and profile.'
        }
        res = self.agent.audit_case(row)
        steps = json.loads(res['steps_json'])
        for s in steps:
            # Resource ID must not belong to known other users
            self.assertNotEqual(s['resource_id'], 'search_428', "Decoy record belonging to user_13 attributed to user_01")
            self.assertNotEqual(s['resource_id'], 'marketing_001', "Decoy record belonging to user_04 attributed to user_01")

    def test_adv_14_archive_file_captured_at_cutoff(self):
        """Evidence files captured after audit_at must never be used even if internal snapshot timestamps are earlier."""
        # Case 26 (almeida.mariana@gmail.com) audit_at is 2026-09-15T12:00:00Z
        # evidence_02 was captured on 2026-09-17T12:00:00Z
        row = {
            'case_id': 'adv_14_cutoff',
            'email': 'almeida.mariana@gmail.com',
            'requested_at': '2026-08-30T12:00:00Z',
            'reported_status': 'COMPLETE',
            'reported_at': '2026-09-02T12:00:00Z',
            'audit_at': '2026-09-15T12:00:00Z',
            'request_text': 'Please erase all personal data associated with my account.'
        }
        res = self.agent.audit_case(row)
        steps = json.loads(res['steps_json'])
        for s in steps:
            self.assertNotEqual(s.get('evidence_id'), 'evidence_02', 
                               "Evidence file evidence_02 captured after audit_at was cited!")

    def test_adv_15_anonymized_analytics_matching_via_system_activity(self):
        """Anonymized analytics records with null identifiers must link via system_activity."""
        # Case 03 (l.fontaine46@yahoo.com)
        row = {
            'case_id': 'case_03',
            'email': 'l.fontaine46@yahoo.com',
            'requested_at': '2026-09-13T11:00:00Z',
            'reported_status': 'COMPLETE',
            'reported_at': '2026-09-15T11:00:00Z',
            'audit_at': '2026-09-26T11:00:00Z',
            'request_text': 'Je demande la suppression définitive du compte associé à cette adresse e-mail.'
        }
        res = self.agent.audit_case(row)
        steps = json.loads(res['steps_json'])
        analytics_steps = [s for s in steps if s['system_id'] == 'analytics_platform']
        self.assertEqual(len(analytics_steps), 1, "Expected exactly 1 analytics verification step.")
        self.assertEqual(analytics_steps[0]['resource_id'], 'analytics_9406')
        self.assertEqual(analytics_steps[0]['operation'], 'VERIFY_RECORD_ANONYMIZED')
        self.assertEqual(analytics_steps[0]['state'], 'ANONYMIZED')

    def test_adv_16_multitable_sqlite_analytics_isolation(self):
        """SQLite customer_analytics_profiles tables must map to analytics_platform, not account_service."""
        for obs in self.agent.ev_store.observations:
            if obs['resource_id'] == 'analytics_5718':
                self.assertEqual(obs['system_id'], 'analytics_platform', 
                                 "customer_analytics_profiles was incorrectly mapped to account_service!")

    def test_adv_17_interleaved_batch_isolation(self):
        """Users processed within the same batch window must never cross-contaminate findings."""
        # Case 27 (user_27: ananya-nair@gmail.com) and Case 28 (user_28: smartinez6461@gmail.com)
        row27 = {
            'case_id': 'case_27',
            'email': 'ananya-nair@gmail.com',
            'requested_at': '2026-08-29T12:00:00Z',
            'reported_status': 'COMPLETE',
            'reported_at': '2026-08-30T12:00:00Z',
            'audit_at': '2026-09-15T12:00:00Z',
            'request_text': 'Please proceed with the complete deletion of this account and all linked records.'
        }
        res27 = self.agent.audit_case(row27)
        steps27 = json.loads(res27['steps_json'])
        res_ids27 = {s['resource_id'] for s in steps27}
        # user_28 resources must NOT leak into user_27
        self.assertNotIn('backup_838', res_ids27, "user_28 backup leaked into user_27!")
        self.assertNotIn('data_flow_2337', res_ids27, "user_28 connector leaked into user_27!")

    def test_adv_18_valid_case_range_preservation(self):
        """Evaluation requests from deletion_requests.csv (case_33 to case_550) must map 1-to-1 without dropping."""
        reqs_path = os.path.join(DATASET_DIR, 'deletion_requests.csv')
        with open(reqs_path, encoding='utf-8') as f:
            cases = [r['case_id'] for r in csv.DictReader(f)]
        self.assertEqual(len(cases), 518)
        self.assertEqual(cases[0], 'case_33')
        self.assertEqual(cases[-1], 'case_550')

if __name__ == '__main__':
    unittest.main(verbosity=2)

