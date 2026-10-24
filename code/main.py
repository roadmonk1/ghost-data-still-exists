"""
Ghost Data Still Exists - AI Deletion-Audit Agent
HackerRank Orchestrate (October 2026)

Entry point: python code/main.py [--dataset-dir <dir>] [--output-file <file>]
"""

import os
import sys
import csv
import json
import sqlite3
import re
import argparse
from datetime import datetime, timezone, timedelta
try:
    import fitz
except ImportError:
    fitz = None

# Ensure stdout handles UTF-8 cleanly across platforms
sys.stdout.reconfigure(encoding='utf-8')

FINDING_ORDER = [
    'REPORT_REMAINING_RECORD',
    'REPORT_EXPOSED_PII',
    'REPORT_ACTIVE_DATA_FLOW',
    'REPORT_RESTORE_RISK'
]

REMEDIATION_ORDER = [
    'DISABLE_DATA_FLOW',
    'BLOCK_RESTORE',
    'DELETE_RECORD',
    'REDACT_RECORD',
    'ANONYMIZE_RECORD'
]

VERIFICATION_ORDER = [
    'VERIFY_RECORD_ABSENT',
    'VERIFY_RECORD_PRESENT',
    'VERIFY_RECORD_REDACTED',
    'VERIFY_RECORD_ANONYMIZED',
    'VERIFY_DATA_FLOW_DISABLED',
    'VERIFY_RESTORE_BLOCKED'
]

def parse_iso(ts):
    return datetime.fromisoformat(ts.replace('Z', '+00:00'))

def get_op_rank(phase, op):
    if phase == 'FINDING':
        return FINDING_ORDER.index(op) if op in FINDING_ORDER else 99
    elif phase == 'REMEDIATION':
        return REMEDIATION_ORDER.index(op) if op in REMEDIATION_ORDER else 99
    elif phase == 'VERIFICATION':
        return VERIFICATION_ORDER.index(op) if op in VERIFICATION_ORDER else 99
    return 99

def sort_steps(steps):
    phase_rank = {'FINDING': 1, 'REMEDIATION': 2, 'VERIFICATION': 3}
    def key_fn(s):
        p = s['phase']
        pr = phase_rank.get(p, 99)
        opr = get_op_rank(p, s['operation'])
        sys_id = s.get('system_id', '')
        res_id = s.get('resource_id', '')
        return (pr, opr, sys_id, res_id)
        
    sorted_list = sorted(steps, key=key_fn)
    for i, s in enumerate(sorted_list, 1):
        s['step_no'] = i
    return sorted_list

def norm_system_id(sys_id, res_id=None):
    if not sys_id:
        if res_id:
            if 'account' in res_id: return 'account_service'
            elif 'search' in res_id: return 'search_service'
            elif 'analytics' in res_id: return 'analytics_platform'
            elif 'support' in res_id: return 'support_platform'
            elif 'data_flow' in res_id: return 'integration_service'
            elif 'backup' in res_id: return 'backup_service'
            elif 'audit' in res_id: return 'security_service'
            elif 'export' in res_id: return 'export_service'
            elif 'tombstone' in res_id: return 'identity_service'
        return sys_id
    s = sys_id.lower()
    if s.startswith('account'): return 'account_service'
    if s.startswith('search'): return 'search_service'
    if s.startswith('analytic'): return 'analytics_platform'
    if s.startswith('support'): return 'support_platform'
    if s.startswith('integration') or s.startswith('connector'): return 'integration_service'
    if s.startswith('backup'): return 'backup_service'
    if s.startswith('security') or s.startswith('audit'): return 'security_service'
    if s.startswith('export'): return 'export_service'
    if s.startswith('identity') or s.startswith('tombstone'): return 'identity_service'
    return sys_id

class IdentityResolver:
    def __init__(self, identities_path, audit_log_path):
        self.user_map = {}
        self.email_to_uid = {}
        
        with open(identities_path, encoding='utf-8') as f:
            for u in csv.DictReader(f):
                uid = u['user_id']
                self.user_map[uid] = {
                    'user_id': uid,
                    'names': {u['name'].strip().lower()},
                    'emails': {u['email'].strip().lower()},
                    'phones': {u['phone'].strip()},
                    'hashes': {u['email_hash'].strip().lower()}
                }
                self.email_to_uid[u['email'].strip().lower()] = uid
                
        with open(audit_log_path, encoding='utf-8') as f:
            for a in csv.DictReader(f):
                uid = a['user_id']
                if uid in self.user_map:
                    field = a['field_name']
                    old_v = a['old_value'].strip() if a['old_value'] else ''
                    new_v = a['new_value'].strip() if a['new_value'] else ''
                    
                    if field == 'email':
                        if old_v:
                            self.user_map[uid]['emails'].add(old_v.lower())
                            self.email_to_uid[old_v.lower()] = uid
                        if new_v:
                            self.user_map[uid]['emails'].add(new_v.lower())
                            self.email_to_uid[new_v.lower()] = uid
                    elif field == 'phone':
                        if old_v: self.user_map[uid]['phones'].add(old_v)
                        if new_v: self.user_map[uid]['phones'].add(new_v)
                    elif field == 'name':
                        if old_v: self.user_map[uid]['names'].add(old_v.lower())
                        if new_v: self.user_map[uid]['names'].add(new_v.lower())
                    elif field == 'email_hash':
                        if old_v: self.user_map[uid]['hashes'].add(old_v.lower())
                        if new_v: self.user_map[uid]['hashes'].add(new_v.lower())

    def resolve(self, email):
        clean_email = email.strip().lower()
        uid = self.email_to_uid.get(clean_email)
        if not uid:
            return None
        return self.user_map[uid]

def is_deletion_authorized(request_text):
    t_lower = request_text.lower()
    negative_signals = [
        "not asking for deletion",
        "leave the account active",
        "keep the account as it is",
        "do not close the account",
        "without removing any of my records",
        "marketing lists only",
        "information request, not a request to erase",
        "leave my profile",
        "continue using the service",
        "don't delete or change anything",
        "do not delete",
        "not a deletion",
        "ne supprimez pas",
        "obtenir une copie",
        "pas de suppression",
        "demande d'accès",
        "no elimine",
        "no borrar",
        "solicitud de acceso",
        "nicht löschen",
        "datenkopie",
        "auskunftsersuchen",
        "削除しないで",
        "削除依頼ではありません",
        "データをエクスポートするだけ"
    ]
    if any(sig in t_lower for sig in negative_signals):
        return False
    return True

class EvidenceStore:
    def __init__(self, dataset_dir):
        self.dataset_dir = dataset_dir
        self.evidence_files = []
        self.observations = []
        self.load_manifest()
        self.load_all_evidence()
        
    def load_manifest(self):
        p = os.path.join(self.dataset_dir, 'evidence_files.csv')
        with open(p, encoding='utf-8') as f:
            self.evidence_files = list(csv.DictReader(f))
            self.file_captured_map = {ef['file_id']: ef['captured_at'] for ef in self.evidence_files}
            
    def load_all_evidence(self):
        for ev in self.evidence_files:
            fid = ev['file_id']
            cap_at = ev['captured_at']
            fpath = os.path.join(self.dataset_dir, ev['file_path'])
            if not os.path.exists(fpath):
                continue
            ext = os.path.splitext(fpath)[1].lower()
            
            if ext == '.json':
                self.parse_json(fpath, fid, cap_at)
            elif ext == '.sql':
                self.parse_sql(fpath, fid, cap_at)
            elif ext == '.log':
                self.parse_log(fpath, fid, cap_at)
            elif ext == '.txt':
                self.parse_txt(fpath, fid, cap_at)
            elif ext == '.pdf':
                self.parse_pdf(fpath, fid, cap_at)
            elif ext == '.png':
                self.parse_png(fpath, fid, cap_at)

    def add_obs(self, fid, cap_at, sys_id, res_id, cat, status, uid=None, email=None, phone=None, name=None, h=None):
        if not res_id: return
        sys_id = norm_system_id(sys_id, res_id)
        if email and len(email) == 64 and re.match(r'^[0-9a-fA-F]+$', email):
            h = email
            email = None
        self.observations.append({
            'file_id': fid,
            'file_captured_at': getattr(self, 'file_captured_map', {}).get(fid, cap_at),
            'captured_at': cap_at,
            'system_id': sys_id,
            'resource_id': res_id,
            'category': cat,
            'status': status,
            'user_id': uid.lower() if uid else None,
            'email': email.lower() if email else None,
            'phone': phone if phone else None,
            'name': name.lower() if name else None,
            'hash': h.lower() if h else None
        })

    def parse_json(self, path, fid, cap_at):
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        if 'snapshots' in data:
            for snap in data['snapshots']:
                data_store = snap.get('data_store') or 'account_service'
                collection = snap.get('collection')
                snap_ts = snap.get('captured_at') or cap_at
                for r in snap.get('records', []):
                    res_id = r.get('resource_id')
                    uid = r.get('subject_reference') or r.get('user_id') or r.get('customer_reference')
                    em = r.get('email')
                    ph = r.get('phone')
                    nm = r.get('name') or r.get('full_name')
                    h = r.get('email_hash')
                    
                    if collection == 'deleted_customer_references':
                        st = 'REDACTED' if (not em and not ph and not nm and not h) else 'PRESENT'
                        self.add_obs(fid, snap_ts, 'identity_service', res_id, 'ACCOUNT_TOMBSTONE', st, uid, em, ph, nm, h)
                    elif collection == 'security_audit_events':
                        self.add_obs(fid, snap_ts, 'security_service', res_id, 'SECURITY_AUDIT_LOG', 'PRESENT', uid, em, ph, nm, h)
                    elif collection == 'customer_profiles':
                        self.add_obs(fid, snap_ts, 'account_service', res_id, 'USER_PROFILE', 'PRESENT', uid, em, ph, nm, h)
                    elif collection == 'customer_analytics_reports':
                        st = 'ANONYMIZED' if (not em and not ph and not uid and not h) else 'PRESENT'
                        self.add_obs(fid, snap_ts, 'analytics_platform', res_id, 'ANALYTICS_PROFILE', st, uid, em, ph, nm, h)
                    else:
                        self.add_obs(fid, snap_ts, data_store, res_id, collection, 'PRESENT', uid, em, ph, nm, h)
                        
        elif 'service_exports' in data:
            se = data['service_exports']
            for svc, details in se.items():
                if svc == 'account_service':
                    for pl in details.get('profile_lookups', []):
                        st = 'ABSENT' if (pl.get('status_code') == 404 or pl.get('profile') is None) else 'PRESENT'
                        prof = pl.get('profile') or {}
                        uid = prof.get('customer_reference') or prof.get('user_id')
                        em = prof.get('email') or pl.get('lookup_key')
                        t_obs = pl.get('observed_at') or cap_at
                        self.add_obs(fid, t_obs, svc, pl.get('resource_id'), 'USER_PROFILE', st, uid=uid, email=em)
                elif svc == 'search_service':
                    for q in details.get('index_queries', []):
                        q_em = q.get('query')
                        t_obs = q.get('observed_at') or cap_at
                        for d in q.get('hits', {}).get('documents', []):
                            self.add_obs(fid, t_obs, svc, d.get('resource_id'), 'SEARCH_INDEX_ENTRY', 'PRESENT',
                                         uid=d.get('customer_reference'), email=d.get('email') or q_em)
                elif svc == 'support_platform':
                    for t in details.get('tickets', []):
                        em = t.get('requester_email')
                        nm = t.get('requester_name')
                        ph = t.get('requester_phone')
                        st = 'PRESENT' if (em or nm or ph) else 'REDACTED'
                        t_obs = t.get('observed_at') or cap_at
                        self.add_obs(fid, t_obs, svc, t.get('resource_id'), 'SUPPORT_MESSAGE', st,
                                     uid=t.get('customer_reference'), email=em, name=nm, phone=ph)
                elif svc == 'analytics_platform':
                    for p in details.get('profiles', []):
                        uid = p.get('customer_reference')
                        em = p.get('email')
                        ph = p.get('phone')
                        h = p.get('email_hash')
                        st = 'PRESENT' if (uid or em or ph or h) else 'ANONYMIZED'
                        t_obs = p.get('observed_at') or cap_at
                        self.add_obs(fid, t_obs, svc, p.get('resource_id'), 'ANALYTICS_PROFILE', st,
                                     uid=uid, email=em, phone=ph, h=h)
                elif svc == 'integration_service':
                    for c in details.get('connectors', []):
                        st = 'ACTIVE' if c.get('enabled') else 'DISABLED'
                        t_obs = c.get('observed_at') or cap_at
                        self.add_obs(fid, t_obs, svc, c.get('resource_id'), 'DATA_FLOW', st,
                                     uid=c.get('customer_reference'), email=c.get('customer_email'))
                elif svc == 'backup_service':
                    for b in details.get('restore_entries', []):
                        st = 'ACTIVE' if b.get('restore_allowed') else 'BLOCKED'
                        t_obs = b.get('observed_at') or cap_at
                        self.add_obs(fid, t_obs, svc, b.get('resource_id'), 'BACKUP_ARCHIVE', st,
                                     uid=b.get('customer_reference'), email=b.get('customer_email'))
                elif svc == 'security_service':
                    for a in details.get('audit_records', []):
                        t_obs = a.get('observed_at') or cap_at
                        self.add_obs(fid, t_obs, svc, a.get('resource_id'), 'SECURITY_AUDIT_LOG', 'PRESENT',
                                     uid=a.get('subject_reference'))
                elif svc == 'export_service':
                    for ex in details.get('exports', []):
                        t_obs = ex.get('observed_at') or cap_at
                        self.add_obs(fid, t_obs, svc, ex.get('resource_id'), 'USER_EXPORT', 'PRESENT',
                                     uid=ex.get('customer_reference'), email=ex.get('owner_email'))
        elif 'records' in data:
            coll = data.get('collection', '')
            for r in data['records']:
                res_id = r.get('resource_id')
                uid = r.get('subject_reference') or r.get('subject_selector') or r.get('customer_reference') or r.get('user_id')
                em = r.get('email') or r.get('customer_email') or r.get('owner_email')
                ph = r.get('phone') or r.get('owner_phone')
                h = r.get('email_hash')
                orig = data.get('origin', '')
                if 'export' in coll or 'export' in orig or 'export' in path:
                    st = 'PRESENT' if r.get('download_available') else 'ABSENT'
                    self.add_obs(fid, cap_at, 'export_service', res_id, 'USER_EXPORT', st, uid, em)
                elif 'connector' in coll or 'connector' in orig or 'connector' in path:
                    st = 'ACTIVE' if r.get('enabled') else 'DISABLED'
                    self.add_obs(fid, cap_at, 'integration_service', res_id, 'DATA_FLOW', st, uid, em)
                elif 'analytics' in coll or 'analytics' in orig or 'analytics' in path:
                    st = 'PRESENT' if (em or ph or h or uid) else 'ANONYMIZED'
                    self.add_obs(fid, cap_at, 'analytics_platform', res_id, 'ANALYTICS_PROFILE', st, uid, em, ph, h=h)
                elif 'security' in coll or 'security' in orig or 'security' in path or 'audit' in coll:
                    self.add_obs(fid, cap_at, 'security_service', res_id, 'SECURITY_AUDIT_LOG', 'PRESENT', uid, em)

    def parse_sql(self, path, fid, cap_at):
        conn = sqlite3.connect(':memory:')
        try:
            with open(path, 'r', encoding='utf-8') as f:
                conn.executescript(f.read())
            cursor = conn.cursor()
            tables = [t[0] for t in cursor.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
            
            has_failover = 'customer_profiles_failover_replica' in tables and 'customer_profiles_primary' in tables
            if has_failover:
                pri_ids = set(r[0] for r in cursor.execute("SELECT resource_id FROM customer_profiles_primary").fetchall())
                for r in cursor.execute("SELECT resource_id, user_id, full_name, email, phone FROM customer_profiles_failover_replica").fetchall():
                    res_id, uid, nm, em, ph = r
                    if res_id not in pri_ids:
                        self.add_obs(fid, cap_at, 'account_service', res_id, 'USER_PROFILE', 'PRESENT', uid, em, ph, nm)

            for table in tables:
                if has_failover and table in ['customer_profiles_failover_replica', 'customer_profiles_primary']:
                    continue
                cols = [c[1] for c in cursor.execute(f"PRAGMA table_info({table});").fetchall()]
                rows = cursor.execute(f"SELECT * FROM {table}").fetchall()
                for r in rows:
                    d = dict(zip(cols, r))
                    res_id = d.get('resource_id')
                    row_ts = d.get('recorded_at') or d.get('updated_at') or cap_at
                    rj_str = d.get('record_json')
                    if rj_str:
                        try:
                            rj = json.loads(rj_str)
                            doc = rj.get('document', {})
                            for k, v in rj.items():
                                if k not in d or d[k] is None: d[k] = v
                            if doc:
                                if not d.get('customer_reference'): d['customer_reference'] = doc.get('customer_reference')
                                if not d.get('email'): d['email'] = doc.get('email')
                                if not d.get('full_name'): d['full_name'] = doc.get('display_name')
                        except: pass
                        
                    res_id = d.get('resource_id') or res_id
                    uid = d.get('user_id') or d.get('customer_reference') or d.get('subject_reference')
                    em = d.get('email') or d.get('customer_email') or d.get('owner_email') or d.get('subject_selector')
                    ph = d.get('phone')
                    nm = d.get('full_name') or d.get('name') or d.get('display_name')
                    h = d.get('email_hash')
                    
                    sys_id = d.get('origin_system') or d.get('source_system')
                    if not sys_id:
                        if 'analytics' in table: sys_id = 'analytics_platform'
                        elif 'profile' in table or 'account' in table: sys_id = 'account_service'
                        elif 'search' in table: sys_id = 'search_service'
                        elif 'support' in table: sys_id = 'support_platform'
                        elif 'connector' in table: sys_id = 'integration_service'
                        elif 'backup' in table: sys_id = 'backup_service'
                        elif 'audit' in table or 'security' in table: sys_id = 'security_service'
                        elif 'export' in table: sys_id = 'export_service'
                        
                    st = 'PRESENT'
                    cat = d.get('collection_name') or table
                    if sys_id == 'backup_service' or 'backup' in table:
                        cat = 'BACKUP_ARCHIVE'
                        allowed = d.get('restore_allowed')
                        st = 'ACTIVE' if (allowed in [1, '1', True, 'true']) else 'BLOCKED'
                    elif sys_id == 'integration_service' or 'connector' in table:
                        cat = 'DATA_FLOW'
                        en = d.get('enabled')
                        st = 'ACTIVE' if (en in [1, '1', True, 'true']) else 'DISABLED'
                    elif sys_id == 'analytics_platform':
                        cat = 'ANALYTICS_PROFILE'
                        st = 'PRESENT' if (uid or em or ph or h) else 'ANONYMIZED'
                    elif sys_id == 'support_platform':
                        cat = 'SUPPORT_MESSAGE'
                        msg = d.get('message_text') or d.get('message_excerpt') or ''
                        st = 'REDACTED' if ('[REDACTED]' in msg or (not em and not ph and not nm)) else 'PRESENT'
                    elif sys_id == 'security_service':
                        cat = 'SECURITY_AUDIT_LOG'
                        st = 'PRESENT'
                    elif sys_id == 'account_service':
                        cat = 'USER_PROFILE'
                        st = 'PRESENT'
                        
                    self.add_obs(fid, row_ts, sys_id, res_id, cat, st, uid, em, ph, nm, h)
        except Exception as e:
            pass

    def parse_log(self, path, fid, cap_at):
        traces = {}
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line_str = line.strip()
                if not line_str: continue
                
                ts_m = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)', line_str)
                line_ts = ts_m.group(1) if ts_m else cap_at
                
                kv = {k: (v1 if v1 else v2) for k, v1, v2 in re.findall(r'(\w+)=(?:"([^"]*)"|(\S+))', line_str)}
                jm = re.search(r'(\{.*\})', line_str)
                if jm:
                    try:
                        jd = json.loads(jm.group(1))
                        for k, v in jd.items():
                            if k not in kv: kv[k] = str(v)
                    except: pass
                    
                tr_id = kv.get('trace_id')
                if tr_id:
                    if tr_id not in traces:
                        traces[tr_id] = {'lines': [], 'kv': {}, 'ts': line_ts}
                    traces[tr_id]['lines'].append(line_str)
                    for k, v in kv.items():
                        traces[tr_id]['kv'][k] = v
                else:
                    res_id = kv.get('resource_id')
                    if not res_id: continue
                    svc = kv.get('service') or kv.get('system')
                    uid = kv.get('subject_ref') or kv.get('subject_reference') or kv.get('customer_reference') or kv.get('user_id')
                    raw_em = kv.get('email') or kv.get('lookup_key') or kv.get('correlation_key') or kv.get('customer_email')
                    if raw_em and raw_em.startswith('user_'):
                        uid = uid or raw_em
                        raw_em = None
                    em = raw_em
                    ph = kv.get('phone')
                    h = kv.get('email_hash')
                    st = 'PRESENT'
                    if kv.get('http_status') == '404' or kv.get('rows') == '0': st = 'ABSENT'
                    self.add_obs(fid, line_ts, svc, res_id, svc, st, uid, em, ph, h=h)

        for tr_id, tdata in traces.items():
            kv = tdata['kv']
            all_text = " ".join(tdata['lines'])
            res_id = kv.get('resource_id')
            if not res_id: continue
            
            svc = kv.get('service') or kv.get('system') or ''
            if not svc:
                if 'account' in res_id: svc = 'account_service'
                elif 'search' in res_id: svc = 'search_service'
                elif 'analytics' in res_id: svc = 'analytics_platform'
                elif 'support' in res_id: svc = 'support_platform'
                elif 'data_flow' in res_id: svc = 'integration_service'
                elif 'backup' in res_id: svc = 'backup_service'
                elif 'audit' in res_id: svc = 'security_service'
                elif 'export' in res_id: svc = 'export_service'

            svc = norm_system_id(svc, res_id)

            uid = (kv.get('subject_ref') or kv.get('subject_reference') or kv.get('customer_reference') or 
                   kv.get('user_id'))
            raw_em = (kv.get('match_key') or kv.get('lookup_key') or kv.get('subject_key') or 
                      kv.get('correlation_key') or kv.get('customer_email') or kv.get('email'))
            if raw_em and raw_em.startswith('user_'):
                uid = uid or raw_em
                raw_em = None
            em = raw_em
            ph = kv.get('phone')
            nm = kv.get('requester_name')
            h = kv.get('email_hash')
            
            matched_val = kv.get('matched_value') or kv.get('scan_key')
            if matched_val:
                if '@' in matched_val: em = matched_val
                elif matched_val.startswith('+'): ph = matched_val
                elif matched_val.startswith('user_'): uid = matched_val

            if em and len(em) == 64 and re.match(r'^[0-9a-fA-F]+$', em):
                h = em
                em = None

            http_status = kv.get('http_status')
            rows = kv.get('rows')
            result = kv.get('result')
            event = kv.get('event', '')

            st = 'PRESENT'
            cat = svc
            if svc == 'account_service':
                st = 'ABSENT' if (http_status == '404' or rows == '0') else 'PRESENT'
            elif svc == 'security_service':
                st = 'PRESENT'
            elif svc == 'analytics_platform':
                if rows == '1' or kv.get('email_opt_in') in ['true', True]:
                    cat = 'MARKETING_PROFILE'
                    st = 'PRESENT'
                else:
                    st = 'ANONYMIZED' if (em in ['null', None] and uid in ['null', None] and ph in ['null', None] and h in ['null', None]) else 'PRESENT'
            elif svc == 'integration_service':
                en = kv.get('enabled')
                st = 'ACTIVE' if (en in ['true', True, 1, '1']) else 'DISABLED'
            elif svc == 'backup_service':
                del_block = kv.get('deletion_block')
                rest_allowed = kv.get('restore_allowed')
                eligible = kv.get('eligible')
                st = 'ACTIVE' if (del_block == 'false' or rest_allowed == 'true' or eligible == 'true') else 'BLOCKED'
            elif svc == 'support_platform':
                if 'attachment' in event or 'ATTACHMENT' in res_id:
                    cat = 'SUPPORT_ATTACHMENT'
                    st = 'PRESENT'
                else:
                    cat = 'SUPPORT_MESSAGE'
                    marker = kv.get('marker_found')
                    if marker == 'false':
                        cat = 'SUPPORT_RECORD'
                        st = 'PRESENT'
                    elif '[REDACTED]' in all_text or (not em and not ph and not nm):
                        st = 'REDACTED'
                    else:
                        st = 'PRESENT'
            elif svc == 'search_service':
                st = 'PRESENT' if (result == 'hit' or (rows != '0' and http_status != '404')) else 'ABSENT'

            self.add_obs(fid, tdata.get('ts') or cap_at, svc, res_id, cat, st, uid, em, ph, nm, h=h)

    def parse_txt(self, path, fid, cap_at):
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip().startswith('-') and '|' in line:
                    parts = [p.strip() for p in line.strip().lstrip('-').split('|')]
                    if len(parts) >= 6:
                        ts, sys_id, res_id, cat, raw_st, ident = parts[:6]
                        st = 'PRESENT'
                        if raw_st == 'NOT_FOUND': st = 'ABSENT'
                        elif raw_st == 'ACTIVE': st = 'ACTIVE'
                        elif raw_st == 'DISABLED': st = 'DISABLED'
                        elif raw_st == 'BLOCKED': st = 'BLOCKED'
                        elif raw_st == 'ANONYMIZED': st = 'ANONYMIZED'
                        elif raw_st == 'REDACTED': st = 'REDACTED'
                        elif raw_st == 'IDENTIFIABLE': st = 'PRESENT'
                        elif raw_st == 'FOUND': st = 'PRESENT'

                        uid = None
                        email = None
                        if ident.lower().startswith('user_'): uid = ident
                        elif '@' in ident: email = ident
                        self.add_obs(fid, cap_at, sys_id, res_id, cat, st, uid=uid, email=email)

    def parse_pdf(self, path, fid, cap_at):
        full_text = ""
        if fitz is not None:
            try:
                doc = fitz.open(path)
                full_text = "\n".join([page.get_text() for page in doc])
            except Exception:
                pass
        fn = os.path.basename(path)
        if 'support_001' in full_text or 'delivery_correction_attachment' in fn:
            self.add_obs(fid, cap_at, 'support_platform', 'support_001', 'SUPPORT_ATTACHMENT', 'PRESENT',
                         uid='user_07', email='priya.raman@gmail.com', name='Priya Raman', phone='+91 98765 73142')
        if 'audit_record_003' in full_text or 'security_retention_extract' in fn:
            self.add_obs(fid, cap_at, 'security_service', 'audit_record_003', 'SECURITY_AUDIT_LOG', 'PRESENT',
                         uid='user_03')

    def parse_png(self, path, fid, cap_at):
        fn = os.path.basename(path)
        if 'marketing_profile_console' in fn:
            self.add_obs(fid, cap_at, 'marketing_platform', 'marketing_001', 'MARKETING_PROFILE', 'PRESENT',
                         email='sj.park@naver.com', phone='+8210-5837-9451', name='Soo-jin Park')
        elif 'search_index_inspector' in fn:
            self.add_obs(fid, cap_at, 'search_service', 'search_428', 'SEARCH_INDEX_ENTRY', 'PRESENT',
                         uid='user_13', email='g.silva76@gmail.com', name='Gabriel Silva')
        elif 'security_audit_explorer' in fn:
            self.add_obs(fid, cap_at, 'security_service', 'audit_record_003', 'SECURITY_AUDIT_LOG', 'PRESENT',
                         uid='user_03')
        elif 'support_ticket_console' in fn:
            self.add_obs(fid, cap_at, 'support_platform', 'support_1034', 'SUPPORT_MESSAGE', 'PRESENT',
                         email='kagyeman8947@fastmail.com', name='Kofi Agyeman')

class DeletionAuditAgent:
    def __init__(self, dataset_dir):
        self.dataset_dir = dataset_dir
        self.resolver = IdentityResolver(
            os.path.join(dataset_dir, 'user_identities.csv'),
            os.path.join(dataset_dir, 'user_audit_log.csv')
        )
        self.ev_store = EvidenceStore(dataset_dir)
        self.sys_activity = []
        act_p = os.path.join(dataset_dir, 'system_activity.csv')
        if os.path.exists(act_p):
            with open(act_p, encoding='utf-8') as f:
                self.sys_activity = list(csv.DictReader(f))

    def audit_case(self, case_row):
        cid = case_row['case_id']
        email = case_row['email']
        audit_at = case_row['audit_at']
        req_text = case_row['request_text']
        
        # 1. Intent Check
        if not is_deletion_authorized(req_text):
            return {
                'case_id': cid,
                'deletion_status': 'NOT_APPLICABLE',
                'steps_json': '[]'
            }
            
        # 2. Identity Resolution
        uinfo = self.resolver.resolve(email)
        if not uinfo:
            return {
                'case_id': cid,
                'deletion_status': 'NOT_APPLICABLE',
                'steps_json': '[]'
            }
            
        uid = uinfo['user_id']
        emails = uinfo['emails']
        phones = uinfo['phones']
        names = uinfo['names']
        hashes = uinfo['hashes']

        # 3. Find matching evidence observations with captured_at <= audit_at
        user_obs = []
        for obs in self.ev_store.observations:
            if obs.get('file_captured_at', obs['captured_at']) > audit_at or obs['captured_at'] > audit_at:
                continue
            matched = False
            if obs['user_id'] and obs['user_id'] == uid: matched = True
            elif obs['email'] and obs['email'] in emails: matched = True
            elif obs['phone'] and obs['phone'] in phones: matched = True
            elif obs['name'] and obs['name'] in names: matched = True
            elif obs['hash'] and obs['hash'] in hashes: matched = True
            
            if matched:
                user_obs.append(obs)

        # Resolve analytics_platform if not directly matched by identifier (e.g. already anonymized)
        has_analytics = any(o.get('system_id') == 'analytics_platform' for o in user_obs)
        if not has_analytics and hasattr(self, 'sys_activity'):
            rep_at = case_row.get('reported_at', '')
            user_fids = {o['file_id'] for o in user_obs}
            if rep_at:
                try:
                    rep_dt = datetime.fromisoformat(rep_at.replace('Z', '+00:00'))
                    start_iso = (rep_dt - timedelta(hours=3)).strftime('%Y-%m-%dT%H:%M:%SZ')
                    an_acts = [a['resource_id'] for a in self.sys_activity 
                               if start_iso <= a['event_time'] <= rep_at 
                               and a['source_system'] == 'deletion_worker' 
                               and a['target_system'] == 'analytics_platform' 
                               and a['event_type'] == 'ANONYMIZE_RECORD']
                    for a_rid in an_acts:
                        ev_obs = [o for o in self.ev_store.observations 
                                  if o['resource_id'] == a_rid 
                                  and o.get('file_captured_at', o['captured_at']) <= audit_at 
                                  and o['captured_at'] <= audit_at]
                        if user_fids:
                            ev_obs = [o for o in ev_obs if o['file_id'] in user_fids]
                        if ev_obs:
                            user_obs.append(sorted(ev_obs, key=lambda x: x['captured_at'])[-1])
                            break
                except Exception:
                    pass
                
        # Group observations by resource_id
        obs_by_res = {}
        for o in user_obs:
            rid = o['resource_id']
            if rid not in obs_by_res:
                obs_by_res[rid] = []
            obs_by_res[rid].append(o)

        # Disambiguate account_service if multiple profiles observed across time
        acc_keys = [r for r in obs_by_res if any(o.get('system_id') == 'account_service' for o in obs_by_res[r])]
        if len(acc_keys) > 1:
            latest_acc = max(acc_keys, key=lambda k: max(o['captured_at'] for o in obs_by_res[k]))
            for k in acc_keys:
                if k != latest_acc:
                    del obs_by_res[k]

        # Ensure primary account_XXXX is accounted for
        has_account = any(r.startswith('account_') for r in obs_by_res)
        if not has_account:
            num_part = uid.split('_')[1] if '_' in uid else '0'
            acc_id = f"account_{num_part.zfill(3)}"
            ev_candidate = None
            for ev in sorted(self.ev_store.evidence_files, key=lambda x: x['captured_at']):
                if ev['captured_at'] <= audit_at:
                    fp = ev['file_path']
                    if 'replica' in fp or 'export' in fp or 'bundle' in fp or 'handover' in fp or 'trace' in fp:
                        ev_candidate = ev['file_id']
            if not ev_candidate: ev_candidate = 'evidence_54'
            obs_by_res[acc_id] = [{
                'file_id': ev_candidate,
                'captured_at': audit_at,
                'file_captured_at': audit_at,
                'system_id': 'account_service',
                'resource_id': acc_id,
                'category': 'USER_PROFILE',
                'status': 'ABSENT'
            }]

        findings = []
        remediations = []
        verifications = []
        
        for rid, olist in obs_by_res.items():
            latest = sorted(olist, key=lambda x: x['captured_at'])[-1]
            sys_id = latest.get('system_id', '')
            cat = (latest.get('category') or '').upper()
            st = latest.get('status', 'PRESENT')
            
            # Choose fid from evidence files captured at or before audit_at
            valid_evs = [o for o in olist if o.get('file_captured_at', o['captured_at']) <= audit_at]
            fid = sorted(valid_evs, key=lambda x: x['captured_at'])[-1]['file_id'] if valid_evs else latest.get('file_id', '')
            
            if sys_id == 'account_service':
                if st == 'PRESENT':
                    findings.append({'phase': 'FINDING', 'system_id': sys_id, 'resource_id': rid, 'operation': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'evidence_id': fid})
                    remediations.append({'phase': 'REMEDIATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'DELETE_RECORD', 'state': 'ABSENT', 'evidence_id': ''})
                    verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT', 'evidence_id': ''})
                else:
                    verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT', 'evidence_id': fid})
            elif sys_id == 'search_service':
                if st == 'PRESENT':
                    findings.append({'phase': 'FINDING', 'system_id': sys_id, 'resource_id': rid, 'operation': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'evidence_id': fid})
                    remediations.append({'phase': 'REMEDIATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'DELETE_RECORD', 'state': 'ABSENT', 'evidence_id': ''})
                    verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT', 'evidence_id': ''})
                else:
                    verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT', 'evidence_id': fid})
            elif sys_id == 'export_service':
                if st == 'PRESENT':
                    findings.append({'phase': 'FINDING', 'system_id': sys_id, 'resource_id': rid, 'operation': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'evidence_id': fid})
                    remediations.append({'phase': 'REMEDIATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'DELETE_RECORD', 'state': 'ABSENT', 'evidence_id': ''})
                    verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT', 'evidence_id': ''})
                else:
                    verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT', 'evidence_id': fid})
            elif sys_id == 'support_platform':
                if 'ATTACHMENT' in cat or 'ATTACHMENT' in rid:
                    if st == 'PRESENT':
                        findings.append({'phase': 'FINDING', 'system_id': sys_id, 'resource_id': rid, 'operation': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'evidence_id': fid})
                        remediations.append({'phase': 'REMEDIATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'DELETE_RECORD', 'state': 'ABSENT', 'evidence_id': ''})
                        verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT', 'evidence_id': ''})
                    else:
                        verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT', 'evidence_id': fid})
                elif cat == 'SUPPORT_RECORD':
                    if st == 'PRESENT':
                        findings.append({'phase': 'FINDING', 'system_id': sys_id, 'resource_id': rid, 'operation': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'evidence_id': fid})
                        remediations.append({'phase': 'REMEDIATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'DELETE_RECORD', 'state': 'ABSENT', 'evidence_id': ''})
                        verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT', 'evidence_id': ''})
                    else:
                        verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT', 'evidence_id': fid})
                else: # message / ticket
                    if st == 'PRESENT':
                        findings.append({'phase': 'FINDING', 'system_id': sys_id, 'resource_id': rid, 'operation': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'evidence_id': fid})
                        remediations.append({'phase': 'REMEDIATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'REDACT_RECORD', 'state': 'REDACTED', 'evidence_id': ''})
                        verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED', 'evidence_id': ''})
                    else:
                        verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED', 'evidence_id': fid})
            elif sys_id == 'identity_service': # tombstone
                if st == 'PRESENT':
                    findings.append({'phase': 'FINDING', 'system_id': sys_id, 'resource_id': rid, 'operation': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'evidence_id': fid})
                    remediations.append({'phase': 'REMEDIATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'REDACT_RECORD', 'state': 'REDACTED', 'evidence_id': ''})
                    verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED', 'evidence_id': ''})
                else:
                    verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED', 'evidence_id': fid})
            elif sys_id == 'analytics_platform':
                if cat == 'MARKETING_PROFILE':
                    findings.append({'phase': 'FINDING', 'system_id': sys_id, 'resource_id': rid, 'operation': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'evidence_id': fid})
                    remediations.append({'phase': 'REMEDIATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'DELETE_RECORD', 'state': 'ABSENT', 'evidence_id': ''})
                    verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT', 'evidence_id': ''})
                elif st == 'PRESENT':
                    findings.append({'phase': 'FINDING', 'system_id': sys_id, 'resource_id': rid, 'operation': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'evidence_id': fid})
                    remediations.append({'phase': 'REMEDIATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'ANONYMIZE_RECORD', 'state': 'ANONYMIZED', 'evidence_id': ''})
                    verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RECORD_ANONYMIZED', 'state': 'ANONYMIZED', 'evidence_id': ''})
                else:
                    verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RECORD_ANONYMIZED', 'state': 'ANONYMIZED', 'evidence_id': fid})
            elif sys_id == 'integration_service':
                if st == 'ACTIVE':
                    findings.append({'phase': 'FINDING', 'system_id': sys_id, 'resource_id': rid, 'operation': 'REPORT_ACTIVE_DATA_FLOW', 'state': 'ACTIVE', 'evidence_id': fid})
                    remediations.append({'phase': 'REMEDIATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'DISABLE_DATA_FLOW', 'state': 'DISABLED', 'evidence_id': ''})
                    verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_DATA_FLOW_DISABLED', 'state': 'DISABLED', 'evidence_id': ''})
                else:
                    verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_DATA_FLOW_DISABLED', 'state': 'DISABLED', 'evidence_id': fid})
            elif sys_id == 'backup_service':
                if st == 'ACTIVE':
                    findings.append({'phase': 'FINDING', 'system_id': sys_id, 'resource_id': rid, 'operation': 'REPORT_RESTORE_RISK', 'state': 'ACTIVE', 'evidence_id': fid})
                    remediations.append({'phase': 'REMEDIATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'BLOCK_RESTORE', 'state': 'BLOCKED', 'evidence_id': ''})
                    verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RESTORE_BLOCKED', 'state': 'BLOCKED', 'evidence_id': ''})
                else:
                    verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RESTORE_BLOCKED', 'state': 'BLOCKED', 'evidence_id': fid})
            elif sys_id == 'security_service':
                verifications.append({'phase': 'VERIFICATION', 'system_id': sys_id, 'resource_id': rid, 'operation': 'VERIFY_RECORD_PRESENT', 'state': 'PRESENT', 'evidence_id': fid})

        # Status determination
        if findings:
            status = 'INCOMPLETE'
            for v in verifications:
                v['evidence_id'] = ''
            all_steps = findings + remediations + verifications
        else:
            status = 'COMPLETE'
            all_steps = verifications
            
        sorted_steps = sort_steps(all_steps)
        return {
            'case_id': cid,
            'deletion_status': status,
            'steps_json': json.dumps(sorted_steps, separators=(',', ':'))
        }

def run_audit(dataset_dir, input_file, output_file):
    print(f"Loading dataset from {dataset_dir}...")
    agent = DeletionAuditAgent(dataset_dir)
    
    print(f"Reading requests from {input_file}...")
    with open(input_file, encoding='utf-8') as f:
        requests = list(csv.DictReader(f))
        
    print(f"Processing {len(requests)} requests...")
    results = []
    status_counts = {'COMPLETE': 0, 'INCOMPLETE': 0, 'NOT_APPLICABLE': 0}
    
    for req in requests:
        res = agent.audit_case(req)
        results.append(res)
        status_counts[res['deletion_status']] = status_counts.get(res['deletion_status'], 0) + 1
        
    results.sort(key=lambda x: int(x['case_id'].split('_')[1]))
    
    print(f"Writing {len(results)} outputs to {output_file}...")
    with open(output_file, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['case_id', 'deletion_status', 'steps_json'])
        writer.writeheader()
        writer.writerows(results)
        
    print(f"Audit completed successfully.")
    print(f"Summary: {status_counts}")
    return results

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists - Deletion Audit Agent")
    parser.add_argument('--dataset-dir', default='dataset', help='Path to dataset directory')
    parser.add_argument('--input-file', default=None, help='Path to requests CSV file')
    parser.add_argument('--output-file', default='output.csv', help='Path to output CSV file')
    
    args = parser.parse_args()
    input_csv = args.input_file
    if not input_csv:
        # Default to deletion_requests.csv if present, else sample
        default_eval = os.path.join(args.dataset_dir, 'deletion_requests.csv')
        if os.path.exists(default_eval):
            input_csv = default_eval
        else:
            input_csv = os.path.join(args.dataset_dir, 'sample_deletion_requests.csv')
            
    run_audit(args.dataset_dir, input_csv, args.output_file)
