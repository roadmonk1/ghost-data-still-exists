"""
Comprehensive Evaluation Suite for Ghost Data Still Exists
HackerRank Orchestrate (October 2026)

Reports:
- Case-Level Status Accuracy
- Exact Sequence Accuracy
- Step-Level Accuracy (position-aligned and set-level)
- Field-Level Accuracy across all standard fields
- Detailed Breakdown of Missing/Extra Steps
- Per-Case Mismatch Diagnostics with Actionable Explanations
"""

import os
import sys
import csv
import json
import argparse
from typing import Dict, List, Any, Tuple

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

COMPARISON_FIELDS = ['phase', 'system_id', 'resource_id', 'operation', 'state', 'evidence_id']

def normalize_step(step: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize step dictionary for comparison, preserving semantic values."""
    return {
        'step_no': step.get('step_no'),
        'phase': str(step.get('phase', '')).strip(),
        'system_id': str(step.get('system_id', '')).strip(),
        'resource_id': str(step.get('resource_id', '')).strip(),
        'operation': str(step.get('operation', '')).strip(),
        'state': str(step.get('state', '')).strip(),
        'evidence_id': str(step.get('evidence_id', '')).strip()
    }

def step_tuple(s: Dict[str, Any]) -> Tuple[str, str, str, str, str, str]:
    """Create a hashable tuple representation of a step ignoring step_no."""
    return (s['phase'], s['system_id'], s['resource_id'], s['operation'], s['state'], s['evidence_id'])

def evaluate_predictions(pred_path: str, truth_path: str, verbose: bool = True) -> Dict[str, Any]:
    print(f"Comparing predictions ({pred_path}) against ground truth ({truth_path})...\n")
    
    if not os.path.exists(pred_path):
        raise FileNotFoundError(f"Prediction file not found: {pred_path}")
    if not os.path.exists(truth_path):
        raise FileNotFoundError(f"Ground truth file not found: {truth_path}")

    with open(pred_path, encoding='utf-8') as f:
        predictions = {r['case_id']: r for r in csv.DictReader(f)}
    with open(truth_path, encoding='utf-8') as f:
        truth = {r['case_id']: r for r in csv.DictReader(f)}

    total_cases = len(truth)
    status_correct = 0
    sequence_correct = 0
    step_total = 0
    step_correct = 0
    field_total = 0
    field_correct = 0

    field_error_counts = {f: 0 for f in COMPARISON_FIELDS}
    missing_steps_total = 0
    extra_steps_total = 0
    mismatches = []

    for cid, exp in truth.items():
        if cid not in predictions:
            mismatches.append({
                'case_id': cid,
                'issue': 'CASE_MISSING_IN_PREDICTIONS',
                'expected_status': exp['deletion_status'],
                'predicted_status': 'MISSING'
            })
            continue

        pred = predictions[cid]
        exp_status = exp['deletion_status']
        pred_status = pred['deletion_status']

        status_match = (pred_status == exp_status)
        if status_match:
            status_correct += 1

        try:
            p_steps = [normalize_step(s) for s in json.loads(pred.get('steps_json', '[]'))]
        except Exception as e:
            p_steps = []
            mismatches.append({
                'case_id': cid,
                'issue': f'MALFORMED_JSON: {e}',
                'expected_status': exp_status,
                'predicted_status': pred_status
            })
            continue

        try:
            e_steps = [normalize_step(s) for s in json.loads(exp.get('steps_json', '[]'))]
        except Exception as e:
            e_steps = []

        # Exact sequence check: arrays must match in length, order, and all step fields
        seq_match = False
        if len(p_steps) == len(e_steps):
            all_match = True
            for ps, es in zip(p_steps, e_steps):
                if any(ps[f] != es[f] for f in COMPARISON_FIELDS):
                    all_match = False
                    break
            if all_match and status_match:
                seq_match = True

        if seq_match:
            sequence_correct += 1

        # Positional step-level and field-level scoring
        step_total += len(e_steps)
        for i, es in enumerate(e_steps):
            field_total += len(COMPARISON_FIELDS)
            if i < len(p_steps):
                ps = p_steps[i]
                matches = 0
                for f in COMPARISON_FIELDS:
                    if ps[f] == es[f]:
                        matches += 1
                        field_correct += 1
                    else:
                        field_error_counts[f] += 1
                if matches == len(COMPARISON_FIELDS):
                    step_correct += 1
            else:
                # Missing corresponding step at position i
                for f in COMPARISON_FIELDS:
                    field_error_counts[f] += 1

        # Set-level analysis (missing vs extra)
        e_set = [step_tuple(s) for s in e_steps]
        p_set = [step_tuple(s) for s in p_steps]

        missing_for_case = [s for s in e_steps if step_tuple(s) not in p_set]
        extra_for_case = [s for s in p_steps if step_tuple(s) not in e_set]

        missing_steps_total += len(missing_for_case)
        extra_steps_total += len(extra_for_case)

        if not seq_match or not status_match:
            mismatches.append({
                'case_id': cid,
                'status_match': status_match,
                'expected_status': exp_status,
                'predicted_status': pred_status,
                'expected_step_count': len(e_steps),
                'predicted_step_count': len(p_steps),
                'missing_steps': missing_for_case,
                'extra_steps': extra_for_case
            })

    # Summary Report
    print("=" * 65)
    print("                 EVALUATION ACCURACY REPORT                      ")
    print("=" * 65)
    print(f"Total Cases Evaluated           : {total_cases}")
    print(f"Case-Level Status Accuracy      : {status_correct}/{total_cases} ({status_correct / total_cases * 100:.2f}%)")
    print(f"Exact Sequence Accuracy         : {sequence_correct}/{total_cases} ({sequence_correct / total_cases * 100:.2f}%)")
    step_pct = (step_correct / step_total * 100) if step_total > 0 else 100.0
    field_pct = (field_correct / field_total * 100) if field_total > 0 else 100.0
    print(f"Step-Level Positional Accuracy  : {step_correct}/{step_total} ({step_pct:.2f}%)")
    print(f"Field-Level Accuracy            : {field_correct}/{field_total} ({field_pct:.2f}%)")
    print(f"Total Missing Steps (Set-level) : {missing_steps_total}")
    print(f"Total Extra Steps (Set-level)   : {extra_steps_total}")
    print("-" * 65)
    print("FIELD-LEVEL ERROR BREAKDOWN:")
    for f in COMPARISON_FIELDS:
        errs = field_error_counts[f]
        acc = ((field_total / len(COMPARISON_FIELDS) - errs) / (field_total / len(COMPARISON_FIELDS)) * 100) if field_total > 0 else 100.0
        print(f"  * {f:<15}: {errs:>4} errors ({acc:.1f}% accuracy)")
    print("=" * 65)

    if verbose and mismatches:
        print("\n" + "=" * 65)
        print(f"        DETAILED MISMATCH BREAKDOWN ({len(mismatches)} CASES)")
        print("=" * 65)
        for m in mismatches:
            cid = m['case_id']
            st_flag = "OK" if m.get('status_match') else "STATUS MISMATCH"
            print(f"\n[{cid}] Status: Exp={m['expected_status']}, Pred={m['predicted_status']} ({st_flag})")
            print(f"  Step Counts: Exp={m.get('expected_step_count')}, Pred={m.get('predicted_step_count')}")
            if m.get('missing_steps'):
                print(f"  Missing Steps ({len(m['missing_steps'])}):")
                for s in m['missing_steps']:
                    print(f"    - {s['phase']} | {s['system_id']} | {s['resource_id']} | {s['operation']} | ev={s['evidence_id']}")
            if m.get('extra_steps'):
                print(f"  Extra Steps ({len(m['extra_steps'])}):")
                for s in m['extra_steps']:
                    print(f"    + {s['phase']} | {s['system_id']} | {s['resource_id']} | {s['operation']} | ev={s['evidence_id']}")
        print("=" * 65)

    return {
        'total_cases': total_cases,
        'status_correct': status_correct,
        'sequence_correct': sequence_correct,
        'step_correct': step_correct,
        'step_total': step_total,
        'field_correct': field_correct,
        'field_total': field_total,
        'field_error_counts': field_error_counts,
        'mismatches': mismatches
    }

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Evaluate Ghost Data Still Exists predictions")
    parser.add_argument("pred_file", nargs="?", default="sample_pred.csv", help="Predictions CSV file")
    parser.add_argument("truth_file", nargs="?", default="dataset/sample_output.csv", help="Ground truth CSV file")
    parser.add_argument("--quiet", action="store_true", help="Suppress detailed mismatch breakdown")
    args = parser.parse_args()

    evaluate_predictions(args.pred_file, args.truth_file, verbose=not args.quiet)
