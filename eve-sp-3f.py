# eve-sp-3f : eve.json | simple prompt | 3 fields | no signature

import json
import requests
import time
from datetime import datetime
import os
import re
from collections import Counter

# ============================================================
# General settings
# ============================================================
MODELS = {
    "mistral:latest": "mistral",
    "llama3.2:3b": "llama3.2_3b",
    "hf.co/segolilylabs/Lily-Cybersecurity-7B-v0.2-GGUF:Q4_K_M": "Lily-Cybersecurity"
}

OLLAMA_BASE_URL = "http://localhost:11434"
EVE_FILE = "C:\\Users\\SYN\\Documents\\soc\\eve_sample.json"
OUTPUT_DIR = "C:\\Users\\SYN\\Documents\\soc\\sample2"
SAMPLE_SIZE = 200

TITLE = "eve-sp-3f : eve.json | simple prompt | 3 fields | no signature"

RISK_ORDER = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}


# ============================================================
# Build baselines (BL_SIG and BL_ACADEMIC)
# ============================================================
def get_baselines(src_port, dest_port, signature=""):
    sig_lower = signature.lower()

    # BL_SIG — based on signature text
    if any(x in sig_lower for x in ['dos', 'ddos', 'flood', 'injection', 'xss', 'brute', 'attack']):
        bl_sig = 'HIGH'
    elif any(x in sig_lower for x in ['scan', 'recon', 'probe', 'sweep']):
        bl_sig = 'MEDIUM'
    elif any(x in sig_lower for x in ['normal', 'informational']):
        bl_sig = 'LOW'
    else:
        bl_sig = 'MEDIUM'

    # BL_ACADEMIC — based on port and academic reference
    if dest_port in [23, 21, 22, 3389]:
        bl_academic = 'HIGH'
        ref = 'CISA-Advisory-2024'
    elif dest_port in [80, 443]:
        if any(x in sig_lower for x in ['sql', 'xss', 'injection', 'attack', 'brute']):
            bl_academic = 'MEDIUM'
            ref = 'OWASP-2021'
        else:
            bl_academic = 'LOW'
            ref = 'NIST-SP-800-123'
    else:
        bl_academic = 'MEDIUM'
        ref = 'CIS-Control-9-2023'

    return bl_sig, bl_academic, ref


# ============================================================
# Read eve.json (JSON Lines)
# ============================================================
def read_eve(file_path, limit=200):
    """يقرا من eve_sample.json (جاهز مع baseline)"""
    records = []
    
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return []
    
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            if len(records) >= limit:
                break
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            records.append(rec)
    
    print(f"Read {len(records)} records")
    return records

# ============================================================
# Build prompt and send to model
# ============================================================
def ask(record, model):
    prompt = f"""You are a Senior Security Investigator. You have captured a network packet.
Analyze it based ONLY on the raw data below.

=== RAW NETWORK DATA ===
- Protocol: {record['protocol']}
- Source: {record['source_ip']}:{record['src_port']}
- Destination: {record['dest_ip']}:{record['dest_port']}

=== TASK ===
1. What service is likely running on the destination port?
2. Is this traffic benign or suspicious? Why?
3. Classify the risk as [[HIGH]], [[MEDIUM]], or [[LOW]]. Do NOT write the question. Write your final classification only using EXACTLY two square brackets. Don't change the brackets and don't add any other stars or symbols or space
4. Give ONE specific recommendation.

Base your answer ONLY on the 3 data points above.
Do NOT guess an attack name. Think from first principles.
"""
    try:
        r = requests.post(f"{OLLAMA_BASE_URL}/api/generate", json={
            "model": model, "prompt": prompt, "stream": False,
            "temperature": 0.3
        }, timeout=180)
        if r.status_code == 200:
            return r.json().get('response', '')
        return f"[ERROR] HTTP {r.status_code}"
    except Exception as e:
        return f"[ERROR] {e}"


# ============================================================
# Extract classification from model response
# ============================================================
def extract(resp):
    text = resp.upper()
    matches = re.findall(r'\[+[^\[\]]*?\b(HIGH|MEDIUM|LOW)\b[^\[\]]*?\]+', text)
    if matches:
        return matches[-1]
    return 'INCONCLUSIVE'


# ============================================================
# Main execution
# ============================================================
print("=" * 70)
print(TITLE)
print("=" * 70)

records = read_eve(EVE_FILE, SAMPLE_SIZE)
if not records:
    exit()
print(f"Records: {len(records)}")

# Distribution
sig_dist = Counter(r['baseline_sig'] for r in records)
ac_dist = Counter(r['baseline_academic'] for r in records)

print("\n--- BL_SIG Distribution ---")
for bl, count in sorted(sig_dist.items()):
    print(f"  {bl}: {count} ({count/len(records)*100:.1f}%)")

print("\n--- BL_ACADEMIC Distribution ---")
for bl, count in sorted(ac_dist.items()):
    print(f"  {bl}: {count} ({count/len(records)*100:.1f}%)")

all_results = {}
model_times = {}

for model_key, model_name in MODELS.items():
    print(f"\nTesting: {model_name}")
    model_t0 = time.time()

    safe = model_name.replace('/', '_').replace(':', '_').replace('.', '_')
    filename = os.path.join(OUTPUT_DIR, f"eve-sp-3f_{safe}.txt")

    with open(filename, "w", encoding="utf-8") as f:
        f.write(TITLE + "\n")
        f.write(f"Model: {model_name}\n")
        f.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")
        f.write("--- BL_SIG Distribution ---\n")
        for bl, count in sorted(sig_dist.items()):
            f.write(f"  {bl}: {count} ({count/len(records)*100:.1f}%)\n")
        f.write("\n--- BL_ACADEMIC Distribution ---\n")
        for bl, count in sorted(ac_dist.items()):
            f.write(f"  {bl}: {count} ({count/len(records)*100:.1f}%)\n")
        f.write("\n" + "=" * 70 + "\n\n")

    t0 = time.time()
    results = []

    correct_sig = fp_sig = fn_sig = inc_sig = 0
    correct_ac = fp_ac = fn_ac = inc_ac = 0

    for i, rec in enumerate(records):
        print(f"  Record {i+1}: [{rec['category']}] {rec['source_ip']}:{rec['src_port']} -> {rec['dest_ip']}:{rec['dest_port']} ({rec['signature'][:40]})")
    
        resp = ask(rec, model_key)
        cls = extract(resp)
       # خد البيس لاين من الملف الجاهز
        bl_sig = rec['baseline_sig']
        bl_academic = rec['baseline_academic']
        ref = rec['baseline_ref']
    
       # استخدمه
        match_sig = cls == bl_sig
        match_academic = cls == bl_academic

        # vs BL_SIG
        if cls == 'INCONCLUSIVE':
            inc_sig += 1
        elif cls == rec['baseline_sig']:
            correct_sig += 1
        elif RISK_ORDER.get(cls, 0) > RISK_ORDER.get(rec['baseline_sig'], 0):
            fp_sig += 1
        elif RISK_ORDER.get(cls, 0) < RISK_ORDER.get(rec['baseline_sig'], 0):
            fn_sig += 1

        # vs BL_ACADEMIC
        if cls == 'INCONCLUSIVE':
            inc_ac += 1
        elif cls == rec['baseline_academic']:
            correct_ac += 1
        elif RISK_ORDER.get(cls, 0) > RISK_ORDER.get(rec['baseline_academic'], 0):
            fp_ac += 1
        elif RISK_ORDER.get(cls, 0) < RISK_ORDER.get(rec['baseline_academic'], 0):
            fn_ac += 1

        with open(filename, "a", encoding="utf-8") as f:
            f.write(f"Record {i+1}:\n")
            f.write(f"  Protocol: {rec['protocol']}\n")
            f.write(f"  Source: {rec['source_ip']}:{rec['src_port']}\n")
            f.write(f"  Destination: {rec['dest_ip']}:{rec['dest_port']}\n")
            f.write(f"  Alert Signature: {rec['signature']}\n")
            f.write(f"  Baseline_SIG: {rec['baseline_sig']}\n")
            f.write(f"  Baseline_ACADEMIC: {rec['baseline_academic']}\n")
            f.write(f"  Baseline_REF: {rec['baseline_ref']}\n")
            f.write(f"  Classification: {cls}\n")
            f.write(f"  Match_SIG: {match_sig}\n")
            f.write(f"  Match_ACADEMIC: {match_academic}\n")
            f.write(f"  Full Response:\n{resp}\n")
            f.write("-" * 50 + "\n\n")
            f.flush()

        results.append({
            'cls': cls,
            'baseline_sig': rec['baseline_sig'],
            'baseline_academic': rec['baseline_academic']
        })
    time.sleep(0.5)

    elapsed = time.time() - t0
    model_elapsed = time.time() - model_t0
    total = len(results)
    model_times[model_name] = model_elapsed

    acc_sig = correct_sig / total * 100 if total else 0
    fp_sig_pct = fp_sig / total * 100 if total else 0
    fn_sig_pct = fn_sig / total * 100 if total else 0
    inc_sig_pct = inc_sig / total * 100 if total else 0

    acc_ac = correct_ac / total * 100 if total else 0
    fp_ac_pct = fp_ac / total * 100 if total else 0
    fn_ac_pct = fn_ac / total * 100 if total else 0
    inc_ac_pct = inc_ac / total * 100 if total else 0

    with open(filename, "a", encoding="utf-8") as f:
        f.write("=" * 70 + "\nSUMMARY\n" + "=" * 70 + "\n")
        f.write(f"Model: {model_name}\n")
        f.write(f"Time: {elapsed:.1f}s ({elapsed/60:.1f} min)\n")
        f.write(f"Total: {total}\n\n")

        f.write("[VS BL_SIG - Signature-based]\n")
        f.write(f"Correct: {correct_sig}/{total} ({acc_sig:.1f}%)\n")
        f.write(f"FP: {fp_sig}/{total} ({fp_sig_pct:.1f}%)\n")
        f.write(f"FN: {fn_sig}/{total} ({fn_sig_pct:.1f}%)\n")
        f.write(f"Inconclusive: {inc_sig}/{total} ({inc_sig_pct:.1f}%)\n\n")

        f.write("[VS BL_ACADEMIC - Reference-based]\n")
        f.write(f"Correct: {correct_ac}/{total} ({acc_ac:.1f}%)\n")
        f.write(f"FP: {fp_ac}/{total} ({fp_ac_pct:.1f}%)\n")
        f.write(f"FN: {fn_ac}/{total} ({fn_ac_pct:.1f}%)\n")
        f.write(f"Inconclusive: {inc_ac}/{total} ({inc_ac_pct:.1f}%)\n")

    print(f"  ⏱ Time: {elapsed:.1f}s ({elapsed/60:.1f} min)")
    print(f"  [BL_SIG]      Correct: {acc_sig:.1f}% | FP: {fp_sig_pct:.1f}% | FN: {fn_sig_pct:.1f}%")
    print(f"  [BL_ACADEMIC] Correct: {acc_ac:.1f}% | FP: {fp_ac_pct:.1f}% | FN: {fn_ac_pct:.1f}%")

    all_results[model_key] = {
        'correct_sig': correct_sig, 'fp_sig': fp_sig, 'fn_sig': fn_sig, 'inc_sig': inc_sig,
        'correct_ac': correct_ac, 'fp_ac': fp_ac, 'fn_ac': fn_ac, 'inc_ac': inc_ac,
        'total': total,
        'acc_sig': acc_sig, 'fp_sig_pct': fp_sig_pct, 'fn_sig_pct': fn_sig_pct, 'inc_sig_pct': inc_sig_pct,
        'acc_ac': acc_ac, 'fp_ac_pct': fp_ac_pct, 'fn_ac_pct': fn_ac_pct, 'inc_ac_pct': inc_ac_pct,
        'time': elapsed
    }

# ============================================================
# Final summary on screen
# ============================================================
print("\n" + "=" * 70)
print(f"FINAL SUMMARY of {TITLE}")
print("=" * 70)

print("\n--- BL_SIG Distribution ---")
for bl, count in sorted(sig_dist.items()):
    print(f"  {bl}: {count} ({count/len(records)*100:.1f}%)")

print("\n--- BL_ACADEMIC Distribution ---")
for bl, count in sorted(ac_dist.items()):
    print(f"  {bl}: {count} ({count/len(records)*100:.1f}%)")

for k, v in all_results.items():
    print(f"\n{k}:")
    print(f"  ⏱ Time: {v['time']:.1f}s ({v['time']/60:.1f} min)")
    print(f"  === vs BL_SIG ===")
    print(f"  Correct: {v['correct_sig']}/{v['total']} ({v['acc_sig']:.1f}%)")
    print(f"  FP: {v['fp_sig']}/{v['total']} ({v['fp_sig_pct']:.1f}%)")
    print(f"  FN: {v['fn_sig']}/{v['total']} ({v['fn_sig_pct']:.1f}%)")
    print(f"  Inconclusive: {v['inc_sig']}/{v['total']} ({v['inc_sig_pct']:.1f}%)")
    print(f"  === vs BL_ACADEMIC ===")
    print(f"  Correct: {v['correct_ac']}/{v['total']} ({v['acc_ac']:.1f}%)")
    print(f"  FP: {v['fp_ac']}/{v['total']} ({v['fp_ac_pct']:.1f}%)")
    print(f"  FN: {v['fn_ac']}/{v['total']} ({v['fn_ac_pct']:.1f}%)")
    print(f"  Inconclusive: {v['inc_ac']}/{v['total']} ({v['inc_ac_pct']:.1f}%)")

# ============================================================
# TIMING SUMMARY
# ============================================================
print("\n" + "=" * 70)
print("TIMING SUMMARY")
print("=" * 70)
total_time = 0
for model_name, t in model_times.items():
    print(f"  {model_name}: {t:.1f}s ({t/60:.1f} min)")
    total_time += t
print(f"  ---")
print(f"  TOTAL: {total_time:.1f}s ({total_time/60:.1f} min)")

print("\nDone.")