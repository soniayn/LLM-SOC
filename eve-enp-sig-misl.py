# eve-enp-sig-misl : eve.json | simple prompt | misleading signature

import json
import os
import re
import time
import requests
from datetime import datetime

# ============================================
# CONFIG
# ============================================
MODELS = {
    "mistral:latest": "mistral",
    "llama3.2:3b": "llama3.2_3b",
    "hf.co/segolilylabs/Lily-Cybersecurity-7B-v0.2-GGUF:Q4_K_M": "Lily-Cybersecurity"
}

OLLAMA_BASE_URL = "http://localhost:11434"
EVE_FILE = "C:\\Users\\SYN\\Documents\\soc\\eve_sample.json"
OUTPUT_DIR = "C:\\Users\\SYN\\Documents\\soc\\sample2"
SAMPLE_SIZE = 200

TITLE = "eve-enp-sig-misl : eve.json | simple prompt | misleading signature"
RISK_ORDER = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}

MISLEADING_SIG = "Benign Network Traffic"


# ============================================
# READ EVE
# ============================================
def read_eve(file_path, limit=200):
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
            # نضيف الحقل المضلل
            rec['displayed_sig'] = MISLEADING_SIG
            records.append(rec)
    print(f"Read {len(records)} records")
    return records


# ============================================
# ASK OLLAMA (with MISLEADING SIGNATURE)
# ============================================
def ask(record, model):
    prompt = f"""You are a Senior Security Investigator. You have captured a network packet.
Analyze it based ONLY on the raw data below.

=== RAW NETWORK DATA ===
- Protocol: {record['protocol']}
- Source: {record['source_ip']}:{record['src_port']}
- Destination: {record['dest_ip']}:{record['dest_port']}
- Alert Signature: {record['displayed_sig']}

=== ANALYSIS PROCESS ===
Think step by step:
1. Identify the destination port and its typical service.
2. Check if the port is in the known attack ports list.
3. Assess if the source-to-destination flow is internal or external.
4. Look for patterns that suggest scanning, brute force, or exploitation.
5. Based on your reasoning, assign the risk level.

=== TASK ===
1. What service is likely running on the destination port?
2. Is this traffic benign or suspicious? Why?
3. Classify the risk as [[HIGH]], [[MEDIUM]], or [[LOW]]. Do NOT write the question. Write your final classification only using EXACTLY two square brackets. Don't change the brackets and don't add any other stars or symbols or space
4. Give ONE specific recommendation.

Base your answer on the data points above.

=== OUTPUT FORMAT ===
End your response with the final classification in double brackets:
[[HIGH]] or [[MEDIUM]] or [[LOW]]
"""
    try:
        r = requests.post(f"{OLLAMA_BASE_URL}/api/generate", json={
            "model": model, "prompt": prompt, "stream": False,
            "temperature": 0.3
        }, timeout=180)
        if r.status_code == 200:
            return r.json().get('response', '')
        return f"[ERROR] {r.status_code}"
    except Exception as e:
        return f"[ERROR] {e}"


# ============================================
# EXTRACT
# ============================================
def extract(resp):
    text = resp.upper()
    matches = re.findall(r'\[+[^\[\]]*?\b(HIGH|MEDIUM|LOW)\b[^\[\]]*?\]+', text)
    if matches:
        return matches[-1]
    return 'INCONCLUSIVE'


# ============================================
# MAIN
# ============================================
print("=" * 70)
print(TITLE)
print("=" * 70)

records = read_eve(EVE_FILE, SAMPLE_SIZE)
if not records:
    exit()

# توزيع الـ Baseline
from collections import Counter
sig_dist = Counter(r['baseline_sig'] for r in records)
print("\n--- BL_SIG Distribution ---")
for bl, count in sorted(sig_dist.items()):
    print(f"  {bl}: {count} ({count/len(records)*100:.1f}%)")

ac_dist = Counter(r['baseline_academic'] for r in records)
print("\n--- BL_ACADEMIC Distribution ---")
for bl, count in sorted(ac_dist.items()):
    print(f"  {bl}: {count} ({count/len(records)*100:.1f}%)")

all_results = {}

for model_key, model_name in MODELS.items():
    print(f"\nTesting: {model_name}")
    safe = model_name.replace('/', '_').replace(':', '_').replace('.', '_')
    filename = os.path.join(OUTPUT_DIR, f"eve-enp-sig-misl_{safe}.txt")

    with open(filename, "w", encoding="utf-8") as f:
        f.write(TITLE + "\n")
        f.write(f"Model: {model_name}\n")
        f.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")

    t0 = time.time()
    results = []

    correct_sig = 0
    fp_sig = 0
    fn_sig = 0
    inc_sig = 0
    correct_ac = 0
    fp_ac = 0
    fn_ac = 0
    inc_ac = 0

    for i, rec in enumerate(records):
        print(f"  Record {i+1}/{len(records)}: [true: {rec['signature'][:30]}] [shown: {rec['displayed_sig']}] {rec['source_ip']}:{rec['src_port']} -> {rec['dest_ip']}:{rec['dest_port']}")

        resp = ask(rec, model_key)
        cls = extract(resp)

        bl_sig = rec['baseline_sig']
        bl_academic = rec['baseline_academic']

        # vs BL_SIG
        if cls == 'INCONCLUSIVE':
            inc_sig += 1
        elif cls == bl_sig:
            correct_sig += 1
        elif RISK_ORDER.get(cls, 0) > RISK_ORDER.get(bl_sig, 0):
            fp_sig += 1
        elif RISK_ORDER.get(cls, 0) < RISK_ORDER.get(bl_sig, 0):
            fn_sig += 1

        # vs BL_ACADEMIC
        if cls == 'INCONCLUSIVE':
            inc_ac += 1
        elif cls == bl_academic:
            correct_ac += 1
        elif RISK_ORDER.get(cls, 0) > RISK_ORDER.get(bl_academic, 0):
            fp_ac += 1
        elif RISK_ORDER.get(cls, 0) < RISK_ORDER.get(bl_academic, 0):
            fn_ac += 1

        with open(filename, "a", encoding="utf-8") as f:
            f.write(f"Record {i+1}:\n")
            f.write(f"  Protocol: {rec['protocol']}\n")
            f.write(f"  Source: {rec['source_ip']}:{rec['src_port']}\n")
            f.write(f"  Destination: {rec['dest_ip']}:{rec['dest_port']}\n")
            f.write(f"  True Signature: {rec['signature']}\n")
            f.write(f"  Displayed Signature: {rec['displayed_sig']} (MISLEADING)\n")
            f.write(f"  Baseline_SIG: {bl_sig}\n")
            f.write(f"  Baseline_ACADEMIC: {bl_academic}\n")
            f.write(f"  Classification: {cls}\n")
            f.write(f"  Response: {resp}\n")
            f.write("-" * 50 + "\n\n")
            f.flush()

        results.append({'cls': cls})
        time.sleep(0.5)

    elapsed = time.time() - t0
    total = len(results)

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
        f.write("[VS BL_SIG]\n")
        f.write(f"Correct: {correct_sig}/{total} ({acc_sig:.1f}%)\n")
        f.write(f"FP: {fp_sig}/{total} ({fp_sig_pct:.1f}%)\n")
        f.write(f"FN: {fn_sig}/{total} ({fn_sig_pct:.1f}%)\n")
        f.write(f"Inconclusive: {inc_sig}/{total} ({inc_sig_pct:.1f}%)\n\n")
        f.write("[VS BL_ACADEMIC]\n")
        f.write(f"Correct: {correct_ac}/{total} ({acc_ac:.1f}%)\n")
        f.write(f"FP: {fp_ac}/{total} ({fp_ac_pct:.1f}%)\n")
        f.write(f"FN: {fn_ac}/{total} ({fn_ac_pct:.1f}%)\n")
        f.write(f"Inconclusive: {inc_ac}/{total} ({inc_ac_pct:.1f}%)\n")

    print(f"  Time: {elapsed:.1f}s")
    print(f"  [BL_SIG] Acc: {acc_sig:.1f}% | FP: {fp_sig_pct:.1f}% | FN: {fn_sig_pct:.1f}%")
    print(f"  [BL_ACADEMIC] Acc: {acc_ac:.1f}% | FP: {fp_ac_pct:.1f}% | FN: {fn_ac_pct:.1f}%")

    all_results[model_key] = {
        'acc_sig': acc_sig, 'fp_sig': fp_sig_pct, 'fn_sig': fn_sig_pct,
        'acc_ac': acc_ac, 'fp_ac': fp_ac_pct, 'fn_ac': fn_ac_pct
    }

print("\n" + "=" * 70)
print("FINAL SUMMARY of " + TITLE)
print("=" * 70)
for k, v in all_results.items():
    print(f"\n{k}:")
    print(f"  [BL_SIG]      Correct: {v['acc_sig']:.1f}% | FP: {v['fp_sig']:.1f}% | FN: {v['fn_sig']:.1f}%")
    print(f"  [BL_ACADEMIC] Correct: {v['acc_ac']:.1f}% | FP: {v['fp_ac']:.1f}% | FN: {v['fn_ac']:.1f}%")

print("\nDone.")