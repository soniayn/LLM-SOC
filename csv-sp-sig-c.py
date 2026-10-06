# csv-sp-sig-c : combined_attacks.csv | simple prompt | correct signature

import csv
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
CSV_FILE = "C:\\Users\\SYN\\Documents\\soc\\sample2\\combined_attacks.csv"
OUTPUT_DIR = "C:\\Users\\SYN\\Documents\\soc\\sample2"
SAMPLE_SIZE = 200

TITLE = "csv-sp-sig-c : combined_attacks.csv | simple prompt | correct signature"

RISK_ORDER = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}


# ============================================================
# Baseline per attack type
# ============================================================
def get_baseline(label):
    label_lower = label.lower().strip()
    if label_lower == 'benign':
        return 'LOW'
    if 'portscan' in label_lower or 'port scan' in label_lower or 'scan' in label_lower:
        return 'MEDIUM'
    if any(x in label_lower for x in [
        'ddos', 'dos', 'hulk', 'goldeneye', 'slowloris', 'slowhttptest',
        'patator', 'brute', 'sql', 'xss', 'injection',
        'infiltration', 'bot', 'heartbleed'
    ]):
        return 'HIGH'
    return 'MEDIUM'


# ============================================================
# Read CSV file
# ============================================================
def read_csv(file_path, limit=200):
    records = []
    encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if len(records) >= limit:
                        break
                    label = row.get(' Label', row.get('Label', '')).strip()
                    if not label:
                        continue
                    src_ip = row.get(' Source IP', row.get('Source IP', '')).strip()
                    dest_ip = row.get(' Destination IP', row.get('Destination IP', '')).strip()
                    src_port = row.get(' Source Port', row.get('Source Port', '')).strip()
                    dest_port = row.get(' Destination Port', row.get('Destination Port', '')).strip()
                    proto = row.get(' Protocol', row.get('Protocol', '')).strip()
                    if not all([src_ip, dest_ip, src_port, dest_port]):
                        continue
                    try:
                        src_port = int(float(src_port))
                        dest_port = int(float(dest_port))
                    except:
                        continue
                    proto_map = {'6': 'TCP', '17': 'UDP', '1': 'ICMP'}
                    proto_name = proto_map.get(str(proto), proto)
                    records.append({
                        'protocol': proto_name,
                        'source_ip': src_ip,
                        'src_port': src_port,
                        'dest_ip': dest_ip,
                        'dest_port': dest_port,
                        'label': label,
                        'baseline': get_baseline(label)
                    })
            print(f"Read {len(records)} records")
            return records
        except UnicodeDecodeError:
            continue
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return []
    return []


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
- Alert Signature: {record['label']}

=== TASK ===
1. What service is likely running on the destination port?
2. Is this traffic benign or suspicious? Why?
3. Classify the risk as [[HIGH]], [[MEDIUM]], or [[LOW]]. Do NOT write the question. Write your final classification only using EXACTLY two square brackets. Don't change the brackets and don't add any other stars or symbols or space
4. Give ONE specific recommendation.

Base your answer ONLY on the 3 data points above.
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

records = read_csv(CSV_FILE, SAMPLE_SIZE)
if not records:
    exit()
print(f"Records: {len(records)}")

baseline_dist = Counter(r['baseline'] for r in records)
label_dist = Counter(r['label'] for r in records)

print("\n--- Baseline Distribution ---")
for bl, count in sorted(baseline_dist.items()):
    print(f"  {bl}: {count} ({count/len(records)*100:.1f}%)")

print("\n--- Label Distribution ---")
for lbl, count in sorted(label_dist.items()):
    print(f"  {lbl}: {count}")

all_results = {}
model_times = {}

for model_key, model_name in MODELS.items():
    print(f"\nTesting: {model_name}")
    model_t0 = time.time()

    safe = model_name.replace('/', '_').replace(':', '_').replace('.', '_')
    filename = os.path.join(OUTPUT_DIR, f"csv-sp-sig-c_{safe}.txt")

    with open(filename, "w", encoding="utf-8") as f:
        f.write(TITLE + "\n")
        f.write(f"Model: {model_name}\n")
        f.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")
        f.write("--- Baseline Distribution ---\n")
        for bl, count in sorted(baseline_dist.items()):
            f.write(f"  {bl}: {count} ({count/len(records)*100:.1f}%)\n")
        f.write("\n--- Label Distribution ---\n")
        for lbl, count in sorted(label_dist.items()):
            f.write(f"  {lbl}: {count}\n")
        f.write("\n" + "=" * 70 + "\n\n")

    t0 = time.time()
    results = []
    correct = fp = fn = inconclusive = 0

    for i, rec in enumerate(records):
        print(f"  Record {i+1}/{len(records)}: {rec['source_ip']}:{rec['src_port']} -> {rec['dest_ip']}:{rec['dest_port']} [{rec['label']}] BL={rec['baseline']}")
        resp = ask(rec, model_key)
        cls = extract(resp)

        match = "OK" if cls == rec['baseline'] else "X"

        if cls == 'INCONCLUSIVE':
            inconclusive += 1
        elif cls == rec['baseline']:
            correct += 1
        elif RISK_ORDER.get(cls, 0) > RISK_ORDER.get(rec['baseline'], 0):
            fp += 1
        elif RISK_ORDER.get(cls, 0) < RISK_ORDER.get(rec['baseline'], 0):
            fn += 1

        with open(filename, "a", encoding="utf-8") as f:
            f.write(f"Record {i+1}:\n")
            f.write(f"  Protocol: {rec['protocol']}\n")
            f.write(f"  Source: {rec['source_ip']}:{rec['src_port']}\n")
            f.write(f"  Destination: {rec['dest_ip']}:{rec['dest_port']}\n")
            f.write(f"  Label: {rec['label']}\n")
            f.write(f"  Baseline: {rec['baseline']}\n")
            f.write(f"  Classification: {cls} [{match}]\n")
            f.write(f"  Full Response:\n{resp}\n")
            f.write("-" * 50 + "\n\n")
            f.flush()

        results.append({'cls': cls, 'baseline': rec['baseline'], 'match': cls == rec['baseline']})
        time.sleep(0.5)

    elapsed = time.time() - t0
    model_elapsed = time.time() - model_t0
    total = len(results)
    model_times[model_name] = model_elapsed

    acc = correct / total * 100 if total else 0
    fp_pct = fp / total * 100 if total else 0
    fn_pct = fn / total * 100 if total else 0
    inc_pct = inconclusive / total * 100 if total else 0

    with open(filename, "a", encoding="utf-8") as f:
        f.write("=" * 70 + "\nSUMMARY\n" + "=" * 70 + "\n")
        f.write(f"Model: {model_name}\n")
        f.write(f"Time: {elapsed:.1f}s ({elapsed/60:.1f} min)\n")
        f.write(f"Total: {total}\n\n")
        f.write("[VS Baseline]\n")
        f.write(f"Correct: {correct}/{total} ({acc:.1f}%)\n")
        f.write(f"FP: {fp}/{total} ({fp_pct:.1f}%)\n")
        f.write(f"FN: {fn}/{total} ({fn_pct:.1f}%)\n")
        f.write(f"Inconclusive: {inconclusive}/{total} ({inc_pct:.1f}%)\n")

    print(f"  ⏱ Time: {elapsed:.1f}s ({elapsed/60:.1f} min) | Correct: {acc:.1f}% | FP: {fp_pct:.1f}% | FN: {fn_pct:.1f}%")

    all_results[model_key] = {
        'correct': correct, 'fp': fp, 'fn': fn, 'inconclusive': inconclusive,
        'total': total, 'acc': acc, 'fp_pct': fp_pct, 'fn_pct': fn_pct, 'inc_pct': inc_pct,
        'time': elapsed
    }

# ============================================================
# Final summary on screen
# ============================================================
print("\n" + "=" * 70)
print(f"FINAL SUMMARY of {TITLE}")
print("=" * 70)

print("\n--- Baseline Distribution ---")
for bl, count in sorted(baseline_dist.items()):
    print(f"  {bl}: {count} ({count/len(records)*100:.1f}%)")

for k, v in all_results.items():
    print(f"\n{k}:")
    print(f"  === vs Baseline ===")
    print(f"  ⏱ Time: {v['time']:.1f}s ({v['time']/60:.1f} min)")
    print(f"  Correct: {v['correct']}/{v['total']} ({v['acc']:.1f}%)")
    print(f"  FP: {v['fp']}/{v['total']} ({v['fp_pct']:.1f}%)")
    print(f"  FN: {v['fn']}/{v['total']} ({v['fn_pct']:.1f}%)")
    print(f"  Inconclusive: {v['inconclusive']}/{v['total']} ({v['inc_pct']:.1f}%)")

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