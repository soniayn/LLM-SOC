# combine.py - تجميع عينة متوازنة من CIC-IDS2017

import csv
import os
import random

# المسار: نفس مجلد الملفات
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# الإخراج: في مجلد soc (الأب)
OUTPUT_FILE = os.path.join(os.path.dirname(BASE_DIR), "combined_big_sample.csv")

FILES = [
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
]

# المطلوب من كل نوع
TARGETS = {
    "FTP-Patator": 15,
    "SSH-Patator": 15,
    "DoS Hulk": 15,
    "DoS GoldenEye": 15,
    "DoS slowloris": 15,
    "Heartbleed": 11,
    "Web Attack  Brute Force": 15,
    "Web Attack  XSS": 15,
    "Web Attack  SQL Injection": 21,
    "Infiltration": 15,
    "Bot": 15,
    "PortScan": 15,
    "DDoS": 15,
    "BENIGN": 15,
}


def normalize(s):
    """توحيد النص للمطابقة"""
    return ' '.join(s.lower().replace('  ', ' ').replace('_', ' ').split())


target_keys = {k: normalize(k) for k in TARGETS}
collected = {}
for k in TARGETS:
    collected[k] = []

header = None
total_read = 0

print("=" * 70)
print("BUILDING BIG SAMPLE")
print("=" * 70)
print(f"Base dir: {BASE_DIR}")
print(f"Output: {OUTPUT_FILE}")
print()

# ============================================
# READ FILES
# ============================================
for filename in FILES:
    file_path = os.path.join(BASE_DIR, filename)
    if not os.path.exists(file_path):
        print(f"[SKIP] Not found: {filename}")
        continue
    
    print(f"\nReading: {filename}")
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        if header is None:
            header = reader.fieldnames
        
        file_counts = {}
        row_count = 0
        
        for row in reader:
            row_count += 1
            total_read += 1
            
            # اقرأ الـ label
            label_raw = ''
            for key in [' Label', 'Label', ' label', 'label']:
                if key in row:
                    label_raw = (row[key] or '').strip()
                    break
            
            if not label_raw:
                continue
            
            label_key = normalize(label_raw)
            
            # مطابقة
            for target_label, target_key in target_keys.items():
                if target_key == label_key:
                    if len(collected[target_label]) < TARGETS[target_label]:
                        collected[target_label].append(row)
                        file_counts[target_label] = file_counts.get(target_label, 0) + 1
                    break
            
            # توقف لو جمعنا كل حاجة
            if all(len(collected[k]) >= TARGETS[k] for k in TARGETS):
                break
        
        print(f"  Rows scanned: {row_count}")
        for k, v in file_counts.items():
            print(f"    → {k}: {v}")
    
    if all(len(collected[k]) >= TARGETS[k] for k in TARGETS):
        print("\nAll targets collected!")
        break


# ============================================
# SUMMARY
# ============================================
print("\n" + "=" * 70)
print("COLLECTION SUMMARY")
print("=" * 70)

total_collected = 0
missing = []
for label, target in TARGETS.items():
    got = len(collected[label])
    status = "OK" if got >= target else f"MISSING {target - got}"
    if got < target:
        missing.append(f"{label} ({got}/{target})")
    print(f"  {label}: {got}/{target} [{status}]")
    total_collected += got

print(f"\nTotal collected: {total_collected}")
if missing:
    print(f"Missing: {missing}")


# ============================================
# SAVE
# ============================================
all_records = []
for label in TARGETS:
    all_records.extend(collected[label])

random.seed(42)
random.shuffle(all_records)

if all_records and header:
    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(all_records)
    print(f"\n✅ Saved: {OUTPUT_FILE}")
    print(f"   Total: {len(all_records)} records")
else:
    print("\n❌ No records to save")