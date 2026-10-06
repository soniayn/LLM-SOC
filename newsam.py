import csv
import os

BASE_DIR = "C:\\Users\\SYN\\Documents\\soc\\sample2\\"

FILES = [
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
]

print("=" * 70)
print(f"BASE_DIR: {BASE_DIR}")
print(f"Exists: {os.path.exists(BASE_DIR)}")
print("=" * 70)

for filename in FILES:
    path = os.path.join(BASE_DIR, filename)
    print(f"\n{'='*70}")
    print(f"FILE: {filename}")
    print(f"Exists: {os.path.exists(path)}")
    
    if not os.path.exists(path):
        continue
    
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        cols = reader.fieldnames
        print(f"Columns (first 3): {cols[:3] if cols else 'NONE'}")
        print(f"Columns (last 3): {cols[-3:] if cols else 'NONE'}")
        
        print("First 3 labels:")
        for i, row in enumerate(reader):
            if i >= 3:
                break
            label = ''
            for key in [' Label', 'Label', ' label', 'label']:
                if key in row:
                    label = row[key]
                    break
            print(f"  Row {i+1}: label='{label}'")

print("\n" + "=" * 70)
print("DONE")