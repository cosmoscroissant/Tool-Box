import re
from collections import defaultdict

with open("../Data/Sample/1_IOC/malware_ioc.txt", 'r') as f:
    content = f.read()

sep = "=" * 80
parts = content.split(sep + "\n\n" + sep)

records = []
for part in parts:
    hash_match = re.search(r'HASH: ([a-f0-9]{64})', part)
    ts_match = re.search(r'TIMESTAMP: ([^\n]+)', part)
    
    if hash_match and ts_match:
        records.append({
            'hash': hash_match.group(1),
            'timestamp': ts_match.group(1),
            'content': part
        })

print(f"Total records before: {len(records)}")

hash_groups = defaultdict(list)
for rec in records:
    hash_groups[rec['hash']].append(rec)

kept = []
for hash_val, group in hash_groups.items():
    newest = max(group, key=lambda x: x['timestamp'])
    kept.append(newest)

new_content = (sep + "\n\n" + sep).join(rec['content'] for rec in kept)
new_content = sep + "\n" + new_content + "\n" + sep

with open("../Data/Sample/1_IOC/malware_ioc.txt", 'w') as f:
    f.write(new_content)

print(f"Total records after: {len(kept)}")
print(f"Removed: {len(records) - len(kept)} duplicates")