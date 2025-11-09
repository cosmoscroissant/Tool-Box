import re

from collections import Counter

import sys
sys.path.insert(0, '..')
from IOC.constants import *

with open(IOC.PATH, 'r') as f:
    content = f.read()

hashes = re.findall(r'HASH: ([a-f0-9]{64})', content)

print(f"Total Hashes Found: {len(hashes)}")

hash_counts = Counter(hashes)
duplicates = {h: count for h, count in hash_counts.items() if count > 1}

if duplicates:
    print(f"\nFound {len(duplicates)} Duplicate Hash(es):\n")
    for hash_val, count in sorted(duplicates.items(), key=lambda x: x[1], reverse=True):
        print(f"  {hash_val}: appears {count} times")
else:
    print("\nNo duplicates found! All hashes are unique.")