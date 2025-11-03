# Analyzer
## ir_analyzer.py
### mine_frequent_subgraphs()
Value for `min_appear` should change as data sets increase, it is a dynamic threshold for pattern indicator.

As for current, `min_appear` is 0.5, so out of 4 total files, this pattern must appear in at least 2 of them to be consider as frequent.

### find_isomorphic_groups()
```
extract hash from canonical form
c045439172215f49e0bef8c3d26c6b61|N5E8|D(1,2,3)
                           [0]   [1]   [2] 

parts[0]: WL (Weisfeiler-Lehman) hash of the graph structure, it is used as a key to group isomorphic files
parts[1]: Graph size info (nodes/edges like N5E8)
parts[2]: Degree sequence like D(1,2,3)
```