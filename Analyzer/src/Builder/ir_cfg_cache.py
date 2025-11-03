import networkx as nx
from typing import List
from ..BasicBlock.ir_block import *
from ..Builder.ir_cfg_builder import *

class CFGCache:    
    def __init__(self, max_size: int = 1000):
        self._cache = {}
        self._max_size = max_size
    
    def get_or_build(self, blocks: List[BasicBlock]) -> nx.DiGraph:
        cache_key = self._generate_cache_key(blocks)
        
        if cache_key not in self._cache:
            if len(self._cache) >= self._max_size:
                first_key = next(iter(self._cache))
                del self._cache[first_key]
            
            self._cache[cache_key] = CFGBuilder.build_cfg(blocks)
        
        return self._cache[cache_key]
    
    def _generate_cache_key(self, blocks: List[BasicBlock]):
        block_ids = tuple(sorted(b.block_id for b in blocks if b.block_id is not None))
        edges = tuple(sorted((b.block_id, out) for b in blocks if b.block_id is not None for out in b.outbounds))
        return (block_ids, edges)
    
    def clear(self):
        self._cache.clear()