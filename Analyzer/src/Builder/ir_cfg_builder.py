import networkx as nx
from typing import List
from ..BasicBlock.ir_block import BasicBlock

class CFGBuilder:
    @staticmethod
    def build_cfg(blocks: List[BasicBlock], include_size: bool = False) -> nx.DiGraph:
        G = nx.DiGraph()
        if not blocks:
            return G
            
        block_ids = {b.block_id for b in blocks if b.block_id is not None}
        
        for block in blocks:
            if block.block_id is None:
                continue
            
            if include_size:
                G.add_node(block.block_id, size=len(block.instructions)) # add instruction count as node attribute
            else:
                G.add_node(block.block_id)
                
            for outbound in block.outbounds:
                if outbound in block_ids and outbound is not None:
                    G.add_edge(block.block_id, outbound)
        
        return G