import re
import time
import hashlib
import warnings

import numpy as np
import networkx as nx

from itertools import combinations, islice
from itertools import combinations
from typing import List
from collections import Counter

from ..RegisterSet.ir_filter_register import *
from ..BasicBlock.ir_block import *
from ..Constant.ir_constants import *
from ..Parser.ir_parser import *
from ..Builder.ir_cfg_builder import *
from ..Builder.ir_cfg_cache import *
from ..Extractor.ir_extract_opcodes import *

class FeatureExtractor:
    def __init__(self, thorough_mode=False):
        self.thorough_mode = thorough_mode
        self._cfg_cache = CFGCache()
        self.feature_names = [
            'num_blocks',
            'num_edges',
            'avg_block_size',
            'max_block_size',
            'cyclomatic_complexity',
            'depth',
            'avg_branching_factor',
            'loop_count',
            'register_diversity',
            'call_diversity',
            'memory_ops_ratio',
            'arithmetic_ops_ratio',
            'control_ops_ratio',
            'floating_point_ops_ratio',
            'condition_ops_ratio',
            'stack_ops_ratio',
            'data_ops_ratio',
            'flag_ops_ratio',
            'special_ops_ratio',

            # average distance between register definition and use
            'def_use_chain_length',

            # how often registers are reused vs new ones allocated
            'register_reuse_ratio',

            # how deep memory access chains go
            'memory_dependency_depth',

            # how long variables stay "alive" in the code
            'live_range_average',

            # number of unique data paths through blocks
            'data_flow_complexity', 

            'abstract_alu_ratio',
            'abstract_mem_ratio',
            'abstract_ctrl_ratio'
        ]

        if len(self.feature_names) != EXPECTED_FEATURE_COUNT:
            raise ValueError(f"Feature count mismatch: {len(self.feature_names)} != {EXPECTED_FEATURE_COUNT}")

    def extract_subgraphs(self, cfg: nx.DiGraph, blocks: List[BasicBlock]) -> List[str]:
        subgraphs = []
        nodes = list(cfg.nodes())
        
        if len(nodes) < 2:
            return subgraphs
        
        block_map = {b.block_id: b for b in blocks if b.block_id is not None}
        
        if not self.thorough_mode:
            if len(nodes) > MAX_NODES_FAST:
                print(f"    WARNING: skipping subgraph extraction ({len(nodes)} nodes > {MAX_NODES_FAST} limit)")
                return subgraphs
        
        sizes = SUBGRAPH_SIZES_THOROUGH if self.thorough_mode else SUBGRAPH_SIZES_FAST
        
        for size_idx, size in enumerate(sizes, 1):
            if size > len(nodes):
                continue
            
            print(f"    processing size {size} ({size_idx}/{len(sizes)})")
            
            node_combinations = (
                combinations(nodes, size) if self.thorough_mode 
                else islice(combinations(nodes, size), MAX_COMBINATIONS_PER_SIZE)
            )
            
            processed_count = 0
            for node_subset in node_combinations:
                processed_count += 1
                
                # progress every 100k combinations
                if processed_count % 100000 == 0:
                    print(f"      processed {processed_count:,} combinations, found {len(subgraphs)} subgraphs so far")
                
                if not self.thorough_mode and len(subgraphs) >= MAX_SUBGRAPHS_FAST:
                    print(f"      reached subgraph limit ({MAX_SUBGRAPHS_FAST}), stopping")
                    break
                
                subgraph = cfg.subgraph(node_subset)
                if nx.is_weakly_connected(subgraph):
                    edges = tuple(sorted(subgraph.edges()))
                    
                    opcode_sig = []
                    for node_id in node_subset:
                        block = block_map.get(node_id)
                        if block and block.instructions:
                            parts = block.instructions[0].split()
                            first_op = parts[0].lower() if parts else 'N/O'
                            opcode_sig.append(first_op)
                    
                    pattern = f"E{edges}|O{tuple(sorted(opcode_sig))}"
                    subgraphs.append(pattern)
            
            if not self.thorough_mode and len(subgraphs) >= MAX_SUBGRAPHS_FAST:
                break
        
        print(f"      completed size {size}: processed {processed_count:,} combinations")

        return subgraphs

    def extract_semantic_signature(self, blocks: List[BasicBlock], cfg: nx.DiGraph = None) -> str:
        if not blocks:
            return ""
        
        # 1. opcode frequency vector
        opcodes = extract_opcodes(blocks)
        if opcodes:
            opcode_counts = Counter(opcodes)
            total = len(opcodes)
            sorted_opcodes = sorted(opcode_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            opcode_sig = ",".join([f"{op}:{cnt/total:.2f}" for op, cnt in sorted_opcodes])
        else:
            opcode_sig = "none"
        
        # 2. control flow record
        if cfg is None:
            cfg = self._get_or_build_cfg(blocks)

        loop_count = self.count_loops(cfg)
        conditional_branches = sum(1 for b in blocks if len(b.outbounds) > 1)
        unconditional_jumps = sum(1 for b in blocks if len(b.outbounds) == 1 and any('goto' in i.lower() for i in b.instructions))
        call_count = sum(len(b.function_calls) for b in blocks)
        switch_count = sum(1 for b in blocks if any('jtbl' in i.lower() for i in b.instructions))
        block_count = len(blocks)
        
        control_sig = f"L{loop_count}B{conditional_branches}C{call_count}U{unconditional_jumps}S{switch_count}K{block_count}"
        
        # 3. register diversity score
        all_regs = set().union(*(b.use_registers | b.def_registers for b in blocks))
        reg_diversity = len(all_regs) / block_count if block_count > 0 else 0
        register_sig = f"R{reg_diversity:.2f}"
        
        # 4. constant record
        constants = []
        for block in blocks:
            for instr in block.instructions:
                # extract hex constants like #0x40.8 or decimal like #7.8
                const_matches = re.findall(r'#(0x[0-9A-Fa-f]+|[0-9]+)', instr)
                for match in const_matches:
                    try:
                        val = int(match, 16) if match.startswith('0x') else int(match)
                        constants.append(val)
                    except ValueError:
                        pass
        
        tiny = sum(1 for c in constants if 0 <= c <= 10)
        small = sum(1 for c in constants if 11 <= c <= 255)
        medium = sum(1 for c in constants if 256 <= c <= 65535)
        large = sum(1 for c in constants if c > 65535)
        
        # common crypto constants
        crypto_constants = {
            0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, # MD5
            0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6, # SHA1
        }
        special = sum(1 for c in constants if c in crypto_constants)
        
        constant_sig = f"C_t{tiny}s{small}m{medium}l{large}x{special}"
        
        # 5. graph topology hash
        nodes = cfg.number_of_nodes()
        edges = cfg.number_of_edges()
        density = edges / (nodes * (nodes - 1)) if nodes > 1 else 0
        
        try:
            degrees = [cfg.in_degree(n) + cfg.out_degree(n) for n in cfg.nodes()]
            avg_degree = np.mean(degrees) if degrees else 0
        except (KeyError, nx.NetworkXError):
            avg_degree = 0
        
        graph_sig = f"G_n{nodes}e{edges}d{density:.2f}a{avg_degree:.1f}"
        
        # combine all components
        signature = f"{opcode_sig}|{control_sig}|{register_sig}|{constant_sig}|{graph_sig}"
        return signature

    def compute_semantic_hash(self, blocks: List[BasicBlock], cfg: nx.DiGraph = None) -> str:
        if not blocks:
            return "0" * 16
        
        # 1. count opcode frequency, sort alphabetically, select top 5 most common
        opcodes = extract_opcodes(blocks)
        top_opcodes = tuple(sorted([op for op, _ in Counter(opcodes).most_common(5)]))
        
        # 2. count loops in cfg, conditional branches (blocks with multiple outgoing edges), function calls
        if cfg is None:
            cfg = self._get_or_build_cfg(blocks)
        
        # L6B3C5, 6 loop 3 branches 5 calls
        loops = self.count_loops(cfg)
        branches = sum(1 for b in blocks if len(b.outbounds) > 1)
        calls = sum(len(b.function_calls) for b in blocks)
        
        # 3. sum all instructions and group into buckets of 10
        total_instrs = sum(len(b.instructions) for b in blocks)
        size_bucket = total_instrs // 10
        
        # 4. collect all unique registers used or defined, and count them
        all_regs = set().union(*(b.use_registers | b.def_registers for b in blocks))
        reg_count = len(all_regs)
        
        # 5. combine & hash into stable representation
        fingerprint = f"{top_opcodes}|L{loops}B{branches}C{calls}|S{size_bucket}R{reg_count}"
        
        # hash to fixed 16 char hex
        return hashlib.sha256(fingerprint.encode()).hexdigest()[:16]
    
    def compare_semantic_signatures(self, sig1: str, sig2: str) -> float:
        if not sig1 or not sig2:
            return 0.0
        
        parts1 = sig1.split('|')
        parts2 = sig2.split('|')
        
        if len(parts1) != 5 or len(parts2) != 5:
            return 0.0
        
        try:
            # 1. opcode similarity (40% weight)
            opcodes1 = {}
            for p in parts1[0].split(','):
                if ':' in p:
                    key, val = p.split(':', 1)  # split only on first colon
                    opcodes1[key] = val
            
            opcodes2 = {}
            for p in parts2[0].split(','):
                if ':' in p:
                    key, val = p.split(':', 1)
                    opcodes2[key] = val
            
            # calculate opcode vector similarity
            all_opcodes = set(opcodes1.keys()) | set(opcodes2.keys())
            if all_opcodes:
                vec1 = [float(opcodes1.get(op, 0)) for op in all_opcodes]
                vec2 = [float(opcodes2.get(op, 0)) for op in all_opcodes]
                norm1 = np.linalg.norm(vec1)
                norm2 = np.linalg.norm(vec2)
                norm_product = norm1 * norm2
                opcode_sim = np.dot(vec1, vec2) / norm_product if norm_product > 1e-10 else 0
            else:
                opcode_sim = 0
            
            # 2. control flow similarity (20% weight)
            ctrl1 = parts1[1]
            ctrl2 = parts2[1]
            control_sim = 1.0 if ctrl1 == ctrl2 else 0.5
            
            # 3. register diversity similarity (15% weight)
            try:
                r1 = float(parts1[2].replace('R', ''))
                r2 = float(parts2[2].replace('R', ''))
            except (ValueError, AttributeError):
                r1, r2 = 0.0, 0.0
            
            if r1 == 0 and r2 == 0:
                register_sim = 1.0  # both have no registers, perfect match
            else:
                max_r = max(r1, r2)
                register_sim = 1 - min(abs(r1 - r2) / max_r, 1.0)
            
            # 4. constant similarity (15% weight)
            const_sim = 1.0 if parts1[3] == parts2[3] else 0.5
            
            # 5. graph topology similarity (10% weight)
            graph_sim = 1.0 if parts1[4] == parts2[4] else 0.5
            
            # weighted average
            total_sim = (0.4 * opcode_sim + 0.2 * control_sim + 0.15 * register_sim + 0.15 * const_sim + 0.1 * graph_sim)
            
            return total_sim
        
        except (ValueError, IndexError, KeyError, AttributeError):
            return 0.0

    def canonicalize_cfg(self, cfg: nx.DiGraph, blocks: List[BasicBlock]) -> str:
        if cfg.number_of_nodes() == 0:
            return "empty"
        
        # Debug: Check if this is hanging
        num_blocks = len(blocks)
        
        for idx, block in enumerate(blocks):
            # Progress every 100 blocks
            if idx % 100 == 0:
                print(f"      canonicalizing block {idx}/{num_blocks}")

            if block.block_id not in cfg.nodes():
                continue
            
            if block.block_id in cfg.nodes():
                opcode_list = []
                for instr in block.instructions:
                    op = IRParser.get_mnemonic(instr, lowercase=True)
                    if op is not None:
                        opcode_list.append(op)
                opcodes = tuple(sorted(opcode_list))
                branch_type = len(block.outbounds)
                size_bucket = len(block.instructions) // 5
                label = f"{opcodes[:3]}_{branch_type}_{size_bucket}"
                cfg.nodes[block.block_id]['label'] = label

        try:
            print(f"      computing WL hash for {cfg.number_of_nodes()} nodes...")
            start_time = time.time()
            
            with warnings.catch_warnings():
                warnings.filterwarnings('ignore', message='.*hashes produced.*', category=UserWarning)
                wl_hash = nx.weisfeiler_lehman_graph_hash(cfg, node_attr='label')
            
            elapsed = time.time() - start_time
            print(f"      WL hash computed in {elapsed:.2f}s")
            
        except (nx.NetworkXError, ValueError, AttributeError) as e:
            print(f"WARNING: WL hash failed: {e}")
            wl_hash = "unknown"

        # add structural fingerprint
        n_nodes = cfg.number_of_nodes()
        n_edges = cfg.number_of_edges()

        # degree sequence
        if n_nodes > 0:
            degree_seq = tuple(sorted([cfg.in_degree(n) + cfg.out_degree(n) for n in cfg.nodes()]))
        else:
            degree_seq = (0,)

        canonical_form = f"{wl_hash}|N{n_nodes}E{n_edges}|D{degree_seq}"
        return canonical_form

    def _get_or_build_cfg(self, blocks: List[BasicBlock], cfg: nx.DiGraph = None) -> nx.DiGraph:
        if cfg is not None:
            return cfg
        return self._cfg_cache.get_or_build(blocks)
    
    def clear_cache(self):
        self._cfg_cache.clear()

    def extract_features(self, blocks: List[BasicBlock], cfg: nx.DiGraph = None):
            if not blocks:
                return np.zeros(len(self.feature_names))
            
            cfg = self._get_or_build_cfg(blocks, cfg)
            features = np.zeros(len(self.feature_names))
            block_sizes = [len(b.instructions) for b in blocks]

            features[NUM_BLOCKS] = len(blocks)
            features[NUM_EDGES] = cfg.number_of_edges()
            features[AVG_BLOCK_SIZE] = np.mean(block_sizes) if block_sizes else 0
            features[MAX_BLOCK_SIZE] = max(block_sizes) if block_sizes else 0

            num_edges = cfg.number_of_edges()
            num_nodes = cfg.number_of_nodes()
            features[CYCLOMATIC_COMPLEXITY] = max(1, num_edges - num_nodes + 2) if num_nodes > 0 else 0

            try:
                if cfg.number_of_nodes() > 0:
                    try:
                        if nx.is_directed_acyclic_graph(cfg):
                            features[DEPTH] = len(nx.dag_longest_path(cfg))
                        else:
                            features[DEPTH] = len(blocks)
                    except nx.NetworkXError as e:
                        features[DEPTH] = len(blocks)
                        if self.thorough_mode:
                            print(f"    DAG analysis failed, using block count: {e}")
                    
                    try:
                        out_degrees = [cfg.out_degree(n) for n in cfg.nodes()]
                        features[AVG_BRANCHING_FACTOR] = np.mean(out_degrees) if out_degrees else 0
                    except (KeyError, AttributeError) as e:
                        features[AVG_BRANCHING_FACTOR] = 0
                        if self.thorough_mode:
                            print(f"    degree calculation failed: {e}")
                else:
                    features[DEPTH] = 0
                    features[AVG_BRANCHING_FACTOR] = 0
            except (nx.NetworkXError, ValueError, KeyError, AttributeError) as e:
                raise RuntimeError(f"critical CFG analysis failure: {e}") from e

            features[LOOP_COUNT] = self.count_loops(cfg)
            
            all_regs = set().union(*(b.use_registers | b.def_registers for b in blocks))
            features[REGISTER_DIVERSITY] = len(all_regs)
            
            all_calls = [call for b in blocks for call in b.function_calls]
            if len(all_calls) > 0:
                features[CALL_DIVERSITY] = len(set(all_calls)) / len(all_calls)
            else:
                features[CALL_DIVERSITY] = 0
            
            opcode_list = extract_opcodes(blocks)
            if opcode_list:
                total = float(len(opcode_list))
                op_types = [
                    (MEMORY_OPS_RATIO, MEMORY_OPS),
                    (ARITHMETIC_OPS_RATIO, ARITHMETIC_OPS),
                    (CONTROL_OPS_RATIO, CTRL_OPS),
                    (FLOATING_POINT_OPS_RATIO, FP_OPS),
                    (CONDITION_OPS_RATIO, CONDITION_OPS),
                    (STACK_OPS_RATIO, STACK_OPS),
                    (DATA_OPS_RATIO, DATA_OPS),
                    (FLAG_OPS_RATIO, FLAG_OPS),
                    (SPECIAL_OPS_RATIO, SPECIAL_OPS)
                ]

                for idx, ops in op_types:
                    count = sum(1 for op in opcode_list if op in ops)
                    features[idx] = count / total if total > 0 else 0.0
            
            all_distances = [dist for b in blocks for dists in b.def_use_distances.values() for _, dist in dists]
            features[DEF_USE_CHAIN_LENGTH] = np.mean(all_distances) if all_distances else 0

            all_defs = [reg for b in blocks for reg in b.def_registers]
            reused_count = sum(1 for reg, count in Counter(all_defs).items() if count > 1)
            unique_defs = set(all_defs)
            features[REGISTER_REUSE_RATIO] = reused_count / len(unique_defs) if unique_defs else 0

            if self.thorough_mode:
                features[MEMORY_DEPENDENCY_DEPTH] = self.compute_memory_dependency_depth(blocks, cfg)
            else:
                features[MEMORY_DEPENDENCY_DEPTH] = 0

            all_ranges = [lr for b in blocks for lr in b.live_ranges.values()]
            features[LIVE_RANGE_AVERAGE] = np.mean(all_ranges) if all_ranges else 0

            unique_paths = set()
            for b in blocks:
                for reg, distances in b.def_use_distances.items():
                    for target_id, dist in distances:
                        unique_paths.add((b.block_id, reg, target_id, dist))
            features[DATA_FLOW_COMPLEXITY] = len(unique_paths)

            abstract_opcodes = extract_opcodes(blocks, abstract=True)
            if abstract_opcodes:
                abstract_counts = Counter(abstract_opcodes)
                total_abstract = len(abstract_opcodes)

                features[ABSTRACT_ALU_RATIO] = abstract_counts.get('ALU_OP', 0) / total_abstract
                features[ABSTRACT_MEM_RATIO] = abstract_counts.get('MEM_OP', 0) / total_abstract
                features[ABSTRACT_CTRL_RATIO] = abstract_counts.get('CTRL_OP', 0) / total_abstract
            else:
                features[ABSTRACT_ALU_RATIO] = 0.0
                features[ABSTRACT_MEM_RATIO] = 0.0
                features[ABSTRACT_CTRL_RATIO] = 0.0
            
            return features
    
    def count_loops(self, cfg: nx.DiGraph) -> int:
        if cfg.number_of_nodes() <= 1:
            return 0
        
        try:
            if cfg.number_of_nodes() > 100 and not self.thorough_mode:
                sccs = list(nx.strongly_connected_components(cfg))
                return sum(1 for scc in sccs if len(scc) > 1)
            else:
                cycles = list(nx.simple_cycles(cfg))
                return len(cycles)
        except nx.NetworkXError:
            return 0
    
    def is_memory_op(self, instruction: str) -> bool:
        opcode = IRParser.get_mnemonic(instruction, lowercase=True)
        return opcode in MEMORY_OPS if opcode else False
    
    def compute_memory_dependency_depth(self, blocks: List[BasicBlock], cfg: nx.DiGraph) -> int:
        print(f"[THOROUGH] computing memory dependency depth")
        mem_blocks = [b for b in blocks if any(self.is_memory_op(i) for i in b.instructions)]
        
        if not mem_blocks or cfg.number_of_nodes() == 0:
            return 0
        
        block_map = {b.block_id: b for b in blocks} # pre-build block map for O(1) lookup
        
        max_chain = 0
        for idx, mb in enumerate(mem_blocks):
            if idx % PROGRESS_LOG_INTERVAL == 0:
                print(f"      processing memory block {idx}/{len(mem_blocks)}")
            try:
                paths = nx.single_source_shortest_path_length(cfg, mb.block_id)
                chain_len = max(
                    (length for target, length in paths.items() 
                    if target in block_map and 
                    any(self.is_memory_op(i) for i in block_map[target].instructions)),
                    default=0
                )
                max_chain = max(max_chain, chain_len)
            except (nx.NetworkXError, ValueError, KeyError):
                pass

        return max_chain
