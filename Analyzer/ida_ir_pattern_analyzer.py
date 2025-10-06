from datetime import datetime
import time
import sys
import shutil
import json
import re
import threading
import webbrowser
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Tuple
import http.server
from collections import deque
import socketserver
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import networkx as nx
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import StandardScaler
from tqdm import tqdm
import argparse

MAX_BLOCKS_FULL_ANALYSIS = 2000
SAMPLE_RATIO = 3
THOROUGH_MAX_DEPTH = float('inf')
THOROUGH_MAX_USES = float('inf')
THOROUGH_MAX_ITERATIONS = 100000
FAST_MAX_DEPTH_FULL = 200
FAST_MAX_USES_FULL = 50
FAST_MAX_DEPTH_SAMPLE = 150
FAST_MAX_USES_SAMPLE = 30
FAST_MAX_REGS = 50
FAST_MAX_ITERATIONS = 10000
PROGRESS_LOG_INTERVAL = 100
DBSCAN_EPS_VALUES = [0.3, 0.5, 0.7, 1.0, 1.5]
SIMILARITY_THRESHOLD = 0.7
MAX_NAME_LENGTH = 30
PORT = 8080
BOUNDS_EXTRACT_LENGTH = 50
MAX_INSTRUCTIONS_PREVIEW = 10
MAX_FILES_PREVIEW = 5
DBSCAN_MIN_SAMPLES_DIVISOR = 5

@dataclass
class BasicBlock:
    block_id: int
    start_address: int
    end_address: int
    instructions: List[str] = field(default_factory=list)
    inbounds: List[int] = field(default_factory=list)
    outbounds: List[int] = field(default_factory=list)
    use_registers: Set[str] = field(default_factory=set)
    def_registers: Set[str] = field(default_factory=set)
    function_calls: List[str] = field(default_factory=list)
    function_name: str = ""
    def_use_distances: Dict[str, List[int]] = field(default_factory=dict)
    live_ranges: Dict[str, int] = field(default_factory=dict)

class IRParser:
    SKIP_REGISTERS = frozenset([
        # CPU flags
        'cf',     # carry flag
        'zf',     # zero flag
        'sf',     # sign flag
        'of',     # overflow flag
        'pf',     # parity flag
        'af',     # auxiliary flag
        'tf',     # trap flag
        'if',     # interrupt flag  
        'df',     # direction flag
        'fl',     # flags register (generic)
        
        # segment registers
        'cs',     # code segment
        'ds',     # data segment
        'es',     # extra segment
        'ss',     # stack segment
        
        # SSE/FPU control
        'mxcsr',  # SSE control/status register
        
        # FPU condition codes (IDA-generated)
        'c0',     # FPU condition code 0
        'c1',     # FPU condition code 1 (not seen but should be included)
        'c2',     # FPU condition code 2
        'c3',     # FPU condition code 3
        
        # synthetic registers (IDA-generated)
        'fps',    # FPU status
        'cc',     # condition code
        
        # memory tracking constructs (IDA synthetic, not registers but worth filtering)
        'GLBLOW',   # global memory low bound tracking
        'GLBHIGH',  # global memory high bound tracking
        'ARGS',     # argument memory region tracking
    ])
    
    def __init__(self, thorough_mode=False):
        self.thorough_mode = thorough_mode
        self.block_pattern = re.compile(
            r'(\d+)\.\s*\d+\s*;\s*.*?-BLOCK\s+(\d+).*?'
            r'OUTBOUNDS:\s*([0-9,\s]+).*?\[START=([0-9A-Fa-f]+)\s+END=([0-9A-Fa-f]+)\]'
        )
        self.simple_block_pattern = re.compile(
            r'(\d+)\.\s*\d+\s*;\s*.*?-BLOCK\s+(\d+).*?\[START=([0-9A-Fa-f]+)\s+END=([0-9A-Fa-f]+)\]'
        )
        self.use_pattern = re.compile(r'USE:\s*([^;]+)')
        self.def_pattern = re.compile(r'DEF:\s*([^;]+)')
        self.call_pattern = re.compile(r'call\s+\$"([^"]+)"')
        self.instruction_pattern = re.compile(r'(\d+)\.\s*(\d+)\s+(.*?)\s*;\s*([0-9A-Fa-f]+)')
        self.function_header_pattern = re.compile(r'---\s*IR\s+FOR\s+(.+?)\s+\(0x[0-9A-Fa-f]+\)\s*---')
        self.bounds_pattern = re.compile(r'(\d+)')
        self.reg_pattern = re.compile(r'([a-z]+\d*)\.')
    
    def parse_microcode(self, ir_text: str) -> List[BasicBlock]:
        if not ir_text or not ir_text.strip():
            return []
         
        blocks = []
        current_block = None
        current_function = "unknown_function"
        
        for line in ir_text.split('\n'):
            func_header_match = self.function_header_pattern.search(line)
            if func_header_match:
                current_function = func_header_match.group(1).strip()
            
            block_match = self.block_pattern.search(line) or self.simple_block_pattern.search(line)
            if block_match:
                if current_block:
                    blocks.append(current_block)
                
                groups = block_match.groups()
                block_id = int(groups[1])
                start_addr = int(groups[3 if len(groups) >= 5 else 2], 16)
                end_addr = int(groups[4 if len(groups) >= 5 else 3], 16)
                
                current_block = BasicBlock(
                    block_id=block_id,
                    start_address=start_addr,
                    end_address=end_addr,
                    inbounds=self.extract_bounds(line, 'INBOUNDS:'),
                    outbounds=self.extract_bounds(line, 'OUTBOUNDS:'),
                    function_name=current_function
                )
                continue
            
            if current_block is None:
                continue
            
            if 'USE:' in line:
                use_match = self.use_pattern.search(line)
                if use_match:
                    current_block.use_registers.update(self.parse_registers(use_match.group(1)))
            
            if 'DEF:' in line:
                def_match = self.def_pattern.search(line)
                if def_match:
                    current_block.def_registers.update(self.parse_registers(def_match.group(1)))
            
            if 'call' in line:
                call_match = self.call_pattern.search(line)
                if call_match:
                    current_block.function_calls.append(call_match.group(1))
            
            instruction_match = self.instruction_pattern.search(line)
            if instruction_match:
                current_block.instructions.append(instruction_match.group(3))
        
        if current_block:
            blocks.append(current_block)
        
        self.analyze_dataflow(blocks)
        
        return blocks
    
    def extract_bounds(self, line: str, bound_type: str) -> List[int]:
        if bound_type not in line:
            return []
        idx = line.find(bound_type)
        segment = line[idx + len(bound_type):idx + len(bound_type) + BOUNDS_EXTRACT_LENGTH]
        return [int(m.group(1)) for m in self.bounds_pattern.finditer(segment)]
    
    def parse_registers(self, reg_string: str) -> Set[str]:
        return {
            m.group(1) for m in self.reg_pattern.finditer(reg_string)
            if m.group(1) not in self.SKIP_REGISTERS
        }
    
    def analyze_dataflow(self, blocks: List[BasicBlock]) -> None:
        block_map = {b.block_id: b for b in blocks}
        total_blocks = len(blocks)
        
        if total_blocks <= MAX_BLOCKS_FULL_ANALYSIS:
            sampled_blocks = blocks
            if self.thorough_mode:
                max_depth = THOROUGH_MAX_DEPTH
                max_uses = THOROUGH_MAX_USES
                max_regs = float('inf')
                max_iterations = THOROUGH_MAX_ITERATIONS
                print(f"[THOROUGH] full exhaustive dataflow analysis on {total_blocks} blocks")
            else:
                max_depth = FAST_MAX_DEPTH_FULL
                max_uses = FAST_MAX_USES_FULL
                max_regs = FAST_MAX_REGS
                max_iterations = FAST_MAX_ITERATIONS
                print(f"full dataflow analysis on {total_blocks} blocks")
        else:
            sample_size = min(MAX_BLOCKS_FULL_ANALYSIS, total_blocks // SAMPLE_RATIO)
            indices = self.representative_sample(total_blocks, sample_size)
            sampled_blocks = [blocks[i] for i in indices if i < total_blocks]
            
            if self.thorough_mode:
                max_depth = THOROUGH_MAX_DEPTH
                max_uses = THOROUGH_MAX_USES
                max_regs = float('inf')
                max_iterations = THOROUGH_MAX_ITERATIONS
                print(f"[THOROUGH] Stratified Sampling: {len(sampled_blocks)}/{total_blocks} blocks")
            else:
                max_depth = FAST_MAX_DEPTH_SAMPLE
                max_uses = FAST_MAX_USES_SAMPLE
                max_regs = FAST_MAX_REGS
                max_iterations = FAST_MAX_ITERATIONS
                print(f"Stratified Sampling: {len(sampled_blocks)}/{total_blocks} blocks")
        
        for block_idx, block in enumerate(sampled_blocks):
            if block_idx % PROGRESS_LOG_INTERVAL == 0:
                print(f"  processing block {block_idx}/{len(sampled_blocks)} (block_id={block.block_id})")
            
            regs_to_analyze = list(block.def_registers)[:int(max_regs) if max_regs != float('inf') else None]
            
            if block_idx % PROGRESS_LOG_INTERVAL == 0 and len(regs_to_analyze) > 0:
                print(f"    analyzing {len(regs_to_analyze)} registers in this block")
            
            for reg in regs_to_analyze:
                distances = self.bfs_def_use_search(
                    block.block_id, reg, block_map, max_depth, max_uses, max_iterations
                )
                if distances:
                    block.def_use_distances[reg] = distances

        for block in sampled_blocks:
            for reg in block.def_registers:
                max_dist = 0
                if reg in block.def_use_distances:
                    max_dist = max(dist for _, dist in block.def_use_distances[reg])
                block.live_ranges[reg] = max_dist
        
        print("Dataflow Analysis Complete")
    
    def bfs_def_use_search(self, start_block_id: int, reg: str, block_map: Dict[int, BasicBlock], max_depth: float, max_uses: float, max_iterations: float) -> List[Tuple[int, int]]:
        distances = []
        visited = set()
        queue = deque([(start_block_id, 0)]) 
        iterations = 0
        
        while queue and len(distances) < max_uses:
            iterations += 1
            if iterations > max_iterations:
                print(f"    Warning: Block {start_block_id}, reg {reg} - BFS exceeded {int(max_iterations)} iterations")
                break
            
            curr_id, dist = queue.popleft()
            if dist > max_depth or curr_id in visited:
                continue
            visited.add(curr_id)
            
            curr_block = block_map.get(curr_id)
            if not curr_block:
                continue
            
            if curr_id != start_block_id and reg in curr_block.use_registers:
                distances.append((curr_id, dist))
                if len(distances) >= max_uses:
                    break
            
            for next_id in curr_block.outbounds:
                if next_id not in visited:
                    queue.append((next_id, dist + 1))
        
        return distances
    
    def representative_sample(self, total: int, sample_size: int) -> List[int]:
        if sample_size >= total:
            return list(range(total))
        
        indices = set()
        samples_per_section = max(1, sample_size // SAMPLE_RATIO)
        section_size = max(1, total // SAMPLE_RATIO)
        
        sections = [
            (0, min(section_size, total)),
            (section_size, min(2 * section_size, total)),
            (2 * section_size, total)
        ]
        
        for start, end in sections:
            if end <= start:
                continue
            count = min(samples_per_section, end - start)
            indices.update(range(start, start + count))
        
        result = sorted(list(indices))[:sample_size]
        if len(result) == 0:
            return [0]
        return result

class FunctionFilter:    
    @staticmethod
    def is_complex(blocks: List[BasicBlock], min_complexity: int = 2) -> bool:
        if not blocks:
            return False
            
        has_multiple_blocks = len(blocks) >= 2
        has_sufficient_instructions = sum(len(b.instructions) for b in blocks) >= 5
        has_control_flow = sum(len(b.outbounds) for b in blocks) >= 1
        is_single_function = len(set(b.function_name for b in blocks)) == 1
        is_not_import_stub = not any('imp_' in b.function_name.lower() for b in blocks)

        criteria_met = sum([
            has_multiple_blocks,
            has_sufficient_instructions,
            has_control_flow,
            is_single_function,
            is_not_import_stub
        ])

        return criteria_met >= min_complexity
    
    @staticmethod
    def categorize_function(blocks: List[BasicBlock]) -> str:
        if not blocks:
            return "empty"
        
        total_instructions = sum(len(b.instructions) for b in blocks)
        has_loops = any(out in b.inbounds for b in blocks for out in b.outbounds)
        has_calls = any(b.function_calls for b in blocks)
        branching = sum(len(b.outbounds) > 1 for b in blocks)
        
        if total_instructions <= 3 and len(blocks) <= 2:
            return "small_functions"
        elif has_loops and branching > 3:
            return "complex_algorithm"
        elif has_calls and not has_loops:
            return "calls_function"
        elif branching > 5:
            return "many_branches"
        elif has_loops:
            return "iterative_logic"
        else:
            return "sequential_code"

class FeatureExtractor:
    MEMORY_OPS = frozenset([
        'nop',      # m_nop (0x00) - no operation
        'stx',      # m_stx (0x01) - store to memory
        'ldx',      # m_ldx (0x02) - load from memory
        'ldc',      # m_ldc (0x03) - load constant
        'mov',      # m_mov (0x04) - move
    ])

    STACK_OPS = frozenset([
        'push',     # m_push (0x3B) - push
        'pop',      # m_pop (0x3C) - pop
    ])

    DATA_OPS = frozenset([
        'xds',      # m_xds (0x08) - extend signed
        'xdu',      # m_xdu (0x09) - extend unsigned
        'low',      # m_low (0x0A) - take low part
        'high',     # m_high (0x0B) - take high part
        'f2i',      # m_f2i (0x3F) - float to int
        'f2u',      # m_f2u (0x40) - float to uint
        'i2f',      # m_i2f (0x41) - int to float
        'u2f',      # m_u2f (0x42) - uint to float
        'f2f',      # m_f2f (0x43) - change float precision
    ])

    ARITHMETIC_OPS = frozenset([
        'neg',      # m_neg (0x05) - negate
        'lnot',     # m_lnot (0x06) - logical not
        'bnot',     # m_bnot (0x07) - bitwise not
        'add',      # m_add (0x0C) - addition
        'sub',      # m_sub (0x0D) - subtraction
        'mul',      # m_mul (0x0E) - multiplication
        'udiv',     # m_udiv (0x0F) - unsigned division
        'sdiv',     # m_sdiv (0x10) - signed division
        'umod',     # m_umod (0x11) - unsigned modulo
        'smod',     # m_smod (0x12) - signed modulo
        'or',       # m_or (0x13) - bitwise or
        'and',      # m_and (0x14) - bitwise and
        'xor',      # m_xor (0x15) - bitwise xor
        'shl',      # m_shl (0x16) - shift logical left
        'shr',      # m_shr (0x17) - shift logical right
        'sar',      # m_sar (0x18) - shift arithmetic right
    ])

    FLAG_OPS = frozenset([
        'cfadd',    # m_cfadd (0x19) - calculate carry of add
        'ofadd',    # m_ofadd (0x1A) - calculate overflow of add
        'cfshl',    # m_cfshl (0x1B) - calculate carry of shl
        'cfshr',    # m_cfshr (0x1C) - calculate carry of shr
    ])

    CONDITION_OPS = frozenset([
        'sets',     # m_sets (0x1D) - set if sign (SF=1)
        'seto',     # m_seto (0x1E) - set if overflow
        'setp',     # m_setp (0x1F) - set if parity/unordered
        'setnz',    # m_setnz (0x20) - set if not zero (ZF=0)
        'setz',     # m_setz (0x21) - set if zero (ZF=1)
        'setae',    # m_setae (0x22) - set if above or equal (CF=0)
        'setb',     # m_setb (0x23) - set if below (CF=1)
        'seta',     # m_seta (0x24) - set if above (CF=0 & ZF=0)
        'setbe',    # m_setbe (0x25) - set if below or equal (CF=1 | ZF=1)
        'setg',     # m_setg (0x26) - set if greater (SF=OF & ZF=0)
        'setge',    # m_setge (0x27) - set if greater or equal (SF=OF)
        'setl',     # m_setl (0x28) - set if less (SF!=OF)
        'setle',    # m_setle (0x29) - set if less or equal (SF!=OF | ZF=1)
    ])

    CTRL_OPS = frozenset([
        'jcnd',     # m_jcnd (0x2A) - conditional jump
        'jnz',      # m_jnz (0x2B) - jump if not zero (ZF=0)
        'jz',       # m_jz (0x2C) - jump if zero (ZF=1)
        'jae',      # m_jae (0x2D) - jump if above or equal (CF=0)
        'jb',       # m_jb (0x2E) - jump if below (CF=1)
        'ja',       # m_ja (0x2F) - jump if above (CF=0 & ZF=0)
        'jbe',      # m_jbe (0x30) - jump if below or equal (CF=1 | ZF=1)
        'jg',       # m_jg (0x31) - jump if greater (SF=OF & ZF=0)
        'jge',      # m_jge (0x32) - jump if greater or equal (SF=OF)
        'jl',       # m_jl (0x33) - jump if less (SF!=OF)
        'jle',      # m_jle (0x34) - jump if less or equal (SF!=OF | ZF=1)
        'jtbl',     # m_jtbl (0x35) - table jump (switch)
        'ijmp',     # m_ijmp (0x36) - indirect unconditional jump
        'goto',     # m_goto (0x37) - unconditional jump
        'call',     # m_call (0x38) - call function
        'icall',    # m_icall (0x39) - indirect call
        'ret',      # m_ret (0x3A) - return
    ])

    # floating point
    FP_OPS = frozenset([
        'fneg',     # m_fneg (0x44) - floating negate
        'fadd',     # m_fadd (0x45) - floating add
        'fsub',     # m_fsub (0x46) - floating subtract
        'fmul',     # m_fmul (0x47) - floating multiply
        'fdiv',     # m_fdiv (0x48) - floating divide
    ])

    SPECIAL_OPS = frozenset([
        'und',      # m_und (0x3D) - undefined
        'ext',      # m_ext (0x3E) - external insn (not microcode)
    ])

    SKIP_REGISTERS = IRParser.SKIP_REGISTERS

    def __init__(self, thorough_mode=False):
        self.thorough_mode = thorough_mode
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
            'indirect_control_flow_ratio',

            # average distance between register definition and use
            'def_use_chain_length',

            # how often registers are reused vs new ones allocated
            'register_reuse_ratio',

            # how deep memory access chains go
            'memory_dependency_depth',

            # how long variables stay "alive" in the code
            'live_range_average',

            # number of unique data paths through blocks
            'data_flow_complexity'
        ]

    def extract_opcodes(self, blocks: List[BasicBlock]) -> List[str]:
        opcodes = []
        for block in blocks:
            for instr in block.instructions:
                if instr and instr.strip():
                    parts = instr.lower().split()
                    if parts:
                        opcodes.append(parts[0])
        return opcodes

    def extract_features(self, blocks: List[BasicBlock]) -> np.ndarray:
        if not blocks:
            return np.zeros(len(self.feature_names))
        
        cfg = self.build_cfg(blocks)
        features = np.zeros(len(self.feature_names))
        block_sizes = [len(b.instructions) for b in blocks]

        features[0] = len(blocks)
        features[1] = cfg.number_of_edges()
        features[2] = np.mean(block_sizes) if block_sizes else 0
        features[3] = float(max(block_sizes)) if block_sizes else 0

        num_edges = cfg.number_of_edges()
        num_nodes = cfg.number_of_nodes()
        features[4] = max(1, num_edges - num_nodes + 2) if num_nodes > 0 else 0

        try:
            if cfg.number_of_nodes() > 0:
                if nx.is_directed_acyclic_graph(cfg):
                    features[5] = len(nx.dag_longest_path(cfg))
                else:
                    features[5] = len(blocks)
                
                out_degrees = [cfg.out_degree(n) for n in cfg.nodes()]
                features[6] = np.mean(out_degrees) if out_degrees else 0
            else:
                features[5] = 0
                features[6] = 0
        except (nx.NetworkXError, ValueError, KeyError, AttributeError) as e:
            print(f"Warning: CFG analysis failed {e}")
            features[5] = 1
            features[6] = 0
        
        features[7] = self.count_loops(cfg)
        
        all_regs = set().union(*(b.use_registers | b.def_registers for b in blocks))
        features[8] = len(all_regs)
        
        all_calls = [call for b in blocks for call in b.function_calls]
        if all_calls:
            features[9] = len(set(all_calls)) / len(all_calls)
        else:
            features[9] = 0
        
        opcode_list = self.extract_opcodes(blocks)
        if opcode_list:
            total = float(len(opcode_list))
            if total == 0:
                total = 1.0
            op_types = [
                (10, self.MEMORY_OPS),
                (11, self.ARITHMETIC_OPS),
                (12, self.CTRL_OPS),
                (13, self.FP_OPS),
                (14, self.CONDITION_OPS),
                (15, self.STACK_OPS),
                (16, {'ijmp', 'icall', 'jtbl'})
            ]

            for idx, ops in op_types:
                count = sum(1 for op in opcode_list if op in ops)
                features[idx] = count / total if total > 0 else 0.0
        
        all_distances = [dist for b in blocks for dists in b.def_use_distances.values() for _, dist in dists]
        features[17] = np.mean(all_distances) if all_distances else 0

        all_defs = [reg for b in blocks for reg in b.def_registers]
        reused_count = sum(1 for reg, count in Counter(all_defs).items() if count > 1)
        features[18] = reused_count / len(set(all_defs)) if all_defs else 0

        features[19] = self.compute_memory_dependency_depth(blocks, cfg) if self.thorough_mode else 0

        all_ranges = [lr for b in blocks for lr in b.live_ranges.values()]
        features[20] = np.mean(all_ranges) if all_ranges else 0

        unique_paths = set()
        for b in blocks:
            for reg, distances in b.def_use_distances.items():
                for target_id, dist in distances:
                    unique_paths.add((b.block_id, reg, target_id, dist))
        features[21] = len(unique_paths)
        
        return features

    def build_cfg(self, blocks: List[BasicBlock]) -> nx.DiGraph:
        G = nx.DiGraph()
        if not blocks:
            return G
            
        block_ids = {b.block_id for b in blocks}
        
        for block in blocks:
            if block.block_id is None:
                continue
            G.add_node(block.block_id, size=len(block.instructions))
            for outbound in block.outbounds:
                if outbound in block_ids and outbound is not None:
                    G.add_edge(block.block_id, outbound)
        return G
    
    def count_loops(self, cfg: nx.DiGraph) -> int:
        if cfg.number_of_nodes() <= 1:
            return 0
        if self.thorough_mode:
            print(f"    [THOROUGH] checking {cfg.number_of_edges()} edges")
            loop_count = 0
            for edge_count, (u, v) in enumerate(cfg.edges(), 1):
                if edge_count % 1000 == 0:
                    print(f"      checked {edge_count}/{cfg.number_of_edges()} edges, found {loop_count} loops")
                if nx.has_path(cfg, v, u):
                    loop_count += 1
            return loop_count
        else:
            return sum(1 for u, v in cfg.edges() if v < u)
    
    def is_memory_op(self, instruction: str) -> bool:
        opcode = instruction.split()[0].lower() if instruction else ""
        return opcode in self.MEMORY_OPS
    
    def compute_memory_dependency_depth(self, blocks: List[BasicBlock], cfg: nx.DiGraph) -> int:
        print(f"    [THOROUGH] computing memory dependency depth")
        mem_blocks = [b for b in blocks if any(self.is_memory_op(i) for i in b.instructions)]
        
        if not mem_blocks or cfg.number_of_nodes() == 0:
            return 0
        
        max_chain = 0
        for idx, mb in enumerate(mem_blocks):
            if idx % PROGRESS_LOG_INTERVAL == 0:
                print(f"      processing memory block {idx}/{len(mem_blocks)}")
            try:
                paths = nx.single_source_shortest_path_length(cfg, mb.block_id)
                chain_len = max(
                    (length for target, length in paths.items() 
                    if any(self.is_memory_op(i) for b in blocks 
                            if b.block_id == target for i in b.instructions)),
                    default=0
                )
                max_chain = max(max_chain, chain_len)
            except (nx.NetworkXError, ValueError, KeyError):
                pass

        return max_chain

class IRStructuralAnalyzer:  
    def __init__(self, output_dir='./ir_analysis_output', thorough_mode=False):
        self.parser = IRParser(thorough_mode=thorough_mode)
        self.extractor = FeatureExtractor(thorough_mode=thorough_mode)
        self.scaler = StandardScaler()
        self.thorough_mode = thorough_mode
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        self.run_dir = self.output_dir / self.timestamp
        self.run_dir.mkdir(exist_ok=True)

        self.images_dir = self.run_dir / 'images'
        self.images_dir.mkdir(exist_ok=True)
        
        print(f"Analysis Run ID: {self.timestamp}")
        print(f"Output Directory: {self.run_dir}")
    
    def analyze(self, path: str) -> None:
        if not path or not path.strip():
            print("Error: path cannot be empty")
            return
        
        path_obj = Path(path)
        if not path_obj.exists():
            print(f"Error: {path} does not exist")
            return
        
        print(f"Scanning Files From: {path}")
        file_data = self.scan_files(path)
        print(f"found {len(file_data)} files\n")
        
        if not file_data:
            print("No files found!")
            return
        
        print("Extracting Features")
        feature_matrix, valid_files, all_blocks, function_categories = self.extract_all_features(file_data)
        
        if len(feature_matrix) == 0:
            print("\nNo valid features extracted!")
            return
        
        print(f"\nNormalizing {len(valid_files)} Feature Vectors")
        normalized_features = self.scaler.fit_transform(feature_matrix)
        
        print("\nClustering Similar Structures")
        labels = self.cluster_files(normalized_features, len(valid_files))
        
        clusters, noise = self.build_clusters(labels, valid_files)
        similarity_matrix = cosine_similarity(normalized_features)
        results = self.create_results(
            file_data, valid_files, clusters, noise,
            similarity_matrix, feature_matrix, function_categories
        )
        
        print("\nGenerating Vsualizations")
        self.save_results(results)
        self.generate_graph_data(all_blocks)
        self.generate_summary_images(results, feature_matrix, valid_files)
        self.copy_html_template()
        self.print_summary(results)
        self.start_server()
    
    def scan_files(self, path: str) -> Dict[str, str]:
        files = {}
        try:
            path_obj = Path(path).resolve()
        except (OSError, RuntimeError) as e:
            print(f"Error Resolving: {e}")
            return files
        
        if path_obj.is_file():
            if path_obj.suffix.lower() in {'.txt', ''} and path_obj.stat().st_size > 0:
                try:
                    try:
                        content = path_obj.read_text(encoding='utf-8')
                    except UnicodeDecodeError:
                        content = path_obj.read_text(encoding='latin-1', errors='replace')
                    files[path_obj.name] = content
                except (OSError, PermissionError) as e:
                    print(f"Error Reading {path_obj}: {e}")
        elif path_obj.is_dir():
            for file_path in path_obj.rglob('*.txt'):
                try:
                    if file_path.stat().st_size > 0:
                        files[file_path.name] = file_path.read_text(encoding='utf-8', errors='ignore')
                except (OSError, UnicodeDecodeError) as e:
                    print(f"Error Scanning {file_path}: {e}")
        
        return files

    def extract_all_features(self, file_data: Dict[str, str]) -> Tuple[np.ndarray, List[str], Dict[str, List[BasicBlock]], Dict[str, str]]:
        feature_matrix = []
        valid_files = []
        all_blocks = {}
        function_categories = {}
        
        func_filter = FunctionFilter()
        
        for filename, content in file_data.items():
            try:
                blocks = self.parser.parse_microcode(content)
                
                if blocks and func_filter.is_complex(blocks):
                    features = self.extractor.extract_features(blocks)
                    
                    if np.any(features):
                        feature_matrix.append(features)
                        valid_files.append(filename)
                        all_blocks[filename] = blocks
                        function_categories[filename] = func_filter.categorize_function(blocks)
                        print(f"{filename}: {len(blocks)} blocks ({function_categories[filename]})")
                    else:
                        print(f"{filename}: skipped (zero features)")
                else:
                    print(f"{filename}: skipped (trivial)")
                    
            except KeyboardInterrupt:
                raise
            except (ValueError, AttributeError, KeyError, IndexError, TypeError) as e:
                print(f"{filename} Error: {type(e).__name__}: {e}")
        
        return (
            np.array(feature_matrix) if feature_matrix else np.array([]),
            valid_files,
            all_blocks,
            function_categories
        )    

    def cluster_files(self, normalized_features: np.ndarray, n_files: int) -> np.ndarray:
        if len(normalized_features) == 0 or n_files == 0:
            return np.array([])
        if np.any(np.isnan(normalized_features)) or np.any(np.isinf(normalized_features)):
            print("Warning: invalid values in features, using fallback clustering")
            return np.array([-1] * n_files)
        
        best_clustering = self.dbscan_cluster(normalized_features, n_files)
        if best_clustering is None:
            best_clustering = self.fallback_similarity_cluster(normalized_features)
        
        return best_clustering
    
    def dbscan_cluster(self, normalized_features: np.ndarray, n_files: int) -> np.ndarray | None:
        best_clustering = None
        best_n_clusters = 0
        
        for eps in DBSCAN_EPS_VALUES:
            clusterer = DBSCAN(eps=eps, min_samples=max(1, n_files // DBSCAN_MIN_SAMPLES_DIVISOR), metric='cosine')
            labels = clusterer.fit_predict(normalized_features)
            n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
            
            if n_clusters > best_n_clusters and n_clusters < n_files:
                best_clustering = labels
                best_n_clusters = n_clusters
        
        return best_clustering if best_n_clusters > 0 else None
    
    def fallback_similarity_cluster(self, normalized_features: np.ndarray) -> np.ndarray:
        similarity_matrix = cosine_similarity(normalized_features)
        n_samples = len(normalized_features)
        labels = [-1] * n_samples
        assigned = set()
        current_label = 0
        
        for i in range(n_samples):
            if i in assigned:
                continue
            
            cluster_members = [
                j for j in range(i+1, n_samples)
                if j not in assigned and similarity_matrix[i][j] > SIMILARITY_THRESHOLD
            ]
            
            if cluster_members:
                cluster_members.insert(0, i)
            
            if len(cluster_members) > 1:
                for idx in cluster_members:
                    labels[idx] = current_label
                    assigned.add(idx)
                current_label += 1
        
        return np.array(labels)
    
    def build_clusters(self, labels: np.ndarray, valid_files: List[str]) -> Tuple[Dict, List]:
        clusters = defaultdict(list)
        for i, label in enumerate(labels):
            clusters[label].append(valid_files[i])
        noise = clusters.pop(-1, [])
        return dict(clusters), noise
    
    def create_results(self, file_data, valid_files, clusters, noise, similarity_matrix, feature_matrix, function_categories):
        return {
            'summary': {
                'total_files': len(file_data),
                'analyzed_files': len(valid_files),
                'num_clusters': len(clusters),
                'noise_files': len(noise)
            },
            'clusters': {
                f"Cluster_{i+1}": files
                for i, files in enumerate(clusters.values())
            } if clusters else {},
            'noise_files': noise,
            'files': valid_files,
            'similarity_matrix': similarity_matrix.tolist(),
            'features': feature_matrix.tolist(),
            'feature_names': self.extractor.feature_names,
            'function_categories': function_categories
        }
    
    def save_results(self, results: Dict):
        output_file = self.run_dir / 'results.json'
        output_file.write_text(json.dumps(results, indent=2))
        
        metadata = {
            'run_id': self.timestamp,
            'timestamp_iso': datetime.now().isoformat(),
            'timestamp_unix': int(time.time()),
            'config': {
                'thorough_mode': self.thorough_mode,
                'max_blocks': MAX_BLOCKS_FULL_ANALYSIS,
                'dbscan_eps': DBSCAN_EPS_VALUES,
                'similarity_threshold': SIMILARITY_THRESHOLD
            },
            'input': {
                'total_files': results['summary']['total_files'],
                'analyzed_files': results['summary']['analyzed_files'],
                'file_list': results['files']
            },
            'output': {
                'num_clusters': results['summary']['num_clusters'],
                'noise_files': results['summary']['noise_files'],
                'cluster_sizes': [len(files) for files in results['clusters'].values()]
            },
            'environment': {
                'python_version': sys.version,
                'numpy_version': np.__version__
            },
            'tags': [],
            'notes': ''
        }
        
        metadata_file = self.run_dir / 'metadata.json'
        metadata_file.write_text(json.dumps(metadata, indent=2))
    
    def generate_graph_data(self, all_blocks: Dict):
        graph_data = {}
        
        for filename, blocks in tqdm(all_blocks.items(), desc="Processing Graph Data"):
            id_mapping = {b.block_id: idx for idx, b in enumerate(blocks)}
            nodes_data = [self.create_node_data(block, idx, id_mapping) for idx, block in enumerate(blocks)]
            dfg_edges = self.create_dfg_edges(blocks, id_mapping)
            
            graph_data[filename] = {
                'nodes': nodes_data,
                'total_blocks': len(blocks),
                'entry_points': [0] if blocks else [],
                'dfg_edges': dfg_edges
            }
        
        output_file = self.run_dir / 'graph_data.json'
        output_file.write_text(json.dumps(graph_data, indent=2))
    
    def create_node_data(self, block: BasicBlock, idx: int, id_mapping: Dict) -> Dict:
        return {
            'id': idx,
            'original_id': block.block_id,
            'label': f'{self.shorten_name(block.function_name)}\nBlock_{idx}',
            'function_name': block.function_name,
            'size': len(block.instructions),
            'instructions': block.instructions[:MAX_INSTRUCTIONS_PREVIEW],
            'instruction_count': len(block.instructions),
            'inbounds': [id_mapping[b] for b in block.inbounds if b in id_mapping],
            'outbounds': [id_mapping[b] for b in block.outbounds if b in id_mapping],
            'registers_used': list(block.use_registers),
            'registers_defined': list(block.def_registers),
            'function_calls': block.function_calls,
            'address_start': hex(block.start_address),
            'address_end': hex(block.end_address),
            'def_use_distances': {k: v for k, v in block.def_use_distances.items()}
        }
    
    def create_dfg_edges(self, blocks: List[BasicBlock], id_mapping: Dict) -> List[Dict]:
        dfg_edges = []
        for idx, block in enumerate(blocks):
            for reg, target_info in block.def_use_distances.items():
                for target_id, distance in target_info:
                    if target_id in id_mapping:
                        dfg_edges.append({
                            'from': idx,
                            'to': id_mapping[target_id],
                            'register': reg,
                            'distance': distance
                        })
        return dfg_edges
    
    @staticmethod
    def shorten_name(name: str) -> str:
        return name if len(name) <= MAX_NAME_LENGTH else f"{name[:MAX_NAME_LENGTH-3]}"
    
    def generate_summary_images(self, results: Dict, feature_matrix: np.ndarray, valid_files: List[str]):
        # feature scatter plot
        fig, ax = plt.subplots(figsize=(12, 8))
        try:
            ax.scatter(
                feature_matrix[:, 0], feature_matrix[:, 1],
                s=100, alpha=0.6, c=range(len(valid_files)), cmap='tab20'
            )
            for i, filename in enumerate(valid_files):
                ax.annotate(
                    filename, (feature_matrix[i, 0], feature_matrix[i, 1]),
                    xytext=(5, 5), textcoords='offset points', fontsize=8
                )
            ax.set_xlabel(results['feature_names'][0], fontsize=12)
            ax.set_ylabel(results['feature_names'][1], fontsize=12)
            ax.set_title('Feature Comparison', fontsize=16)
            ax.grid(True, alpha=0.3)
            plt.tight_layout()
            plt.savefig(self.images_dir / 'feature_scatter.png', dpi=300, bbox_inches='tight')
        finally:
            plt.close(fig)

        # similarity heatmap
        fig = plt.figure(figsize=(12, 10))
        try:
            sns.heatmap(
                results['similarity_matrix'],
                xticklabels=valid_files,
                yticklabels=valid_files,
                cmap='viridis',
                square=True,
                cbar_kws={'label': 'Similarity'}
            )
            plt.title('Structural Similarity Matrix', fontsize=16, pad=20)
            plt.xticks(rotation=45, ha='right')
            plt.yticks(rotation=0)
            plt.tight_layout()
            plt.savefig(self.images_dir / 'similarity_heatmap.png', dpi=300, bbox_inches='tight')
        finally:
            plt.close(fig)
    
    def copy_html_template(self):
        html_template = Path(__file__).parent / 'ida_ir_pattern_visualizer.html'
        if html_template.exists():
            shutil.copy(html_template, self.run_dir / 'index.html')
    
    def print_summary(self, results: Dict):
        print(f"\n{'='*60}")
        print("IR STRUCTURAL ANALYSIS RESULTS")
        print(f"{'='*60}")
        print(f"Total Files Scanned: {results['summary']['total_files']}")
        print(f"Successfully Analyzed: {results['summary']['analyzed_files']}")
        print(f"Structural Clusters: {results['summary']['num_clusters']}")
        print(f"Unique/Unmatched Files: {results['summary']['noise_files']}")
        
        if results['clusters']:
            for group, files in results['clusters'].items():
                print(f"\n{group} ({len(files)} files):")
                for f in files[:MAX_FILES_PREVIEW]:
                    print(f"  • {f}")
                if len(files) > MAX_FILES_PREVIEW:
                    print(f"   and {len(files)-MAX_FILES_PREVIEW} more")
        
        print(f"\n{'='*60}")
        print(f"Results Directory: {self.run_dir}")
        print(f"Starting Web Visualizer")
        print(f"{'='*60}\n")
    
    def start_server(self):
        output_dir = self.run_dir
        httpd = None
        server_ready = threading.Event()
        server_error = [None]
        
        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(output_dir), **kwargs)
            
            def log_message(self, format, *args):
                pass
        
        def run_server():
            nonlocal httpd
            try:
                httpd = socketserver.TCPServer(("", PORT), Handler)
                httpd.allow_reuse_address = True
                server_ready.set()
                httpd.serve_forever()
            except OSError as e:
                server_error[0] = e
                server_ready.set()
        
        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        
        if not server_ready.wait(timeout=2.0):
            print(f"Error: Server failed to start within timeout")
            return
        
        if server_error[0]:
            print(f"Error: could not start server")
            print(f"\n       {server_error[0]}")
            return
        
        webbrowser.open(f'http://localhost:{PORT}/index.html')
        
        try:
            print("press Ctrl+C to stop the server")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting Down")
            if httpd:
                httpd.shutdown()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='IR Structural Similarity Analyzer')
    parser.add_argument('path', help='path to IR files (IDA microcode .txt files)')
    parser.add_argument('--thorough', action='store_true', help='exhaustive dataflow analysis, slower')
    args = parser.parse_args()

    print("="*60)
    print("IR STRUCTURAL SIMILARITY ANALYZER")
    print("="*60)
    print("Purpose: analyze and cluster IDA microcode by structural patterns")
    print("Features: CFG/DFG analysis with 22 structural features")
    print("="*60 + "\n")

    analyzer = IRStructuralAnalyzer(thorough_mode=args.thorough)
    analyzer.analyze(args.path)