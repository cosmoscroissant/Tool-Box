import re

from typing import List, Optional, Tuple
from collections import deque

from ..BasicBlock.ir_block import *
from ..Constant.ir_constants import *
from ..RegisterSet.ir_filter_register import *

class IRParser:
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
            if m.group(1) not in SKIP_REGISTERS
        }
    
    def analyze_dataflow(self, blocks: List[BasicBlock]) -> None:
        if not blocks:
            print("WARNING: analyze_dataflow called with empty blocks")
            return
        
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
                print(f"     processing block {block_idx}/{len(sampled_blocks)} (block_id={block.block_id})")
            
            regs_to_analyze = list(block.def_registers)[:int(max_regs) if max_regs != float('inf') else None]
            
            if block_idx % PROGRESS_LOG_INTERVAL == 0 and len(regs_to_analyze) > 0:
                print(f"       analyzing {len(regs_to_analyze)} registers in this block")
            
            for reg in regs_to_analyze:
                distances = self.bfs_def_use_search(block.block_id, reg, block_map, max_depth, max_uses, max_iterations)
                if distances:
                    block.def_use_distances[reg] = distances

        for block in sampled_blocks:
            for reg in block.def_registers:
                max_dist = 0
                if reg in block.def_use_distances:
                    max_dist = max(dist for _, dist in block.def_use_distances[reg])
                block.live_ranges[reg] = max_dist
        
        print("Dataflow Analysis Complete")
    
    def bfs_def_use_search(self, start_block_id: int, reg: str, block_map: Dict[int, BasicBlock], max_depth: float, max_uses: int, max_iterations: int) -> List[Tuple[int, int]]:
        distances = []
        visited = set()
        queue = deque([(start_block_id, 0)]) 
        iterations = 0
        
        while queue and len(distances) < max_uses:
            iterations += 1
            if iterations > max_iterations:
                print(f"    WARNING: Block {start_block_id}, reg {reg} - BFS exceeded {max_iterations} iterations")
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
    
    def get_mnemonic(instruction: str, lowercase: bool = True) -> Optional[str]:
        if not instruction or not instruction.strip():
            return None
        
        instr = instruction.lower() if lowercase else instruction
        parts = instr.split()
        return parts[0] if parts else None
