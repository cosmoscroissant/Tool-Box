from typing import List
from ..BasicBlock.ir_block import *
from ..Parser.ir_parser import *
from ..RegisterSet.ir_filter_register import *

def extract_opcodes(blocks: List[BasicBlock], abstract: bool = False) -> List[str]:
    opcodes = []
    for block in blocks:
        for instr in block.instructions:
            op = IRParser.get_mnemonic(instr, lowercase=True)
            if op is None:
                continue
            
            if abstract:
                if op in ARITHMETIC_OPS:
                    opcodes.append('ALU_OP')
                elif op in MEMORY_OPS:
                    opcodes.append('MEM_OP')
                elif op in CTRL_OPS:
                    opcodes.append('CTRL_OP')
            else:
                opcodes.append(op)
    return opcodes