from ..BasicBlock.ir_block import *

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
