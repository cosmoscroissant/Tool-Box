from dataclasses import dataclass, field
from typing import Dict, List, Set

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
