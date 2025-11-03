import re
import networkx as nx

from typing import List, Dict
from collections import Counter

from ..BasicBlock.ir_block import *
from ..Builder.ir_cfg_builder import *
from ..Extractor.ir_extract_opcodes import *

class SemanticPatternLibrary:
    def __init__(self):
        self.crypto_patterns = self._init_crypto_patterns()
        self.stdlib_patterns = self._init_stdlib_patterns()
    
    def _init_crypto_patterns(self) -> Dict:
        return {
            'aes': {
                'constants': {
                    0x637c777b, 0x7b52fbd5, 0x6bd631f8, 0x7c63a4f3,  # AES S-box start
                    0x02010100, 0x04030201,  # Key schedule constants
                    0x01000000, 0x1b000000,  # Rcon values
                    0xfb9776d6, 0x6fed3d6d,  # AES S-box continuation
                },
                'opcodes': {'mul', 'xor', 'shl', 'shr', 'and', 'or'},
                'patterns': [
                    r'(?:aes|rijndael)',
                    r'(?:key_schedule|expand_key)',
                    r'(?:mix_columns|shift_rows|sub_bytes)',
                ],
                'score': 0,
                'confidence': 'high'
            },
            'des': {
                'constants': {
                    0x01010400, 0x02020801, 0x04040802,  # DES PC1/PC2 tables
                },
                'opcodes': {'rol', 'ror', 'xor', 'and', 'or'},
                'patterns': [
                    r'(?:des|data_encryption_standard)',
                    r'(?:feistel|initial_permutation)',
                ],
                'score': 0,
                'confidence': 'high'
            },
            'rc4': {
                'constants': {
                    0x00010203, 0x04050607, 0x08090a0b,  # RC4 identity permutation
                },
                'opcodes': {'add', 'xor', 'mov', 'ldx', 'stx'},
                'patterns': [
                    r'(?:rc4|arcfour)',
                    r'(?:ksa|prga)',  # key scheduling, pseudo-random generation
                ],
                'score': 0,
                'confidence': 'high'
            },
            'md5': {
                'constants': {
                    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,  # MD5 init
                    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,  # MD5 constants
                },
                'opcodes': {'add', 'xor', 'and', 'or', 'rol'},
                'patterns': [
                    r'(?:md5|message_digest_5)',
                    r'(?:round|f_function|g_function)',
                ],
                'score': 0,
                'confidence': 'high'
            },
            'sha1': {
                'constants': {
                    0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6,  # SHA1 constants
                    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
                },
                'opcodes': {'add', 'xor', 'or', 'rol'},
                'patterns': [
                    r'(?:sha1|secure_hash_1)',
                    r'(?:expand|compress)',
                ],
                'score': 0,
                'confidence': 'high'
            },
            'sha256': {
                'constants': {
                    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,  # SHA256 constants
                    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                },
                'opcodes': {'add', 'xor', 'shr', 'ror'},
                'patterns': [
                    r'(?:sha256|secure_hash_256)',
                    r'(?:ch|maj|sigma)',  # SHA256 boolean functions
                ],
                'score': 0,
                'confidence': 'high'
            }
        }
    
    def _init_stdlib_patterns(self) -> Dict:
        return {
            'memset': {
                'pattern_name': 'memory_fill',
                'indicators': [
                    {
                        'name': 'loop_with_constant_store',
                        'description': 'loop storing constant value to memory',
                        'opcodes': ['stx', 'ldx', 'mov'],
                        'signature': r'(?:stx|mov).*(?:stx|mov)',  # repeated stores
                    },
                    {
                        'name': 'xor_loop',
                        'description': 'XOR loop initialization (memset with 0)',
                        'opcodes': ['xor', 'stx'],
                        'signature': r'xor.*stx',
                    }
                ],
                'score': 0
            },
            'strcpy': {
                'pattern_name': 'string_copy',
                'indicators': [
                    {
                        'name': 'byte_by_byte_copy',
                        'description': 'byte by byte copy with null check',
                        'opcodes': ['ldx', 'stx', 'jcnd', 'jz'],
                        'signature': r'(?:ldx|mov).*(?:stx|mov).*(?:jcnd|jz)',
                    },
                    {
                        'name': 'cmp_null_terminate',
                        'description': 'comparison with null terminator',
                        'opcodes': ['ldx', 'setz'],
                        'signature': r'ldx.*setz',
                    }
                ],
                'score': 0
            },
            'malloc': {
                'pattern_name': 'heap_allocation',
                'indicators': [
                    {
                        'name': 'allocation_sequence',
                        'description': 'call to allocation function followed by initialization',
                        'opcodes': ['call', 'mov', 'stx'],
                        'signature': r'call.*(?:mov|stx)',
                    },
                    {
                        'name': 'size_calculation',
                        'description': 'size calculation before allocation',
                        'opcodes': ['mul', 'add', 'call'],
                        'signature': r'(?:mul|add).*call',
                    }
                ],
                'score': 0
            },
            'memcpy': {
                'pattern_name': 'memory_copy',
                'indicators': [
                    {
                        'name': 'bulk_copy_loop',
                        'description': 'loop copying memory blocks',
                        'opcodes': ['ldx', 'stx', 'add', 'jcnd'],
                        'signature': r'ldx.*stx.*add',
                    }
                ],
                'score': 0
            },
            'strlen': {
                'pattern_name': 'string_length',
                'indicators': [
                    {
                        'name': 'null_scan_loop',
                        'description': 'loop scanning for null terminator',
                        'opcodes': ['ldx', 'setz', 'jz', 'add'],
                        'signature': r'ldx.*setz.*jz',
                    }
                ],
                'score': 0
            }
        }
    
    def extract_constants(self, blocks: List[BasicBlock]) -> Dict[int, int]:
        constants = {}
        for block in blocks:
            for instr in block.instructions:
                matches = re.findall(r'#(0x[0-9A-Fa-f]+|[0-9]{5,})', instr) # hex like #0x40ABC123 or decimal #12345
                for match in matches:
                    try:
                        val = int(match, 16) if match.startswith('0x') else int(match)
                        constants[val] = constants.get(val, 0) + 1
                    except ValueError:
                        pass
        return constants
    
    def detect_crypto_algorithm(self, blocks: List[BasicBlock], cfg=None, extracted_features=None) -> Dict:
        """
            1. XOR/shift ratio  (AES characteristic)
            2. loop count matching (10-14 for AES, 64/80 for SHA, 256 for RC4)
            3. register reuse patterns
            4. data flow complexity
            5. constant matching (optional, low weight)
        """
        findings = {}
        
        if extracted_features is not None:
            if len(extracted_features) < 24:  # Need at least indices 0-23
                print(f"WARNING: Feature vector too short ({len(extracted_features)} < 24), computing locally")
                extracted_features = None

        opcodes = extract_opcodes(blocks) if extracted_features is None else None
        total_ops = len(opcodes) if opcodes else 0
        
        if extracted_features is not None:
            xor_shl_shr_ratio = extracted_features[10] + extracted_features[11]
            loop_count = extracted_features[7]
            register_reuse = extracted_features[20]
            data_flow_complexity = extracted_features[23]
        else:
            if total_ops == 0:
                return findings
            
            xor_shl_shr_ratio = sum(1 for op in opcodes if op in {'xor', 'shl', 'shr', 'rol', 'ror'}) / total_ops
            loop_count = len(list(nx.simple_cycles(cfg))) if cfg and cfg.number_of_nodes() > 0 else 0
            
            # compute register reuse manually
            all_defs = [reg for b in blocks for reg in b.def_registers]
            reused = sum(1 for count in Counter(all_defs).items() if count > 1)
            register_reuse = reused / len(set(all_defs)) if all_defs else 0
            
            data_flow_complexity = sum(len(b.def_use_distances) for b in blocks)
        
        # AES detection profile
        aes_score = 0
        aes_evidence = []
        
        # AES: high XOR/shift ratio (>40%)
        if xor_shl_shr_ratio > 0.4:
            aes_score += 3
            aes_evidence.append(f"high_xor_shift_ratio_{xor_shl_shr_ratio:.2f}")
        
        # AES: loop count 10-14 (standard rounds)
        if 10 <= loop_count <= 14:
            aes_score += 4
            aes_evidence.append(f"aes_round_count_{loop_count}")
        
        # AES: high register reuse (state variables)
        if register_reuse > 0.6:
            aes_score += 2
            aes_evidence.append(f"high_register_reuse_{register_reuse:.2f}")
        
        # AES: complex data flow (many dependencies)
        if data_flow_complexity > 50:
            aes_score += 2
            aes_evidence.append(f"complex_dataflow_{data_flow_complexity}")
        
        # optional: Check for S-box constants (low weight)
        constants = self.extract_constants(blocks)
        aes_constants = {0x637c777b, 0x7b52fbd5, 0x6bd631f8}
        if any(c in constants for c in aes_constants):
            aes_score += 5
            aes_evidence.append(f"sbox_constant_0x{list(c for c in constants if c in aes_constants)[0]:08x}")
        
        if aes_score >= 3:  # threshold: need strong evidence
            findings['aes'] = {
                'score': aes_score,
                'confidence': 'high' if aes_score >= 7 else 'medium' if aes_score >= 5 else 'low',
                'evidence': aes_evidence,
                'method': 'behavioral_profiling',
                'matching_constants': 1 if aes_evidence and 'sbox' in str(aes_evidence) else 0,
                'opcode_ratio': xor_shl_shr_ratio
            }
        
        # MD5/SHA detection profile
        hash_score = 0
        hash_evidence = []
        hash_type = None
        
        # Hash functions: very high loop count (64 or 80 rounds)
        if loop_count == 64:
            hash_score += 5
            hash_evidence.append("md5_or_sha256_round_count_64")
            hash_type = 'md5_or_sha256'
        elif loop_count == 80:
            hash_score += 5
            hash_evidence.append("sha1_round_count_80")
            hash_type = 'sha1'
        elif 60 <= loop_count <= 85:
            hash_score += 2
            hash_evidence.append(f"hash_like_round_count_{loop_count}")
            hash_type = 'hash_function'
        
        # Hash: high ADD/ROL operations
        opcodes = extract_opcodes(blocks)
        if opcodes:
            add_rol_ratio = sum(1 for op in opcodes if op in {'add', 'rol'}) / len(opcodes)
            if add_rol_ratio > 0.3:
                hash_score += 3
                hash_evidence.append(f"high_add_rol_ratio_{add_rol_ratio:.2f}")
        
        # Hash: moderate register reuse (accumulator pattern)
        if 0.3 <= register_reuse <= 0.7:
            hash_score += 2
            hash_evidence.append(f"accumulator_pattern_{register_reuse:.2f}")
        
        if hash_score >= 5 and hash_type:
            findings[hash_type] = {
                'score': hash_score,
                'confidence': 'high' if hash_score >= 7 else 'medium',
                'evidence': hash_evidence,
                'method': 'behavioral_profiling',
                'matching_constants': 0,
                'opcode_ratio': add_rol_ratio if 'add_rol_ratio' in locals() else 0
            }
        
        # RC4 detection profile
        rc4_score = 0
        rc4_evidence = []
        
        # RC4: loop count 256 (KSA initialization)
        if loop_count == 256:
            rc4_score += 5
            rc4_evidence.append("rc4_ksa_loop_256")
        
        # RC4: high memory operations (swap pattern)
        if extracted_features is not None:
            mem_ops_ratio = extracted_features[10]  # MEMORY_OPS_RATIO
        else:
            mem_ops_ratio = sum(1 for op in opcodes if op in {'ldx', 'stx', 'mov'}) / len(opcodes) if opcodes else 0
        
        if mem_ops_ratio > 0.4:
            rc4_score += 3
            rc4_evidence.append(f"high_memory_ops_{mem_ops_ratio:.2f}")
        
        # RC4: simple control flow (not much branching)
        if extracted_features is not None:
            control_ops_ratio = extracted_features[12]  # CONTROL_OPS_RATIO
            if control_ops_ratio < 0.2:
                rc4_score += 2
                rc4_evidence.append("simple_control_flow")
        
        if rc4_score >= 5:
            findings['rc4'] = {
                'score': rc4_score,
                'confidence': 'high' if rc4_score >= 7 else 'medium',
                'evidence': rc4_evidence,
                'method': 'behavioral_profiling',
                'matching_constants': 0,
                'opcode_ratio': mem_ops_ratio
            }
        
        return findings

    def detect_stdlib_function(self, block: BasicBlock) -> Dict:
        if not block.instructions:
            return {}
        
        opcodes = [instr.split()[0].lower() for instr in block.instructions if instr.split()]
        instr_str = ' '.join(block.instructions).lower()
        
        findings = {}
        
        for func_name, func_sig in self.stdlib_patterns.items():
            detected_indicators = []
            
            for indicator in func_sig['indicators']:
                score = 0
                
                # opcodes
                matching_opcodes = sum(1 for op in indicator['opcodes'] if op in opcodes)
                if matching_opcodes >= len(indicator['opcodes']) * 0.6:
                    score += matching_opcodes
                
                # signature pattern
                if re.search(indicator['signature'], instr_str):
                    score += 3
                
                # loop detection for iterative functions
                if len(block.outbounds) > 0 and block.block_id in block.inbounds:
                    if func_name in ['memset', 'strcpy', 'memcpy', 'strlen']:
                        score += 2
                
                if score > 0:
                    detected_indicators.append({
                        'indicator': indicator['name'],
                        'score': score,
                        'description': indicator['description']
                    })
            
            if detected_indicators:
                findings[func_name] = {
                    'pattern_name': func_sig['pattern_name'],
                    'indicators': detected_indicators,
                    'combined_score': sum(ind['score'] for ind in detected_indicators),
                    'confidence': 'high' if len(detected_indicators) >= 2 else 'medium'
                }
        
        return findings
    
    def analyze_crypto_patterns(self, blocks: List[BasicBlock], cfg=None, extracted_features=None) -> Dict:
        crypto_findings = self.detect_crypto_algorithm(blocks, cfg, extracted_features)
        
        return {
            'crypto_algorithms': crypto_findings,
            'has_crypto': len(crypto_findings) > 0,
            'primary_algorithm': max(crypto_findings.items(), key=lambda x: x[1]['score'])[0] if crypto_findings else None,
            'algorithm_confidence': max([f['confidence'] for f in crypto_findings.values()] or ['none']) if crypto_findings else 'none'
        }
    
    def analyze_stdlib_patterns(self, blocks: List[BasicBlock]) -> Dict:
        stdlib_findings = {}
        
        for block in blocks:
            block_findings = self.detect_stdlib_function(block)
            for func_name, findings in block_findings.items():
                if func_name not in stdlib_findings:
                    stdlib_findings[func_name] = findings
                else:
                    stdlib_findings[func_name]['combined_score'] += findings['combined_score']
        
        return {
            'stdlib_functions': stdlib_findings,
            'has_stdlib': len(stdlib_findings) > 0,
            'detected_functions': list(stdlib_findings.keys())
        }
    
    def enrich_function_semantics(self, blocks: List[BasicBlock], cfg=None, extracted_features=None) -> Dict:
        if not blocks:
            return {'semantic_tags': [], 'crypto': {}, 'stdlib': {}, 'method': 'none'}
    
        if cfg is None:
            cfg = CFGBuilder.build_cfg(blocks)
        
        crypto_analysis = self.analyze_crypto_patterns(blocks, cfg, extracted_features)
        stdlib_analysis = self.analyze_stdlib_patterns(blocks)
        
        semantic_tags = []
        
        if crypto_analysis['has_crypto']:
            semantic_tags.append(f"uses_{crypto_analysis['primary_algorithm']}")
            semantic_tags.extend([f"{algo}_detected" for algo in crypto_analysis['crypto_algorithms'].keys()])
        
        if stdlib_analysis['has_stdlib']:
            semantic_tags.extend([f"has_{func}" for func in stdlib_analysis['detected_functions']])
        
        return {
            'semantic_tags': semantic_tags,
            'crypto': crypto_analysis,
            'stdlib': stdlib_analysis,
            'combined_score': (
                sum(f['score'] for f in crypto_analysis['crypto_algorithms'].values()) +
                sum(f['combined_score'] for f in stdlib_analysis['stdlib_functions'].values())
            ),
            'method': 'behavioral_profiling_with_cfg',
            'limitations': [
                'detection based on behavioral patterns, not exhaustive',
                'may miss obfuscated or custom implementations',
                'thresholds tuned for standard compiled code'
            ]
        }
    