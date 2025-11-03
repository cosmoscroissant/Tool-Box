import json
import re

from typing import Dict, List, Set
from collections import defaultdict
from dataclasses import dataclass, field

from .src.BasicBlock.ir_block import *

@dataclass
class IoC:
    value: str
    category: str
    confidence: float = 1.0
    source: str = ""

@dataclass
class FunctionSignature:
    filename: str
    function_name: str
    semantic_tags: List[str] = field(default_factory=list)
    crypto_algo: str = ""
    iocs_used: List[IoC] = field(default_factory=list)
    infrastructure: Set[str] = field(default_factory=set)
    related_functions: Set[str] = field(default_factory=set)

class CrossReferenceModule:
    def __init__(self):
        self.ir_results = {}
        self.asm_results = {}
        self.cross_references = defaultdict(list)
        self.infrastructure_graph = defaultdict(set)
        self.family_clusters = defaultdict(set)
        self.ioc_to_functions = defaultdict(set)
    
    def load_ir_results(self, ir_json_path: str) -> bool:
        try:
            with open(ir_json_path, 'r') as f:
                self.ir_results = json.load(f)
            print(f"Loaded IR results from {ir_json_path}")
            return True
        except FileNotFoundError:
            print(f"WARNING: IR results not found at {ir_json_path}")
            return False
        except json.JSONDecodeError as e:
            print(f"ERROR: Failed to parse IR results: {e}")
            return False
    
    def load_asm_results(self, asm_json_path: str) -> bool:
        try:
            with open(asm_json_path, 'r') as f:
                asm_raw = json.load(f)

                self.asm_results = {
                    r['file']: r for r in asm_raw 
                    if isinstance(r, dict) and 'file' in r
                }

            normalized_results = {}
            for filepath, data in self.asm_results.items():
                basename = filepath.split('/')[-1].split('\\')[-1]
                basename = basename.replace('.asm', '.txt')
                normalized_results[basename] = data
                normalized_results[basename]['original_path'] = filepath
            
            self.asm_results = normalized_results
            print(f"  Normalized {len(self.asm_results)} filenames to match IR format")
            print(f"Loaded ASM results from {asm_json_path}")
            return True
        except FileNotFoundError:
            print(f"WARNING: ASM results not found at {asm_json_path}")
            return False
        except json.JSONDecodeError as e:
            print(f"ERROR: Failed to parse ASM results: {e}")
            return False
        
    def extract_iocs_from_asm(self, filename: str) -> List[IoC]:
        iocs = []
        
        if filename not in self.asm_results:
            return iocs
        
        asm_entry = self.asm_results[filename]
        
        if 'file_hashes' in asm_entry:
            for hash_type, hash_value in asm_entry['file_hashes'].items():
                iocs.append(IoC(
                    value=hash_value,
                    category=f'file_hash_{hash_type}',
                    confidence=1.0,
                    source='asm_sniffer'
                ))
        
        if 'iocs' in asm_entry:
            ioc_categories = {
                'protocols_full': 'c2_url',
                'urls': 'url',
                'domains': 'c2_domain',
                'files': 'executable_reference',
                'main_patterns': 'function_reference',
                'ssh_patterns': 'ssh_reference',
                'openssh_full': 'openssh_reference',
                'operational_files': 'file_path',
                'dependency_paths': 'library_path'
            }
            
            for category, ioc_list in asm_entry['iocs'].items():
                mapped_category = ioc_categories.get(category, category)
                for ioc_value in ioc_list:
                    iocs.append(IoC(
                        value=ioc_value,
                        category=mapped_category,
                        confidence=self._confidence_for_category(mapped_category),
                        source='asm_sniffer'
                    ))
        
        return iocs
    
    def _confidence_for_category(self, category: str) -> float:
        confidence_map = {
            'c2_url': 0.95,
            'c2_domain': 0.9,
            'executable_reference': 0.85,
            'function_reference': 0.7,
            'ssh_reference': 0.8,
            'file_hash_sha256': 0.95,
            'file_hash_md5': 0.9,
            'library_path': 0.6,
            'file_path': 0.65
        }
        return confidence_map.get(category, 0.5)

    def match_iocs_to_functions(self, filename: str) -> Dict[str, List[IoC]]:
        matches = defaultdict(list)
        
        if 'semantic_enrichments' not in self.ir_results:
            return matches
        if filename not in self.ir_results['semantic_enrichments']:
            return matches
        
        iocs = self.extract_iocs_from_asm(filename)
        if not iocs:
            return matches
        
        semantic_enrichment = self.ir_results['semantic_enrichments'][filename]
        
        # 1: crypto + C2
        if semantic_enrichment.get('crypto', {}).get('has_crypto', False):
            crypto_algo = semantic_enrichment['crypto'].get('primary_algorithm', 'unknown')
            c2_iocs = [ioc for ioc in iocs if 'c2_' in ioc.category]
            if c2_iocs:
                func_key = f"crypto_{crypto_algo}_function"
                for ioc in c2_iocs:
                    ioc.confidence = min(ioc.confidence * 1.1, 1.0)
                    matches[func_key].append(ioc)

        # 2: stdlib
        if semantic_enrichment.get('stdlib', {}).get('has_stdlib', False):
            stdlib_funcs = semantic_enrichment['stdlib'].get('detected_functions', [])
            if any(f in stdlib_funcs for f in ['malloc', 'memcpy', 'strlen']):
                file_iocs = [ioc for ioc in iocs if 'file' in ioc.category or 'path' in ioc.category]
                if file_iocs:
                    func_key = "memory_operation_function"
                    matches[func_key].extend(file_iocs)
        
        return matches

    def build_infrastructure_graph(self) -> Dict[str, Set[str]]:
        infrastructure_graph = defaultdict(set)
        
        files = self.ir_results.get('files', [])
        if not files:
            return {}
        
        for filename in files:
            iocs = self.extract_iocs_from_asm(filename)
            if not iocs:
                continue
            
            c2_domains = {ioc.value for ioc in iocs if ioc.category == 'c2_domain'}
            c2_urls = {ioc.value for ioc in iocs if ioc.category == 'c2_url'}
            
            for domain in c2_domains:
                infrastructure_graph[f"c2_domain_{domain}"].add(filename)
            
            for url in c2_urls:
                try:
                    domain_match = re.search(r'https?://([^/]+)', url)
                    if domain_match:
                        domain = domain_match.group(1)
                        infrastructure_graph[f"c2_url_domain_{domain}"].add(filename)
                except (AttributeError, re.error):
                    pass  # skip malformed URLs
            
            # lower priority indicators
            file_hashes = {ioc.value for ioc in iocs if 'hash' in ioc.category}
            for hash_val in file_hashes:
                infrastructure_graph[f"file_hash_{hash_val}"].add(filename)
        
        # filter: only keep infrastructure shared by 2+ samples
        return {infra: samples for infra, samples in infrastructure_graph.items() if len(samples) >= 2}

    def identify_variants(self, similarity_threshold: float = 0.75) -> Dict[str, List[str]]:
        """
        identify malware variants sharing:
            - same infrastructure (C2 domains, hashes)
            - same crypto algorithms
            - same anti-analysis patterns
        """
        variants = defaultdict(list)
        
        processed = set()
        files = self.ir_results.get('files', [])
        
        if not files:
            return variants
        
        for i, file1 in enumerate(files):
            if file1 in processed:
                continue
            
            cluster = [file1]
            
            for file2 in files[i+1:]:
                if file2 in processed:
                    continue
                
                similarity = self._compute_variant_similarity(file1, file2)
                if similarity >= similarity_threshold:
                    cluster.append(file2)
                    processed.add(file2)
            
            if len(cluster) > 1:
                family_id = f"variant_family_{hash(frozenset(cluster)) & 0xffffffff:x}"
                variants[family_id] = cluster
                processed.add(file1)
        
        return variants

    def _compute_variant_similarity(self, file1: str, file2: str) -> float:
        score = 0.0
        max_score = 0.0
        factors_met = 0  # track how many factors have evidence
        
        # 1: shared infrastructure (35% weight)
        # only count if they share C2 domains specifically (high confidence)
        max_score += 0.35
        try:
            iocs1 = [ioc for ioc in self.extract_iocs_from_asm(file1) if 'c2_' in ioc.category]
            iocs2 = [ioc for ioc in self.extract_iocs_from_asm(file2) if 'c2_' in ioc.category]
            
            if iocs1 and iocs2:  # both have C2 infrastructure
                iocs1_set = set(ioc.value for ioc in iocs1)
                iocs2_set = set(ioc.value for ioc in iocs2)
                shared_c2 = iocs1_set & iocs2_set
                
                if shared_c2:  # actually share C2 domains/URLs
                    score += 0.35  # Full credit for shared C2
                    factors_met += 1
                elif len(iocs1_set & iocs2_set) > 0:  # partial overlap
                    score += 0.15  # reduced credit
        except Exception:
            pass  # missing ASM data for this file
        
        # 2: same crypto algorithm (30% weight)
        max_score += 0.3
        try:
            sem1 = self.ir_results.get('semantic_enrichments', {}).get(file1, {})
            sem2 = self.ir_results.get('semantic_enrichments', {}).get(file2, {})
            
            has_crypto1 = sem1.get('crypto', {}).get('has_crypto', False)
            has_crypto2 = sem2.get('crypto', {}).get('has_crypto', False)
            
            if has_crypto1 and has_crypto2:
                algo1 = sem1['crypto'].get('primary_algorithm', 'none')
                algo2 = sem2['crypto'].get('primary_algorithm', 'none')
                
                if algo1 and algo2 and algo1 == algo2:
                    score += 0.3
                    factors_met += 1
        except (KeyError, AttributeError):
            pass  # missing semantic data
        
        # 3: structural similarity (10% weight)
        max_score += 0.1
        try:
            if 'similarity_matrix' in self.ir_results and 'files' in self.ir_results:
                idx1 = self.ir_results['files'].index(file1)
                idx2 = self.ir_results['files'].index(file2)
                sim_matrix = self.ir_results['similarity_matrix']
                
                if idx1 < len(sim_matrix) and idx2 < len(sim_matrix[idx1]):
                    structural_sim = sim_matrix[idx1][idx2]
                    if structural_sim > 0.6:  # only count if moderately similar
                        score += 0.1 * min(structural_sim, 1.0)
                        factors_met += 1
        except (ValueError, IndexError, TypeError, KeyError):
            pass  # files not found or data missing
        
        # enforce minimum requirement: need evidence from at least 2 factors
        if factors_met < 1:
            return 0.0  # reject if fewer than 2 factors provide evidence
        
        return score / max_score if max_score > 0 else 0.0

    def generate_cross_reference_report(self) -> str:
        report = []
        
        print("=" * 60)
        print("CROSS REFERENCE ANALYSIS REPORT")
        print("=" * 60)
        
        infra_graph = self.build_infrastructure_graph()
        if infra_graph:
            print(f"\nShared Infrastructure ({len(infra_graph)} indicators):")
            for infra_id, samples in sorted(infra_graph.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
                print(f"  {infra_id}: {len(samples)} samples")
                for sample in list(samples)[:3]:
                    print(f"    • {sample}")
                if len(samples) > 3:
                    print(f"     and {len(samples) - 3} more")
        else:
            print(f"\nShared Infrastructure: None detected")
            print("  (no samples share C2 domains, URLs, or file hashes)")
        
        variants = self.identify_variants()
        if variants:
            print(f"\nIdentified Variant Families ({len(variants)} families):")
            for family_id, samples in sorted(variants.items(), key=lambda x: len(x[1]), reverse=True):
                print(f"  {family_id}: {len(samples)} samples")
                
                if len(samples) >= 2:
                    sample1, sample2 = samples[0], samples[1]
                    similarity = self._compute_variant_similarity(sample1, sample2)
                    print(f"    Similarity Score: {similarity*100:.1f}%")
                
                for sample in samples[:4]:
                    print(f"    • {sample}")
                if len(samples) > 4:
                    print(f"     and {len(samples) - 4} more")
        else:
            print(f"\nIdentified Variant Families: None detected")
            print("  (No samples meet the 75% similarity threshold across multiple factors)")
        
        has_mappings = False
        mapping_preview = []
        for filename in self.ir_results.get('files', []):
            matches = self.match_iocs_to_functions(filename)
            if matches:
                has_mappings = True
                mapping_preview.append((filename, matches))
                if len(mapping_preview) >= 3:  # Preview first 3
                    break
        
        if has_mappings:
            print(f"\nFunction to IoC Mappings (showing first 3 files):")
            for filename, matches in mapping_preview:
                print(f"\n  {filename}:")
                for func_type, iocs in matches.items():
                    if iocs:
                        print(f"    {func_type}: {len(iocs)} IoCs")
                        for ioc in iocs[:3]:
                            print(f"      • {ioc.category}: {ioc.value}")
                        if len(iocs) > 3:
                            print(f"       and {len(iocs) - 3} more")
        else:
            print(f"\nFunction to IoC Mappings: None detected")
            print("  (could not correlate semantic patterns with IoC data)")
        
        c2_infrastructure = []
        for filename in self.ir_results.get('files', []):
            iocs = self.extract_iocs_from_asm(filename)
            c2_iocs = [ioc for ioc in iocs if 'c2_' in ioc.category and ioc.confidence > 0.8]
            if c2_iocs:
                c2_infrastructure.append((filename, c2_iocs))
        
        if c2_infrastructure:
            print(f"\nHigh Confidence C2 Infrastructure ({len(c2_infrastructure)} files):")
            for filename, c2_iocs in c2_infrastructure[:5]:  # Show first 5
                print(f"  {filename}:")
                for ioc in c2_iocs:
                    print(f"    • {ioc.value} ({ioc.category}, confidence: {ioc.confidence:.2f})")
            if len(c2_infrastructure) > 5:
                print(f"   and {len(c2_infrastructure) - 5} more files")
        else:
            print(f"\nHigh Confidence C2 Infrastructure: none detected")
            print("  (no C2 domains or URLs with confidence > 0.8 found)")
        
        print(f"\n" + "-" * 60)
        print("Summary Statistics:")
        print(f"  Total Files Analyzed: {len(self.ir_results.get('files', []))}")
        print(f"  Files with IoCs: {sum(1 for f in self.ir_results.get('files', []) if self.extract_iocs_from_asm(f))}")
        print(f"  Shared Infrastructure Indicators: {len(infra_graph)}")
        print(f"  Variant Families Identified: {len(variants)}")
        print(f"  Files with C2 Indicators: {len(c2_infrastructure)}")
                
        return '\n'.join(report)

    def export_cross_references(self, output_path: str) -> None:
        export_data = {
            'infrastructure_graph': {
                infra: list(samples) 
                for infra, samples in self.build_infrastructure_graph().items()
            },
            'variant_families': {
                family: samples 
                for family, samples in self.identify_variants().items()
            },
            'function_ioc_mappings': {
                filename: {
                    func_type: [
                        {'value': ioc.value, 'category': ioc.category, 'confidence': ioc.confidence}
                        for ioc in iocs
                    ]
                    for func_type, iocs in self.match_iocs_to_functions(filename).items()
                }
                for filename in self.ir_results.get('files', [])
            }
        }
        
        try:
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            print(f"\nCross reference data exported to {output_path}")
        except Exception as e:
            print(f"ERROR: Failed to export cross references: {e}")

    def get_cross_reference_summary(self) -> Dict:
        infra_graph = self.build_infrastructure_graph()
        variants = self.identify_variants()
        
        c2_count = 0
        for filename in self.ir_results.get('files', []):
            iocs = self.extract_iocs_from_asm(filename)
            c2_iocs = [ioc for ioc in iocs if 'c2_' in ioc.category and ioc.confidence > 0.8]
            if c2_iocs:
                c2_count += 1
        
        return {
            'total_files': len(self.ir_results.get('files', [])),
            'shared_infrastructure_count': len(infra_graph),
            'variant_families_count': len(variants),
            'c2_infrastructure_count': c2_count,
            'has_meaningful_data': len(infra_graph) > 0 or len(variants) > 0 or c2_count > 0
        }
    
    def analyze(self, ir_json_path: str, asm_json_path: str) -> bool:
        print("=" * 60)
        print("CROSS REFERENCE ANALYSIS")
        print("=" * 60)
        
        ir_ok = self.load_ir_results(ir_json_path)
        asm_ok = self.load_asm_results(asm_json_path)
        
        data_completeness = []
        if ir_ok:
            data_completeness.append(f"IR: {len(self.ir_results.get('files', []))} files")
            if 'semantic_enrichments' in self.ir_results:
                data_completeness.append(f"  + Semantic enrichments")
        else:
            print("\nERROR: IR results required but not found at", ir_json_path)
            return False
        
        if asm_ok:
            data_completeness.append(f"ASM: {len(self.asm_results)} files")
        else:
            print("\nWARNING: ASM IoC results not found, infrastructure correlation will be limited")
        
        print(f"\nData loaded:")
        for item in data_completeness:
            print(f"  {item}")
        
        print(f"\n")
        
        if not ir_ok:
            print("\nCannot proceed without IR results!")
            return False
        
        print("\nGenerating cross reference analysis...")
        try:
            self.generate_cross_reference_report()
            return True
        except Exception as e:
            print(f"\n[ERROR] During Analysis: {e}")
            print("cross reference analysis partially completed")
            return False
