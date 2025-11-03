import json
import sys
import re

import matplotlib
matplotlib.use('Agg') # non interactive backend for plt.savefig()
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import networkx as nx

from sklearn.preprocessing import StandardScaler
from pathlib import Path
from collections import defaultdict
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import DBSCAN
from tqdm import tqdm
from typing import Tuple, Optional

from ..Parser.ir_parser import *
from ..Extractor.ir_extractor import *
from ..Filter.ir_filter import *
from ..Semantic.ir_semantic_pattern import *
from ..Builder.ir_cfg_builder import *
from ..Builder.ir_cfg_cache import *

class IRStructuralAnalyzer:  
    def __init__(self, output_dir='./Data/Analytics', thorough_mode=False):
        self.thorough_mode = thorough_mode
        
        self.parser = IRParser(thorough_mode=thorough_mode)
        self.extractor = FeatureExtractor(thorough_mode=thorough_mode)
        self.scaler = StandardScaler()
        self.semantic_lib = SemanticPatternLibrary()
        self.cfg_cache = CFGCache()
        
        self.run_dir = Path(output_dir)
        self.output_dir = self.run_dir.parent
        
        self.images_dir = self.run_dir / 'images'
        self.images_dir.mkdir(parents=True, exist_ok=True)
        
    def get_or_build_cfg(self, blocks: List[BasicBlock]) -> nx.DiGraph:
        return self.cfg_cache.get_or_build(blocks)

    def mine_frequent_subgraphs(self, all_blocks: Dict[str, List[BasicBlock]], min_appear: float = 0.5) -> Tuple[Dict[str, int], Dict[str, List[str]]]:
        all_patterns = defaultdict(int)
        file_subgraphs = {} # cache subgraphs
        file_count = len(all_blocks)
        
        if file_count == 1:
            print(f"skipping subgraph mining (only 1 file, need 2+ for patterns)")
            filename = list(all_blocks.keys())[0]
            file_subgraphs[filename] = []
            return {}, file_subgraphs
        
        print(f"processing {file_count} files")
        
        for idx, (filename, blocks) in enumerate(all_blocks.items(), 1):
            print(f"  [{idx}/{file_count}] {filename} ({len(blocks)} blocks)")
            
            if not self.thorough_mode and len(all_patterns) >= MAX_PATTERNS:
                print(f"  pattern limit reached ({MAX_PATTERNS}), skipping remaining files")
                file_subgraphs[filename] = []
                continue
            
            try:
                cfg = self.get_or_build_cfg(blocks)
                subgraphs = self.extractor.extract_subgraphs(cfg, blocks)
                
                # cache the subgraphs for this file
                file_subgraphs[filename] = subgraphs
                
                if len(subgraphs) > 0:
                    print(f"  extracted {len(subgraphs)} subgraphs")
                else:
                    print(f"  no subgraphs (file too large or too simple)")
                
                unique_patterns = set(subgraphs)
                for pattern in unique_patterns:
                    all_patterns[pattern] += 1
                    
                    if not self.thorough_mode and len(all_patterns) >= MAX_PATTERNS:
                        print(f"    pattern limit reached ({MAX_PATTERNS})")
                        break
                    
            except Exception as e:
                print(f"    ERROR: {type(e).__name__}: {e}")
                file_subgraphs[filename] = []
                continue
        
        print(f"  collected {len(all_patterns)} total unique patterns")
                
        if self.thorough_mode:
            frequent_patterns = dict(all_patterns)
            print(f"  returning all {len(frequent_patterns)} patterns (thorough mode)")
        else:
            min_files = max(2, int(file_count * min_appear))
            frequent_patterns = {
                pattern: count 
                for pattern, count in all_patterns.items() 
                if count >= min_files
            }
            print(f"Found {len(frequent_patterns)} Frequent Patterns (appearing in {min_files}+ files)\n")
                        
        if not frequent_patterns and all_patterns:
            if self.thorough_mode:
                print(f"  no patterns meet threshold, returning all {len(all_patterns)} patterns")
                sorted_patterns = sorted(all_patterns.items(), key=lambda x: x[1], reverse=True)
                frequent_patterns = dict(sorted_patterns)
            else:
                print(f"  no patterns meet threshold, returning top {min(10, MAX_PATTERNS)} patterns")
                sorted_patterns = sorted(all_patterns.items(), key=lambda x: x[1], reverse=True)
                frequent_patterns = dict(sorted_patterns[:min(10, MAX_PATTERNS)])

        return frequent_patterns, file_subgraphs
    
    def find_isomorphic_groups(self, canonical_forms):
        hash_to_files = defaultdict(list)
        
        total_files = len(canonical_forms)
        print(f"Computing Isomorphic Groups for {total_files} Files")
        
        for idx, (filename, canonical) in enumerate(canonical_forms.items(), 1):
            if idx % 100 == 0:
                print(f"  processed {idx}/{total_files} files")
            
            if not canonical or canonical == "empty":
                continue

            hash_part = canonical.split('|')[0]
            hash_to_files[hash_part].append(filename)

        isomorphic_groups = {}
        group_id = 1
        
        for _, files in hash_to_files.items():
            if len(files) > 1:
                isomorphic_groups[f"iso_group_{group_id}"] = files
                group_id += 1
        
        print(f"found {len(isomorphic_groups)} isomorphic groups")
        return isomorphic_groups

    def analyze(self, path: str) -> None:
        if not path or not path.strip():
            print("ERROR: path cannot be empty")
            return
        
        path_obj = Path(path)
        if not path_obj.exists():
            print(f"ERROR: {path} does not exist")
            return
        
        print(f"Scanning Files From: {path}")
        file_data = self.scan_files(path)
        print(f"found {len(file_data)} files\n")
        
        if not file_data:
            print("No files found!")
            return
        
        print("Extracting Features")
        feature_matrix, valid_files, all_blocks, function_categories, semantic_signatures, semantic_hashes, semantic_enrichments = self.extract_all_features(file_data)

        print(f"\nFeature Extraction Complete:")
        print(f"  - valid_files: {len(valid_files)}")
        print(f"  - all_blocks: {len(all_blocks)}")
        print(f"  - feature_matrix shape: {feature_matrix.shape if hasattr(feature_matrix, 'shape') else 'N/A'}")

        if not all_blocks:
            print("\nNo complex functions found!")
            return

        if len(valid_files) == 0:
            print("\nNo valid features extracted!")
            return

        try:
            print("\nAttempting canonical graph extraction...")
            canonical_forms = self.extract_canonical_graphs(all_blocks)
            print(f"SUCCESS: extracted {len(canonical_forms)} canonical forms")
        except Exception as e:
            print(f"[ERROR] Canonical graph extraction FAILED: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            return

        try:
            print("\nAttempting isomorphic group detection...")
            isomorphic_groups = self.find_isomorphic_groups(canonical_forms)
            print(f"SUCCESS: found {len(isomorphic_groups)} groups")
        except Exception as e:
            print(f"[ERROR] Isomorphic detection FAILED: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            return
        
        if len(feature_matrix) == 0:
            print("\nNo valid features extracted!")
            return
        
        print(f"\nNormalizing {len(valid_files)} Feature Vectors")
        normalized_features = self.scaler.fit_transform(feature_matrix)
        
        print("Clustering Similar Structures")
        labels = self.cluster_files(normalized_features, canonical_forms, valid_files)
        
        if len(all_blocks) > 1:
            print("\nMining Frequent Subgraph Patterns")
            frequent_patterns, file_subgraphs = self.mine_frequent_subgraphs(all_blocks)
            
            print("Matching Patterns to Files")
            file_patterns = self.match_patterns_to_files(file_subgraphs, frequent_patterns)
        else:
            print("\nskipping subgraph mining (single file)")
            frequent_patterns = {}
            file_patterns = {list(all_blocks.keys())[0]: []}

        clusters, noise = self.build_clusters(labels, valid_files)
        similarity_matrix = cosine_similarity(normalized_features)
        semantic_similarity_matrix = self.compute_semantic_similarity_matrix(semantic_signatures, valid_files)

        print("\nComputing Structural Similarity from Canonical Forms")
        canonical_similarity_matrix = self.compute_canonical_similarity_matrix(canonical_forms, valid_files)
    
        results = self.create_results(
            len(file_data), valid_files, clusters, noise,
            similarity_matrix, feature_matrix, function_categories, 
            semantic_signatures, semantic_hashes, semantic_similarity_matrix,
            canonical_forms, isomorphic_groups, frequent_patterns, file_patterns, canonical_similarity_matrix, semantic_enrichments
        )
        
        print("\nGenerating Visualizations")
        self.save_results(results)
        self.generate_graph_data(all_blocks)
        self.generate_summary_images(results, feature_matrix, valid_files)
        self.print_summary(results)

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

    def extract_all_features(self, file_data: Dict[str, str]) -> Tuple[np.ndarray, List[str], Dict[str, List[BasicBlock]], Dict[str, str], Dict[str, str], Dict[str, str], Dict[str, Dict]]:
        feature_matrix = []
        valid_files = []
        all_blocks = {}
        function_categories = {}
        semantic_signatures = {}
        semantic_hashes = {}
        semantic_enrichments = {}
        
        func_filter = FunctionFilter()
        
        for filename, content in file_data.items():
            try:
                print(f"\nProcessing file: {filename}")
                blocks = self.parser.parse_microcode(content)
                print(f"Parse Microcode Complete: {len(blocks) if blocks else 0} blocks")
                
                if blocks and func_filter.is_complex(blocks):
                    print(f"building CFG...")
                    cfg = self.get_or_build_cfg(blocks)
                    print(f"CFG built: {cfg.number_of_nodes()} nodes")
                    
                    print(f"extracting features...")
                    features = self.extractor.extract_features(blocks, cfg)
                    print(f"Features Extracted: {len(features)} features")
                    
                    if np.any(features):
                        feature_matrix.append(features)
                        valid_files.append(filename)
                        all_blocks[filename] = blocks
                        function_categories[filename] = func_filter.categorize_function(blocks)

                        print(f"enriching semantics...")
                        semantic_enrichments[filename] = self.semantic_lib.enrich_function_semantics(blocks, cfg, features)
                        print(f"semantic enrichment done")

                        print(f"computing semantic signature...")
                        semantic_sig = self.extractor.extract_semantic_signature(blocks, cfg)
                        semantic_signatures[filename] = semantic_sig
                        print(f"signature done")
                        
                        print(f"computing semantic hash...")
                        semantic_hash = self.extractor.compute_semantic_hash(blocks, cfg)
                        semantic_hashes[filename] = semantic_hash
                        print(f"hash done")

                        print(f"{filename}: {len(blocks)} blocks ({function_categories[filename]})")

                        if semantic_enrichments[filename]['semantic_tags']:
                            print(f"Tags: {', '.join(semantic_enrichments[filename]['semantic_tags'])}")
                    else:
                        print(f"{filename}: skipped (zero features)")
                else:
                    print(f"{filename}: skipped (trivial)")
                    
            except KeyboardInterrupt:
                raise
            except (ValueError, AttributeError, KeyError, IndexError, TypeError) as e:
                print(f"{filename} ERROR: {type(e).__name__}: {e}")
        
        return (
            np.array(feature_matrix) if feature_matrix else np.array([]),
            valid_files,
            all_blocks,
            function_categories,
            semantic_signatures,
            semantic_hashes,
            semantic_enrichments
        )
    
    def compute_semantic_similarity_matrix(self, semantic_signatures: Dict[str, str], valid_files: List[str]) -> np.ndarray:
        n = len(valid_files)
        matrix = np.zeros((n, n))
        
        print(f"\nComputing Semantic Similarity Matrix ({n}x{n} = {n*n} comparisons)")
        total_comparisons = (n * (n - 1)) // 2  # upper triangle only
        completed = 0
        
        for i in range(n):
            for j in range(i, n):
                if i == j:
                    matrix[i][j] = 1.0
                else:
                    sig1 = semantic_signatures.get(valid_files[i], "")
                    sig2 = semantic_signatures.get(valid_files[j], "")
                    sim = self.extractor.compare_semantic_signatures(sig1, sig2)
                    matrix[i][j] = sim
                    matrix[j][i] = sim
                    completed += 1
            
            if i % 10 == 0 or i == n - 1:
                percent = (completed / total_comparisons * 100) if total_comparisons > 0 else 100
                print(f"  processed {i}/{n} files ({completed}/{total_comparisons} comparisons, {percent:.1f}%)")
        
        return matrix
    
    def extract_canonical_graphs(self, all_blocks: Dict[str, List[BasicBlock]]) -> Dict[str, str]:
        canonical_forms = {}
        
        print("Extracting Canonical Graph Forms")
        total_files = len(all_blocks)
        for idx, (filename, blocks) in enumerate(all_blocks.items(), 1):
            print(f"  [{idx}/{total_files}] processing {filename} ({len(blocks)} blocks)")
            cfg = self.get_or_build_cfg(blocks)
            
            # canonicalized cfg
            canonical = self.extractor.canonicalize_cfg(cfg, blocks)
            canonical_forms[filename] = canonical
        
        return canonical_forms

    def cluster_files(self, normalized_features: np.ndarray, canonical_forms: Optional[Dict[str, str]] = None, valid_files: Optional[List[str]] = None) -> np.ndarray:
        if len(normalized_features) == 0:
            return np.array([])
        
        # standard clustering
        best_clustering = self.dbscan_cluster(normalized_features)
        if best_clustering is None:
            best_clustering = self.fallback_similarity_cluster(normalized_features)
        
        # post process to merge isomorphic files
        if canonical_forms and valid_files:
            # files with same canonical form should be in same cluster
            hash_to_indices = defaultdict(list)

            for idx, filename in enumerate(valid_files):
                canon = canonical_forms.get(filename, "")
                hash_to_indices[canon].append(idx)
            
            best_clustering = best_clustering.copy()
            
            # merge clusters for isomorphic groups
            for indices in hash_to_indices.values():
                if len(indices) > 1:
                    # get existing labels
                    existing_labels = [best_clustering[i] for i in indices]

                    # find the most common non noise label
                    non_noise = [l for l in existing_labels if l != -1]

                    if non_noise:
                        target_label = max(set(non_noise), key=non_noise.count)
                    else:
                        target_label = max(existing_labels)  # all noise, keep first
                    
                    # assign all to same cluster
                    for idx in indices:
                        best_clustering[idx] = target_label
        
        return best_clustering
    
    def dbscan_cluster(self, normalized_features: np.ndarray) -> Optional[np.ndarray]:
        best_clustering = None
        best_n_clusters = 0
        n_files = len(normalized_features)
        
        print(f"Trying {len(DBSCAN_EPS_VALUES)} Different DBSCAN Epsilon Values")
        for idx, eps in enumerate(DBSCAN_EPS_VALUES, 1):
            print(f"  [{idx}/{len(DBSCAN_EPS_VALUES)}] testing eps={eps}")
            clusterer = DBSCAN(eps=eps, min_samples=max(1, n_files // DBSCAN_MIN_SAMPLES_DIVISOR), metric='cosine')
            labels = clusterer.fit_predict(normalized_features)
            n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
            print(f"    found {n_clusters} clusters")
            
            if n_clusters > best_n_clusters and n_clusters < n_files:
                best_clustering = labels
                best_n_clusters = n_clusters
        
        print(f"best clustering: {best_n_clusters} clusters")
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

    def create_results(self, total_files, valid_files, clusters, noise, similarity_matrix, feature_matrix, function_categories, semantic_signatures, semantic_hashes, semantic_similarity_matrix, canonical_forms, isomorphic_groups, frequent_patterns, file_patterns, canonical_similarity_matrix, semantic_enrichments):
        return {
            'summary': {
                'total_files': total_files,
                'analyzed_files': len(valid_files),
                'num_clusters': len(clusters),
                'noise_files': len(noise),
                'isomorphic_groups': len(isomorphic_groups)
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
            'function_categories': function_categories,
            'semantic_signatures': semantic_signatures,
            'semantic_hashes': semantic_hashes,
            'semantic_similarity_matrix': semantic_similarity_matrix.tolist(),
            'canonical_similarity_matrix': canonical_similarity_matrix.tolist(),
            'canonical_forms': canonical_forms,
            'isomorphic_groups': isomorphic_groups,
            'frequent_patterns': frequent_patterns if self.thorough_mode else {k: v for k, v in list(frequent_patterns.items())[:50]}, # default: top 50 
            'file_patterns': file_patterns,
            'semantic_enrichments': semantic_enrichments
        }
    
    def save_results(self, results: Dict):
        output_file = self.run_dir / 'results.json'
        output_file.write_text(json.dumps(results, indent=2))
        
        metadata = {
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
        
        for filename, blocks in tqdm(all_blocks.items(), desc="Processing Graph Data", file=sys.stderr):
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
            'label': f'{IRStructuralAnalyzer.shorten_name(block.function_name)}\nBlock_{idx}',
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
        
        # 1. register dependencies
        for block in blocks:
            if block.block_id not in id_mapping:
                continue
            source_idx = id_mapping[block.block_id]
            for reg, target_info in block.def_use_distances.items():
                for target_id, distance in target_info:
                    if target_id in id_mapping:
                        dfg_edges.append({
                            'from': source_idx,
                            'to': id_mapping[target_id],
                            'type': 'register',
                            'register': reg,
                            'distance': distance
                        })
        
        # 2. memory dependencies
        memory_ops = []
        for block in blocks:
            if block.block_id not in id_mapping:
                continue
            
            for idx, instr in enumerate(block.instructions):
                if self.extractor.is_memory_op(instr):
                    opcode = instr.split()[0].lower()
                    op_type = 'store' if opcode in {'stloc', 'starg', 'stsfld', 'stfld', 'stelem'} else 'load'
                    memory_ops.append((id_mapping[block.block_id], opcode, op_type, idx))
        
        # link stores to subsequent loads
        for i, (store_block, store_op, store_type, store_idx) in enumerate(memory_ops):
            if store_type == 'store':
                for j, (load_block, load_op, load_type, load_idx) in enumerate(memory_ops[i+1:], i+1):
                    if load_type == 'load':
                        dfg_edges.append({
                            'from': store_block,
                            'to': load_block,
                            'type': 'memory',
                            'store_op': store_op,
                            'store_idx': store_idx,
                            'load_op': load_op,
                            'load_idx': load_idx,
                            'register': 'mem',
                            'distance': j - i
                        })
        
        return dfg_edges

    def match_patterns_to_files(self, file_subgraphs: Dict[str, List[str]], frequent_patterns: Dict[str, int]) -> Dict[str, List[str]]:
        file_patterns = {}
        
        if not frequent_patterns:
            print("no frequent patterns to match")
            return {filename: [] for filename in file_subgraphs.keys()}
        
        print(f"matching {len(frequent_patterns)} patterns to files")
        
        for filename, subgraphs in file_subgraphs.items():
            matched = [pattern for pattern in frequent_patterns.keys() if pattern in subgraphs]
            file_patterns[filename] = matched
            
            if matched:
                print(f"  {filename}: {len(matched)} patterns matched")
        
        return file_patterns

    def compute_canonical_similarity_matrix(self, canonical_forms: Dict[str, str], valid_files: List[str]) -> np.ndarray:
        n = len(valid_files)
        matrix = np.zeros((n, n))
        
        print(f"computing canonical similarity matrix ({n}x{n} comparisons)")
        total_comparisons = (n * (n - 1)) // 2
        completed = 0
        
        for i in range(n):
            for j in range(i, n):
                if i == j:
                    matrix[i][j] = 1.0
                else:
                    canon1 = canonical_forms.get(valid_files[i], "")
                    canon2 = canonical_forms.get(valid_files[j], "")
                    
                    if canon1 == canon2 and canon1 != "" and canon1 != "empty":
                        matrix[i][j] = 1.0
                        matrix[j][i] = 1.0
                    else:
                        sim = self._compare_canonical_forms(canon1, canon2)
                        matrix[i][j] = sim
                        matrix[j][i] = sim
                    completed += 1
            
            if i % 10 == 0 or i == n - 1:
                percent = (completed / total_comparisons * 100) if total_comparisons > 0 else 100
                print(f"  processed {i}/{n} files ({completed}/{total_comparisons} comparisons, {percent:.1f}%)")
        
        return matrix

    def _compare_canonical_forms(self, canon1: str, canon2: str) -> float:
        if not canon1 or not canon2 or canon1 == "empty" or canon2 == "empty":
            return 0.0
        
        try:
            parts1 = canon1.split('|')
            parts2 = canon2.split('|')
            
            if len(parts1) < 3 or len(parts2) < 3:
                return 0.0
            
            # 1. WL hash comparison (50% weight)
            wl_match = 1.0 if parts1[0] == parts2[0] else 0.0
            
            # 2. size similarity (25% weight)
            size1_match = re.search(r'N(\d+)E(\d+)', parts1[1])
            size2_match = re.search(r'N(\d+)E(\d+)', parts2[1])
            
            if size1_match and size2_match:
                n1, e1 = int(size1_match.group(1)), int(size1_match.group(2))
                n2, e2 = int(size2_match.group(1)), int(size2_match.group(2))
                
                n_sim = 1.0 - min(abs(n1 - n2) / max(n1, n2, 1), 1.0)
                e_sim = 1.0 - min(abs(e1 - e2) / max(e1, e2, 1), 1.0)
                size_sim = (n_sim + e_sim) / 2
            else:
                size_sim = 0.0
            
            # 3. degree sequence similarity (25% weight)
            deg1_match = re.search(r'D\(([\d,\s]+)\)', parts1[2])
            deg2_match = re.search(r'D\(([\d,\s]+)\)', parts2[2])
            
            if deg1_match and deg2_match:
                deg1_str = deg1_match.group(1).replace(' ', '')
                deg2_str = deg2_match.group(1).replace(' ', '')
                
                if deg1_str and deg2_str:
                    deg1 = tuple(map(int, deg1_str.split(',')))
                    deg2 = tuple(map(int, deg2_str.split(',')))
                    
                    deg1_set = set(deg1)
                    deg2_set = set(deg2)
                    
                    union_size = len(deg1_set | deg2_set)
                    if union_size > 0:
                        degree_sim = len(deg1_set & deg2_set) / union_size
                    else:
                        degree_sim = 0.0
                else:
                    degree_sim = 0.0
            else:
                degree_sim = 0.0
            
            total_sim = 0.5 * wl_match + 0.25 * size_sim + 0.25 * degree_sim
            return total_sim
            
        except Exception as e:
            print(f"WARNING: canonical comparison failed {e}")
            return 0.0

    @staticmethod
    def shorten_name(name: str, max_length: int = MAX_NAME_LENGTH) -> str:
        return name if len(name) <= max_length else f"{name[:max_length-3]}..."
    
    def generate_summary_images(self, results: Dict, feature_matrix: np.ndarray, valid_files: List[str]):
        if feature_matrix.size == 0 or len(feature_matrix.shape) < 2 or feature_matrix.shape[1] < 2:
            print("WARNING: insufficient features for visualization")
            return
        
        if len(valid_files) != feature_matrix.shape[0]:
            print("WARNING: mismatch between files and feature matrix rows")
            return
    
        # feature scatter plot
        fig, ax = plt.subplots(figsize=(12, 8))
        try:
            ax.scatter(feature_matrix[:, 0], feature_matrix[:, 1],s=100, alpha=0.6, c=range(len(valid_files)), cmap='tab20')
            for i, filename in enumerate(valid_files):
                ax.annotate(filename, (feature_matrix[i, 0], feature_matrix[i, 1]),xytext=(5, 5), textcoords='offset points', fontsize=8)
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

        # canonical similarity heatmap
        if results.get('canonical_similarity_matrix'):
            fig = plt.figure(figsize=(12, 10))
            try:
                sns.heatmap(
                    results['canonical_similarity_matrix'],
                    xticklabels=valid_files,
                    yticklabels=valid_files,
                    cmap='RdYlGn',
                    square=True,
                    cbar_kws={'label': 'Structural Similarity'},
                    vmin=0, vmax=1
                )
                plt.title('Canonical Graph Similarity (isomorphism based)', fontsize=16, pad=20)
                plt.xticks(rotation=45, ha='right')
                plt.yticks(rotation=0)
                plt.tight_layout()
                plt.savefig(self.images_dir / 'canonical_similarity_heatmap.png', dpi=300, bbox_inches='tight')
            finally:
                plt.close(fig)
    
    def print_summary(self, results: Dict):
        print(f"\n{'='*60}")
        print("IR STRUCTURAL ANALYSIS RESULTS")
        print(f"{'='*60}")
        print(f"Total Files Scanned: {results['summary']['total_files']}")
        print(f"Successfully Analyzed: {results['summary']['analyzed_files']}")
        print(f"Structural Clusters: {results['summary']['num_clusters']}")
        print(f"Unique/Unmatched Files: {results['summary']['noise_files']}")

        if results.get('semantic_enrichments'):
            crypto_files = sum(1 for e in results['semantic_enrichments'].values() if e.get('crypto', {}).get('has_crypto'))
            stdlib_files = sum(1 for e in results['semantic_enrichments'].values() if e.get('stdlib', {}).get('has_stdlib'))
            
            print(f"\nSemantic Analysis:")
            print(f"  Files with Crypto: {crypto_files}")
            print(f"  Files with Stdlib Patterns: {stdlib_files}")
            
            print(f"\nCryptographic Algorithms Detected:")
            algo_counts = {}
            for enrichment in results['semantic_enrichments'].values():
                if enrichment['crypto']['has_crypto']:
                    algo = enrichment['crypto']['primary_algorithm']
                    algo_counts[algo] = algo_counts.get(algo, 0) + 1
            for algo, count in sorted(algo_counts.items(), key=lambda x: x[1], reverse=True):
                print(f"  {algo.upper()}: {count} samples")
        
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

        valid_files = results['files']
        if len(valid_files) > 1:
            sem_sim = np.array(results.get('semantic_similarity_matrix', []))
            if sem_sim.size > 0:
                pairs_found = False
                for i in range(len(valid_files)):
                    for j in range(i+1, len(valid_files)):
                        if sem_sim[i][j] > 0.8:
                            if not pairs_found:
                                print(f"\nHigh Semantic Similarity Pairs (>80%):")
                                pairs_found = True
                            print(f" {valid_files[i]} ↔ {valid_files[j]}: {sem_sim[i][j]*100:.1f}%")

        if results.get('isomorphic_groups'):
            print(f"\nIsomorphic Function Groups (identical CFG structure):")
            for group_name, files in results['isomorphic_groups'].items():
                print(f"  {group_name}: {len(files)} files")
                for f in files[:5]:
                    print(f"    • {f}")
                if len(files) > 5:
                    print(f"    ... and {len(files)-5} more")

        # compare different similarity metrics
        if len(results['files']) > 1:
            print(f"\n{'='*60}")
            print("SIMILARITY METRICS COMPARISON")
            print(f"{'='*60}")
            feature_sim = np.array(results['similarity_matrix'])
            semantic_sim = np.array(results.get('semantic_similarity_matrix', []))
            canonical_sim = np.array(results.get('canonical_similarity_matrix', []))
            
            structural_diff = []
            semantic_diff = []
            all_similar = []
            
            for i in range(len(results['files'])):
                for j in range(i+1, len(results['files'])):
                    if canonical_sim.size > 0 and feature_sim.size > 0:
                        if canonical_sim[i][j] > 0.7 and feature_sim[i][j] < 0.5:
                            structural_diff.append((i, j))
                    if semantic_sim.size > 0 and canonical_sim.size > 0:
                        if semantic_sim[i][j] > 0.7 and canonical_sim[i][j] < 0.5:
                            semantic_diff.append((i, j))
                    if semantic_sim.size > 0 and canonical_sim.size > 0 and feature_sim.size > 0:
                        if (semantic_sim[i][j] > 0.75 and canonical_sim[i][j] > 0.75 
                            and feature_sim[i][j] > 0.75):
                            all_similar.append((i, j))
            
            if structural_diff:
                print("\nStructurally Similar but Feature Different Pairs:")
                for i, j in structural_diff:
                    print(f" {results['files'][i]} ↔ {results['files'][j]}")
                    print(f" Structural: {canonical_sim[i][j]*100:.1f}% | Feature: {feature_sim[i][j]*100:.1f}% | Semantic: {semantic_sim[i][j]*100:.1f}%")
            
            if semantic_diff:
                print("\nSemantically Similar but Structurally Different Pairs:")
                for i, j in semantic_diff:
                    print(f" {results['files'][i]} ↔ {results['files'][j]}")
                    print(f" Semantic: {semantic_sim[i][j]*100:.1f}% | Structural: {canonical_sim[i][j]*100:.1f}% | Feature: {feature_sim[i][j]*100:.1f}%")
            
            if all_similar:
                print("\nHighly Similar Across All Metrics (>75%):")
                for i, j in all_similar:
                    print(f" {results['files'][i]} ↔ {results['files'][j]}")
                    print(f" Semantic: {semantic_sim[i][j]*100:.1f}% | Structural: {canonical_sim[i][j]*100:.1f}% | Feature: {feature_sim[i][j]*100:.1f}%")

        if results.get('frequent_patterns'):
            print(f"\nFrequent Code Patterns:")
            patterns = results['frequent_patterns']
            if patterns:
                print(f"  Found {len(patterns)} patterns across multiple functions")
                
                # show top 5 most common
                sorted_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:5]
                for i, (pattern, count) in enumerate(sorted_patterns, 1):
                    print(f"  {i}. Pattern: {pattern}")
                    print(f"     Appears in {count} functions")
            else:
                print(f"  no patterns found (dataset too small or diverse)")

        if results.get('file_patterns'):
            print(f"\nPattern-based Similarity:")
            file_pats = results['file_patterns']
            valid_files = results['files']
            
            # find files sharing many patterns
            for i in range(len(valid_files)):
                for j in range(i+1, len(valid_files)):
                    f1, f2 = valid_files[i], valid_files[j]
                    shared = set(file_pats.get(f1, [])) & set(file_pats.get(f2, []))
                    total = set(file_pats.get(f1, [])) | set(file_pats.get(f2, []))
                    
                    if len(total) > 0:
                        similarity = len(shared) / len(total)
                        if similarity > 0.5:
                            print(f"  {f1} ↔ {f2}: {len(shared)}/{len(total)} patterns ({similarity*100:.0f}%)")
