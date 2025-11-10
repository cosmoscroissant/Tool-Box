import json
import argparse
import re

from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict

class IOCComparator:
    def __init__(self, whitelist_file: Path = None):
        self.whitelist = self.load_whitelist(whitelist_file) if whitelist_file else set()
    
    def load_whitelist(self, whitelist_file: Path) -> Set[str]:
        whitelist = set()
        try:
            with open(whitelist_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('===') or line == 'WHITELIST':
                        continue
                    base = self.get_base_name(line)
                    if base and len(base) > 1:
                        whitelist.add(base)
                    whitelist.add(line.lower())
            print(f"Loaded {len(whitelist)} whitelist item(s).")
            return whitelist
        except Exception as e:
            print(f"Warning: could not load whitelist from {whitelist_file}: {e}")
            return set()
    
    def get_base_name(self, ioc: str) -> str:
        ioc = str(ioc).strip()
        
        # remove bullet points and leading markers
        ioc = re.sub(r'^[\*\-\>•]+\s*', '', ioc)
        ioc = ioc.strip()
        
        # remove process IDs and other prefixes
        ioc = re.sub(r'^\d+\s*-\s*', '', ioc)
        
        # remove quotes
        ioc = ioc.strip('"\'')
        
        # remove path separators
        ioc = ioc.split('\\')[-1].split('/')[-1]
        
        # remove command line arguments
        if any(ioc.lower().endswith(ext) for ext in ['.exe', '.dll', '.sys', '.bat', '.cmd']):
            ioc = ioc.split()[0] if ' ' in ioc else ioc
        
        # remove common extensions
        extensions = ['.dll', '.exe', '.sys', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.com', '.scr', '.tmp', '.msi']
        ioc_lower = ioc.lower()
        for ext in extensions:
            if ioc_lower.endswith(ext):
                ioc = ioc[:-len(ext)]
                break
        
        return ioc.lower().strip()
    
    def parse_json_file(self, json_file: Path) -> Dict[str, str]:
        try:
            with open(json_file, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            
            iocs = {}
            
            if isinstance(data, list):
                for item in data:
                    if item.get('file_hashes'):
                        for hash_type, hash_val in item['file_hashes'].items():
                            if hash_val and str(hash_val).strip():
                                hash_str = str(hash_val).strip().lower()
                                iocs[hash_str] = hash_str
                    
                    if item.get('iocs'):
                        for category, ioc_list in item['iocs'].items():
                            if isinstance(ioc_list, list):
                                for ioc in ioc_list:
                                    if ioc and str(ioc).strip():
                                        base = self.get_base_name(str(ioc))
                                        if base and len(base) > 1:
                                            if base not in iocs:
                                                iocs[base] = str(ioc)
            
            elif isinstance(data, dict):
                if data.get('file_hashes'):
                    for hash_type, hash_val in data['file_hashes'].items():
                        if hash_val and str(hash_val).strip():
                            hash_str = str(hash_val).strip().lower()
                            iocs[hash_str] = hash_str

                if data.get('iocs'):
                    for category, ioc_list in data['iocs'].items():
                        if isinstance(ioc_list, list):
                            for ioc in ioc_list:
                                if ioc and str(ioc).strip():
                                    base = self.get_base_name(str(ioc))
                                    if base and len(base) > 1:
                                        if base not in iocs:
                                            iocs[base] = str(ioc)
            
            return iocs
        except Exception as e:
            print(f"Error parsing {json_file}: {e}")
            return {}
    
    def parse_text_file(self, text_file: Path) -> Dict[str, List[str]]:
        try:
            with open(text_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = content.split('\n')
            hash_indicators = defaultdict(list)
            current_hash = ""
            
            skip_exact = {
                'Not Found!', 'Not Found', 'None', 'NOT FOUND',
                'Files Opened', 'Files Written', 'Files Deleted', 
                'Files With Modified Attributes', 'Files Dropped',
                'Registry Keys Opened', 'Registry Keys Set',
                'Calls', 'Shell Commands', 'Processes Terminated',
                'Services Opened', 'Mutexes Opened', 'Mutexes Created'
            }
            
            for line in lines:
                stripped = line.strip()
                
                if not stripped or len(stripped) < 2:
                    continue
                
                hash_match = re.match(r'^HASH:\s*(.*)$', stripped, re.IGNORECASE)
                if hash_match:
                    current_hash = hash_match.group(1).strip().lower()
                    if current_hash:
                        hash_indicators[current_hash].append(f"HASH: {current_hash}")
                    continue
                
                if re.match(r'^[=\-\*]+$', stripped):
                    continue
                
                # skip exact matches in skip list
                cleaned = stripped.lstrip('*- ').strip()
                if cleaned in skip_exact:
                    continue
                
                if re.match(r'^[A-Z\s]+:$', stripped):
                    continue
                
                if any(x in stripped for x in ['TIMESTAMP:', 'VENDOR DETECTIONS:', 'VENDOR:']):
                    continue
                
                indicator = re.sub(r'^[\*\-\>•]+\s*', '', stripped).strip()
                
                if not indicator or len(indicator) < 2:
                    continue
                
                if indicator.isdigit():
                    continue
                
                hash_indicators[current_hash].append(indicator)
            
            return dict(hash_indicators)
        except Exception as e:
            print(f"Error Reading {text_file}: {e}")
            return {}
    
    def compare(self, json_iocs: Dict[str, str], hash_indicators: Dict[str, List[str]]) -> Tuple[Dict, Dict, Dict, Dict]:
        results = defaultdict(lambda: defaultdict(set))
        whitelisted = defaultdict(lambda: defaultdict(set))
        
        for hash_val, indicators in hash_indicators.items():
            if hash_val and hash_val in json_iocs:
                if hash_val.lower() in self.whitelist:
                    whitelisted[hash_val]["[HASH_MATCH]"].add(f"HASH: {hash_val}")
                else:
                    results[hash_val]["[HASH_MATCH]"].add(f"HASH: {hash_val}")
            
            for indicator in indicators:
                if indicator.startswith("HASH:"):
                    continue
                
                ind_base = self.get_base_name(indicator)
                
                if len(ind_base) < 2:
                    continue
                
                if ind_base in json_iocs:
                    if ind_base in self.whitelist or indicator.lower() in self.whitelist:
                        whitelisted[hash_val][ind_base].add(indicator)
                    else:
                        results[hash_val][ind_base].add(indicator)
        
        results_final = {}
        hash_match_counts = {}
        whitelisted_final = {}
        whitelist_counts = {}
        
        for hash_val, base_dict in results.items():
            results_final[hash_val] = {base: sorted(list(inds)) for base, inds in base_dict.items()}
            hash_match_counts[hash_val] = len(base_dict)
        
        for hash_val, base_dict in whitelisted.items():
            whitelisted_final[hash_val] = {base: sorted(list(inds)) for base, inds in base_dict.items()}
            whitelist_counts[hash_val] = len(base_dict)
        
        return results_final, hash_match_counts, whitelisted_final, whitelist_counts
    
    def generate_json_report(self, json_file: Path, text_file: Path, results: Dict, hash_counts: Dict, whitelisted: Dict, whitelist_counts: Dict) -> Dict:
        # top 5 hash statistics
        hash_statistics = []
        sorted_hashes = sorted(hash_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for hash_val, count in sorted_hashes:
            hash_statistics.append({
                'hash': hash_val if hash_val else "NO_HASH",
                'ioc_count': count
            })
        
        # calculate totals
        total_hashes = len(results)
        total_ioc_groups = sum(hash_counts.values())
        total_indicators = sum(
            sum(len(indicators) for indicators in base_dict.values())
            for base_dict in results.values()
        )
        
        # reorganize by base_name -> {hash -> [indicators]}
        base_name_map = defaultdict(lambda: defaultdict(list))
        for hash_val, base_dict in results.items():
            for base_name, indicators in base_dict.items():
                base_name_map[base_name][hash_val] = indicators
        
        # convert for JSON
        ioc_matches = {}
        for base_name in sorted(base_name_map.keys(), key=lambda x: (x != "[HASH_MATCH]", x)):
            display_name = "[HASH MATCH]" if base_name == "[HASH_MATCH]" else base_name
            ioc_matches[display_name] = {}
            
            hash_dict = base_name_map[base_name]
            for hash_val, indicators in sorted(hash_dict.items(), 
                                              key=lambda x: hash_counts.get(x[0], 0), 
                                              reverse=True):
                display_hash = hash_val if hash_val else "NO_HASH"
                ioc_matches[display_name][display_hash] = indicators
        
        # whitelisted section
        whitelisted_matches = {}
        wl_total_indicators = 0
        if whitelisted:
            wl_total_indicators = sum(
                sum(len(indicators) for indicators in base_dict.values())
                for base_dict in whitelisted.values()
            )
            
            wl_base_name_map = defaultdict(lambda: defaultdict(list))
            for hash_val, base_dict in whitelisted.items():
                for base_name, indicators in base_dict.items():
                    wl_base_name_map[base_name][hash_val] = indicators
            
            for base_name in sorted(wl_base_name_map.keys(), key=lambda x: (x != "[HASH_MATCH]", x)):
                display_name = "[HASH MATCH]" if base_name == "[HASH_MATCH]" else base_name
                whitelisted_matches[display_name] = {}
                
                hash_dict = wl_base_name_map[base_name]
                for hash_val, indicators in sorted(hash_dict.items(),
                                                  key=lambda x: whitelist_counts.get(x[0], 0),
                                                  reverse=True):
                    display_hash = hash_val if hash_val else "NO_HASH"
                    whitelisted_matches[display_name][display_hash] = indicators
        
        return {
            'json_file': json_file.name,
            'text_file': text_file.name,
            'total_hashes': total_hashes,
            'total_ioc_groups': total_ioc_groups,
            'total_indicators': total_indicators,
            'whitelisted_total_indicators': wl_total_indicators,
            'hash_statistics': hash_statistics,
            'ioc_matches': ioc_matches,
            'whitelisted_matches': whitelisted_matches if whitelisted else {}
        }
    
    def generate_top5_json_report(self, json_file: Path, text_file: Path, results: Dict, hash_counts: Dict) -> Dict:
        sorted_hashes = sorted(hash_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        top5_data = []
        for hash_val, ioc_count in sorted_hashes:
            all_indicators = []
            ioc_groups = {}
            
            if hash_val in results:
                for base_name, indicators in results[hash_val].items():
                    ioc_groups[base_name] = indicators
                    all_indicators.extend(indicators)
            
            top5_data.append({
                'hash': hash_val if hash_val else "NO_HASH",
                'ioc_count': ioc_count,
                'total_indicators': len(all_indicators),
                'ioc_groups': ioc_groups,
                'all_indicators': sorted(list(set(all_indicators)))
            })
        
        return {
            'json_file': json_file.name,
            'text_file': text_file.name,
            'top5_hashes': top5_data
        }
    
    def generate_report(self, json_file: Path, text_file: Path, results: Dict, hash_counts: Dict, whitelisted: Dict, whitelist_counts: Dict) -> str:
        report = []
        
        # hash statistics (top 5 by IOC count, case sensitive, Windows only)
        report.append("=" * 100)
        report.append("HASH STATISTICS")
        report.append("=" * 100)
        sorted_hashes = sorted(hash_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for hash_val, count in sorted_hashes:
            display_hash = hash_val[:64] if hash_val and len(hash_val) > 64 else (hash_val if hash_val else "NO_HASH")
            report.append(f"  {display_hash}: {count} IOC(s)")
        report.append("=" * 100)
        report.append("")
        
        # report header
        report.append("=" * 100)
        report.append("IOC COMPARISON REPORT")
        report.append("=" * 100)
        report.append(f"JSON File: {json_file.name}")
        report.append(f"Text File: {text_file.name}")
        
        # calculate totals
        total_hashes = len(results)
        total_ioc_groups = sum(hash_counts.values())
        total_indicators = sum(
            sum(len(indicators) for indicators in base_dict.values())
            for base_dict in results.values()
        )
        
        report.append(f"Total Hashes with Matches: {total_hashes}")
        report.append(f"Total IOC Groups Found: {total_ioc_groups}")
        report.append(f"Total Indicators Matched: {total_indicators}")
        report.append("=" * 100)
        report.append("")
        
        # reorganize by base_name -> {hash -> [indicators]}
        base_name_map = defaultdict(lambda: defaultdict(list))
        for hash_val, base_dict in results.items():
            for base_name, indicators in base_dict.items():
                base_name_map[base_name][hash_val] = indicators
        
        # output grouped by base name (hash matches first)
        sorted_base_names = sorted(base_name_map.keys(), key=lambda x: (x != "[HASH_MATCH]", x)) # [HASH_MATCH] appears first
        
        for base_name in sorted_base_names:
            if base_name == "[HASH_MATCH]":
                display_name = "[HASH MATCH]"
            else:
                display_name = base_name
            
            report.append(f"{display_name}:")
            
            hash_dict = base_name_map[base_name]
            sorted_hashes_for_base = sorted(
                hash_dict.items(),
                key=lambda x: hash_counts.get(x[0], 0),
                reverse=True
            )
            
            for hash_val, indicators in sorted_hashes_for_base:
                display_hash = hash_val[:64] if hash_val and len(hash_val) > 64 else (hash_val if hash_val else "NO_HASH")
                report.append(f"  * {display_hash}")
                
                for indicator in indicators:
                    report.append(f"    * {indicator}")
            
            report.append("")
        
        report.append("=" * 100)
        
        # whitelist section
        if whitelisted:
            report.append("")
            report.append("=" * 100)
            report.append("WHITELISTED INDICATORS")
            report.append("=" * 100)
            
            wl_total_hashes = len(whitelisted)
            wl_total_ioc_groups = sum(whitelist_counts.values())
            wl_total_indicators = sum(
                sum(len(indicators) for indicators in base_dict.values())
                for base_dict in whitelisted.values()
            )
            
            report.append(f"Total Hashes with Whitelisted Matches: {wl_total_hashes}")
            report.append(f"Total Whitelisted IOC Groups: {wl_total_ioc_groups}")
            report.append(f"Total Whitelisted Indicators: {wl_total_indicators}")
            report.append("=" * 100)
            report.append("")
            
            wl_base_name_map = defaultdict(lambda: defaultdict(list))
            for hash_val, base_dict in whitelisted.items():
                for base_name, indicators in base_dict.items():
                    wl_base_name_map[base_name][hash_val] = indicators
            
            sorted_wl_base_names = sorted(wl_base_name_map.keys(), key=lambda x: (x != "[HASH_MATCH]", x))
            
            for base_name in sorted_wl_base_names:
                if base_name == "[HASH_MATCH]":
                    display_name = "[HASH MATCH]"
                else:
                    display_name = base_name
                
                report.append(f"{display_name}:")
                
                hash_dict = wl_base_name_map[base_name]
                sorted_hashes_for_base = sorted(
                    hash_dict.items(),
                    key=lambda x: whitelist_counts.get(x[0], 0),
                    reverse=True
                )
                
                for hash_val, indicators in sorted_hashes_for_base:
                    display_hash = hash_val[:64] if hash_val and len(hash_val) > 64 else (hash_val if hash_val else "NO_HASH")
                    report.append(f"  * {display_hash}")
                    
                    for indicator in indicators:
                        report.append(f"    * {indicator}")
                
                report.append("")
            
            report.append("=" * 100)
        
        return '\n'.join(report)

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('text_path', help='TXT file or folder containing TEXT files')
    parser.add_argument('json_path', help='JSON file or folder containing JSON files')
    parser.add_argument('-o', '--output', help='output file or directory for reports')
    parser.add_argument('--no-recursive', action='store_true', help='don\'t search subdirectories recursively')
    args = parser.parse_args()
    
    # whitelist
    script_dir = Path(__file__).parent
    whitelist_path = script_dir / 'whitelist.txt'
    
    if not whitelist_path.exists():
        whitelist_path = None
        print("Note: No whitelist.txt found in script directory!")
    
    comparator = IOCComparator(whitelist_path)

    # text files
    text_path = Path(args.text_path)
    if text_path.is_file():
        text_files = [text_path]
    else:
        pattern = "*.txt" if args.no_recursive else "**/*.txt"
        text_files = sorted(text_path.glob(pattern))
    
    if not text_files:
        print("ERROR: No text files found!")
        return
    
    print(f"Found {len(text_files)} text file(s).")
    print()
    
    # JSON files
    json_path = Path(args.json_path)
    if json_path.is_file():
        json_files = [json_path]
    else:
        pattern = "*.json" if args.no_recursive else "**/*.json"
        json_files = sorted(json_path.glob(pattern))
    
    if not json_files:
        print("ERROR: No JSON files found!")
        return
    
    print(f"Found {len(json_files)} JSON file(s).")
    
    # process all combinations
    all_results = []
    for json_file in json_files:
        json_iocs = comparator.parse_json_file(json_file)
        if not json_iocs:
            print(f"WARNING: No IOCs found in {json_file.name}!")
            continue
        
        print(f"processing {json_file.name} ({len(json_iocs)} unique IOCs including hashes)")
        
        for text_file in text_files:
            hash_indicators = comparator.parse_text_file(text_file)
            if not hash_indicators:
                print(f"  WARNING: No indicators in {text_file.name}!")
                continue
            
            results, hash_counts, whitelisted, whitelist_counts = comparator.compare(json_iocs, hash_indicators)
            
            if results or whitelisted:
                total_matches = sum(hash_counts.values())
                total_indicator_instances = sum(
                    sum(len(v) for v in base_dict.values())
                    for base_dict in results.values()
                )
                wl_matches = sum(whitelist_counts.values())
                print(f"  vs {text_file.name}: {len(results)} hash(es), {total_matches} unique IOC(s), {total_indicator_instances} match(es) [{wl_matches} whitelisted]")
                all_results.append({
                    'json_file': json_file,
                    'text_file': text_file,
                    'results': results,
                    'hash_counts': hash_counts,
                    'whitelisted': whitelisted,
                    'whitelist_counts': whitelist_counts
                })
            else:
                print(f"  vs {text_file.name}: No Matches")
    
    if not all_results:
        print("\nNo matches found across all comparisons!")
        return
    
    print(f"\nSuccessfully compared {len(all_results)} file pair(s)!")
    
    # output
    if args.output:
        output_path = Path(args.output)
        
        if output_path.is_dir() or str(output_path).endswith('/') or str(output_path).endswith('\\'):
            output_path.mkdir(parents=True, exist_ok=True)
            
            for result in all_results:
                report = comparator.generate_report(
                    result['json_file'],
                    result['text_file'],
                    result['results'],
                    result['hash_counts'],
                    result['whitelisted'],
                    result['whitelist_counts']
                )
                filename = f"{result['json_file'].stem}_vs_{result['text_file'].stem}.txt"
                output_file = output_path / filename
                output_file.write_text(report, encoding='utf-8')
                
                json_report = comparator.generate_json_report(
                    result['json_file'],
                    result['text_file'],
                    result['results'],
                    result['hash_counts'],
                    result['whitelisted'],
                    result['whitelist_counts']
                )
                json_filename = f"{result['json_file'].stem}_vs_{result['text_file'].stem}.json"
                json_output_file = output_path / json_filename
                with open(json_output_file, 'w', encoding='utf-8') as f:
                    json.dump(json_report, f, indent=2)
                
                top5_report = comparator.generate_top5_json_report(
                    result['json_file'],
                    result['text_file'],
                    result['results'],
                    result['hash_counts']
                )
                top5_filename = f"{result['json_file'].stem}_vs_{result['text_file'].stem}_top5.json"
                top5_output_file = output_path / top5_filename
                with open(top5_output_file, 'w', encoding='utf-8') as f:
                    json.dump(top5_report, f, indent=2)
            
            script_dir = Path(__file__).parent
            html_viewer = script_dir / 'IOC_visualizer.html'
            if html_viewer.exists():
                import shutil
                shutil.copy(html_viewer, output_path / 'IOC_visualizer.html')
                print(f"\nHTML Viewer Copied to: {output_path / 'IOC_visualizer.html'}")
            
            print(f"\nAll Reports Saved to: {output_path}")
        else:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                for i, result in enumerate(all_results):
                    if i > 0:
                        f.write("\n\n")
                    report = comparator.generate_report(
                        result['json_file'],
                        result['text_file'],
                        result['results'],
                        result['hash_counts'],
                        result['whitelisted'],
                        result['whitelist_counts']
                    )
                    f.write(report)
            
            if all_results:
                json_output = output_path.parent / 'ioc_comparison_report.json'
                json_report = comparator.generate_json_report(
                    all_results[0]['json_file'],
                    all_results[0]['text_file'],
                    all_results[0]['results'],
                    all_results[0]['hash_counts'],
                    all_results[0]['whitelisted'],
                    all_results[0]['whitelist_counts']
                )
                with open(json_output, 'w', encoding='utf-8') as f:
                    json.dump(json_report, f, indent=2)
            
            print(f"\nCombined Report Saved to: {output_path}")
    else:
        for i, result in enumerate(all_results):
            if i > 0:
                print("\n\n")
            print(comparator.generate_report(
                result['json_file'],
                result['text_file'],
                result['results'],
                result['hash_counts'],
                result['whitelisted'],
                result['whitelist_counts']
            ))

if __name__ == "__main__":
    main()