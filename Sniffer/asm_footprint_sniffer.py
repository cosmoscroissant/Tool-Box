import re
import sys
import argparse
import json

from pathlib import Path
from typing import List, Dict, Set, Optional

from src.Constant.asm_constants import *
from src.LoadFiles.asm_load_files import *
from src.Extractor.asm_extractor import *
from src.Validator.asm_validator import *

class IoCScanner:    
    def __init__(self):
        loader = LoadFiles()
        self.lib = loader.load_lib()
        self.custom_data = loader.load_custom_patterns()
        
        if self.custom_data['regex_patterns']:
            ioc_patterns.update(self.custom_data['regex_patterns'])
            for pattern_name in self.custom_data['regex_patterns'].keys():
                if pattern_name not in IOC_CATEGORY_ORDER:
                    IOC_CATEGORY_ORDER.append(pattern_name)
                if pattern_name not in CATEGORY_NAMES:
                    CATEGORY_NAMES[pattern_name] = pattern_name.replace('_', ' ').title()
        
        if self.custom_data['keyword_sets']:
            for set_name, keywords in self.custom_data['keyword_sets'].items():
                if hasattr(sys.modules['src.Constant.asm_constants'], set_name):
                    existing = getattr(sys.modules['src.Constant.asm_constants'], set_name)
                    if isinstance(existing, set):
                        merged = existing.copy()
                        merged.update(keywords)
                        setattr(self, set_name, merged)
                        print(f"  merged {len(keywords)} keywords into existing '{set_name}'")
                else:
                    setattr(self, set_name, keywords)
                    print(f"  created new keyword set '{set_name}'")
    
    def clean_content(self, content: str) -> str:
        return '\n'.join(line for line in content.split('\n') if not ida_exclude_pattern.match(line))

    def search_custom_strings(self, content: str) -> Set[str]:
        found_strings = set()
        
        if not self.custom_data['simple_strings']:
            return found_strings
        
        for custom_str in self.custom_data['simple_strings']:
            if custom_str.startswith('" ') and custom_str.endswith(' "'):
                # exact match with surrounding spaces
                exact_str = custom_str[2:-2]
                pattern = re.compile(r'\s' + re.escape(exact_str) + r'\s', re.IGNORECASE)
                for match in pattern.finditer(content):
                    start = max(0, match.start() - 20)
                    end = min(len(content), match.end() + 20)
                    context_match = content[start:end].strip()
                    found_strings.add(context_match)
            
            elif custom_str.startswith('"') and custom_str.endswith('"'):
                # exact match without surrounding space requirement
                exact_str = custom_str.strip('"')
                pattern = re.compile(re.escape(exact_str), re.IGNORECASE)
                for match in pattern.finditer(content):
                    start = max(0, match.start() - 10)
                    end = min(len(content), match.end() + 10)
                    context_match = content[start:end].strip()
                    found_strings.add(context_match)
            
            else:
                search_str = custom_str.strip()
                
                # case insensitively
                pattern = re.compile(re.escape(search_str), re.IGNORECASE)
                
                for match in pattern.finditer(content):
                    # extract surrounding context
                    start_pos = match.start()
                    end_pos = match.end()
                    
                    # go backwards
                    context_start = start_pos
                    chars_before = 0
                    while context_start > 0 and chars_before < MAXChars:
                        if content[context_start - 1] in '\n\r':
                            break
                        context_start -= 1
                        chars_before += 1
                    
                    # go forwards
                    context_end = end_pos
                    chars_after = 0
                    while context_end < len(content) and chars_after < MAXChars:
                        if content[context_end] in '\n\r':
                            break
                        context_end += 1
                        chars_after += 1
                    
                    # extract the match with context
                    full_match = content[context_start:context_end].strip()
                    
                    # clean up the match (remove leading/trailing special chars that aren't meaningful)
                    full_match = re.sub(r'^[;,.\s]+', '', full_match)
                    full_match = re.sub(r'[;,.\s]+$', '', full_match)
                    
                    if full_match and len(full_match) >= len(search_str):
                        found_strings.add(full_match)
        
        return found_strings
    
    def clean_command_string(self, cmd: str) -> str:
        cmd = cmd.rstrip('.,;:')
        
        if cmd.count('"') % 2 == 1:
            cmd = cmd.rstrip('"')
        if cmd.count("'") % 2 == 1:
            cmd = cmd.rstrip("'")
        
        return cmd.strip()
    
    def scan_content(self, content: str, filename: str) -> Optional[Dict]:
        try:
            result = {'file': filename}
            
            ida_metadata = InformationExtractor.extract_ida_metadata(content)
            if ida_metadata:
                result.update(ida_metadata)
            
            cleaned_content = self.clean_content(content)
            strings = InformationExtractor.extract_strings(cleaned_content)
            full_content = f"{cleaned_content}\n{chr(10).join(strings)}"
            
            all_found_iocs = {}
            
            windows_paths = InformationExtractor.extract_windows_paths(full_content)
            for path_type, paths in windows_paths.items():
                if paths:
                    all_found_iocs[path_type] = sorted(paths)

            custom_matches = self.search_custom_strings(full_content)
            if custom_matches:
                all_found_iocs['custom_strings'] = sorted(custom_matches)
                    
            for category, pattern in ioc_patterns.items():
                matches = set()
                for match in pattern.finditer(full_content):
                    if category == 'indicator_strings':
                        if match.lastindex and match.lastindex >= 1:
                            text = match.group(1).strip()
                        else:
                            continue
                    elif category in ('universal_paths', 'administrative_shares'):
                        text = InformationExtractor.extract_full_path_context(full_content, match)
                    elif category == 'format_string_commands':
                        text = InformationExtractor.extract_format_command_context(full_content, match)
                    else:
                        text = match.group().strip().strip('"\'')
                    
                    # get surrounding context for assembly noise detection
                    start = max(0, match.start() - MAXChars)
                    end = min(len(full_content), match.end() + MAXChars)
                    context = full_content[start:end]
                    
                    if ASMValidator.is_assembly_noise(text, context):
                        continue
                    
                    if category in ('windows_commands', 'linux_commands', 'powershell_cmdlets', 'command_line_strings'):
                        text = self.clean_command_string(text)
                        if len(text) < 5:
                            continue
                    
                    if ASMValidator.is_valid_ioc(text, category, self.lib):
                        matches.add(text)
                        
                if matches:
                    all_found_iocs[category] = sorted(matches)
            
            if all_found_iocs:
                result['iocs'] = {category: all_found_iocs[category] for category in IOC_CATEGORY_ORDER if category in all_found_iocs}
            
            return result if len(result) > 1 else None
            
        except Exception as e:
            return {'file': filename, 'error': str(e)}
        
    def scan_file(self, filepath: Path) -> Optional[Dict]:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return self.scan_content(content, str(filepath))
        except Exception as e:
            return {'file': str(filepath), 'error': str(e)}
    
    def scan_directory(self, directory: Path, recursive: bool = True) -> List[Dict]:
        pattern = "**/*.asm" if recursive else "*.asm"
        files = list(directory.glob(pattern))
        
        if not files:
            print(f"no .asm files found in {directory}")
            return []
            
        print(f"scanning {len(files)} files...")
        results = []
        
        for i, filepath in enumerate(files, 1):
            if i % 25 == 0:
                print(f"Progress: {i}/{len(files)} files processed")
                
            result = self.scan_file(filepath)
            if result:
                results.append(result)
                
        return results
    
    def generate_report(self, results: List[Dict], format_type: str = 'text') -> str:
        if format_type == 'json':
            return json.dumps(results, indent=2)
        
        total_files = len(results)
        files_with_iocs = sum(1 for r in results if r.get('iocs'))
        files_with_hashes = sum(1 for r in results if r.get('file_hashes'))
        files_with_errors = sum(1 for r in results if r.get('error'))
        
        category_counts = {}
        for result in results:
            if result.get('iocs'):
                for category, iocs in result['iocs'].items():
                    category_counts[category] = category_counts.get(category, 0) + len(iocs)
        
        report = [
            "=" * 80,
            f"Sniffer Report",
            "=" * 80,
            "",
            "SUMMARY",
            "-" * 40,
            f"Total Files Processed: {total_files}",
            f"Files with IoCs: {files_with_iocs}",
            f"Files with Hashes: {files_with_hashes}",
            f"Files with Errors: {files_with_errors}",
            ""
        ]
        
        if category_counts:
            report.extend(["IoC CATEGORIES", "-" * 40])
            for category in IOC_CATEGORY_ORDER:
                if category in category_counts:
                    report.append(f"{CATEGORY_NAMES[category]}: {category_counts[category]}")
            report.append("")
        
        report.extend(["DETAILED RESULTS", "=" * 80])
        
        for result in results:
            if result.get('error'):
                report.extend([f"ERROR - {result['file']}", f"  Error: {result['error']}", ""])
                continue
                
            report.extend([f"File: {result['file']}", "-" * 60])
                
            if result.get('file_hashes'):
                report.append("File Hashes:")
                for hash_type, hash_value in result['file_hashes'].items():
                    report.append(f"{hash_type.upper()}: {hash_value}")
                report.append("")
                
            if result.get('iocs'):
                for category in IOC_CATEGORY_ORDER:
                    if category in result['iocs']:
                        report.append(f"{CATEGORY_NAMES[category]}:")
                        for ioc in result['iocs'][category]:
                            report.append(f"{ioc}")
                        report.append("")
            
            report.append("")
            
        return '\n'.join(report)

    def save_results_json(self, results: List[Dict], output_file: Path) -> None:
        try:
            output_file.write_text(json.dumps(results, indent=2))
            print(f"JSON results saved to: {output_file}")
        except Exception as e:
            print(f"Error Saving JSON Results: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('path', help='path to .asm file or directory')
    parser.add_argument('-r', '--recursive', action='store_true', help='scan recursively')
    parser.add_argument('-o', '--output', help='output file path')
    parser.add_argument('-f', '--format', choices=['json', 'text'], default='text', help='output format (default: text)')    
    args = parser.parse_args()
    
    path = Path(args.path)
    if not path.exists():
        print(f"ERROR: Path '{args.path}' does not exist", file=sys.stderr)
        sys.exit(1)
    
    scanner = IoCScanner()
    
    if path.is_file():
        if path.suffix.lower() != '.asm':
            print(f"ERROR: '{args.path}' is not a .asm file", file=sys.stderr)
            sys.exit(1)
        result = scanner.scan_file(path)
        results = [result] if result else []
    elif path.is_dir():
        results = scanner.scan_directory(path, args.recursive)
    else:
        print(f"ERROR: '{args.path}' is not a file or directory", file=sys.stderr)
        sys.exit(1)
    
    if not results:
        print("no IoCs found in the scanned files")
        return
    
    report = scanner.generate_report(results, args.format)
    
    json_output = Path(args.output).parent / 'asm_footprint_result.json' if args.output else Path('asm_footprint_result.json')
    scanner.save_results_json(results, json_output)
    
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"report saved to: {args.output}")
        except Exception as e:
            print(f"error writing to {args.output}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(report)


if __name__ == "__main__":
    main()