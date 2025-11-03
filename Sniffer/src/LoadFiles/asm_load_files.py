import re

from pathlib import Path
from typing import Set, Dict

class LoadFiles:
    def load_lib(self) -> Set[str]:
        script_dir = Path(__file__).parent
        lib_file = script_dir / "asm_footprint_sniffer_lib.txt"
        lib = set()
        
        try:
            if Path(lib_file).exists():
                with open(lib_file, 'r', encoding='utf-8') as f:
                    lib = {line.strip().lower() for line in f if line.strip() and not line.startswith(('#', '==='))}
                print(f"loaded {len(lib)} lib entries from {lib_file}")
            else:
                print(f"Info: lib file '{lib_file}' not found, running without lib")
        except Exception as e:
            print(f"WARNING: error loading lib file '{lib_file}': {e}")
            
        return lib
    
    def load_custom_patterns(self) -> Dict:
        script_dir = Path(__file__).parent
        custom_file: str = script_dir / "custom_pattern.txt"
        custom_data = {
            'regex_patterns': {},
            'keyword_sets': {},
            'simple_strings': []
        }
        
        if not Path(custom_file).exists():
            print(f"Info: Custom patterns file '{custom_file}' not found, skipping!")
            return custom_data
        
        try:
            with open(custom_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # parse regex patterns
            regex_pattern = re.compile(
                r"['\"]([a-zA-Z_][a-zA-Z0-9_]*)['\"]:\s*re\.compile\s*\(\s*r?['\"](.+?)['\"]\s*(?:,\s*re\.\w+)?\s*\)",
                re.DOTALL
            )
            for match in regex_pattern.finditer(content):
                pattern_name = match.group(1)
                pattern_str = match.group(2)
                try:
                    custom_data['regex_patterns'][pattern_name] = re.compile(pattern_str, re.IGNORECASE)
                    print(f"  Loaded Regex Pattern: {pattern_name}")
                except re.error as e:
                    print(f"  WARNING: invalid regex for '{pattern_name}': {e}")
            
            # parse keyword sets
            set_pattern = re.compile(
                r"([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\{([^}]+)\}",
                re.DOTALL | re.MULTILINE
            )
            for match in set_pattern.finditer(content):
                set_name = match.group(1)
                set_content = match.group(2)
                keywords = re.findall(r"['\"]([^'\"]+)['\"]", set_content)
                if keywords:
                    custom_data['keyword_sets'][set_name] = set(keywords)
                    print(f"  Loaded Keyword Set: {set_name} ({len(keywords)} items)")
            
            # parse simple strings (lines without special syntax)
            lines = content.split('\n')
            for line in lines:
                stripped = line.strip()
                if (stripped and 
                    not stripped.startswith('#') and 
                    not stripped.startswith('//') and
                    not re.match(r'^[a-zA-Z_]+\s*[=:]\s*[{\[]', stripped) and
                    not 're.compile' in stripped and
                    not stripped.startswith('{') and
                    len(stripped) >= 2):
                    custom_data['simple_strings'].append(stripped)
            
            if custom_data['simple_strings']:
                print(f"  loaded {len(custom_data['simple_strings'])} simple strings")
            
            print(f"loaded custom patterns from {custom_file}")
            return custom_data
            
        except Exception as e:
            print(f"WARNING: error loading custom patterns file '{custom_file}': {e}")
            return custom_data
    