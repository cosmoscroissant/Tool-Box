import re
import math

from datetime import datetime
from typing import List, Dict, Tuple

from ..Constant.asm_constants import *

class ASMGenerator:
    @staticmethod
    def _sanitize_string(text: str) -> str:
        if not text:
            return ""
        
        # escape backslashes first
        text = text.replace('\\', '\\\\')

        # escape double quotes
        text = text.replace('"', '\\"')

        # escape control characters
        text = text.replace('\n', '\\n')
        text = text.replace('\r', '\\r')
        text = text.replace('\t', '\\t')
        
        return text
    
    # calculate Shannon entropy for string prioritization
    @staticmethod
    def _calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        
        entropy = 0.0
        text_len = len(text)
        
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        for count in freq.values():
            prob = count / text_len
            if prob > 0:
                entropy -= prob * math.log2(prob)
        
        return entropy
    
    @staticmethod
    def _prioritize_strings(strings: List[str]) -> List[str]:
        if not strings:
            return []
        
        scored_strings = []
        for s in strings:
            entropy = ASMGenerator._calculate_entropy(s)
            length_score = min(len(s) / 50, 1.0)
            penalty = 0
            common_patterns = ['http', 'www', 'com', 'exe', 'dll', 'tmp', 'temp', 'test']

            for pattern in common_patterns:
                if pattern in s.lower():
                    penalty += 0.1
            
            score = (entropy * 0.6 + length_score * 0.4) - penalty
            scored_strings.append((score, s))
        
        scored_strings.sort(reverse=True, key=lambda x: x[0])
        return [s for _, s in scored_strings]
    
    @staticmethod
    def _deduplicate_strings(strings: List[str]) -> List[str]:
        if not strings:
            return []
        
        # remove duplicates (case insensitive)
        seen = set()
        unique = []
        for s in strings:
            s_lower = s.lower()
            if s_lower not in seen:
                seen.add(s_lower)
                unique.append(s)
        
        # remove substrings
        filtered = []
        for i, s1 in enumerate(unique):
            is_substring = False
            for j, s2 in enumerate(unique):
                if i != j and len(s1) < len(s2) and s1.lower() in s2.lower():
                    is_substring = True
                    break
            if not is_substring:
                filtered.append(s1)
        
        return filtered
    
    @staticmethod
    def _generate_string_definitions(all_iocs: Dict[str, List[str]]) -> Tuple[List[str], Dict[str, List[str]]]:
        """
            nocase: case insensitive matching
            wide: UTF-16LE (two bytes per character)
            ascii: explicit ASCII (default, but good for clarity with 'wide')
            fullword: match only when delimited by non alphanumeric chars
        """
        strings_section = []
        category_vars = {}
        string_counter = 0
        
        string_configs = {
            'protocols_full': {'modifier': 'nocase ascii', 'prefix': 'url'},
            'urls': {'modifier': 'nocase ascii', 'prefix': 'url'},
            'domains': {'modifier': 'nocase ascii', 'prefix': 'domain'},
            'universal_paths': {'modifier': 'nocase wide ascii', 'prefix': 'path'},
            'operational_files': {'modifier': 'nocase wide ascii', 'prefix': 'file'},
            'dependency_paths': {'modifier': 'nocase wide ascii', 'prefix': 'dep'},
            'administrative_shares': {'modifier': 'nocase wide ascii', 'prefix': 'share'},
            'files': {'modifier': 'nocase ascii', 'prefix': 'fname'},
            'main_patterns': {'modifier': 'nocase ascii', 'prefix': 'func'},
            'ssh_patterns': {'modifier': 'nocase ascii', 'prefix': 'ssh'},
            'openssh_full': {'modifier': 'nocase ascii', 'prefix': 'openssh'},
            'suspicious_string': {'modifier': 'nocase ascii', 'prefix': 'susp'},
            'bitcoin_wallets': {'modifier': 'ascii', 'prefix': 'btc'},
            'ethereum_wallets': {'modifier': 'ascii', 'prefix': 'eth'},
            'monero_wallets': {'modifier': 'ascii', 'prefix': 'xmr'},
            'windows_commands': {'modifier': 'nocase ascii', 'prefix': 'wcmd'},
            'linux_commands': {'modifier': 'nocase ascii', 'prefix': 'lcmd'},
            'powershell_cmdlets': {'modifier': 'nocase ascii', 'prefix': 'ps'},
            'command_line_strings': {'modifier': 'nocase ascii', 'prefix': 'cmdline'},
            'format_string_commands': {'modifier': 'nocase ascii', 'prefix': 'fmt'},
            'custom_strings': {'modifier': 'nocase ascii', 'prefix': 'custom'},
            'indicator_strings': {'modifier': 'nocase ascii', 'prefix': 'ind'},
        }
        
        for category, iocs in all_iocs.items():
            if category not in string_configs:
                config = {'modifier': 'nocase ascii', 'prefix': 'str'}
            else:
                config = string_configs[category]
            
            valid_iocs = [
                ioc for ioc in iocs 
                if MIN_STRING_LENGTH <= len(ioc) <= MAX_STRING_LENGTH
            ]
            
            valid_iocs = ASMGenerator._deduplicate_strings(valid_iocs)
            valid_iocs = ASMGenerator._prioritize_strings(valid_iocs)
            
            valid_iocs = valid_iocs[:MAX_STRINGS_PER_CATEGORY]
            
            if not valid_iocs:
                continue
            
            category_vars[category] = []
            
            for ioc in valid_iocs:
                var_name = f"${config['prefix']}_{string_counter}"
                category_vars[category].append(var_name)
                
                sanitized = ASMGenerator._sanitize_string(ioc)
                
                string_def = f'{var_name} = "{sanitized}"'
                if config['modifier']:
                    string_def += f' {config["modifier"]}'
                
                strings_section.append(string_def)
                string_counter += 1
        
        return strings_section, category_vars
    
    @staticmethod
    def _generate_condition(category_vars: Dict[str, List[str]], total_strings: int) -> str:
        if total_strings == 0:
            return "false"
        
        high_conf = []
        for category in ['bitcoin_wallets', 'ethereum_wallets', 'monero_wallets']:
            if category in category_vars:
                high_conf.extend(category_vars[category])
        
        medium_conf = []
        for category in ['windows_commands', 'linux_commands', 'powershell_cmdlets', 'protocols_full', 'urls', 'administrative_shares', 'format_string_commands']:
            if category in category_vars:
                medium_conf.extend(category_vars[category][:10])
        
        low_conf = []
        for category in ['domains', 'files', 'suspicious_string', 'custom_strings', 'indicator_strings']:
            if category in category_vars:
                low_conf.extend(category_vars[category][:5])
        
        tier_conditions = []
        
        # Tier 1: any high confidence indicator
        if high_conf:
            if len(high_conf) == 1:
                tier_conditions.append(f"        {high_conf[0]}")
            else:
                hc_set = " or ".join(high_conf[:10])
                tier_conditions.append(f"        ({hc_set})")
        
        # Tier 2: multiple medium confidence indicators
        if medium_conf:
            threshold = min(3, max(2, len(medium_conf) // 3))
            if len(medium_conf) == 1:
                tier_conditions.append(f"        {medium_conf[0]}")
            else:
                tier_conditions.append(f"        {threshold} of ({', '.join(medium_conf)})")
        
        # Tier 3: low and medium combination
        if low_conf and medium_conf:
            low_threshold = min(3, max(2, len(low_conf) // 2))
            if len(low_conf) >= 2:
                tier_conditions.append(f"        ({low_threshold} of ({', '.join(low_conf)}) and 1 of ({', '.join(medium_conf[:5])}))")
        
        # Tier 4: broad match (many strings overall)
        if total_strings >= 10:
            threshold = min(5, max(3, total_strings // 5))
            tier_conditions.append(f"        {threshold} of them")
        
        # fallback
        if not tier_conditions:
            if total_strings >= 3:
                threshold = max(2, total_strings // 3)
                tier_conditions.append(f"        {threshold} of them")
            else:
                tier_conditions.append("        any of them")
        
        return " or\n\n".join(tier_conditions)
    
    @staticmethod
    def generate_yara_rule(results: List[Dict], rule_name_suffix: str = "") -> str:
        if not results:
            return "/* no results provided for YARA rule generation */"
        
        all_iocs = {}
        file_hashes = {}
        sample_files = []
        
        for result in results:
            if result.get('file_hashes'):
                file_hashes.update(result['file_hashes'])
            
            if result.get('file'):
                sample_files.append(result['file'])
            
            if not result.get('iocs'):
                continue
            
            for category, iocs in result['iocs'].items():
                if category not in all_iocs:
                    all_iocs[category] = []
                all_iocs[category].extend(iocs)
        
        if not all_iocs:
            return "/* no IOCs found in analysis results */"
        
        # rule name (max 128 chars, alphanumeric and underscore)
        timestamp = datetime.now().strftime("%Y%m%d")
        rule_name = f"ASM_Footprint_{timestamp}"
        if rule_name_suffix:
            safe_suffix = re.sub(r'[^a-zA-Z0-9_]', '_', rule_name_suffix)
            rule_name += f"_{safe_suffix}"
        rule_name = rule_name[:128]
        
        meta_lines = [
            '    meta:',
            '        description = "Auto-Generated YARA Rule from ASM Footprint Analysis"',
            '        author = "ASM Footprint Sniffer"',
            f'        date = "{datetime.now().strftime("%Y-%m-%d")}"',
            f'        version = "1.0"',
        ]
        
        if file_hashes:
            if 'sha256' in file_hashes:
                meta_lines.append(f'        sample_sha256 = "{file_hashes["sha256"]}"')
            if 'md5' in file_hashes:
                meta_lines.append(f'        sample_md5 = "{file_hashes["md5"]}"')
        
        category_stats = {cat: len(iocs) for cat, iocs in all_iocs.items()}
        total_iocs = sum(category_stats.values())
        meta_lines.append(f'        total_indicators = "{total_iocs}"')
        meta_lines.append(f'        categories = "{len(category_stats)}"')
        
        # generate strings
        string_lines, category_vars = ASMGenerator._generate_string_definitions(all_iocs)
        
        if not string_lines:
            return "/* no valid strings generated for YARA rule */"
        
        strings_section = ['    strings:']
        for line in string_lines:
            strings_section.append(f'        {line}')
        
        # generate condition
        total_strings = len(string_lines)
        condition_text = ASMGenerator._generate_condition(category_vars, total_strings)
        
        # assemble rule
        yara_parts = [
            f"rule {rule_name}",
            "{",
            "\n".join(meta_lines),
            "",
            "\n".join(strings_section),
            "",
            "    condition:",
            condition_text,
            "}"
        ]
        
        yara_rule = '\n'.join(yara_parts)
        
        header = [
            "/*",
            " * YARA Rule: " + rule_name,
            " * Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            " * ",
            f" * Auto-Generated from Analysis of {len(results)} Sample(s)",
            f" * Total IOCs: {total_iocs} across {len(category_stats)} categories",
            " * ",
            " * Categories:",
        ]
        
        for category, count in sorted(category_stats.items(), key=lambda x: x[1], reverse=True):
            header.append(f" *   {category}: {count}")
        
        header.extend([
            " * ",
            " * Detection Strategy:",
            " *   Tier 1: High Confidence indicators (crypto wallets)",
            " *   Tier 2: Medium Confidence (commands, URLs, specific paths)",
            " *   Tier 3: Combined Low and Medium Confidence",
            " *   Tier 4: Broad Match (multiple indicators)",
            " */",
            ""
        ])
        
        return '\n'.join(header) + yara_rule