from typing import Dict, List, Set

from ..Constant.asm_constants import *
from ..Validator.asm_validator import *

class InformationExtractor:
    @staticmethod
    def extract_ida_metadata(content: str) -> Dict:
        file_hashes = {}
        for key, pattern in ida_patterns.items():
            match = pattern.search(content)
            if match:
                file_hashes[key] = match.group(1).strip().lower()
        return {'file_hashes': file_hashes} if file_hashes else {}
    
    @staticmethod
    def extract_strings(content: str) -> List[str]:
        return [match.strip() for match in string_pattern.findall(content) if not any(bad in match for bad in bad_string_patterns)]
    
    @staticmethod
    def extract_windows_paths(content: str) -> Dict[str, Set[str]]:
        dependency_paths = set()
        operational_files = set()
        
        for pattern in windows_path_patterns:
            for match in pattern.findall(content):
                cleaned_path = match.strip().strip('"\'')
                
                if ASMValidator.is_valid_windows_path(cleaned_path):
                    if path_validation['dependency'].search(cleaned_path.lower()):
                        dependency_paths.add(cleaned_path)
                    else:
                        operational_files.add(cleaned_path)
                    
        return {'dependency_paths': dependency_paths, 'operational_files': operational_files}
    
    #  \\\\%s\\%s\\%s\\IPC$, C:\\%s\\folder, etc.
    @staticmethod
    def extract_full_path_context(content: str, anchor_match) -> str:
        anchor_pos = anchor_match.start()
        content_len = len(content)
        path_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\\/_.-$%:')
        
        # backwards
        start = anchor_pos
        while start > 0:
            char = content[start - 1]
            
            if char in '\r\n\t ,;()[]{}':
                break
            
            if char in '"\'':
                if start >= 2 and content[start - 2] not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789':
                    start -= 1
                break
            
            if char in path_chars:
                start -= 1
            else:
                break
            
            # safety limit
            if anchor_pos - start > 200:
                break
        
        # forwards
        end = anchor_match.end()
        while end < content_len:
            char = content[end]
            
            if char in '\r\n\t ,;()[]{}':
                break
            
            if char in '"\'':
                if end + 1 < content_len and content[end + 1] in ' \r\n\t,;':
                    end += 1
                break
            
            if char in path_chars:
                end += 1
            else:
                break
            
            # safety limit
            if end - anchor_pos > 200:
                break
        
        full_path = content[start:end].strip()
        
        # clean up quotes
        if full_path.startswith('"') and full_path.endswith('"'):
            full_path = full_path[1:-1]
        elif full_path.startswith("'") and full_path.endswith("'"):
            full_path = full_path[1:-1]
        
        return full_path
    
    # ssh %s@%s -p %s, %s -flag something, etc.
    @staticmethod
    def extract_format_command_context(content: str, anchor_match) -> str:
        match_start = anchor_match.start()
        match_end = anchor_match.end()
        content_len = len(content)
        cmd_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=@:/\\.%$ ')
        
        # backwards
        start = match_start
        while start > 0:
            char = content[start - 1]
            
            if char in '\r\n\t;|&':
                break
            
            if char in '"\'`':
                if start >= 2 and content[start - 2] in ' \t;|&,(':
                    start -= 1
                break
            
            if char in '()[]{},' and content[start:start+10].strip()[:1] not in cmd_chars:
                break
            
            if char in cmd_chars or char in '()':
                start -= 1
            else:
                break
            
            # safety limit
            if match_start - start > 500:
                break
        
        # forwards
        end = match_end
        in_quotes = False
        quote_char = None
        
        while end < content_len:
            char = content[end]
            
            if char in '"\'`':
                if not in_quotes:
                    in_quotes = True
                    quote_char = char
                elif char == quote_char:
                    in_quotes = False
                    end += 1
                    break
            
            if in_quotes:
                end += 1
                continue
            
            if char in '\r\n\t;|&':
                break
            
            if char in ')]}':
                snippet = content[start:end]
                if snippet.count('(') <= snippet.count(')'):
                    break
            
            if char in cmd_chars:
                end += 1
            else:
                break
            
            # safety limit
            if end - match_start > 500:
                break
        
        full_command = content[start:end].strip()
        
        # clean up quotes
        if full_command.startswith('"') and full_command.endswith('"'):
            full_command = full_command[1:-1]
        elif full_command.startswith("'") and full_command.endswith("'"):
            full_command = full_command[1:-1]
        elif full_command.startswith("`") and full_command.endswith("`"):
            full_command = full_command[1:-1]
        
        # remove instructions
        assembly_prefixes = ['push offset', 'push', 'lea', 'mov', 'offset']
        full_command_lower = full_command.lower()
        for prefix in assembly_prefixes:
            if full_command_lower.startswith(prefix + ' '):
                full_command = full_command[len(prefix):].strip()
                if full_command.startswith(','): # remove comma
                    full_command = full_command[1:].strip()
                break
        
        return full_command
