from ..Constant.asm_constants import *
from ..LoadFiles.asm_load_files import *

class ASMValidator:
    @staticmethod
    def is_libed(text: str, lib: Set[str]) -> bool:
        if not lib:
            return False
        text_lower = text.lower()
        return any(term in text_lower for term in lib)
    
    @staticmethod
    def is_valid_windows_path(path: str) -> bool:
        if (len(path) < 6 or 
            any(pattern in path for pattern in ['%s', '%d', '%c', '%x', '%y', ':%', '@%']) or
            path_validation['go_module'].search(path)):
            return False
            
        return (path_validation['suspicious_path'].search(path) or 
                path.startswith(('\\\\', '//')) or 
                (len(path) > 4 and path[1:3] == ':[/\\]' and 
                (path.count('\\') >= 2 or path.count('/') >= 2)) or
                path.upper().startswith('HKEY_'))
    
    @staticmethod
    def is_valid_ioc(text: str, category: str, lib: Set[str] = None) -> bool:
        if not text or len(text) < 3:
            return False
        
        if '...' in text or any(text.endswith(bad) for bad in bad_endings):
            return False
        
        if lib and ASMValidator.is_libed(text, lib):
            return False
        
        if category in ('protocols_full', 'urls'):
            if text.startswith(format_prefixes) or text.endswith(format_prefixes):
                return False
            valid_protocols = ('http://', 'https://', 'ftp://', 'socks4://', 'socks5://', 'ssh://')
            return text.startswith(valid_protocols) and len(text) > 10
        
        if category == 'universal_paths':
            if len(text) < 3:
                return False
            
            has_backslash = '\\' in text
            is_unc = text.startswith('\\\\')
            is_drive = len(text) > 2 and text[1] == ':'
            
            if not (has_backslash or is_unc or is_drive):
                return False
            
            if any(asm_tokens in text.lower() for asm_tokens in ['offset', 'loc_', 'sub_', 'var_', 'ptr']):
                return False
            
            return True

        if category == 'administrative_shares':
            if not text.startswith('\\\\'):
                return False
            
            valid_shares = ['$', 'IPC$', 'ADMIN$', 'PRINT$', 'NETLOGON', 'SYSVOL']
            return any(share in text.upper() for share in valid_shares)
        
        if category == 'openssh_full':
            return '@openssh.com' in text.lower()
        
        if category == 'files':
            return not text.startswith('.') and '.' in text and len(text.split('.', 1)[0]) > 0
        
        if category == 'suspicious_string':
            # accept *@* pattern
            if '@' not in text or len(text) < 3:
                return False
            
            # reject assembly noise
            if re.search(r'\bat\s+[0-9A-Fa-f]+', text, re.IGNORECASE):  # "at 0000A0"
                return False
            
            parts = text.split('@')
            # must have something before and after @
            return len(parts[0]) >= 1 and len(parts[1]) >= 1
        
        if category in ('bitcoin_wallets', 'ethereum_wallets', 'monero_wallets'):
            return len(text) >= 26  # minimum crypto wallet length
        
        if category in ('windows_commands', 'linux_commands', 'powershell_cmdlets'):
            stripped = text.strip()
            stripped_lower = stripped.lower()
            
            cpp_indicator = ['constructor', 'destructor', 'descriptor', 'exception', 'template', 'namespace', 'operator', 'virtual']
            if any(indicator in stripped_lower for indicator in cpp_indicator):
                return False
            
            # false for "word : word" pattern, "type : MS Windows" vs "type file.txt"
            if re.search(r'^\w+\s*:\s*\w+', stripped):
                return False
            
            technical_descriptions = ['incomplete', 'invalid', 'literal', 'dynamic', 'bit lengths', 'stored block', 'following']
            if any(desc in stripped_lower for desc in technical_descriptions):
                return False
            
            # might change length later
            if len(stripped) < 4 or len(stripped) > 300:
                return False
            
            """
                a single word without any argument, it's suspicious
                allow if it has file extensions, paths, or flags
            """
            if ' ' not in stripped:
                return False
            
            # has arguments, check if they look legitimate
            words = stripped.split()
            if len(words) >= 2:
                # Check if second word looks like a valid argument
                arg = words[1]
                
                looks_valid = (
                    arg.startswith(('-', '/', '+', '\\', '.')) or  # flags or paths
                    any(ext in arg.lower() for ext in ['.exe', '.dll', '.txt', '.bat', '.ps1', '.sh']) or  # files
                    '/' in arg or '\\' in arg or  # paths
                    re.match(r'^\d+\.\d+\.\d+\.\d+', arg) or  # IP
                    arg.startswith(('http://', 'https://')) or  # URL
                    arg.isdigit() or  # PID or number
                    '@' in arg or  # user@host
                    ':' in arg  # host:port or C:\path
                )
                
                if not looks_valid:
                    return False
            
            return True
        
        if category == 'format_string_commands':
            if not ('%s' in text or '%d' in text or '%x' in text or '%X' in text):
                return False
            
            if not ' -' in text:
                return False
            
            if len(text) < 5 or len(text) > 500:
                return False
            
            if any(noise in text.lower() for noise in ['type descriptor', 'offset loc_', 'sub_']):
                return False
            
            return True

        if category == 'command_line_strings':
            cleaned = text.strip('"\'`')
            return len(cleaned) > 10 and not cleaned.startswith(('%s', '%d', '%c'))
        
        if category == 'indicator_strings':
            if len(text) < 2 or len(text) > 200:
                return False
            
            if text.startswith(('%s', '%d', '%c', '%x')) or '%' in text[:3]:
                return False
            
            if text.lower() in ('sub_', 'loc_', 'var_', 'arg_', 'unk_'):
                return False
            
            return True
    
        return True
    
    @staticmethod
    def is_assembly_noise(text: str, context: str = '') -> bool:
        text_lower = text.lower().strip()
        
        for pattern in assembly_noise_patterns:
            if pattern.search(text):
                return True
        
        if ' ' not in text_lower and context:
            context_lower = context.lower()
            
            if any(keyword in context_lower for keyword in assembly_context_keywords):
                return True
            
            # "Type : MS Windows" or "Type Descriptor"
            if re.search(rf'\b{re.escape(text_lower)}\s*[:]\s*\w+', context_lower):
                return True
            if re.search(rf'\b{re.escape(text_lower)}\s+descriptor', context_lower):
                return True
        
        # filter out certain phrases, might change later
        false_positive_phrases = [
            r'^type\s+descriptor',
            r'^type\s*:\s*ms\s+windows',
            r'^copy\s+constructor',
            r'incomplete\s+dynamic',
            r'invalid\s+stored',
            r'bit\s+lengths\s+tree',
            r'class\s+exception',
            r'addresses\s+following',
            r'type\s+description',
            r"type\s+['\"]class",
            r'following\s+type',
            r'literal/length\s+tree',
        ]
        
        for pattern in false_positive_phrases:
            if re.search(pattern, text_lower):
                return True
        
        return False
    