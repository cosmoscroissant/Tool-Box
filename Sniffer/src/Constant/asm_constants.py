import re

IOC_CATEGORY_ORDER = [
    'protocols_full',
    'urls',
    'domains',
    'universal_paths',
    'administrative_shares',
    'files',
    'main_patterns',
    'ssh_patterns',
    'openssh_full',
    'operational_files',
    'dependency_paths',
    'suspicious_string',
    'bitcoin_wallets',
    'ethereum_wallets',
    'monero_wallets',
    'windows_commands',
    'linux_commands',
    'powershell_cmdlets',
    'command_line_strings',
    'format_string_commands',
    'custom_strings',
    'indicator_strings',
]

CATEGORY_NAMES = {
    'protocols_full': 'Protocol URLs',
    'urls': 'URLs',
    'domains': 'Domains',
    'universal_paths': 'Universal Paths',
    'administrative_shares': 'Administrative Shares',
    'files': 'Files',
    'main_patterns': 'Main Functions/Variables',
    'ssh_patterns': 'SSH Client References',
    'openssh_full': 'OpenSSH Full References',
    'operational_files': 'Operational Files',
    'dependency_paths': 'Dependency/Library Paths',
    'suspicious_string': 'Suspicious String (email, name/password, etc.)',
    'bitcoin_wallets': 'Bitcoin Wallet Addresses',
    'ethereum_wallets': 'Ethereum Wallet Addresses',
    'monero_wallets': 'Monero Wallet Addresses',
    'windows_commands': 'Windows Commands',
    'linux_commands': 'Linux Commands',
    'powershell_cmdlets': 'PowerShell Cmdlets',
    'command_line_strings': 'Command Line Strings',
    'format_string_commands': 'Format String Commands',
    'custom_strings': 'Custom String Matches',
    'indicator_strings': 'Indicator Based Strings',
}

ioc_patterns = {
    'protocols_full': re.compile(
        r'\b(?:https?|ftp|socks[45]?|ssh)://[a-zA-Z0-9._-]+(?:\.[a-zA-Z]{2,})?(?::[0-9]+)?(?:/[^\s"\'<>]*)?',
        re.IGNORECASE
    ),
    'urls': re.compile(r'\b(?:https?|ftp|socks[45]?)://[^\s"\'<>]{8,}', re.IGNORECASE),
    'domains': re.compile(
        r'\b[a-zA-Z0-9.-]+\.(?:tk|ml|ga|cf|top|click|download|security|update|onion|com|net|org|io|dev|ai|xyz)\b',
        re.IGNORECASE
    ),

    'universal_paths': re.compile(
        r'(?:'
        r'\\+[A-Z]?\$|' # Match \IPC$, \C$, \\ADMIN$, etc.
        r'[A-Z]:\\|'  # Match C:\, D:\, etc.
        r'\\\\|' # Match \\ (UNC start)
        r'\\[a-zA-Z0-9_.-]{2,}' # Match \folder, \Windows, etc.
        r')',
        re.IGNORECASE
    ),
    'administrative_shares': re.compile(
        r'\\\\[a-zA-Z0-9_.-]+\\(?:'
        r'[A-Z]\$|'  # drive shares: C$, D$, etc.
        r'ADMIN\$|IPC\$|PRINT\$|FAX\$|'  # built in shares
        r'NETLOGON|SYSVOL|'  # domain controller shares
        r'[a-zA-Z0-9_-]+\$'  # any custom administrative share ending with $
        r')(?:\\[^\s"\'<>|]*)?',
        re.IGNORECASE
    ),

    'files': re.compile(r'\b[a-zA-Z0-9_.-]+\.(?:exe|dll|scr|bat|cmd|pif|com|vbs|js|jar|zip|rar|7z|php|ps1|sh)\b', re.IGNORECASE),
    'main_patterns': re.compile(r'\b(?:main\.[a-zA-Z0-9_]+|main_[a-zA-Z0-9_]+|_main[a-zA-Z0-9_]*)\b', re.IGNORECASE),
    'ssh_patterns': re.compile(r'\b[a-zA-Z0-9_]*SSH(?:Client|Connection|Session)[a-zA-Z0-9_]*\b', re.IGNORECASE),
    'openssh_full': re.compile(r'\b[a-zA-Z0-9._-]+@openssh\.com\b', re.IGNORECASE),
    'suspicious_string': re.compile(r'\b[a-zA-Z0-9._%+-]{2,}@[a-zA-Z0-9.-]+\b', re.IGNORECASE),
    'bitcoin_wallets': re.compile(r'\b(?:bc1|[13])[a-zA-Z0-9]{25,62}\b'),
    'ethereum_wallets': re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
    'monero_wallets': re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'),

    'windows_commands': re.compile(
        r'\b(icacls\s+[^\r\n]{3,200}|'
        r'net(?:\.exe)?\s+(?:user|share|use|stop|start|localgroup|accounts|group|session|file|view|time|config|statistics|print|send|name|computer|help)[^\r\n]{0,200}|'
        r'sc(?:\.exe)?\s+(?:create|delete|config|query|start|stop|pause|interrogate|qc|qdescription|getdisplayname|getkeyname|enumdepend)[^\r\n]{0,200}|'
        r'reg(?:\.exe)?\s+(?:add|delete|query|copy|save|restore|load|unload|compare|export|import|flags)[^\r\n]{0,200}|'
        r'wmic\s+[^\r\n]{3,200}|'
        r'powershell(?:\.exe)?\s+[^\r\n]{3,200}|'
        r'cmd(?:\.exe)?\s+/[cCkK]\s+[^\r\n]{3,200}|'
        r'taskkill\s+[^\r\n]{3,200}|'
        r'schtasks\s+[^\r\n]{3,200}|'
        r'netsh\s+[^\r\n]{3,200}|'
        r'certutil\s+[^\r\n]{3,200}|'
        r'bitsadmin\s+[^\r\n]{3,200}|'
        r'bcdedit\s+[^\r\n]{3,200}|'
        r'vssadmin\s+[^\r\n]{3,200}|'
        r'wbadmin\s+[^\r\n]{3,200}|'
        r'rundll32(?:\.exe)?\s+[^\r\n]{3,200}|'
        r'regsvr32(?:\.exe)?\s+[^\r\n]{3,200}|'
        r'mshta(?:\.exe)?\s+[^\r\n]{3,200}|'
        r'(?:c|w)script(?:\.exe)?\s+[^\r\n]{3,200}|'
        r'msiexec(?:\.exe)?\s+[^\r\n]{3,200}|'
        r'xcopy\s+[^\r\n]{3,200}|'
        r'robocopy\s+[^\r\n]{3,200}|'
        r'del\s+(?:/[A-Z]\s+)?[^\r\n]{2,200}|'
        r'copy\s+(?:/[A-Z]\s+)?[^\r\n\\]{3,200}\\[^\r\n]{1,200}|'
        r'move\s+[^\r\n]{3,200}|'
        r'mkdir\s+[^\r\n]{2,200}|'
        r'rmdir\s+[^\r\n]{2,200}|'
        r'attrib\s+[+\-][a-z]+\s+[^\r\n]{1,200}|'
        r'type\s+[^\r\n:]{3,200}\.[a-z]{2,4}[^\r\n]{0,100}|'
        r'echo\s+[^\r\n]{3,200}|'
        r'findstr\s+[^\r\n]{3,200}|'
        r'ipconfig\s+[^\r\n]{0,200}|'
        r'netstat\s+[^\r\n]{0,200}|'
        r'nslookup\s+[^\r\n]{3,200}|'
        r'ping\s+(?:-[a-z]\s+)?[\w\.\-]+[^\r\n]{0,100}|'
        r'tracert\s+[\w\.\-]+[^\r\n]{0,100})',
        re.IGNORECASE
    ),
    'linux_commands': re.compile(
        r'\b(chmod\s+[0-7]{3,4}\s+[^\r\n]{1,200}|'
        r'chown\s+[\w\-]+(?::[\w\-]+)?\s+[^\r\n]{1,200}|'
        r'wget\s+(?:-[a-zA-Z]\s+)?https?://[^\r\n]{5,200}|'
        r'curl\s+(?:-[a-zA-Z]+\s+)?[^\r\n]{3,200}|'
        r'nc\s+-[^\r\n]{1,200}|'
        r'bash\s+-c\s+[^\r\n]{3,200}|'
        r'sh\s+-c\s+[^\r\n]{3,200}|'
        r'python[23]?\s+[^\r\n]{3,200}|'
        r'perl\s+[^\r\n]{3,200}|'
        r'iptables\s+-[^\r\n]{1,200}|'
        r'systemctl\s+(?:start|stop|enable|disable|restart|status)\s+[^\r\n]{1,200}|'
        r'kill\s+-\d+\s+\d+|'
        r'crontab\s+-[el]\s*[^\r\n]{0,200}|'
        r'useradd\s+[\w\-]+[^\r\n]{0,200}|'
        r'ssh\s+[\w\-]+@[^\r\n]{3,200}|'
        r'scp\s+[^\r\n]{5,200}|'
        r'tar\s+-[a-z]+\s+[^\r\n]{3,200}|'
        r'rm\s+-[rf]+\s+[^\r\n]{2,200}|'
        r'cat\s+/[^\r\n]{3,200}|'
        r'grep\s+(?:-[a-zA-Z]+\s+)?[^\r\n]{3,200}|'
        r'find\s+/[^\r\n]{3,200}|'
        r'echo\s+[^\r\n]{3,200})',
        re.IGNORECASE
    ),
    'powershell_cmdlets': re.compile(
        r'\b(?:Invoke-|Get-|Set-|New-|Remove-|Start-|Stop-|Add-|Enable-|Disable-)'
        r'[A-Z][a-zA-Z]+'
        r'(?:\s+(?:-[A-Za-z]+\s+)?[^\r\n;|]{1,200})?',  # capture parameters and arguments
        re.IGNORECASE
    ),
    'command_line_strings': re.compile(
        r'(?:["\'`])(?:(?:cmd|powershell|bash|sh|wscript|cscript)\s+[^"\'`]{5,300}|'
        r'[a-zA-Z]:\\[^"\'`]{10,300}|'
        r'(?:/bin/|/usr/bin/)[^"\'`]{5,300})'
        r'(?:["\'`])',
        re.IGNORECASE
    ),
    'format_string_commands': re.compile(
        r'(?:'
        # commands with format strings and flags: %s -flag or %s@%s -flag
        r'(?:ssh|scp|curl|wget|nc|netcat|python|perl|bash|sh|cmd|powershell|psexec|wmic|net|sc|reg|certutil|bitsadmin)\s+'
        r'(?:%[sdxX][@:/\\]?)+\s+-[a-zA-Z0-9]+[^\r\n]{0,300}|'
        # generic %s -anything (captures any command pattern)
        r'%[sdxX]\s+-[a-zA-Z0-9]+[^\r\n]{0,300}|'
        # multiple format strings with flags: %s@%s -p %s
        r'(?:%[sdxX][@:/\\.]?)+\s+-[a-zA-Z][^\r\n]{0,300}'
        r')',
        re.IGNORECASE
    ),

    'indicator_strings': re.compile(
        r'(?:ServiceName|DisplayName|Description|ImagePath|CommandLine|FileName|'
        r'KeyName|ValueName|RegistryPath|RegistryKey|RegKey|'
        r'MutexName|Mutex|PipeName|Pipe|EventName|Event|'
        r'ProcessName|Process|ModuleName|Module|'
        r'ClassName|Class|WindowName|Window|'
        r'UserName|User|Password|Pass|'
        r'Host|Server|Domain|URL|Path|'
        r'TaskName|JobName|ScheduledTask|'
        r'CertName|Certificate|Thumbprint|'
        r'ShareName|Share|NetworkPath|'
        r'DllName|Library|Export|Import)\s*'
        r'[;,]\s*["\']([^"\']+)["\']',
        re.IGNORECASE
    ),
}

ida_patterns = {
    'sha256': re.compile(r';\s*Input SHA256\s*:\s*([A-Fa-f0-9]{64})', re.IGNORECASE),
    'md5': re.compile(r';\s*Input MD5\s*:\s*([A-Fa-f0-9]{32})', re.IGNORECASE),
    'crc32': re.compile(r';\s*Input CRC32\s*:\s*([A-Fa-f0-9]{8})', re.IGNORECASE)
}

ida_exclude_pattern = re.compile(
    r';\s*(?:\+\-+\+|\|\s*(?:This file was generated by|Copyright|License info).*|Input (?:SHA256|MD5|CRC32)\s*:|File Name\s*:|(?:Compiler|Format|Imagebase)\s*:)',
    re.IGNORECASE
)

windows_path_patterns = [
    re.compile(r'["\']([A-Za-z]:[/\\][^"\']*[/\\][^"/\'\\]*(?:\.[a-zA-Z0-9]{2,4})?)["\']', re.IGNORECASE),
    re.compile(r'\b([A-Za-z]:[/\\][a-zA-Z0-9_\.\-/\\]+\.[a-zA-Z0-9]{2,4})\b', re.IGNORECASE),
    re.compile(r'["\']([/\\][/\\][a-zA-Z0-9.-]+[/\\][^"\'\\]+[/\\][^"\']*)["\']', re.IGNORECASE),
    re.compile(r'["\']?(HKEY_[A-Z_]+[/\\][^"\'\\s]+)["\']?', re.IGNORECASE)
]

string_pattern = re.compile(r'(?:db\s+)?["\']([^"\']{5,200})["\']', re.IGNORECASE)

path_validation = {
    'go_module': re.compile(r'[/\\]pkg[/\\]mod[/\\].*(?:@v\d+\.\d+\.\d+|\.org[/\\]x[/\\]|@[^/\\]*[/\\])', re.IGNORECASE),
    'suspicious_path': re.compile(r'(?:[/\\](?:work|project|src|source|code|build|bin|cmd|command)[/\\]|[/\\](?:main|app|tool|util|client|server)\.[a-z]+$|^[A-Za-z]:[/\\](?:work|project|src|code|build|bin)[/\\])', re.IGNORECASE),
    'dependency': re.compile(r'(?:go[/\\]pkg[/\\]|[/\\]program files(?:\s\(x86\))?[/\\])', re.IGNORECASE)
}

bad_string_patterns = {'...', '%s', '%a', '%d', '%c'}
bad_endings = ['...', '@"', "@'", '"', "'"]
format_prefixes = ('%s', '%a', '%d')

assembly_context_keywords = {
    'descriptor', 'constructor', 'destructor', 'exception', 'literal', 
    'dynamic', 'stored block', 'incomplete', 'invalid', 'following',
    'ms windows', 'bit lengths', 'class ', 'struct ', 'union ',
    'namespace', 'template', 'operator', 'virtual', 'override',
    'const ', 'static ', 'extern ', 'typedef', 'sizeof'
}

assembly_noise_patterns = [
    re.compile(r'\bat\s+[0-9A-Fa-f]{4,8}\b', re.IGNORECASE),  # "at 0000A0"
    re.compile(r'\bType\s+db\b', re.IGNORECASE),  # "Type db"
    re.compile(r'\bat\s*\([^)]*\)', re.IGNORECASE),  # "at (0, -1, 0, 0)"
    re.compile(r'\btree\s+\w+\s+\w+/\w+\s+tree\b', re.IGNORECASE),  # "tree incomplete literal/length tree"
    re.compile(r'\b(?:offset|loc|sub|var|arg)_[0-9A-Fa-f]+\b', re.IGNORECASE),  # IDA variables
    re.compile(r'\bunk_[0-9A-Fa-f]+\b', re.IGNORECASE),  # IDA unknown vars
    re.compile(r'^\s*(?:db|dw|dd|dq|dt)\s+', re.IGNORECASE | re.MULTILINE),  # Assembly directives at line start
    re.compile(r'\b(?:byte|word|dword|qword)\s+ptr\b', re.IGNORECASE),  # Assembly pointer syntax
    re.compile(r'^[\s;]*(?:public|extern|extrn|proc|endp)\s', re.IGNORECASE | re.MULTILINE),  # Assembly declarations
]

# hard coded number, might change later
MAXChars = 50