import sys
import re
from datetime import datetime

class DualLogger:
    BLACKLIST = (
        # titles for runs
        'RUNNING IR PATTERN ANALYSIS',
        'RUNNING ASM SNIFFER',
        'RUNNING CROSS REFERENCE ANALYSIS',

        # process
        'building CFG...',
        'extracting features...',
        'Extracting Features',
        'Dataflow Analysis Complete',

        # regex for process
        re.compile(r'.*\.\.\.\n?'),
        re.compile(r'.*done\n?'),
        re.compile(r'WL hash computed in *'),
        re.compile(r'canonicalizing block *'),
        re.compile(r'processing block *'),
        re.compile(r'analyzing *'),
        re.compile(r'Processing Graph Data: *'),
        re.compile(r'Generating *'),
        re.compile(r'Normalizing *'),
        re.compile(r'processing size *'),
        re.compile(r'completed size *'),

        # regex special character
        re.compile(r'\n={80}.*'),
        re.compile(r'={80}\n')
    )

    def __init__(self, log_file='analysis_log.txt'):
        self.terminal = sys.stdout
        self.log = open(log_file, 'a', encoding='utf-8', buffering=16384)
        self.last_blocked = False
        self.log.write(f"{'='*80}\n")
        self.log.write(f"Session started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.log.write(f"Logging to: {log_file}\n")
        self.log.write(f"{'='*80}\n")
    
    def write(self, message):
        self.terminal.write(message)

        if self.last_blocked and message == '\n':
            self.last_blocked = False
            return
        
        if not message.strip():
            self.log.write(message)
            self.last_blocked = False
            return
        
        for pattern in self.BLACKLIST:
            if isinstance(pattern, str):
                if pattern in message:
                    self.last_blocked = True
                    return
            else:
                if pattern.search(message):
                    self.last_blocked = True
                    return
        
        self.last_blocked = False
        self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()
    
    def close(self):
        self.log.write(f"\n{'='*80}\n")
        self.log.write(f"Session ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.log.write(f"{'='*80}\n")
        self.log.close()