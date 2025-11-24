import os

from ..Constant.ioc_constants import *
from ..Logger.ioc_logger import *

class IOCLoader:
    def load_existing_hashes():
        hashes = set()
        if os.path.exists(HASHES_FILE):
            try:
                with open(HASHES_FILE, 'r') as f:
                    for line in f:
                        if line.strip() and not line.startswith('#'):
                            hashes.add(line.strip())
            except Exception as e:
                IOCLogger.log_message(f"error loading existing hashes: {e}")
        return hashes