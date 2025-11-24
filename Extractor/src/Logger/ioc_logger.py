from ..Constant.ioc_constants import *
from ..GetTime.ioc_get_time import *

class IOCLogger:
    def log_message(msg):
        timestamp = IOCGetTime.get_utc_timestamp_short()
        log_msg = f"[{timestamp}] {msg}"
        print(log_msg)
        try:
            with open(LOG_FILE, 'a') as f:
                f.write(log_msg + '\n')
        except:
            pass