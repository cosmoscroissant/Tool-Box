from datetime import datetime, timezone

class IOCGetTime:
    def get_utc_timestamp_short():
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    def get_utc_timestamp_long():
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")