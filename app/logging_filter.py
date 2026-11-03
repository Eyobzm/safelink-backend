import logging
import re

_QUERY = re.compile(r"\?[^\s\"']*")


class RedactQueryFilter(logging.Filter):
    """Strip query strings from any log line (NFR-PRIV-02)."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _QUERY.sub("?[redacted]", str(record.msg))
        return True
