"""
core/parser.py
Regular expression parser for standard Nginx/Apache Combined Log Format.
"""

import re
from typing import Dict, Any, Optional
from urllib.parse import unquote


class LogParser:
    # Standard Nginx/Apache Combined Log Format Regex
    LOG_REGEX = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d{3})\s+(?P<bytes>\S+)\s+'
        r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
    )

    @classmethod
    def parse_line(cls, line: str) -> Optional[Dict[str, Any]]:
        """
        Parses a single log line and returns a structured dictionary.
        Automatically unquotes URL-encoded characters for deep inspection.
        """
        match = cls.LOG_REGEX.match(line.strip())
        if not match:
            return None

        data = match.groupdict()
        # Decode obfuscated URL payloads (e.g., %20 -> space, %27 -> ')
        data["decoded_url"] = unquote(data["url"])
        data["status"] = int(data["status"])
        return data