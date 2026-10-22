"""Stealth100 utilities: HTTP header order randomization + JA4 helpers.

Used by bypass.py and profiles.py to produce Chrome-indistinguishable
header order + TLS variations.
"""
from __future__ import annotations

import random

# Chrome 120+ mobile header order (stable baseline)
# Real Chrome sends: method, authority, scheme, path, then sorted-ish headers
# with sec-ch-ua* interleaved after accept-language
_CHROME_HEADER_ORDER_BASE = [
    "accept",
    "accept-language",
    "accept-encoding",
    "referer",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-model",
    "user-agent",
    "upgrade-insecure-requests",
    "cache-control",
    "connection",
]

def randomized_header_order() -> list[str]:
    """Return a Chrome-plausible header order with minor shuffling.

    Keeps sec-ch-ua block contiguous (real Chrome does), jitters cache-control
    and accept-encoding position to mimic Chrome version drift.
    """
    order = _CHROME_HEADER_ORDER_BASE[:]
    # Small jitter: 30% swap accept-encoding ↔ cache-control
    if random.random() < 0.3:
        try:
            a = order.index("accept-encoding")
            b = order.index("cache-control")
            order[a], order[b] = order[b], order[a]
        except ValueError:
            pass
    # 20% shuffle sec-ch-ua sub-order (Chrome GREASE permutation)
    if random.random() < 0.2:
        # Shuffle only the sec-ch-ua* block
        start = order.index("sec-ch-ua")
        end = order.index("sec-ch-ua-model") + 1
        block = order[start:end]
        random.shuffle(block)
        order[start:end] = block
    return order

# HTTP/2 SETTINGS variations observed on real Android Chrome
_HTTP2_SETTINGS_POOL = [
    # SETTINGS_HEADER_TABLE_SIZE, ENABLE_PUSH, MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, MAX_HEADER_LIST_SIZE
    {"header_table_size": 65536, "enable_push": 0, "max_concurrent": 1000, "window_size": 6291456, "max_frame": 16384, "header_list": 262144},
    {"header_table_size": 4096, "enable_push": 0, "max_concurrent": 100, "window_size": 1048576, "max_frame": 16384, "header_list": 65536},
]

def random_http2_settings() -> dict:
    return random.choice(_HTTP2_SETTINGS_POOL)
