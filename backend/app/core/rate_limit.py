"""In-memory sliding-window login rate limiter.

IMPORTANT ARCHITECTURAL NOTE:
This rate limiter is bounded in memory and operates strictly within a single Python process.
In a distributed, multi-worker (e.g. Uvicorn with multiple workers), or horizontally scaled
environment, an external centralized cache (such as Redis or SQL Server) must be used.
"""

from collections import deque
import math
import threading
import time
from typing import Dict, Tuple

from app.core.config import settings
from app.core.exceptions import RateLimitExceededException


class LoginRateLimiter:
    """Thread-safe, memory-bounded, sliding-window rate limiter for login attempts."""

    def __init__(
        self,
        max_attempts: int = settings.RATE_LIMIT_LOGIN_MAX_ATTEMPTS,
        window_seconds: int = settings.RATE_LIMIT_LOGIN_WINDOW_SECONDS,
        max_tracked_ips: int = settings.RATE_LIMIT_MAX_TRACKED_IPS,
    ):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.max_tracked_ips = max_tracked_ips
        self._lock = threading.Lock()
        self._records: Dict[str, deque] = {}

    def _cleanup_expired(self, now: float) -> None:
        """Remove timestamps older than the active sliding window and empty IP buckets."""
        cutoff = now - self.window_seconds
        expired_ips = []
        for ip, timestamps in self._records.items():
            while timestamps and timestamps[0] < cutoff:
                timestamps.popleft()
            if not timestamps:
                expired_ips.append(ip)

        for ip in expired_ips:
            del self._records[ip]

    def _evict_if_full(self) -> None:
        """Evict the oldest tracked IP if storage exceeds max_tracked_ips capacity."""
        if len(self._records) >= self.max_tracked_ips:
            # Pop the first (oldest inserted) key
            oldest_ip = next(iter(self._records))
            del self._records[oldest_ip]

    def check_rate_limit(self, client_ip: str) -> None:
        """Check if client IP is currently rate limited. Raises RateLimitExceededException if exceeded."""
        now = time.time()
        with self._lock:
            self._cleanup_expired(now)
            timestamps = self._records.get(client_ip)
            if timestamps and len(timestamps) >= self.max_attempts:
                # Calculate remaining seconds until oldest attempt expires
                oldest_attempt = timestamps[0]
                retry_after = max(1, math.ceil((oldest_attempt + self.window_seconds) - now))
                raise RateLimitExceededException(retry_after=retry_after)

    def record_attempt(self, client_ip: str) -> None:
        """Record a login attempt timestamp for client IP, keeping storage bounded."""
        now = time.time()
        with self._lock:
            self._cleanup_expired(now)
            if client_ip not in self._records:
                self._evict_if_full()
                self._records[client_ip] = deque()
            self._records[client_ip].append(now)

    def reset(self) -> None:
        """Reset all rate limit tracking. Used primarily in test suites."""
        with self._lock:
            self._records.clear()


login_rate_limiter = LoginRateLimiter()
