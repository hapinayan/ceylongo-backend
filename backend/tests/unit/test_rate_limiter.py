"""Unit tests for bounded, sliding-window login rate limiter."""

import time
import pytest
from app.core.exceptions import RateLimitExceededException
from app.core.rate_limit import LoginRateLimiter


@pytest.mark.unit
def test_rate_limiter_threshold_enforcement():
    """Test that requests exceeding max_attempts within window raise RateLimitExceededException."""
    limiter = LoginRateLimiter(max_attempts=3, window_seconds=10, max_tracked_ips=100)
    client_ip = "192.168.1.100"

    # First 2 attempts allowed
    limiter.record_attempt(client_ip)
    limiter.check_rate_limit(client_ip)
    limiter.record_attempt(client_ip)
    limiter.check_rate_limit(client_ip)

    # 3rd attempt recorded reaches limit
    limiter.record_attempt(client_ip)
    with pytest.raises(RateLimitExceededException) as exc_info:
        limiter.check_rate_limit(client_ip)

    assert exc_info.value.retry_after > 0
    assert exc_info.value.retry_after <= 10


@pytest.mark.unit
def test_rate_limiter_memory_bounded_eviction():
    """Test that storage capacity is bounded and oldest IP is evicted when full."""
    max_capacity = 3
    limiter = LoginRateLimiter(max_attempts=5, window_seconds=60, max_tracked_ips=max_capacity)

    limiter.record_attempt("10.0.0.1")
    limiter.record_attempt("10.0.0.2")
    limiter.record_attempt("10.0.0.3")
    assert len(limiter._records) == 3

    # Adding a 4th IP must evict the oldest (10.0.0.1)
    limiter.record_attempt("10.0.0.4")
    assert len(limiter._records) == 3
    assert "10.0.0.1" not in limiter._records
    assert "10.0.0.4" in limiter._records


@pytest.mark.unit
def test_rate_limiter_expired_entries_cleanup():
    """Test that timestamps outside the sliding window are pruned."""
    limiter = LoginRateLimiter(max_attempts=2, window_seconds=1, max_tracked_ips=100)
    client_ip = "10.0.0.5"

    limiter.record_attempt(client_ip)
    limiter.record_attempt(client_ip)

    # Reached limit
    with pytest.raises(RateLimitExceededException):
        limiter.check_rate_limit(client_ip)

    # Wait for window to expire
    time.sleep(1.1)

    # Check should now pass without raising
    limiter.check_rate_limit(client_ip)
    assert client_ip not in limiter._records  # Cleaned up
