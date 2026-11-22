use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;

struct Bucket {
    tokens: f64,
    last_update: Instant,
    capacity: f64,
    refill_rate_per_sec: f64,
}

impl Bucket {
    fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            last_update: Instant::now(),
            capacity,
            refill_rate_per_sec: refill_rate,
        }
    }

    fn update_limits(&mut self, capacity: f64, refill_rate_per_sec: f64) {
        self.capacity = capacity;
        self.refill_rate_per_sec = refill_rate_per_sec;
        self.tokens = self.tokens.min(capacity);
    }

    fn try_acquire(&mut self, cost: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;

        // Refill tokens
        self.tokens = (self.tokens + elapsed * self.refill_rate_per_sec).min(self.capacity);

        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

/// Thread-safe Lock-free Token Bucket Rate Limiter per client identity/IP
#[derive(Clone)]
pub struct TokenBucketLimiter {
    buckets: Arc<DashMap<String, Bucket>>,
    default_capacity: f64,
    default_rps: f64,
}

impl TokenBucketLimiter {
    pub fn new(capacity: u32, rps: u32) -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            default_capacity: capacity as f64,
            default_rps: rps as f64,
        }
    }

    /// Checks if a client/endpoint is allowed to proceed
    pub fn check_allowed(&self, key: &str, limit_rps: Option<u32>) -> bool {
        let rps = limit_rps.map(|r| r as f64).unwrap_or(self.default_rps);
        let cap = limit_rps.map(|r| r as f64).unwrap_or(self.default_capacity);

        let mut entry = self.buckets.entry(key.to_string()).or_insert_with(|| {
            Bucket::new(cap, rps)
        });
        entry.update_limits(cap, rps);

        entry.try_acquire(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_bucket_applies_updated_limits() {
        let mut bucket = Bucket::new(10.0, 10.0);
        bucket.tokens = 8.0;

        bucket.update_limits(3.0, 2.0);

        assert_eq!(bucket.capacity, 3.0);
        assert_eq!(bucket.refill_rate_per_sec, 2.0);
        assert_eq!(bucket.tokens, 3.0);
    }

    #[test]
    fn separate_keys_keep_independent_buckets() {
        let limiter = TokenBucketLimiter::new(5, 5);

        for _ in 0..5 {
            assert!(limiter.check_allowed("client:general", None));
        }
        assert!(!limiter.check_allowed("client:general", None));

        assert!(limiter.check_allowed("client:policy:uploads", Some(2)));
        assert!(limiter.check_allowed("client:policy:uploads", Some(2)));
        assert!(!limiter.check_allowed("client:policy:uploads", Some(2)));
        assert!(limiter.check_allowed("client:general", None));
    }
}
