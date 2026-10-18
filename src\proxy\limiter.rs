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

        entry.try_acquire(1.0)
    }
}
