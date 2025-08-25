// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use core::time::Duration;

/// The trait for the backoff strategy.
pub trait Backoff: Iterator<Item = Duration> + Send + Sync + Unpin {}
impl<T> Backoff for T where T: Iterator<Item = Duration> + Send + Sync + Unpin {}

/// The trait for the backoff builder.
pub trait BackoffBuilder: Send + Sync + Unpin {
    /// The backoff strategy.
    type Backoff: Backoff;

    /// Build the backoff strategy.
    fn build(self) -> Self::Backoff;
}

impl<B: Backoff> BackoffBuilder for B {
    type Backoff = B;

    fn build(self) -> Self::Backoff {
        self
    }
}

/// The builder for the exponential backoff strategy.
#[derive(Debug, Clone, Copy)]
pub struct ExponentialBuilder {
    jitter: bool,
    factor: f32,
    min_delay: Duration,
    max_delay: Option<Duration>,
    max_times: Option<usize>,
    total_delay: Option<Duration>,
    seed: Option<u64>,
}

/// The default implementation for the exponential backoff builder.
impl Default for ExponentialBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ExponentialBuilder {
    /// Create a new exponential backoff builder.
    pub fn new() -> Self {
        Self {
            jitter: false,
            factor: 2.0,
            min_delay: Duration::from_secs(1),
            max_delay: Some(Duration::from_secs(60)),
            max_times: Some(3),
            total_delay: None,
            seed: None,
        }
    }

    /// Enable the jitter for the exponential backoff.
    pub const fn with_jitter(mut self) -> Self {
        self.jitter = true;
        self
    }

    /// Set the seed for the jitter.
    pub const fn with_jitter_seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    /// Set the factor for the exponential backoff.
    pub const fn with_factor(mut self, factor: f32) -> Self {
        self.factor = factor;
        self
    }

    /// Set the minimum delay for the exponential backoff.
    pub const fn with_min_delay(mut self, min_delay: Duration) -> Self {
        self.min_delay = min_delay;
        self
    }

    /// Set the maximum delay for the exponential backoff.
    pub const fn with_max_delay(mut self, max_delay: Duration) -> Self {
        self.max_delay = Some(max_delay);
        self
    }

    /// Set the maximum times for the exponential backoff.
    pub const fn with_max_times(mut self, max_times: usize) -> Self {
        self.max_times = Some(max_times);
        self
    }

    /// Set the total delay for the exponential backoff.
    pub const fn with_total_delay(mut self, total_delay: Duration) -> Self {
        self.total_delay = Some(total_delay);
        self
    }
}

/// The implementation for the exponential backoff builder.
impl BackoffBuilder for ExponentialBuilder {
    type Backoff = ExponentialBackoff;

    fn build(self) -> Self::Backoff {
        ExponentialBackoff {
            jitter: self.jitter,
            rng: if let Some(seed) = self.seed {
                fastrand::Rng::with_seed(seed)
            } else {
                fastrand::Rng::new()
            },
            factor: self.factor,
            min_delay: self.min_delay,
            max_delay: self.max_delay,
            max_times: self.max_times,
            total_delay: self.total_delay,
            current_delay: None,
            cumulative_delay: Duration::from_secs(0),
            attempts: 0,
        }
    }
}

/// The implementation for the exponential backoff.
#[derive(Debug)]
pub struct ExponentialBackoff {
    jitter: bool,
    rng: fastrand::Rng,
    factor: f32,
    min_delay: Duration,
    max_delay: Option<Duration>,
    max_times: Option<usize>,
    total_delay: Option<Duration>,

    current_delay: Option<Duration>,
    cumulative_delay: Duration,
    attempts: usize,
}

/// The implementation for the exponential backoff.
impl Iterator for ExponentialBackoff {
    type Item = Duration;
    
    fn next(&mut self) -> Option<Self::Item> {
        if self.attempts >= self.max_times.unwrap_or(usize::MAX) {
            return None;
        }
        self.attempts += 1;

        let mut tmp_cur = match self.current_delay {
            None => {
                // If current_delay is None, it's must be the first time to retry.
                self.min_delay
            }
            Some(mut cur) => {
                // If current delay larger than max delay, we should stop increment anymore.
                if let Some(max_delay) = self.max_delay {
                    if cur < max_delay {
                        cur = saturating_mul(cur, self.factor);
                    }
                    if cur > max_delay {
                        cur = max_delay;
                    }
                } else {
                    cur = saturating_mul(cur, self.factor);
                }
                cur
            }
        };

        let current_delay = tmp_cur;
        // If jitter is enabled, add random jitter based on min delay.
        if self.jitter {
            tmp_cur = tmp_cur.saturating_add(tmp_cur.mul_f32(self.rng.f32()));
        }

        // Check if adding the current delay would exceed the total delay limit.
        let total_delay_check = self
            .total_delay
            .map_or(true, |total| self.cumulative_delay + tmp_cur <= total);

        if !total_delay_check {
            return None;
        }

        if self.total_delay.is_some() {
            self.cumulative_delay = self.cumulative_delay.saturating_add(tmp_cur);
        }

        self.current_delay = Some(current_delay);

        Some(tmp_cur)
    }
}

#[inline]
pub(crate) fn saturating_mul(d: Duration, rhs: f32) -> Duration {
    Duration::try_from_secs_f32(rhs * d.as_secs_f32()).unwrap_or(Duration::MAX)
}