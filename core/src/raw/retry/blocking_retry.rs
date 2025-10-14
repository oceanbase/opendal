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

use std::{time::Duration, time::Instant};

use super::{Backoff, BackoffBuilder};

/// The trait for the blocking retryable.
pub trait BlockingRetryable<B: BackoffBuilder, T, E, F: FnMut() -> Result<T, E>> {
    /// Retry the function with the builder.
    fn retry(self, builder: B) -> BlockingRetry<B::Backoff, T, E, F>;
}

impl<B, T, E, F> BlockingRetryable<B, T, E, F> for F
where
    B: BackoffBuilder,
    F: FnMut() -> Result<T, E>,
{
    fn retry(self, builder: B) -> BlockingRetry<B::Backoff, T, E, F> {
        BlockingRetry::new(self, builder.build())
    }
}

/// The implementation for the blocking retry.
pub struct BlockingRetry<
    B: Backoff,
    T,
    E,
    F: FnMut() -> Result<T, E>,
    RF = fn(&E) -> bool,
    NF = fn(&E, Duration),
> {
    backoff: B,
    start_time: Option<Instant>,
    timeout: Option<Duration>,
    f: F,
    retryable: RF,
    notify: NF,
}

/// The implementation for the blocking retry.
impl<B: Backoff, T, E, F: FnMut() -> Result<T, E>> BlockingRetry<B, T, E, F> {
    /// Create a new blocking retry.
    pub fn new(f: F, backoff: B) -> Self {
        Self {
            backoff,
            start_time: None,
            timeout: None,
            f,
            retryable: |_: &E| true,
            notify: |_: &E, _: Duration| {},
        }
    }
}

impl<B, T, E, F, RF, NF> BlockingRetry<B, T, E, F, RF, NF>
where
    B: Backoff,
    F: FnMut() -> Result<T, E>,
    RF: FnMut(&E) -> bool,
    NF: FnMut(&E, Duration),
{
    /// Set the timeout for the retry.
    pub fn with_timeout(self, timeout: Option<Duration>) -> BlockingRetry<B, T, E, F, RF, NF> {
        BlockingRetry {
            backoff: self.backoff,
            f: self.f,
            retryable: self.retryable,
            notify: self.notify,
            start_time: self.start_time,
            timeout,
        }
    }

    /// Set the retryable function for the retry.
    pub fn when<RN: FnMut(&E) -> bool>(self, retryable: RN) -> BlockingRetry<B, T, E, F, RN, NF> {
        BlockingRetry {
            backoff: self.backoff,
            start_time: self.start_time,
            timeout: self.timeout,
            f: self.f,
            retryable,
            notify: self.notify,
        }
    }

    /// Set the notify function for the retry.
    pub fn notify<NN: FnMut(&E, Duration)>(self, notify: NN) -> BlockingRetry<B, T, E, F, RF, NN> {
        BlockingRetry {
            backoff: self.backoff,
            start_time: self.start_time,
            timeout: self.timeout,
            f: self.f,
            retryable: self.retryable,
            notify,
        }
    }
}

impl<B, T, E, F, RF, NF> BlockingRetry<B, T, E, F, RF, NF>
where 
    B: Backoff,
    F: FnMut() -> Result<T, E>,
    RF: FnMut(&E) -> bool,
    NF: FnMut(&E, Duration),
{
    /// Call the retry.
    pub fn call(mut self) -> Result<T, E> {
        let start_time = self.start_time.get_or_insert(Instant::now());
        loop {
            let result = (self.f)();
            match result {
                Ok(v) => return Ok(v),
                Err(e) => {
                    if !(self.retryable)(&e) {
                        return Err(e);
                    }
                    let delay = self.backoff.next();
                    if let Some(timeout) = self.timeout {
                        if start_time.elapsed() + delay.unwrap_or(Duration::from_secs(0)) >= timeout {
                            return Err(e);
                        }
                    }

                    match delay {
                        None => return Err(e),
                        Some(duration) => {
                            (self.notify)(&e, duration);
                            std::thread::sleep(duration);
                        }
                    }
                }
            }
        }
    }
}
