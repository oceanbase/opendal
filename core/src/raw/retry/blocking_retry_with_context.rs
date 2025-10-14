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

/// The trait for the blocking retryable with context.
pub trait BlockingRetryableWithContext<B: BackoffBuilder, T, E, Ctx, F: FnMut(Ctx) -> (Ctx, Result<T, E>)> {
    /// Retry the function with the builder.
    fn retry(self, builder: B) -> BlockingRetryWithContext<B::Backoff, T, E, Ctx, F>;
}

/// The implementation for the blocking retryable with context.
impl<B, T, E, Ctx, F> BlockingRetryableWithContext<B, T, E, Ctx, F> for F
where
    B: BackoffBuilder,
    F: FnMut(Ctx) -> (Ctx, Result<T, E>),
{
    fn retry(self, builder: B) -> BlockingRetryWithContext<B::Backoff, T, E, Ctx, F> {
        BlockingRetryWithContext::new(self, builder.build())
    }
}

/// The implementation for the blocking retry with context.
pub struct BlockingRetryWithContext<
    B: Backoff,
    T,
    E,
    Ctx,
    F: FnMut(Ctx) -> (Ctx, Result<T, E>),
    RF = fn(&E) -> bool,
    NF = fn(&E, Duration),
> {
    backoff: B,
    start_time: Option<Instant>,
    timeout: Option<Duration>,
    f: F,
    retryable: RF,
    notify: NF,
    ctx: Option<Ctx>,
}

/// The implementation for the blocking retry with context.
impl<B: Backoff, T, E, Ctx, F: FnMut(Ctx) -> (Ctx, Result<T, E>)> BlockingRetryWithContext<B, T, E, Ctx, F> {
    /// Create a new blocking retry.
    pub fn new(f: F, backoff: B) -> Self {
        Self {
            backoff,
            start_time: None,
            timeout: None,
            f,
            retryable: |_: &E| true,
            notify: |_: &E, _: Duration| {},
            ctx: None,
        }
    }
}

/// The implementation for the blocking retry with context.
impl<B, T, E, Ctx, F, RF, NF> BlockingRetryWithContext<B, T, E, Ctx, F, RF, NF>
where
    B: Backoff,
    F: FnMut(Ctx) -> (Ctx, Result<T, E>),
    RF: FnMut(&E) -> bool,
    NF: FnMut(&E, Duration),
{
    /// Set the timeout for the retry.
    pub fn with_timeout(self, timeout: Option<Duration>) -> BlockingRetryWithContext<B, T, E, Ctx, F, RF, NF> {
        BlockingRetryWithContext {
            backoff: self.backoff,
            f: self.f,
            retryable: self.retryable,
            notify: self.notify,
            start_time: self.start_time,
            timeout,
            ctx: self.ctx,
        }
    }

    /// Set the retryable function for the retry.
    pub fn when<RN: FnMut(&E) -> bool>(self, retryable: RN) -> BlockingRetryWithContext<B, T, E, Ctx, F, RN, NF> {
        BlockingRetryWithContext {
            backoff: self.backoff,
            start_time: self.start_time,
            timeout: self.timeout,
            f: self.f,
            retryable,
            notify: self.notify,
            ctx: self.ctx,
        }
    }

    /// Set the context for the retry.
    pub fn context(self, ctx: Ctx) -> BlockingRetryWithContext<B, T, E, Ctx, F, RF, NF> {
        BlockingRetryWithContext {
            backoff: self.backoff,
            start_time: self.start_time,
            timeout: self.timeout,
            f: self.f,
            retryable: self.retryable,
            notify: self.notify,
            ctx: Some(ctx),
        }
    }

    /// Set the notify function for the retry.
    pub fn notify<NN: FnMut(&E, Duration)>(self, notify: NN) -> BlockingRetryWithContext<B, T, E, Ctx, F, RF, NN> {
        BlockingRetryWithContext {
            backoff: self.backoff,
            start_time: self.start_time,
            timeout: self.timeout,
            f: self.f,
            retryable: self.retryable,
            notify,
            ctx: self.ctx,
        }
    }
}

/// The implementation for the blocking retry with context.
impl<B, T, E, Ctx, F, RF, NF> BlockingRetryWithContext<B, T, E, Ctx, F, RF, NF>
where 
    B: Backoff,
    F: FnMut(Ctx) -> (Ctx, Result<T, E>),
    RF: FnMut(&E) -> bool,
    NF: FnMut(&E, Duration),
{
    /// Call the retry with the context.
    pub fn call(mut self) -> (Ctx, Result<T, E>) {
        let start_time = self.start_time.get_or_insert(Instant::now());
        let mut ctx = self.ctx.take().expect("context must be valid");
        loop {
            let (new_ctx, result) = (self.f)(ctx);
            ctx = new_ctx;
            match result {
                Ok(v) => return (ctx, Ok(v)),
                Err(e) => {
                    if !(self.retryable)(&e) {
                        return (ctx, Err(e));
                    }
                    let delay = self.backoff.next();
                    if let Some(timeout) = self.timeout {
                        if start_time.elapsed() + delay.unwrap_or(Duration::from_secs(0)) >= timeout {
                            return (ctx, Err(e));
                        }
                    }

                    match delay {
                        None => return (ctx, Err(e)),
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
