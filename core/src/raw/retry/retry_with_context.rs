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

use core::future::Future;
use core::pin::Pin;
use core::task::Context;
use core::task::{ready, Poll};
use core::time::Duration;

use std::time::Instant;
use tokio::time::Sleep;

use super::backoff::{Backoff, BackoffBuilder};

/// The trait for the retryable with context.
pub trait RetryableWithContext<
    B: BackoffBuilder,
    T,
    E,
    Ctx,
    Fut: Future<Output = (Ctx, Result<T, E>)>,
    FutureFn: FnMut(Ctx) -> Fut,
>
{
    /// Retry the function with the builder.
    fn retry(self, builder: B) -> RetryWithContext<B::Backoff, T, E, Ctx, Fut, FutureFn>;
}

impl<B, T, E, Ctx, Fut, FutureFn> RetryableWithContext<B, T, E, Ctx, Fut, FutureFn> for FutureFn
where
    B: BackoffBuilder,
    Fut: Future<Output = (Ctx, Result<T, E>)>,
    FutureFn: FnMut(Ctx) -> Fut,
{
    fn retry(self, builder: B) -> RetryWithContext<B::Backoff, T, E, Ctx, Fut, FutureFn> {
        RetryWithContext::new(self, builder.build())
    }
}

/// The implementation for the retry with context.
pub struct RetryWithContext<
    B: Backoff,
    T,
    E,
    Ctx,
    Fut: Future<Output = (Ctx, Result<T, E>)>,
    FutureFn: FnMut(Ctx) -> Fut,
    RF = fn(&E) -> bool,
    NF = fn(&E, Duration),
> {
    backoff: B,
    start_time: Option<Instant>,
    timeout: Option<Duration>,
    retryable: RF,
    notify: NF,
    future_fn: FutureFn,
    state: State<T, E, Ctx, Fut>,
}

impl<B, T, E, Ctx, Fut, FutureFn> RetryWithContext<B, T, E, Ctx, Fut, FutureFn>
where
    B: Backoff,
    Fut: Future<Output = (Ctx, Result<T, E>)>,
    FutureFn: FnMut(Ctx) -> Fut,
{
    fn new(future_fn: FutureFn, backoff: B) -> Self {
        Self {
            backoff,
            start_time: None,
            timeout: None,
            retryable: |_: &E| true,
            notify: |_: &E, _: Duration| {},
            future_fn,
            state: State::Idle(None),
        }
    }
}

impl<B, T, E, Ctx, Fut, FutureFn, RF, NF> RetryWithContext<B, T, E, Ctx, Fut, FutureFn, RF, NF>
where
    B: Backoff,
    Fut: Future<Output = (Ctx, Result<T, E>)>,
    FutureFn: FnMut(Ctx) -> Fut,
    RF: FnMut(&E) -> bool,
    NF: FnMut(&E, Duration),
{
    /// Set the timeout for the retry.
    pub fn with_timeout(
        self,
        timeout: Option<Duration>,
    ) -> RetryWithContext<B, T, E, Ctx, Fut, FutureFn, RF, NF> {
        RetryWithContext {
            backoff: self.backoff,
            start_time: Some(Instant::now()),
            timeout,
            retryable: self.retryable,
            notify: self.notify,
            future_fn: self.future_fn,
            state: self.state,
        }
    }

    /// Set the context for the retry.
    pub fn context(self, context: Ctx) -> RetryWithContext<B, T, E, Ctx, Fut, FutureFn, RF, NF> {
        RetryWithContext {
            backoff: self.backoff,
            start_time: self.start_time,
            timeout: self.timeout,
            retryable: self.retryable,
            notify: self.notify,
            future_fn: self.future_fn,
            state: State::Idle(Some(context)),
        }
    }

    /// Set the retryable function for the retry.
    pub fn when<RN: FnMut(&E) -> bool>(
        self,
        retryable: RN,
    ) -> RetryWithContext<B, T, E, Ctx, Fut, FutureFn, RN, NF> {
        RetryWithContext {
            backoff: self.backoff,
            start_time: self.start_time,
            timeout: self.timeout,
            retryable,
            notify: self.notify,
            future_fn: self.future_fn,
            state: self.state,
        }
    }

    /// Set the notify function for the retry.
    pub fn notify<NN: FnMut(&E, Duration)>(
        self,
        notify: NN,
    ) -> RetryWithContext<B, T, E, Ctx, Fut, FutureFn, RF, NN> {
        RetryWithContext {
            backoff: self.backoff,
            start_time: self.start_time,
            timeout: self.timeout,
            retryable: self.retryable,
            notify,
            future_fn: self.future_fn,
            state: self.state,
        }
    }
}

/// The state for the retry with context.
enum State<T, E, Ctx, Fut: Future<Output = (Ctx, Result<T, E>)>> {
    Idle(Option<Ctx>),
    Polling(Fut),
    Sleeping((Option<Ctx>, Sleep)),
}

/// The implementation for the future for the retry with context.
impl<B, T, E, Ctx, Fut, FutureFn, RF, NF> Future
    for RetryWithContext<B, T, E, Ctx, Fut, FutureFn, RF, NF>
where
    B: Backoff,
    Fut: Future<Output = (Ctx, Result<T, E>)>,
    FutureFn: FnMut(Ctx) -> Fut,
    RF: FnMut(&E) -> bool,
    NF: FnMut(&E, Duration),
{
    type Output = (Ctx, Result<T, E>);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        let start_time = this.start_time.get_or_insert(Instant::now());

        loop {
            match &mut this.state {
                State::Idle(ctx) => {
                    let ctx = ctx.take().expect("context must be valid");
                    let fut = (this.future_fn)(ctx);
                    this.state = State::Polling(fut);
                    continue;
                }
                State::Polling(fut) => {
                    let mut fut = unsafe { Pin::new_unchecked(fut) };
                    let (ctx, res) = ready!(fut.as_mut().poll(cx));
                    match res {
                        Ok(v) => return Poll::Ready((ctx, Ok(v))),
                        Err(err) => {
                            if !(this.retryable)(&err) {
                                return Poll::Ready((ctx, Err(err)));
                            }
                            let delay = this.backoff.next();
                            if let Some(timeout) = this.timeout.as_ref() {
                                if start_time.elapsed() + delay.unwrap_or(Duration::from_secs(0))
                                    >= *timeout
                                {
                                    return Poll::Ready((ctx, Err(err)));
                                }
                            }
                            match delay {
                                Some(delay) => {
                                    (this.notify)(&err, delay);
                                    this.state =
                                        State::Sleeping((Some(ctx), tokio::time::sleep(delay)));
                                    continue;
                                }
                                None => return Poll::Ready((ctx, Err(err))),
                            }
                        }
                    }
                }
                State::Sleeping((ctx, sleep)) => {
                    let mut sleep = unsafe { Pin::new_unchecked(sleep) };
                    ready!(sleep.as_mut().poll(cx));
                    let ctx = ctx.take().expect("context must be valid");
                    this.state = State::Idle(Some(ctx));
                    continue;
                }
            }
        }
    }
}
