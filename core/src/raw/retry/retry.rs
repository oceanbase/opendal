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

/// The trait for the retryable.
pub trait Retryable<
    B: BackoffBuilder,
    T,
    E,
    Fut: Future<Output = Result<T, E>>,
    FutureFn: FnMut() -> Fut,
>
{
    /// Retry the function with the builder.
    fn retry(self, builder: B) -> Retry<B::Backoff, T, E, Fut, FutureFn>;
}

impl<B, T, E, Fut, FutureFn> Retryable<B, T, E, Fut, FutureFn> for FutureFn
where
    B: BackoffBuilder,
    Fut: Future<Output = Result<T, E>>,
    FutureFn: FnMut() -> Fut,
{
    fn retry(self, builder: B) -> Retry<B::Backoff, T, E, Fut, FutureFn> {
        Retry::new(self, builder.build())
    }
}

/// The implementation for the retry.
pub struct Retry<
    B: Backoff,
    T,
    E,
    Fut: Future<Output = Result<T, E>>,
    FutureFn: FnMut() -> Fut,
    RF = fn(&E) -> bool,
    NF = fn(&E, Duration),
> {
    backoff: B,
    start_time: Option<Instant>,
    timeout: Option<Duration>,
    retryable: RF,
    notify: NF,
    future_fn: FutureFn,
    state: State<T, E, Fut>,
}

impl<B, T, E, Fut, FutureFn> Retry<B, T, E, Fut, FutureFn>
where
    B: Backoff,
    Fut: Future<Output = Result<T, E>>,
    FutureFn: FnMut() -> Fut,
{
    fn new(future_fn: FutureFn, backoff: B) -> Self {
        Self {
            backoff,
            start_time: None,
            timeout: None,
            retryable: |_: &E| true,
            notify: |_: &E, _: Duration| {},
            future_fn,
            state: State::Idle,
        }
    }
}

impl<B, T, E, Fut, FutureFn, RF, NF> Retry<B, T, E, Fut, FutureFn, RF, NF>
where
    B: Backoff,
    Fut: Future<Output = Result<T, E>>,
    FutureFn: FnMut() -> Fut,
    RF: FnMut(&E) -> bool,
    NF: FnMut(&E, Duration),
{
    /// Set the timeout for the retry.
    pub fn with_timeout(self, timeout: Option<Duration>) -> Retry<B, T, E, Fut, FutureFn, RF, NF> {
        Retry {
            backoff: self.backoff,
            start_time: Some(Instant::now()),
            timeout,
            retryable: self.retryable,
            notify: self.notify,
            future_fn: self.future_fn,
            state: self.state,
        }
    }

    /// Set the retryable function for the retry.
    pub fn when<RN: FnMut(&E) -> bool>(
        self,
        retryable: RN,
    ) -> Retry<B, T, E, Fut, FutureFn, RN, NF> {
        Retry {
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
    ) -> Retry<B, T, E, Fut, FutureFn, RF, NN> {
        Retry {
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

/// The state for the retry.
enum State<T, E, Fut: Future<Output = Result<T, E>>> {
    Idle,
    Polling(Fut),
    Sleeping(Sleep),
}

/// The implementation for the future for the retry.
impl<B, T, E, Fut, FutureFn, RF, NF> Future for Retry<B, T, E, Fut, FutureFn, RF, NF>
where
    B: Backoff,
    Fut: Future<Output = Result<T, E>>,
    FutureFn: FnMut() -> Fut,
    RF: FnMut(&E) -> bool,
    NF: FnMut(&E, Duration),
{
    type Output = Result<T, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        let start_time = this.start_time.get_or_insert(Instant::now());
        loop {
            match &mut this.state {
                State::Idle => {
                    let fut = (this.future_fn)();
                    this.state = State::Polling(fut);
                    continue;
                }
                State::Polling(fut) => {
                    let mut fut = unsafe { Pin::new_unchecked(fut) };
                    let res = ready!(fut.as_mut().poll(cx));
                    match res {
                        Ok(v) => return Poll::Ready(Ok(v)),
                        Err(err) => {
                            if !(this.retryable)(&err) {
                                return Poll::Ready(Err(err));
                            }
                            let delay = this.backoff.next();
                            if let Some(timeout) = this.timeout.as_ref() {
                                if start_time.elapsed() + delay.unwrap_or(Duration::from_secs(0))
                                    >= *timeout
                                {
                                    return Poll::Ready(Err(err));
                                }
                            }
                            match delay {
                                Some(delay) => {
                                    (this.notify)(&err, delay);
                                    this.state = State::Sleeping(tokio::time::sleep(delay));
                                    continue;
                                }
                                None => return Poll::Ready(Err(err)),
                            }
                        }
                    }
                }
                State::Sleeping(sleep) => {
                    let mut sleep = unsafe { Pin::new_unchecked(sleep) };
                    ready!(sleep.as_mut().poll(cx));
                    this.state = State::Idle;
                    continue;
                }
            }
        }
    }
}
