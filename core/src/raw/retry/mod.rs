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

//! `retry` provides the retry functionality for the raw API.
//! reference to [`backoff`] module for the retry backoff strategy.

mod backoff;
pub use backoff::*;

mod retry;
pub use retry::*;

mod retry_with_context;
pub use retry_with_context::*;


mod blocking_retry;
pub use blocking_retry::*;

mod blocking_retry_with_context;
pub use blocking_retry_with_context::*;