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


use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::RwLock;
use std::sync::Once;
use std::ffi::{c_void, CString, c_char};
use std::fmt::Write;
use std::panic::catch_unwind;
use std::collections::HashMap;
use std::time::Duration;
use std::cell::RefCell;

use tokio::runtime::Runtime;
use tracing::{
  field::Field,
  level_filters::LevelFilter,
  span,
  Event,
  Subscriber,
};
use tracing_subscriber::{
  self,
  fmt,
  layer::{Context, Layer, SubscriberExt},
  registry::LookupSpan,
  util::SubscriberInitExt,
  fmt::time::OffsetTime,
};

use core::ErrorKind;
use ::opendal as core;
use core::raw::HttpClient;
use core::layers::DEFAULT_TENANT_ID;
use super::*;

pub static RUNTIME: RwLock<Option<Runtime>> = RwLock::new(None);
pub static HTTP_CLIENT: RwLock<Option<HttpClient>> = RwLock::new(None);
pub static TRACING_INIT_ONCE: Once = Once::new();

pub type AllocFn = unsafe extern "C" fn(size: usize, align: usize) -> *mut u8;
pub type FreeFn = unsafe extern "C" fn(ptr: *mut u8);
static mut ALLOC_FN: Option<AllocFn> = None;
static mut FREE_FN: Option<FreeFn> = None;

thread_local! {
  pub static THREAD_TENANT_ID: RefCell<u64> = RefCell::new(DEFAULT_TENANT_ID);
}

struct CustomAllocator;

unsafe impl GlobalAlloc for CustomAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if let Some(alloc_fn) = ALLOC_FN {
            alloc_fn(layout.size(), layout.align())
        } else {
            System.alloc(layout)
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(free_fn) = FREE_FN {
            if !ptr.is_null() {
                free_fn(ptr);
            }
        } else {
            System.dealloc(ptr, layout)
        }
    }
}

#[global_allocator]
static GLOBAL: CustomAllocator = CustomAllocator;

struct ObLogLayer;

pub type LogHandler = unsafe extern "C" fn(level: *const c_char, message: *const c_char);
static mut OB_LOG_HANDLER: Option<LogHandler> = None;

impl<S> Layer<S> for ObLogLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event, ctx: Context<S>) {
        let mut message = String::with_capacity(256);

        let metadata = event.metadata();

        match (metadata.file(), metadata.line()) {
            (Some(file), Some(line)) => {
                let _ = write!(&mut message, "location={}:{}", file, line);
            }
            (Some(file), None) => {
                let _ = write!(&mut message, "file={}", file);
            }
            (None, Some(line)) => {
                let _ = write!(&mut message, "line={}", line);
            }
            (None, None) => {}
        };

        event.record(&mut |field: &Field, value: &dyn std::fmt::Debug| {
            let _ = write!(&mut message, ", {}: {:?}", field.name(), value);
        });

        if let Some(current_span) = ctx.current_span().id() {
            if let Some(span_ref) = ctx.span(current_span) {
                if let Some(fields) = span_ref.extensions().get::<HashMap<String, String>>() {
                    for (name, value) in fields {
                        let _ = write!(&mut message, ", {}: {}", name, value);
                    }
                }
            }
        }

        match (
            CString::new(metadata.level().as_str()),
            CString::new(message),
        ) {
            (Ok(level), Ok(message)) => unsafe {
                if let Some(loghandler) = OB_LOG_HANDLER {
                    loghandler(level.as_ptr(), message.as_ptr());
                }
            },
            _ => {}
        }
    }

    fn on_new_span(
        &self,
        attrs: &span::Attributes<'_>,
        id: &span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let span = ctx.span(id).expect("Span must exist!");
        let mut extensions = span.extensions_mut();

        let mut fields = HashMap::new();
        attrs.record(&mut |field: &Field, value: &dyn std::fmt::Debug| {
            fields.insert(field.name().to_string(), format!("{:?}", value));
        });

        extensions.insert(fields);
    }
}

#[no_mangle]
pub extern "C" fn opendal_get_tenant_id() -> u64 {
    let mut tenant_id = DEFAULT_TENANT_ID;
    match core::layers::TENANT_ID.try_with(|id| {
        tenant_id = *id;
    }) {
        Ok(_) => {},
        Err(_) => {
          THREAD_TENANT_ID.with(|id| {
            tenant_id = *id.borrow();
          });
        }
    }
    tenant_id
}

/// \brief init opendal environment
///
/// Task to initialize the environment include:
/// - init global allocator and releaser
/// - init global runtime
/// - init global http client
/// - init global log handler
///
/// @param alloc: the function to allocate memory
/// @param free: the function to release memory
/// @param loghandler: the function to handle log message
/// @param thread_cnt: the thread count of global runtime
/// @param pool_max_idle_per_host: the max idle connection per host
/// @param pool_max_idle_time_s: the max idle time for a connection
/// @param connect_timeout_s: the connect timeout for a connection
#[no_mangle]
pub extern "C" fn opendal_init_env(
    alloc: *mut c_void,
    free: *mut c_void,
    loghandler: *mut c_void,
    log_level: u32,
    thread_cnt: usize,
    pool_max_idle_per_host: usize,
    pool_max_idle_time_s: u64,
    connect_timeout_s: u64,
) -> *mut opendal_error {
    let ret = catch_unwind(|| {
        if alloc.is_null() || free.is_null() {
            let err = core::Error::new(core::ErrorKind::ConfigInvalid, "invalid mem func");
            return opendal_error::new(err);
        } else {
            unsafe {
                ALLOC_FN = Some(std::mem::transmute(alloc));
                FREE_FN = Some(std::mem::transmute(free));
                OB_LOG_HANDLER = if loghandler.is_null() {
                    None
                } else {
                    Some(std::mem::transmute(loghandler))
                };
            }
        }

        let mut global_runtime = RUNTIME.write().expect("failed to lock global RUNTIME");
        match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(thread_cnt as usize)
            .thread_name("obdal")
            .enable_all()
            .build() {
            Ok(runtime) => *global_runtime = Some(runtime),
            Err(e) => {
                return opendal_error::new(
                    core::Error::new(
                        core::ErrorKind::Unexpected, format!("failed to build tokio runtime: {}", e.to_string())
                    )
                )
            }
        }

        let client = reqwest::Client::builder()
                .pool_idle_timeout(Some(Duration::from_secs(pool_max_idle_time_s)))
                .pool_max_idle_per_host(pool_max_idle_per_host)
                .connect_timeout(Duration::from_secs(connect_timeout_s))
                .build();
        match client {
            Ok(client) => {
                let mut http_client = HTTP_CLIENT.write().expect("failed to lock global HTTP_CLIENT");
                *http_client = Some(HttpClient::with(client));
            }
            Err(e) => {
                return opendal_error::new(core::Error::new(
                    core::ErrorKind::Unexpected,
                    format!("failed to build reqwest client: {}", e.to_string()),
                ));
            }
        }

        let log_level = match log_level {
            // OB_LOG_LEVEL_INFO
            2 => LevelFilter::INFO,
            // OB_LOG_LEVEL_ERROR
            3 => LevelFilter::ERROR,
            // OB_LOG_LEVEL_WARN
            4 => LevelFilter::WARN,
            // OB_LOG_LEVEL_TRACE
            5 => LevelFilter::DEBUG,
            // OB_LOG_LEVEL_DEBUG
            6 => LevelFilter::TRACE,
            _ => LevelFilter::INFO,
        };

        let mut ret: *mut opendal_error = std::ptr::null_mut(); 
        TRACING_INIT_ONCE.call_once(|| {
            if loghandler.is_null() {
                let timer = OffsetTime::local_rfc_3339();
                if let Err(e) = timer {
                    ret = opendal_error::new(core::Error::new(
                            core::ErrorKind::Unexpected,
                            format!("{}, {}", e.to_string(), "failed to get local offset"),
                        ));
                }
                match tracing_subscriber::registry()
                    .with(fmt::layer().pretty().with_timer(timer.unwrap()).with_filter(log_level))
                    .try_init()
                {
                    Ok(_) => {},
                    Err(e) => {
                        unsafe {
                            ALLOC_FN = None;
                            FREE_FN = None;
                            OB_LOG_HANDLER = None;
                        }
                        let err = core::Error::new(core::ErrorKind::Unexpected, e.to_string());
                        ret = opendal_error::new(err);
                    }
                }
            } else {
                match tracing_subscriber::registry()
                        .with(ObLogLayer.with_filter(log_level)).try_init() {
                    Ok(_) => {},
                    Err(e) => {
                        unsafe {
                            ALLOC_FN = None;
                            FREE_FN = None;
                            OB_LOG_HANDLER = None;
                        }
                        let err = core::Error::new(core::ErrorKind::Unexpected, e.to_string());
                        ret = opendal_error::new(err);
                    }
                }
            }
        });
        ret
    });
    match handle_result(ret) {
        Ok(ret) => ret,
        Err(error) => error,
    }
}

/// \brief fin opendal environment
///
/// Task to finalize the environment include:
/// - drop global runtime
/// - drop global http client
#[no_mangle]
pub extern "C" fn opendal_fin_env() {
    match HTTP_CLIENT.write() {
        Ok(mut http_client) => {
            *http_client = None;
        }
        Err(e) => {
            tracing::error!("failed to lock global HTTP_CLIENT: {}", e);
        }
    }
    match RUNTIME.write() {
        Ok(mut runtime) => {
            *runtime = None;
        }
        Err(e) => {
            tracing::error!("failed to lock global RUNTIME: {}", e);
        }
    }

    unsafe  {
        OB_LOG_HANDLER = None;
        // Even after the tokio runtime is dropped, some TLS (Thread Local Storage) variables 
        // are only released when the thread exits, preventing malloc and free from being unlinked.
        // ALLOC_FN = None;
        // FREE_FN = None;
    }
}

/// \Prief Convert the c_char to str
pub fn c_char_to_str<'a>(path: *const c_char) -> Result<&'a str, *mut opendal_error> {
    if path.is_null() {
        return Err(opendal_error::new(core::Error::new(
            core::ErrorKind::ConfigInvalid,
            "invalid args",
        )));
    }

    let c_str = unsafe { std::ffi::CStr::from_ptr(path) };
    match c_str.to_str() {
        Ok(valid_str) => Ok(valid_str),
        Err(e) => Err(opendal_error::new(
            core::Error::new(core::ErrorKind::ConfigInvalid, "invalid args").set_source(e),
        )),
    }
}

/// \breif Handle the result of panic::catch_unwind
/// if panic happens, return the error
/// if not, return the result
pub fn handle_result<T>(
    result: Result<T, Box<dyn std::any::Any + Send>>,
) -> Result<T, *mut opendal_error> {
    match result {
        Ok(ret) => Ok(ret),
        Err(err) => {
            if let Some(msg) = err.downcast_ref::<&str>() {
                return Err(opendal_error::new(core::Error::new(
                    ErrorKind::Unexpected,
                    format!("Caught a panic: {}", msg),
                )));
            } else {
                return Err(opendal_error::new(core::Error::new(
                    ErrorKind::Unexpected,
                    format!("Caught a panic without msg",),
                )));
            }
        }
    }
}

/// \brief dump panic error
pub fn dump_panic(err: Box<dyn std::any::Any + Send>) {
    if let Some(msg) = err.downcast_ref::<&str>() {
        tracing::error!("Caught a panic: {}", msg);
    } else {
        tracing::error!("Caught a panic without msg");
    }
}



/// \breif Handle the result of panic::catch_unwind
/// if panic happens, log the error
/// if not, return null
pub fn handle_result_without_ret<T>(result: Result<T, Box<dyn std::any::Any + Send>>) -> () {
    match result {
        Ok(_) => (),
        Err(err) => {
            if let Some(msg) = err.downcast_ref::<&str>() {
                tracing::error!("Caught a panic: {}", msg);
            } else {
                tracing::error!("Caught a panic without msg");
            }
        }
    }
}
