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
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_char, c_void, CString, CStr};
use std::fmt::Write;
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Once;
use std::sync::RwLock;
use std::time::Duration;
use std::time::Instant;

use tokio::runtime::Runtime;
use tracing::Instrument;
use tracing::{field::Field, level_filters::LevelFilter, span, Event, Subscriber};
use tracing_subscriber::{
    self, fmt,
    fmt::time::OffsetTime,
    layer::{Context, Layer, SubscriberExt},
    registry::LookupSpan,
    util::SubscriberInitExt,
};
use md5::{Md5, Digest};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;

use super::*;
use ::opendal as core;
use core::layers::{
    DEFAULT_TENANT_ID, 
    RETRY_TIMEOUT, 
    TASK_START_TIME, 
    TENANT_ID, 
    TRACE_ID,
    RETRY_TIMEOUT_MS_FN,
    get_retry_timeout_from_ob,
};
use core::raw::HttpClient;
use core::ErrorKind;
use core::Builder;

// used for async io callback
pub type OpenDalAsyncCallbackFn =
    unsafe extern "C" fn(*mut opendal_error, bytes: i64, ctx: *mut c_void);

pub static RUNTIME: RwLock<Option<Runtime>> = RwLock::new(None);
pub static HTTP_CLIENT: RwLock<Option<HttpClient>> = RwLock::new(None);
pub static TRACING_INIT_ONCE: Once = Once::new();

pub type AllocFn = unsafe extern "C" fn(size: usize, align: usize) -> *mut u8;
pub type FreeFn = unsafe extern "C" fn(ptr: *mut u8);
static mut ALLOC_FN: Option<AllocFn> = None;
static mut FREE_FN: Option<FreeFn> = None;



pub static SINGLE_IO_TIMEOUT_DEFAULT_S: u64 = 60;
pub static RETRY_MAX_TIMES: u64 = 10;

// before enter the tokio runtime, all the memory allocation will use this thread local variable
thread_local! {
  pub static THREAD_TENANT_ID: RefCell<u64> = RefCell::new(DEFAULT_TENANT_ID);
}

/// A guard to set the tenant id for the current thread
pub struct ThreadTenantIdGuard {
    last_thread_tenant_id: u64,
}

impl ThreadTenantIdGuard {
    pub fn new(thread_tenant_id: u64) -> Self {
        let guard = ThreadTenantIdGuard {
            last_thread_tenant_id: THREAD_TENANT_ID.with(|val| *val.borrow()),
        };

        THREAD_TENANT_ID.with(|val| *val.borrow_mut() = thread_tenant_id);
        guard
    }
}

impl Drop for ThreadTenantIdGuard {
    fn drop(&mut self) {
        THREAD_TENANT_ID.with(|val| *val.borrow_mut() = self.last_thread_tenant_id);
    }
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
        Ok(_) => {}
        Err(_) => {
            THREAD_TENANT_ID.with(|id| {
                tenant_id = *id.borrow();
            });
        }
    }
    tenant_id
}

/// return the c_char pointer of the trace_id, may be null
/// ownership remains with the TRACE_ID
#[no_mangle]
pub extern "C" fn opendal_get_trace_id() -> *const c_char {
    let mut trace_id = std::ptr::null();
    let _ = TRACE_ID.try_with(|id| {
        unsafe {
            trace_id = id.as_ref().map(|id| id.as_ptr()).unwrap_or(std::ptr::null());
        }
    });
    trace_id
}

#[no_mangle]
pub extern "C" fn opendal_register_retry_timeout_fn(retry_timeout_ms_fn: *mut c_void) {
    unsafe {
        RETRY_TIMEOUT_MS_FN = if retry_timeout_ms_fn.is_null() {
            None
        } else {
            Some(std::mem::transmute(retry_timeout_ms_fn))
        };
    }
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
    work_thread_cnt: usize,
    block_thread_max_cnt: usize,
    block_thread_keep_alive_time_s: u64,
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
            .worker_threads(work_thread_cnt)
            .max_blocking_threads(block_thread_max_cnt)
            .thread_keep_alive(Duration::from_secs(block_thread_keep_alive_time_s))
            .thread_name("obdal")
            .enable_all()
            .build()
        {
            Ok(runtime) => *global_runtime = Some(runtime),
            Err(e) => {
                return opendal_error::new(core::Error::new(
                    core::ErrorKind::Unexpected,
                    format!("failed to build tokio runtime: {}", e.to_string()),
                ))
            }
        }

        let client = reqwest::Client::builder()
            .pool_idle_timeout(Some(Duration::from_secs(pool_max_idle_time_s)))
            .pool_max_idle_per_host(pool_max_idle_per_host)
            .connect_timeout(Duration::from_secs(connect_timeout_s))
            .build();
        match client {
            Ok(client) => {
                let mut http_client = HTTP_CLIENT
                    .write()
                    .expect("failed to lock global HTTP_CLIENT");
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
                    .with(
                        fmt::layer()
                            .pretty()
                            .with_timer(timer.unwrap())
                            .with_filter(log_level),
                    )
                    .try_init()
                {
                    Ok(_) => {}
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
                    .with(ObLogLayer.with_filter(log_level))
                    .try_init()
                {
                    Ok(_) => {}
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
    // fastrace::flush();

    unsafe {
        OB_LOG_HANDLER = None;
        // Even after the tokio runtime is dropped, some TLS (Thread Local Storage) variables
        // are only released when the thread exits, preventing malloc and free from being unlinked.
        // ALLOC_FN = None;
        // FREE_FN = None;
    }
}

pub fn build_basic_operator_with_config(
    schema: core::Scheme,
    config: &opendal_operator_config,
) -> core::Result<core::Operator> {
    unsafe {
        let bucket = config.get_str(config.bucket).expect("bucket should not be none");
        let endpoint = config.get_str(config.endpoint).expect("endpoint should not be none");
        let access_key_id = config.get_str(config.access_key_id).expect("access_key_id should not be none");
        let secret_access_key = config.get_str(config.secret_access_key).expect("secret_access_key should not be none");
        match schema {
            core::Scheme::S3 => {
                let mut builder = core::services::S3::default();
                
                builder = builder
                    .bucket(bucket)
                    .endpoint(endpoint)
                    .access_key_id(access_key_id)
                    .secret_access_key(secret_access_key);
                
                // Optional fields
                if let Some(region) = config.get_str(config.region) {
                    builder = builder.region(region);
                }
                if let Some(session_token) = config.get_str(config.session_token) {
                    builder = builder.session_token(session_token);
                }
                if let Some(checksum_algorithm) = config.get_str(config.checksum_algorithm) {
                    builder = builder.checksum_algorithm(checksum_algorithm);
                }
            
                // S3-specific configuration
                if config.disable_config_load {
                    builder = builder.disable_config_load();
                }
                if config.disable_ec2_metadata {
                    builder = builder.disable_ec2_metadata();
                }
                if config.enable_virtual_host_style {
                    builder = builder.enable_virtual_host_style();
                }
                
                // HTTP Client
                let http_client = HTTP_CLIENT.read().map_err(|_| {
                    core::Error::new(core::ErrorKind::Unexpected, "failed to get HTTP CLIENT")
                })?;
                if let Some(client) = http_client.as_ref() {
                    builder = builder.http_client(client.clone());
                }
                
                let acc = builder.build()?;
                Ok(core::OperatorBuilder::new(acc).finish())
            }
            
            core::Scheme::Oss => {
                let mut builder = core::services::Oss::default();
                
                builder = builder
                    .bucket(bucket)
                    .endpoint(endpoint)
                    .access_key_id(access_key_id)
                    .access_key_secret(secret_access_key);
                
                // Optional fields
                if let Some(session_token) = config.get_str(config.session_token) {
                    builder = builder.session_token(session_token);
                }
                if let Some(checksum_algorithm) = config.get_str(config.checksum_algorithm) {
                    builder = builder.checksum_algorithm(checksum_algorithm);
                }
                
                // HTTP Client
                let http_client = HTTP_CLIENT.read().map_err(|_| {
                    core::Error::new(core::ErrorKind::Unexpected, "failed to get HTTP CLIENT")
                })?;
                if let Some(client) = http_client.as_ref() {
                    builder = builder.http_client(client.clone());
                }
                
                let acc = builder.build()?;
                Ok(core::OperatorBuilder::new(acc).finish())
            }
            
            core::Scheme::Azblob => {
                let mut builder = core::services::Azblob::default();
                
                builder = builder
                    .container(bucket)
                    .endpoint(endpoint)
                    .account_name(access_key_id)
                    .account_key(secret_access_key);
                
                // Optional fields
                if let Some(checksum_algorithm) = config.get_str(config.checksum_algorithm) {
                    builder = builder.checksum_algorithm(checksum_algorithm);
                }
                
                // HTTP Client
                let http_client = HTTP_CLIENT.read().map_err(|_| {
                    core::Error::new(core::ErrorKind::Unexpected, "failed to get HTTP CLIENT")
                })?;
                if let Some(client) = http_client.as_ref() {
                    builder = builder.http_client(client.clone());
                }
                
                let acc = builder.build()?;
                Ok(core::OperatorBuilder::new(acc).finish())
            }
            
            v => {
                Err(core::Error::new(
                    core::ErrorKind::Unsupported,
                    "scheme is not enabled or supported",
                )
                .with_context("scheme", v))
            }
        }
    }
}

/// \brief calc md5, return the rust String
pub fn calc_buffer_md5(buf: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(buf);
    let digest = hasher.finalize();
    BASE64_STANDARD.encode(digest)
}

/// \brief calc md5
/// please free the memory after using it
#[no_mangle]
pub unsafe extern "C" fn opendal_calc_md5(buf: *const u8, buf_len: usize) -> *mut c_char {
    let ret = obdal_catch_unwind(|| {
        if buf.is_null() {
            tracing::warn!("invalid args: buf is null");
            return std::ptr::null_mut();
        }
        let buf = unsafe { std::slice::from_raw_parts(buf, buf_len) };
        let md5 = calc_buffer_md5(&buf);
        CString::new(md5).unwrap().into_raw()
    });
    match ret {
        Ok(ret) => ret,
        Err(err) => {
            tracing::warn!("opendal calc md5 error: {}", *err);
            opendal_error::opendal_error_free(err);
            std::ptr::null_mut()
        }
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

pub fn obdal_catch_unwind<T>(f: impl FnOnce() -> T) -> Result<T, *mut opendal_error> {
    let ret = catch_unwind(AssertUnwindSafe(|| f()));
    handle_result(ret)
}

pub fn get_tenant_id_from_map(map: &HashMap<String, String>) -> u64 {
    map.get("tenant_id")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TENANT_ID)
}

fn with_context<F>(tenant_id: u64, trace_id: *const c_char, f: F) -> impl Future<Output = F::Output>
where 
    F:Future
{
    let trace_id = if trace_id.is_null() {
        None
    } else {
        unsafe {
            Some(CString::new(CStr::from_ptr(trace_id).to_str().unwrap_or_default()).unwrap_or_default())
        }
    };
    let retry_timeout = get_retry_timeout_from_ob();

    let f = f.in_current_span();
    let f = RETRY_TIMEOUT.scope(Some(retry_timeout), f);
    let f = TASK_START_TIME.scope(Some(Instant::now()), f);
    let f = TRACE_ID.scope(trace_id, f);
    let f = TENANT_ID.scope(tenant_id, f);
    f
}

/// spawn a future in the tokio runtime, with some task local variables,
/// like tenant_id and retry_timeout,
/// may be panic, so if you use it, should be in a obdal_catch_unwind block
pub fn obdal_spawn(f: impl Future<Output = ()> + Send + 'static, tenant_id: u64, trace_id: *const c_char) {
    let runtime_guard = RUNTIME.read().expect("failed to lock global RUNTIME");
    let runtime = runtime_guard.as_ref().expect("runtime not initialized");
    runtime.spawn(with_context(tenant_id, trace_id, f));
}

/// block on a future in the tokio runtime, with some task local variables,
/// like tenant_id and retry_timeout,
/// may be panic, so if you use it, should be in a obdal_catch_unwind block
pub fn obdal_block_on<'a, T>(f: impl Future<Output = T> + Send + 'a, tenant_id: u64, trace_id: *const c_char) -> T {
    let runtime_guard = RUNTIME.read().expect("failed to lock global RUNTIME");
    let runtime = runtime_guard.as_ref().expect("runtime not initialized");
    runtime.block_on(with_context(tenant_id, trace_id, f))
}

#[cfg(test)]
mod test {
    #[warn(unused_imports)]
    use super::*;

    #[test]
    fn test_thread_tenant_id() {
        assert_eq!(opendal_get_tenant_id(), DEFAULT_TENANT_ID);
        {
            let _guard = ThreadTenantIdGuard::new(1003);
            assert_eq!(opendal_get_tenant_id(), 1003);
        }
        assert_eq!(opendal_get_tenant_id(), DEFAULT_TENANT_ID);
    }
}
