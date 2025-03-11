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
use std::collections::HashMap;
use std::ffi::c_void;
use std::ffi::CString;
use std::fmt::Write;
use std::os::raw::c_char;
use std::panic::catch_unwind;
use std::str::FromStr;
use std::sync::RwLock;
use std::sync::Once;
use std::time::Duration;
use tracing::field::Field;
use tracing::level_filters::LevelFilter;
use tracing::{span, Event, Subscriber};
use tracing_subscriber::{self};
use tracing_subscriber::fmt;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{fmt::time::OffsetTime, layer::SubscriberExt, util::SubscriberInitExt};
use tracing::error;

use ::opendal as core;
use core::layers::TimeoutLayer;
use core::raw::HttpClient;
use core::Builder;
use core::Configurator;
use core::ErrorKind;

use super::*;

static RUNTIME: RwLock<Option<tokio::runtime::Runtime>> = RwLock::new(None);
static HTTP_CLIENT: RwLock<Option<HttpClient>> = RwLock::new(None);
static TRACING_INIT_ONCE: Once = Once::new();

pub type AllocFn = unsafe extern "C" fn(size: usize, align: usize) -> *mut u8;
pub type FreeFn = unsafe extern "C" fn(ptr: *mut u8);
static mut ALLOC_FN: Option<AllocFn> = None;
static mut FREE_FN: Option<FreeFn> = None;

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

#[global_allocator]
static GLOBAL: CustomAllocator = CustomAllocator;

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
#[no_mangle]
pub extern "C" fn opendal_init_env(
    alloc: *mut c_void,
    free: *mut c_void,
    loghandler: *mut c_void,
    log_level: u32,
    thread_cnt: usize,
    pool_max_idle_per_host: usize,
    pool_max_idle_time_s: u64,
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
/// - drop global allocator and releaser
/// - drop global runtime
/// - drop global http client
#[no_mangle]
pub extern "C" fn opendal_fin_env() {
    let mut http_client = HTTP_CLIENT.write().expect("failed to lock global HTTP_CLIENT");
    *http_client = None;
    let mut global_runtime = RUNTIME.write().expect("failed to lock global RUNTIME");
    if let Some(runtime) = global_runtime.take() {
        drop(runtime);
    } 
    *global_runtime = None;

    unsafe  {
        OB_LOG_HANDLER = None;
        ALLOC_FN = None;
        FREE_FN = None;
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

/// \brief Used to access almost all OpenDAL APIs. It represents an
/// operator that provides the unified interfaces provided by OpenDAL.
///
/// @see opendal_operator_new This function construct the operator
/// @see opendal_operator_free This function frees the heap memory of the operator
///
/// \note The opendal_operator actually owns a pointer to
/// an opendal::BlockingOperator, which is inside the Rust core code.
///
/// \remark You may use the field `ptr` to check whether this is a NULL
/// operator.
#[repr(C)]
pub struct opendal_operator {
    /// The pointer to the opendal::BlockingOperator in the Rust code.
    /// Only touch this on judging whether it is NULL.
    inner: *mut c_void,
}

impl opendal_operator {
    pub(crate) fn deref(&self) -> &core::BlockingOperator {
        // Safety: the inner should never be null once constructed
        // The use-after-free is undefined behavior
        unsafe { &*(self.inner as *mut core::BlockingOperator) }
    }
}

impl opendal_operator {
    /// \brief Free the heap-allocated operator pointed by opendal_operator.
    ///
    /// Please only use this for a pointer pointing at a valid opendal_operator.
    /// Calling this function on NULL does nothing, but calling this function on pointers
    /// of other type will lead to segfault.
    ///
    /// # Example
    ///
    /// ```C
    /// opendal_operator *op = opendal_operator_new("fs", NULL);
    /// // ... use this op, maybe some reads and writes
    ///
    /// // free this operator
    /// opendal_operator_free(op);
    /// ```
    #[no_mangle]
    pub unsafe extern "C" fn opendal_operator_free(ptr: *const opendal_operator) {
        let ret = catch_unwind(|| {
            if !ptr.is_null() {
                drop(Box::from_raw((*ptr).inner as *mut core::BlockingOperator));
                drop(Box::from_raw(ptr as *mut opendal_operator));
            }
        });

        handle_result_without_ret(ret);
    }
}

fn build_operator(
    schema: core::Scheme,
    map: HashMap<String, String>,
) -> core::Result<core::Operator> {
    let timeout: u64 = map
        .get("timeout")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60);

    // TODO 简化代码，由于个别 service 没有 http_client 方法，无法直接基于 `Operator::via_iter` 函数修改
    // 若需要简化，可新建一个包含 http_clietn 的 trait，并为 oss 和 s3 impl，然后用一个智能指针去接实现了该 trait 的 builder
    let mut op = match schema {
        core::Scheme::S3 => {
            let mut builder: core::services::S3 =
                core::services::S3Config::from_iter(map)?.into_builder();
            let http_client = HTTP_CLIENT.read().map_err(|_| {
                core::Error::new(core::ErrorKind::Unexpected, "failed to get HTTP CLIENT")
            })?;
            if let Some(client) = http_client.as_ref() {
                builder = builder.http_client(client.clone());
            }
            let acc = builder.build()?;
            core::OperatorBuilder::new(acc).finish()
        }
        core::Scheme::Oss => {
            let mut builder: core::services::Oss =
                core::services::OssConfig::from_iter(map)?.into_builder();
            let http_client = HTTP_CLIENT.read().map_err(|_| {
                core::Error::new(core::ErrorKind::Unexpected, "failed to get HTTP CLIENT")
            })?;
            if let Some(client) = http_client.as_ref() {
                builder = builder.http_client(client.clone());
            }
            let acc = builder.build()?;
            core::OperatorBuilder::new(acc).finish()
        }
        v => {
            return Err(core::Error::new(
                core::ErrorKind::Unsupported,
                "scheme is not enabled or supported",
            )
            .with_context("scheme", v))
        }
    };

    op = op.layer(core::layers::TracingLayer);
    op = op.layer(
        TimeoutLayer::new()
            .with_timeout(Duration::from_secs(timeout))
            .with_io_timeout(Duration::from_secs(timeout)),
    );
    if !op.info().full_capability().blocking {
        if let Some(runtime) = RUNTIME.read().expect("runtime not initialized").as_ref() {
            let handle = tokio::runtime::Handle::try_current()
                .unwrap_or_else(|_| (*runtime).handle().clone());
            let _guard = handle.enter();
            let blocking_layer = core::layers::BlockingLayer::create()?;
            op = op.layer(blocking_layer);
        } else {
            return Err(core::Error::new(
                core::ErrorKind::ConfigInvalid,
                "failed to get global RUNTIME, obdal env maybe not inited",
            ));
        }
    }
    Ok(op)
}

/// \brief Construct an operator based on `scheme` and `options`
///
/// Uses an array of key-value pairs to initialize the operator based on provided `scheme`
/// and `options`. For each scheme, i.e. Backend, different options could be set, you may
/// reference the [documentation](https://opendal.apache.org/docs/category/services/) for
/// each service, especially for the **Configuration Part**.
///
/// @param scheme the service scheme you want to specify, e.g. "fs", "s3", "supabase"
/// @param options the pointer to the options for this operator, it could be NULL, which means no
/// option is set
/// @see opendal_operator_options
/// @return A valid opendal_result_operator_new setup with the `scheme` and `options` is the construction
/// succeeds. On success the operator field is a valid pointer to a newly allocated opendal_operator,
/// and the error field is NULL. Otherwise, the operator field is a NULL pointer and the error field.
///
/// # Example
///
/// Following is an example.
/// ```C
/// // Allocate a new options
/// opendal_operator_options *options = opendal_operator_options_new();
/// // Set the options you need
/// opendal_operator_options_set(options, "root", "/myroot");
///
/// // Construct the operator based on the options and scheme
/// opendal_result_operator_new result = opendal_operator_new("memory", options);
/// opendal_operator* op = result.op;
///
/// // you could free the options right away since the options is not used afterwards
/// opendal_operator_options_free(options);
///
/// // ... your operations
/// ```
///
/// # Safety
///
/// The only unsafe case is passing an invalid c string pointer to the `scheme` argument.
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_new(
    scheme: *const c_char,
    options: *const opendal_operator_options,
) -> opendal_result_operator_new {
    let ret = catch_unwind(|| {
        let scheme = match c_char_to_str(scheme) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return opendal_result_operator_new {
                    op: std::ptr::null_mut(),
                    error: e,
                };
            }
        };
        let scheme = match core::Scheme::from_str(scheme) {
            Ok(s) => s,
            Err(e) => {
                return opendal_result_operator_new {
                    op: std::ptr::null_mut(),
                    error: opendal_error::new(e),
                };
            }
        };

        let mut map = HashMap::<String, String>::default();
        if !options.is_null() {
            for (k, v) in (*options).deref() {
                map.insert(k.to_string(), v.to_string());
            }
        }

        match build_operator(scheme, map) {
            Ok(op) => opendal_result_operator_new {
                op: Box::into_raw(Box::new(opendal_operator {
                    inner: Box::into_raw(Box::new(op.blocking())) as _,
                })),
                error: std::ptr::null_mut(),
            },
            Err(e) => opendal_result_operator_new {
                op: std::ptr::null_mut(),
                error: opendal_error::new(e),
            },
        }
    });
    match handle_result(ret) {
        Ok(ret) => ret,
        Err(error) => opendal_result_operator_new {
            op: std::ptr::null_mut(),
            error,
        },
    }
}

/// \brief Blocking write raw bytes to `path`.
///
/// Write the `bytes` into the `path` blocking by `op_ptr`.
/// Error is NULL if successful, otherwise it contains the error code and error message.
///
/// \note It is important to notice that the `bytes` that is passes in will be consumed by this
///       function. Therefore, you should not use the `bytes` after this function returns.
///
/// @param op The opendal_operator created previously
/// @param path The designated path you want to write your bytes in
/// @param bytes The opendal_byte typed bytes to be written
/// @see opendal_operator
/// @see opendal_bytes
/// @see opendal_error
/// @return NULL if succeeds, otherwise it contains the error code and error message.
///
/// # Example
///
/// Following is an example
/// ```C
/// //...prepare your opendal_operator, named op for example
///
/// // prepare your data
/// char* data = "Hello, World!";
/// opendal_bytes bytes = opendal_bytes { .data = (uint8_t*)data, .len = 13 };
///
/// // now you can write!
/// opendal_error *err = opendal_operator_write(op, "/testpath", bytes);
///
/// // Assert that this succeeds
/// assert(err == NULL);
/// ```
///
/// # Safety
///
/// It is **safe** under the cases below
/// * The memory pointed to by `path` must contain a valid nul terminator at the end of
///   the string.
/// * The `bytes` provided has valid byte in the `data` field and the `len` field is set
///   correctly.
///
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_write(
    op: &opendal_operator,
    path: *const c_char,
    bytes: &opendal_bytes,
) -> *mut opendal_error {
    let ret = catch_unwind(|| {
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return e;
            }
        };

        match op.deref().write(path, bytes) {
            Ok(_) => std::ptr::null_mut(),
            Err(e) => opendal_error::new(e),
        }
    });
    match handle_result(ret) {
        Ok(ret) => ret,
        Err(error) => error,
    }
}

/// \brief Blocking read the data from `path`.
///
/// Read the data out from `path` blocking by operator.
///
/// @param op The opendal_operator created previously
/// @param path The path you want to read the data out
/// @see opendal_operator
/// @see opendal_result_read
/// @see opendal_error
/// @return Returns opendal_result_read, the `data` field is a pointer to a newly allocated
/// opendal_bytes, the `error` field contains the error. If the `error` is not NULL, then
/// the operation failed and the `data` field is a nullptr.
///
/// \note If the read operation succeeds, the returned opendal_bytes is newly allocated on heap.
/// After your usage of that, please call opendal_bytes_free() to free the space.
///
/// # Example
///
/// Following is an example
/// ```C
/// // ... you have write "Hello, World!" to path "/testpath"
///
/// opendal_result_read r = opendal_operator_read(op, "testpath");
/// assert(r.error == NULL);
///
/// opendal_bytes bytes = r.data;
/// assert(bytes.len == 13);
/// opendal_bytes_free(&bytes);
/// ```
///
/// # Safety
///
/// It is **safe** under the cases below
/// * The memory pointed to by `path` must contain a valid nul terminator at the end of
///   the string.
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_read(
    op: &opendal_operator,
    path: *const c_char,
) -> opendal_result_read {
    let ret = catch_unwind(|| {
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return opendal_result_read {
                    data: opendal_bytes::empty(),
                    error: e,
                };
            }
        };

        match op.deref().read(path) {
            Ok(b) => opendal_result_read {
                data: opendal_bytes::new(b),
                error: std::ptr::null_mut(),
            },
            Err(e) => opendal_result_read {
                data: opendal_bytes::empty(),
                error: opendal_error::new(e),
            },
        }
    });
    match handle_result(ret) {
        Ok(ret) => ret,
        Err(error) => opendal_result_read {
            data: opendal_bytes::empty(),
            error,
        },
    }
}

/// \brief Blocking read the data from `path`.
///
/// Read the data out from `path` blocking by operator, returns
/// an opendal_result_read with error code.
///
/// @param op The opendal_operator created previously
/// @param path The path you want to read the data out
/// @see opendal_operator
/// @see opendal_result_read
/// @see opendal_code
/// @return Returns opendal_code
///
/// \note If the read operation succeeds, the returned opendal_bytes is newly allocated on heap.
/// After your usage of that, please call opendal_bytes_free() to free the space.
///
/// # Example
///
/// Following is an example
/// ```C
/// // ... you have created an operator named op
///
/// opendal_result_operator_reader result = opendal_operator_reader(op, "/testpath");
/// assert(result.error == NULL);
/// // The reader is in result.reader
/// opendal_reader *reader = result.reader;
/// ```
///
/// # Safety
///
/// It is **safe** under the cases below
/// * The memory pointed to by `path` must contain a valid nul terminator at the end of
///   the string.
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_reader(
    op: &opendal_operator,
    path: *const c_char,
) -> opendal_result_operator_reader {
    let ret = catch_unwind(|| {
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return opendal_result_operator_reader {
                    reader: std::ptr::null_mut(),
                    error: e,
                };
            }
        };

        match op.deref().reader(path) {
            Ok(reader) => opendal_result_operator_reader {
                reader: Box::into_raw(Box::new(opendal_reader::new(reader))),
                error: std::ptr::null_mut(),
            },
            Err(e) => opendal_result_operator_reader {
                reader: std::ptr::null_mut(),
                error: opendal_error::new(e),
            },
        }
    });
    match handle_result(ret) {
        Ok(ret) => ret,
        Err(error) => opendal_result_operator_reader {
            reader: std::ptr::null_mut(),
            error,
        },
    }
}

/// \brief Blocking create a writer for the specified path.
///
/// This function prepares a writer that can be used to write data to the specified path
/// using the provided operator. If successful, it returns a valid writer; otherwise, it
/// returns an error.
///
/// @param op The opendal_operator created previously
/// @param path The designated path where the writer will be used
/// @see opendal_operator
/// @see opendal_result_operator_writer
/// @see opendal_error
/// @return Returns opendal_result_operator_writer, containing a writer and an opendal_error.
/// If the operation succeeds, the `writer` field holds a valid writer and the `error` field
/// is null. Otherwise, the `writer` will be null and the `error` will be set correspondingly.
///
/// # Example
///
/// Following is an example
/// ```C
/// //...prepare your opendal_operator, named op for example
///
/// opendal_result_operator_writer result = opendal_operator_writer(op, "/testpath");
/// assert(result.error == NULL);
/// opendal_writer *writer = result.writer;
/// // Use the writer to write data...
/// ```
///
/// # Safety
///
/// It is **safe** under the cases below
/// * The memory pointed to by `path` must contain a valid nul terminator at the end of
///   the string.
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_writer(
    op: &opendal_operator,
    path: *const c_char,
) -> opendal_result_operator_writer {
    let ret = catch_unwind(|| {
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return opendal_result_operator_writer {
                    writer: std::ptr::null_mut(),
                    error: e,
                };
            }
        };

        let writer = match op.deref().writer(path) {
            Ok(writer) => writer,
            Err(err) => {
                return opendal_result_operator_writer {
                    writer: std::ptr::null_mut(),
                    error: opendal_error::new(err),
                }
            }
        };

        opendal_result_operator_writer {
            writer: Box::into_raw(Box::new(opendal_writer::new(writer))),
            error: std::ptr::null_mut(),
        }
    });
    match handle_result(ret) {
        Ok(ret) => ret,
        Err(error) => opendal_result_operator_writer {
            writer: std::ptr::null_mut(),
            error,
        },
    }
}

/// \brief Blocking create a append_writer for the specified path.
///
/// This function prepares a append writer that can be used to append data to the specified path
/// using the provided operator. If successful, it returns a valid writer with append option; otherwise, it
/// returns an error.
///
/// @param op The opendal_operator created previously
/// @param path The designated path where the writer will be used
/// @see opendal_operator
/// @see opendal_result_operator_writer
/// @see opendal_error
/// @return Returns opendal_result_operator_writer, containing a writer and an opendal_error.
/// If the operation succeeds, the `writer` field holds a valid writer and the `error` field
/// is null. Otherwise, the `writer` will be null and the `error` will be set correspondingly.
///
/// # Safety
///
/// It is **safe** under the cases below
/// * The memory pointed to by `path` must contain a valid nul terminator at the end of
///   the string.
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_append_writer(
    op: &opendal_operator,
    path: *const c_char,
) -> opendal_result_operator_writer {
    let ret = catch_unwind(|| {
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return opendal_result_operator_writer {
                    writer: std::ptr::null_mut(),
                    error: e,
                };
            }
        };

        let writer = match op.deref().writer_with(path).append(true).call() {
            Ok(writer) => writer,
            Err(err) => {
                return opendal_result_operator_writer {
                    writer: std::ptr::null_mut(),
                    error: opendal_error::new(err),
                }
            }
        };

        opendal_result_operator_writer {
            writer: Box::into_raw(Box::new(opendal_writer::new(writer))),
            error: std::ptr::null_mut(),
        }
    });
    match handle_result(ret) {
        Ok(ret) => ret,
        Err(error) => opendal_result_operator_writer {
            writer: std::ptr::null_mut(),
            error,
        },
    }
}

/// \brief Blocking create a ob_multipart_writer for the specified path.
///
/// ob_multipart_writer is designed to enable writing with a part ID. Although Opendal's
/// MultipartWriter automatically performs uploads based on buffer conditions, to maintain
/// compatibilty with ob's existing code logic, it is necessary to expose a method for
/// uplaoding with a specified part_id.
///
/// This function prepares a ob_multipart_writer that can be used to write data to the
/// specified path using the provided operator. If successful, it returns a valid
/// ob_multipart_writer; otherwise, it returns an error.
///
/// @param op The opendal_operator created previously
/// @param path The designated path where the writer will be used
/// @see opendal_operator
/// @see opendal_result_operator_multipart_writer.
/// @see opendal_error
/// @return Returns opendal_result_operator_multipart_writer, containing a multipart_writer
/// and an opendal_error.
/// If the operation succeeds, the `multipart_writer` field holds a valid writer and the `error` field
/// is null. Otherwise, the `multipart_writer` will be null and the `error` will be set correspondingly.

#[no_mangle]
pub unsafe extern "C" fn opendal_operator_multipart_writer(
    op: &opendal_operator,
    path: *const c_char,
) -> opendal_result_operator_multipart_writer {
    let ret = catch_unwind(|| {
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return opendal_result_operator_multipart_writer {
                    multipart_writer: std::ptr::null_mut(),
                    error: e,
                };
            }
        };

        let writer = match op.deref().ob_multipart_writer(path) {
            Ok(writer) => writer,
            Err(err) => {
                return opendal_result_operator_multipart_writer {
                    multipart_writer: std::ptr::null_mut(),
                    error: opendal_error::new(err),
                }
            }
        };

        opendal_result_operator_multipart_writer {
            multipart_writer: Box::into_raw(Box::new(opendal_multipart_writer::new(writer))),
            error: std::ptr::null_mut(),
        }
    });
    match handle_result(ret) {
        Ok(ret) => ret,
        Err(error) => opendal_result_operator_multipart_writer {
            multipart_writer: std::ptr::null_mut(),
            error,
        },
    }
}

/// \brief Blocking delete the object in `path`.
///
/// Delete the object in `path` blocking by `op_ptr`.
/// Error is NULL if successful, otherwise it contains the error code and error message.
///
/// @param op The opendal_operator created previously
/// @param path The designated path you want to delete
/// @see opendal_operator
/// @see opendal_error
/// @return NULL if succeeds, otherwise it contains the error code and error message.
///
/// # Example
///
/// Following is an example
/// ```C
/// //...prepare your opendal_operator, named op for example
///
/// // prepare your data
/// char* data = "Hello, World!";
/// opendal_bytes bytes = opendal_bytes { .data = (uint8_t*)data, .len = 13 };
/// opendal_error *error = opendal_operator_write(op, "/testpath", bytes);
///
/// assert(error == NULL);
///
/// // now you can delete!
/// opendal_error *error = opendal_operator_delete(op, "/testpath");
///
/// // Assert that this succeeds
/// assert(error == NULL);
/// ```
///
/// # Safety
///
/// It is **safe** under the cases below
/// * The memory pointed to by `path` must contain a valid nul terminator at the end of
///   the string.
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_delete(
    op: &opendal_operator,
    path: *const c_char,
) -> *mut opendal_error {
    let ret = catch_unwind(|| {
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return e;
            }
        };
        match op.deref().delete(path) {
            Ok(_) => std::ptr::null_mut(),
            Err(e) => opendal_error::new(e),
        }
    });
    match handle_result(ret) {
        Ok(ret) => ret,
        Err(error) => error,
    }
}

/// \brief Blocking put tagging to object in `path`
///
/// Put tagging to object in `path` blocking by `op_ptr`
/// Error is NULL if successful, otherwise it contains the error code and error message.
///
/// @param op The opendal_operator created previously
/// @param path The designated path you want to put tagging to
/// @param tagging The tagging you want to put
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_put_object_tagging(
    op: &opendal_operator,
    path: *const c_char,
    tagging: &opendal_object_tagging,
) -> *mut opendal_error {
    let ret = catch_unwind(|| {
        if path.is_null() {
            return opendal_error::new(core::Error::new(
                core::ErrorKind::ConfigInvalid,
                "invalid args",
            ));
        }

        let path = std::ffi::CStr::from_ptr(path)
            .to_str()
            .expect("malformed path");

        match op
            .deref()
            .put_object_tagging_with(path)
            .tag_set(HashMap::from(tagging))
            .call()
        {
            Ok(_) => std::ptr::null_mut(),
            Err(e) => opendal_error::new(e),
        }
    });
    match handle_result(ret) {
        Ok(ret) => ret,
        Err(error) => error,
    }
}

/// \brief Blocking get tagging of object in `path`
///
/// Get tagging of object in `path` blocking by `op_ptr`
/// If successful, it returns a valid tagging; otherwise, it returns an error.
///
/// @param op The opendal_operator created previously
/// @param path The path of the object that you want to retrieve tagging
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_get_object_tagging(
    op: &opendal_operator,
    path: *const c_char,
) -> opendal_result_get_object_tagging {
    let ret = catch_unwind(|| {
        if path.is_null() {
            return opendal_result_get_object_tagging {
                tagging: std::ptr::null_mut(),
                error: opendal_error::new(core::Error::new(
                    core::ErrorKind::ConfigInvalid,
                    "invalid_args",
                )),
            };
        }

        let path = std::ffi::CStr::from_ptr(path)
            .to_str()
            .expect("malformed path");

        match op.deref().get_object_tagging(path) {
            Ok(hashmap) => opendal_result_get_object_tagging {
                tagging: opendal_object_tagging::from_hashmap(hashmap),
                error: std::ptr::null_mut(),
            },
            Err(e) => opendal_result_get_object_tagging {
                tagging: std::ptr::null_mut(),
                error: opendal_error::new(e),
            },
        }
    });
    match handle_result(ret) {
        Ok(ret) => ret,
        Err(error) => opendal_result_get_object_tagging {
            tagging: std::ptr::null_mut(),
            error,
        },
    }
}

/// \brief Check whether the path exists.
///
/// If the operation succeeds, no matter the path exists or not,
/// the error should be a nullptr. Otherwise, the field `is_exist`
/// is filled with false, and the error is set
///
/// @param op The opendal_operator created previously
/// @param path The path you want to check existence
/// @see opendal_operator
/// @see opendal_result_is_exist
/// @see opendal_error
/// @return Returns opendal_result_is_exist, the `is_exist` field contains whether the path exists.
/// However, it the operation fails, the `is_exist` will contain false and the error will be set.
///
/// # Example
///
/// ```C
/// // .. you previously wrote some data to path "/mytest/obj"
/// opendal_result_is_exist e = opendal_operator_is_exist(op, "/mytest/obj");
/// assert(e.error == NULL);
/// assert(e.is_exist);
///
/// // but you previously did **not** write any data to path "/yourtest/obj"
/// opendal_result_is_exist e = opendal_operator_is_exist(op, "/yourtest/obj");
/// assert(e.error == NULL);
/// assert(!e.is_exist);
/// ```
///
/// # Safety
///
/// It is **safe** under the cases below
/// * The memory pointed to by `path` must contain a valid nul terminator at the end of
///   the string.
#[no_mangle]
#[deprecated(note = "Use opendal_operator_exists() instead.")]
pub unsafe extern "C" fn opendal_operator_is_exist(
    op: &opendal_operator,
    path: *const c_char,
) -> opendal_result_is_exist {
    let ret = catch_unwind(|| {
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return opendal_result_is_exist {
                    is_exist: false,
                    error: e,
                };
            }
        };
        match op.deref().exists(path) {
            Ok(e) => opendal_result_is_exist {
                is_exist: e,
                error: std::ptr::null_mut(),
            },
            Err(e) => opendal_result_is_exist {
                is_exist: false,
                error: opendal_error::new(e),
            },
        }
    });
    match handle_result(ret) {
        Ok(ret) => ret,
        Err(error) => opendal_result_is_exist {
            is_exist: false,
            error,
        },
    }
}

/// \brief Check whether the path exists.
///
/// If the operation succeeds, no matter the path exists or not,
/// the error should be a nullptr. Otherwise, the field `exists`
/// is filled with false, and the error is set
///
/// @param op The opendal_operator created previously
/// @param path The path you want to check existence
/// @see opendal_operator
/// @see opendal_result_exists
/// @see opendal_error
/// @return Returns opendal_result_exists, the `exists` field contains whether the path exists.
/// However, it the operation fails, the `exists` will contain false and the error will be set.
///
/// # Example
///
/// ```C
/// // .. you previously wrote some data to path "/mytest/obj"
/// opendal_result_exists e = opendal_operator_exists(op, "/mytest/obj");
/// assert(e.error == NULL);
/// assert(e.exists);
///
/// // but you previously did **not** write any data to path "/yourtest/obj"
/// opendal_result_exists e = opendal_operator_exists(op, "/yourtest/obj");
/// assert(e.error == NULL);
/// assert(!e.exists);
/// ```
///
/// # Safety
///
/// It is **safe** under the cases below
/// * The memory pointed to by `path` must contain a valid nul terminator at the end of
///   the string.
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_exists(
    op: &opendal_operator,
    path: *const c_char,
) -> opendal_result_exists {
    let ret = catch_unwind(|| {
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return opendal_result_exists {
                    exists: false,
                    error: e,
                };
            }
        };
        match op.deref().exists(path) {
            Ok(e) => opendal_result_exists {
                exists: e,
                error: std::ptr::null_mut(),
            },
            Err(e) => opendal_result_exists {
                exists: false,
                error: opendal_error::new(e),
            },
        }
    });
    match handle_result(ret) {
        Ok(ret) => ret,
        Err(error) => opendal_result_exists {
            exists: false,
            error,
        },
    }
}

/// \brief Stat the path, return its metadata.
///
/// Error is NULL if successful, otherwise it contains the error code and error message.
///
/// @param op The opendal_operator created previously
/// @param path The path you want to stat
/// @see opendal_operator
/// @see opendal_result_stat
/// @see opendal_metadata
/// @return Returns opendal_result_stat, containing a metadata and an opendal_error.
/// If the operation succeeds, the `meta` field would hold a valid metadata and
/// the `error` field should hold nullptr. Otherwise, the metadata will contain a
/// NULL pointer, i.e. invalid, and the `error` will be set correspondingly.
///
/// # Example
///
/// ```C
/// // ... previously you wrote "Hello, World!" to path "/testpath"
/// opendal_result_stat s = opendal_operator_stat(op, "/testpath");
/// assert(s.error == NULL);
///
/// const opendal_metadata *meta = s.meta;
///
/// // ... you could now use your metadata, notice that please only access metadata
/// // using the APIs provided by OpenDAL
/// ```
///
/// # Safety
///
/// It is **safe** under the cases below
/// * The memory pointed to by `path` must contain a valid nul terminator at the end of
///   the string.
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_stat(
    op: &opendal_operator,
    path: *const c_char,
) -> opendal_result_stat {
    let ret = catch_unwind(|| {
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return opendal_result_stat {
                    meta: std::ptr::null_mut(),
                    error: e,
                };
            }
        };
        match op.deref().stat(path) {
            Ok(m) => opendal_result_stat {
                meta: Box::into_raw(Box::new(opendal_metadata::new(m))),
                error: std::ptr::null_mut(),
            },
            Err(e) => opendal_result_stat {
                meta: std::ptr::null_mut(),
                error: opendal_error::new(e),
            },
        }
    });
    match handle_result(ret) {
        Ok(ret) => ret,
        Err(error) => opendal_result_stat {
            meta: std::ptr::null_mut(),
            error,
        },
    }
}

/// \brief Blocking list the objects in `path`.
///
/// List the object in `path` blocking by `op_ptr`, return a result with an
/// opendal_lister. Users should call opendal_lister_next() on the
/// lister.
///
/// @param op The opendal_operator created previously
/// @param path The designated path you want to list
/// @see opendal_lister
/// @return Returns opendal_result_list, containing a lister and an opendal_error.
/// If the operation succeeds, the `lister` field would hold a valid lister and
/// the `error` field should hold nullptr. Otherwise, the `lister`` will contain a
/// NULL pointer, i.e. invalid, and the `error` will be set correspondingly.
///
/// # Example
///
/// Following is an example
/// ```C
/// // You have written some data into some files path "root/dir1"
/// // Your opendal_operator was called op
/// opendal_result_list l = opendal_operator_list(op, "root/dir1");
/// assert(l.error == ERROR);
///
/// opendal_lister *lister = l.lister;
/// opendal_list_entry *entry;
///
/// while ((entry = opendal_lister_next(lister)) != NULL) {
///     const char* de_path = opendal_list_entry_path(entry);
///     const char* de_name = opendal_list_entry_name(entry);
///     // ...... your operations
///
///     // remember to free the entry after you are done using it
///     opendal_list_entry_free(entry);
/// }
///
/// // and remember to free the lister
/// opendal_lister_free(lister);
/// ```
///
/// # Safety
///
/// It is **safe** under the cases below
/// * The memory pointed to by `path` must contain a valid nul terminator at the end of
///   the string.
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_list(
    op: &opendal_operator,
    path: *const c_char,
    limit: usize,
    recursive: bool,
    start_after: *const c_char,
) -> opendal_result_list {
    let ret = catch_unwind(|| {
        if limit == 0 {
            return opendal_result_list {
                lister: std::ptr::null_mut(),
                error: opendal_error::new(core::Error::new(
                    core::ErrorKind::ConfigInvalid,
                    "invalid args",
                )),
            };
        }

        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return opendal_result_list {
                    lister: std::ptr::null_mut(),
                    error: e,
                };
            }
        };

        let start_after = if start_after.is_null() {
            ""
        } else {
            match c_char_to_str(start_after) {
                Ok(valid_str) => valid_str,
                Err(e) => {
                    return opendal_result_list {
                        lister: std::ptr::null_mut(),
                        error: e,
                    };
                }
            }
        };

        match op
            .deref()
            .lister_with(path)
            .limit(limit)
            .recursive(recursive)
            .start_after(start_after)
            .call()
        {
            Ok(lister) => opendal_result_list {
                lister: Box::into_raw(Box::new(opendal_lister::new(lister))),
                error: std::ptr::null_mut(),
            },
            Err(e) => opendal_result_list {
                lister: std::ptr::null_mut(),
                error: opendal_error::new(e),
            },
        }
    });

    match handle_result(ret) {
        Ok(ret) => ret,
        Err(error) => opendal_result_list {
            lister: std::ptr::null_mut(),
            error,
        },
    }
}

/// \brief Create a deleter by opendal_operator
///
/// You can use the deleter to delete objects in batch.
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_deleter(
    op: &opendal_operator,
) -> opendal_result_operator_deleter {
    let ret = catch_unwind(|| match op.deref().deleter() {
        Ok(deleter) => opendal_result_operator_deleter {
            deleter: Box::into_raw(Box::new(opendal_deleter::new(deleter))),
            error: std::ptr::null_mut(),
        },
        Err(e) => opendal_result_operator_deleter {
            deleter: std::ptr::null_mut(),
            error: opendal_error::new(e),
        },
    });

    match handle_result(ret) {
        Ok(ret) => ret,
        Err(error) => opendal_result_operator_deleter {
            deleter: std::ptr::null_mut(),
            error,
        },
    }
}

/// \brief Blocking create the directory in `path`.
///
/// Create the directory in `path` blocking by `op_ptr`.
/// Error is NULL if successful, otherwise it contains the error code and error message.
///
/// @param op The opendal_operator created previously
/// @param path The designated directory you want to create
/// @see opendal_operator
/// @see opendal_error
/// @return NULL if succeeds, otherwise it contains the error code and error message.
///
/// # Example
///
/// Following is an example
/// ```C
/// //...prepare your opendal_operator, named op for example
///
/// // create your directory
/// opendal_error *error = opendal_operator_create_dir(op, "/testdir/");
///
/// // Assert that this succeeds
/// assert(error == NULL);
/// ```
///
/// # Safety
///
/// It is **safe** under the cases below
/// * The memory pointed to by `path` must contain a valid nul terminator at the end of
///   the string.
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_create_dir(
    op: &opendal_operator,
    path: *const c_char,
) -> *mut opendal_error {
    let ret = catch_unwind(|| {
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return e;
            }
        };
        if let Err(err) = op.deref().create_dir(path) {
            opendal_error::new(err)
        } else {
            std::ptr::null_mut()
        }
    });

    match handle_result(ret) {
        Ok(ret) => ret,
        Err(err) => err,
    }
}

/// \brief Blocking rename the object in `path`.
///
/// Rename the object in `src` to `dest` blocking by `op`.
/// Error is NULL if successful, otherwise it contains the error code and error message.
///
/// @param op The opendal_operator created previously
/// @param src The designated source path you want to rename
/// @param dest The designated destination path you want to rename
/// @see opendal_operator
/// @see opendal_error
/// @return NULL if succeeds, otherwise it contains the error code and error message.
///
/// # Example
///
/// Following is an example
/// ```C
/// //...prepare your opendal_operator, named op for example
///
/// // prepare your data
/// char* data = "Hello, World!";
/// opendal_bytes bytes = opendal_bytes { .data = (uint8_t*)data, .len = 13 };
/// opendal_error *error = opendal_operator_write(op, "/testpath", bytes);
///
/// assert(error == NULL);
///
/// // now you can rename!
/// opendal_error *error = opendal_operator_rename(op, "/testpath", "/testpath2");
///
/// // Assert that this succeeds
/// assert(error == NULL);
/// ```
///
/// # Safety
///
/// It is **safe** under the cases below
/// * The memory pointed to by `path` must contain a valid nul terminator at the end of
///   the string.
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_rename(
    op: &opendal_operator,
    src: *const c_char,
    dest: *const c_char,
) -> *mut opendal_error {
    let ret = catch_unwind(|| {
        let src = match c_char_to_str(src) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return e;
            }
        };
        let dest = match c_char_to_str(dest) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return e;
            }
        };

        if let Err(err) = op.deref().rename(src, dest) {
            opendal_error::new(err)
        } else {
            std::ptr::null_mut()
        }
    });
    match handle_result(ret) {
        Ok(ret) => ret,
        Err(err) => err,
    }
}

/// \brief Blocking copy the object in `path`.
///
/// Copy the object in `src` to `dest` blocking by `op`.
/// Error is NULL if successful, otherwise it contains the error code and error message.
///
/// @param op The opendal_operator created previously
/// @param src The designated source path you want to copy
/// @param dest The designated destination path you want to copy
/// @see opendal_operator
/// @see opendal_error
/// @return NULL if succeeds, otherwise it contains the error code and error message.
///
/// # Example
///
/// Following is an example
/// ```C
/// //...prepare your opendal_operator, named op for example
///
/// // prepare your data
/// char* data = "Hello, World!";
/// opendal_bytes bytes = opendal_bytes { .data = (uint8_t*)data, .len = 13 };
/// opendal_error *error = opendal_operator_write(op, "/testpath", bytes);
///
/// assert(error == NULL);
///
/// // now you can rename!
/// opendal_error *error = opendal_operator_copy(op, "/testpath", "/testpath2");
///
/// // Assert that this succeeds
/// assert(error == NULL);
/// ```
///
/// # Safety
///
/// It is **safe** under the cases below
/// * The memory pointed to by `path` must contain a valid nul terminator at the end of
///   the string.
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_copy(
    op: &opendal_operator,
    src: *const c_char,
    dest: *const c_char,
) -> *mut opendal_error {
    let ret = catch_unwind(|| {
        let src = match c_char_to_str(src) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return e;
            }
        };
        let dest = match c_char_to_str(dest) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return e;
            }
        };

        if let Err(err) = op.deref().copy(src, dest) {
            opendal_error::new(err)
        } else {
            std::ptr::null_mut()
        }
    });

    match handle_result(ret) {
        Ok(ret) => ret,
        Err(err) => err,
    }
}

/// free the c char
#[no_mangle]
pub unsafe extern "C" fn opendal_c_char_free(ptr: *mut c_char) {
    let ret = catch_unwind(|| {
        if !ptr.is_null() {
            let _ = CString::from_raw(ptr);
        }
    });
    match handle_result(ret) {
        Ok(r) => r,
        Err(err) => {
            error!("opendal_c_char_free error: {}", *err);
            opendal_error::opendal_error_free(err);
        }
    }
}

/// \brief panic test function.
#[no_mangle]
pub unsafe extern "C" fn opendal_panic_test() -> *mut opendal_error {
    let result = std::panic::catch_unwind(|| {
        panic!("This is a panic message!");
    });

    match handle_result(result) {
        Ok(ret) => ret,
        Err(err) => err,
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
