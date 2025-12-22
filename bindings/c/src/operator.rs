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

use md5::{Md5, Digest};
use opendal::Buffer;

use std::collections::HashMap;
use std::ffi::c_void;
use std::ffi::CString;
use std::os::raw::c_char;
use std::panic::catch_unwind;
use std::str::FromStr;
use std::time::Duration;
use tracing::error;

use ::opendal as core;
use core::layers::TimeoutLayer;
use core::Builder;
use core::Configurator;

use super::*;
use common::*;
use crate::types::opendal_operator_config;

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
    tenant_id: u64,
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
        .unwrap_or(SINGLE_IO_TIMEOUT_DEFAULT_S);

    let retry_max_times: usize = map
        .get("retry_max_times")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(RETRY_MAX_TIMES as usize);

    let tenant_id: u64 = get_tenant_id_from_map(&map);

    // TODO 简化代码，由于个别 service 没有 http_client 方法，无法直接基于 `Operator::via_iter` 函数修改
    // 若需要简化，可新建一个包含 http_client 的 trait，并为 oss 和 s3 impl，然后用一个智能指针去接实现了该 trait 的 builder
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
        core::Scheme::Azblob => {
            let mut builder: core::services::Azblob = 
                core::services::AzblobConfig::from_iter(map)?.into_builder();
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
    op = op.layer(core::layers::RetryLayer::new().with_max_times(retry_max_times));
    op = op.layer(core::layers::ObGuardLayer::new());

    if !op.info().full_capability().blocking {
        if let Some(runtime) = RUNTIME.read().expect("runtime not initialized").as_ref() {
            let handle = tokio::runtime::Handle::try_current()
                .unwrap_or_else(|_| (*runtime).handle().clone());
            let _guard = handle.enter();
            let blocking_layer = core::layers::BlockingLayer::create(Some(tenant_id))?;
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

/// Build operator from configuration struct (avoid HashMap overhead)
fn build_operator2(
    schema: core::Scheme,
    config: &opendal_operator_config,
) -> core::Result<core::Operator> {
    // 1. Validate configuration
    config.is_valid().map_err(|e| 
        core::Error::new(core::ErrorKind::ConfigInvalid, e))?;
    
    // 2. Extract common configuration (defaults already set in opendal_operator_config_new)
    let timeout = config.timeout;
    let retry_max_times = config.retry_max_times as usize;
    let tenant_id = config.tenant_id;

    
    // 3. Build operator based on scheme - directly call builder methods
    let build_result = |schema: core::Scheme| -> core::Result<core::Operator> {
        unsafe {
            let bucket = config.get_str(config.bucket).expect("bucket should be none");
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
    };
    
    let mut op = build_result(schema)?;
    
    // 4. Add common layers
    op = op.layer(core::layers::TracingLayer);
    op = op.layer(
        TimeoutLayer::new()
            .with_timeout(Duration::from_secs(timeout))
            .with_io_timeout(Duration::from_secs(timeout)),
    );
    op = op.layer(core::layers::RetryLayer::new().with_max_times(retry_max_times));
    op = op.layer(core::layers::ObGuardLayer::new());
    
    // 5. Add BlockingLayer if needed (for blocking operator)
    if !op.info().full_capability().blocking {
        if let Some(runtime) = RUNTIME.read().expect("runtime not initialized").as_ref() {
            let handle = tokio::runtime::Handle::try_current()
                .unwrap_or_else(|_| (*runtime).handle().clone());
            let _guard = handle.enter();
            let blocking_layer = core::layers::BlockingLayer::create(Some(tenant_id))?;
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

        let tenant_id = get_tenant_id_from_map(&map);

        match build_operator(scheme, map) {
            Ok(op) => opendal_result_operator_new {
                op: Box::into_raw(Box::new(opendal_operator {
                    inner: Box::into_raw(Box::new(op.blocking())) as _,
                    tenant_id,
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

/// \brief Construct an operator based on `scheme` and `config` (optimized version)
///
/// This is an optimized version of opendal_operator_new that avoids HashMap overhead
/// by directly using a configuration structure. This provides better performance for
/// operator initialization.
///
/// @param scheme the service scheme you want to specify, e.g. "s3", "oss", "azblob"
/// @param config the pointer to the configuration structure
/// @see opendal_operator_config
/// @see opendal_operator_config_new
/// @return A valid opendal_result_operator_new with the operator and error fields
///
/// # Example
///
/// ```C
/// // Allocate a new config
/// opendal_operator_config *config = opendal_operator_config_new();
/// 
/// // Set the required fields
/// config->bucket = "my-bucket";
/// config->endpoint = "https://s3.amazonaws.com";
/// config->access_key_id = "my-access-key";
/// config->secret_access_key = "my-secret-key";
/// config->region = "us-east-1";
///
/// // Construct the operator based on the config and scheme
/// opendal_result_operator_new result = opendal_operator_new2("s3", config);
/// opendal_operator* op = result.op;
///
/// // You can free the config right away since it's copied
/// opendal_operator_config_free(config);
///
/// // ... your operations
/// ```
///
/// # Safety
///
/// The only unsafe case is passing invalid pointers to the `scheme` or `config` arguments.
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_new2(
    scheme: *const c_char,
    config: *const opendal_operator_config,
) -> opendal_result_operator_new {
    let ret = catch_unwind(|| {
        // Parse scheme
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
        
        // Validate config pointer
        if config.is_null() {
            return opendal_result_operator_new {
                op: std::ptr::null_mut(),
                error: opendal_error::new(core::Error::new(
                    core::ErrorKind::ConfigInvalid,
                    "config is null",
                )),
            };
        }
        
        let config_ref = &*config;
        let tenant_id = config_ref.tenant_id;
        
        // Build operator using config
        match build_operator2(scheme, config_ref) {
            Ok(op) => opendal_result_operator_new {
                op: Box::into_raw(Box::new(opendal_operator {
                    inner: Box::into_raw(Box::new(op.blocking())) as _,
                    tenant_id,
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
        let _guard = ThreadTenantIdGuard::new(op.tenant_id);
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

/// write if match
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_write_with_if_match(
    op: &opendal_operator,
    path: *const c_char,
    bytes: &opendal_bytes,
) -> *mut opendal_error {
    let ret = catch_unwind(|| {
        let _guard = ThreadTenantIdGuard::new(op.tenant_id);
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return e;
            }
        };

        let mut hasher = Md5::new();
        hasher.update(Buffer::from(bytes).to_bytes());
        let etag = format!("\"{:x}\"", hasher.finalize());

        match op.deref().write_with(path, bytes).if_match(&etag).call() {
            Ok(_) => std::ptr::null_mut(),
            Err(e) => opendal_error::new(e),
        }
    });
    match handle_result(ret) {
        Ok(ret) => ret,
        Err(error) => error,
    }
}

/// write if none match
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_write_with_if_none_match(
    op: &opendal_operator,
    path: *const c_char,
    bytes: &opendal_bytes
) -> *mut opendal_error {
    let ret = catch_unwind(|| {
        let _guard = ThreadTenantIdGuard::new(op.tenant_id);
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return e;
            }
        };

        match op.deref().write_with(path, bytes).if_none_match("*").call() {
            Ok(_) => std::ptr::null_mut(),
            Err(e) => opendal_error::new(e),
        }
    });
    match handle_result(ret) {
        Ok(ret) => ret,
        Err(error) => error,
    }
}

/// write if not exists
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_write_with_if_not_exists(
    op: &opendal_operator,
    path: *const c_char,
    bytes: &opendal_bytes
) -> *mut opendal_error {
    let ret = catch_unwind(|| {
        let _guard = ThreadTenantIdGuard::new(op.tenant_id);
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => {
                return e;
            }
        };

        match op.deref().write_with(path, bytes).if_not_exists(true).call() {
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
        let _guard = ThreadTenantIdGuard::new(op.tenant_id);
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
        let _guard = ThreadTenantIdGuard::new(op.tenant_id);
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
                reader: Box::into_raw(Box::new(opendal_reader::new(reader, op.tenant_id))),
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
        let _guard = ThreadTenantIdGuard::new(op.tenant_id);
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
            writer: Box::into_raw(Box::new(opendal_writer::new(writer, op.tenant_id))),
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
        let _guard = ThreadTenantIdGuard::new(op.tenant_id);
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
            writer: Box::into_raw(Box::new(opendal_writer::new(writer, op.tenant_id))),
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
        let _guard = ThreadTenantIdGuard::new(op.tenant_id);
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
            multipart_writer: Box::into_raw(Box::new(opendal_multipart_writer::new(writer, op.tenant_id))),
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
        let _guard = ThreadTenantIdGuard::new(op.tenant_id);
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
        let _guard = ThreadTenantIdGuard::new(op.tenant_id);
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
        let _guard = ThreadTenantIdGuard::new(op.tenant_id);
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
    obdal_catch_unwind(|| {
        if !ptr.is_null() {
            let _ = CString::from_raw(ptr);
        }
    }).map_or_else(|err| {
        error!("opendal_c_char_free error: {}", *err);
        opendal_error::opendal_error_free(err);
    }, |_| ());
}

/// \brief panic test function.
#[no_mangle]
pub unsafe extern "C" fn opendal_panic_test() -> *mut opendal_error {
    obdal_catch_unwind(|| {    
        panic!("This is a panic message!");
    }).map_or_else(|err| err, |_| std::ptr::null_mut())
}