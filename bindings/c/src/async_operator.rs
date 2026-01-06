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

use std::ffi::c_char;
use std::ffi::c_void;
use std::ffi::CString;
use std::str::FromStr;
use std::time::Duration;

use ::opendal as core;
use core::layers::TimeoutLayer;
use core::Buffer;

use super::*;
use crate::common::*;
use crate::types::opendal_operator_config;

/// 异步操作 operator
#[repr(C)]
pub struct opendal_async_operator {
    inner: *mut c_void,
    tenant_id: u64,
    trace_id: *const c_char,
}

unsafe impl Sync for opendal_async_operator {}
unsafe impl Send for opendal_async_operator {}

impl opendal_async_operator {
    pub(crate) fn deref(&self) -> &core::Operator {
        unsafe { &*(self.inner as *mut core::Operator) }
    }

    /// 释放异步操作 operator 的内存
    #[no_mangle]
    pub unsafe extern "C" fn opendal_async_operator_free(ptr: *const opendal_async_operator) {
        obdal_catch_unwind(|| {
            if !ptr.is_null() {
                let _ = CString::from_raw((*ptr).trace_id as *mut c_char);
                drop(Box::from_raw((*ptr).inner as *mut core::Operator));
                drop(Box::from_raw(ptr as *mut opendal_async_operator));
            }
        })
        .map_or_else(
            |err| {
                tracing::error!("{:?}", err);
            },
            |_| (),
        );
    }
}

/// Build async operator from configuration struct (avoid HashMap overhead)
fn build_async_operator(
    schema: core::Scheme,
    config: &opendal_operator_config,
) -> core::Result<core::Operator> {
    // 1. Validate configuration
    config.is_valid().map_err(|e| 
        core::Error::new(core::ErrorKind::ConfigInvalid, e))?;
    
    // 2. Extract common configuration (defaults already set in opendal_operator_config_new)
    let timeout = config.timeout;
    let retry_max_times = config.retry_max_times as usize;
    
    let mut op = build_basic_operator_with_config(schema, config)?;
    
    // 4. Add common layers (no BlockingLayer for async operator)
    op = op.layer(core::layers::TracingLayer);
    op = op.layer(
        TimeoutLayer::new()
            .with_timeout(Duration::from_secs(timeout))
            .with_io_timeout(Duration::from_secs(timeout)),
    );
    op = op.layer(core::layers::RetryLayer::new().with_max_times(retry_max_times));
    op = op.layer(core::layers::ObGuardLayer::new());
    
    Ok(op)
}

#[no_mangle]
pub unsafe extern "C" fn opendal_async_operator_new(
    scheme: *const c_char,
    config: *const opendal_operator_config,
    async_operator: *mut *mut opendal_async_operator,
) -> *mut opendal_error {
    obdal_catch_unwind(|| {
        // Parse scheme
        let scheme = match c_char_to_str(scheme) {
            Ok(valid_str) => valid_str,
            Err(e) => return e,
        };
        let scheme = match core::Scheme::from_str(scheme) {
            Ok(s) => s,
            Err(e) => return opendal_error::new(e),
        };

        // Validate config pointer
        if config.is_null() {
            return opendal_error::new(core::Error::new(
                core::ErrorKind::ConfigInvalid,
                "config is null",
            ));
        }
        
        let config_ref = &*config;
        let tenant_id = config_ref.tenant_id;
        let trace_id = match c_char_to_str(config_ref.trace_id) {
            Ok(valid_str) => CString::new(valid_str).expect("failed to convert to CString"),
            Err(e) => return e,
        };

        // Build async operator using config
        match build_async_operator(scheme, config_ref) {
            Ok(op) => {
                *async_operator = Box::into_raw(Box::new(opendal_async_operator {
                    inner: Box::into_raw(Box::new(op)) as _,
                    tenant_id,
                    trace_id: trace_id.into_raw(),
                }));
                std::ptr::null_mut()
            }
            Err(e) => opendal_error::new(e),
        }
    })
    .map_or_else(|err| err, |ret| ret)
}

#[no_mangle]
pub unsafe extern "C" fn opendal_async_operator_write(
    op: &'static opendal_async_operator,
    path: *const c_char,
    bytes: &opendal_bytes,
    callback: OpenDalAsyncCallbackFn,
    ctx: *mut c_void,
) {
    let err = obdal_catch_unwind(|| {
        let _guard = ThreadTenantIdGuard::new(op.tenant_id);
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => return e,
        };

        let buffer = Buffer::from(bytes);
        let callback_clone = callback.clone();
        let ctx_clone = ctx as usize;
        obdal_spawn(
            async move {
                let length = buffer.len() as i64;
                let ret = op.deref().write(path, buffer).await;

                tracing::info!("write result: {:?}", ret);
                unsafe {
                    match ret {
                        Ok(_) => {
                            callback_clone(std::ptr::null_mut(), length, ctx_clone as *mut c_void);
                        }
                        Err(e) => {
                            callback_clone(opendal_error::new(e), length, ctx_clone as *mut c_void);
                        }
                    }
                }
            },
            op.tenant_id,
            op.trace_id,
        );
        std::ptr::null_mut()
    }).map_or_else(|err| err, |ret| ret);
    if !err.is_null() {
        callback(err, 0, ctx);
    }
}

#[no_mangle]
pub unsafe extern "C" fn opendal_async_operator_read(
    op: &'static opendal_async_operator,
    path: *const c_char,
    buf: *mut u8,
    len: usize,
    offset: usize,
    callback: OpenDalAsyncCallbackFn,
    ctx: *mut c_void,
) {
    let err = obdal_catch_unwind(|| {
        let _guard = ThreadTenantIdGuard::new(op.tenant_id);
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => return e,
        };

        if buf.is_null() || len == 0 {
            return opendal_error::new(core::Error::new(
                core::ErrorKind::ConfigInvalid,
                "invalid args",
            ));
        }

        let range = (offset as u64)..((offset + len) as u64);
        let buf_clone = buf as usize;
        let callback_clone = callback.clone();
        let ctx_clone = ctx as usize;

        obdal_spawn(
            async move {
                let ret = op.deref().read_with(path).range(range).await;
                match ret {
                    Ok(mut buffer) => {
                        let read_len = buffer.len();
                        if read_len > len {
                            callback_clone(
                                opendal_error::new(core::Error::new(
                                    core::ErrorKind::Unexpected,
                                    "returned data is larger than expected",
                                )),
                                read_len as i64,
                                ctx_clone as *mut c_void,
                            );
                            return;
                        }
                        unsafe {
                            use bytes::Buf;
                            buffer.copy_to_slice(std::slice::from_raw_parts_mut(buf_clone as *mut u8, read_len));
                        }
                        callback_clone(
                            std::ptr::null_mut(),
                            read_len as i64,
                            ctx_clone as *mut c_void,
                        );
                    }
                    Err(e) => {
                        callback_clone(opendal_error::new(e), 0, ctx_clone as *mut c_void);
                    }
                }
            },
            op.tenant_id,
            op.trace_id,
        );

        std::ptr::null_mut()
    })
    .map_or_else(|err| err, |ret| ret);

    if !err.is_null() {
        callback(err, 0, ctx);
    }
}

/// write with if match, only the object is not exist, or the content
/// is match, the write will succeed. Because not all the services support if_match,
/// we use write with if not exists and read to implement it.
#[no_mangle]
pub unsafe extern "C" fn opendal_async_operator_write_with_if_match(
    op: &'static opendal_async_operator,
    path: *const c_char,
    bytes: &opendal_bytes,
    callback: OpenDalAsyncCallbackFn,
    ctx: *mut c_void,
) {
    let err = obdal_catch_unwind(|| {
        let _guard = ThreadTenantIdGuard::new(op.tenant_id);
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => return e,
        };

        let buffer = Buffer::from(bytes);
        let callback_clone = callback.clone();
        let ctx_clone = ctx as usize;
        obdal_spawn(
            async move {
                let buffer_clone = buffer.clone();
                let length = buffer.len() as i64;
                let mut ret = op
                    .deref()
                    .write_with(path, buffer)
                    .if_not_exists(true)
                    .await;

                if ret.is_err() {
                    tracing::warn!("failed to write with if not exists: {}", ret.as_ref().err().unwrap());
                    // Unstable useage
                    // please notice that read more one byte to check the content is match
                    // but in some service, the range overflow error will be returned.
                    let read_length = buffer_clone.len() + 1;
                    match op.deref().read_with(path).range(0 as u64..(read_length as u64)).await {
                        Ok(read_buffer) => {
                            if read_buffer.to_bytes() != buffer_clone.to_bytes() {
                                ret = Err(core::Error::new(
                                            core::ErrorKind::ConditionNotMatch,
                                            "failed to write with if match",
                                        )
                                        .with_context("path", path)
                                        .with_context("write buffer length", buffer_clone.len())
                                        .with_context("read buffer length", read_buffer.len()),
                                    );
                            } else {
                                ret = Ok(());
                            }
                        }
                        Err(e) => {
                            ret = Err(e);
                        }
                    }
                }
                match ret {
                    Ok(_) => {
                        callback_clone(std::ptr::null_mut(), length, ctx_clone as *mut c_void);
                    }
                    Err(e) => {
                        callback_clone(opendal_error::new(e), 0, ctx_clone as *mut c_void);
                    }
                }
            },
            op.tenant_id,
            op.trace_id,
        );

        std::ptr::null_mut()
    })
    .map_or_else(|err| err, |ret| ret);

    if !err.is_null() {
        callback(err, 0, ctx);
    }
}

#[no_mangle]
pub unsafe extern "C" fn opendal_async_operator_write_with_worm_check(
    op: &'static opendal_async_operator,
    path: *const c_char,
    bytes: &opendal_bytes,
    callback: OpenDalAsyncCallbackFn,
    ctx: *mut c_void,
) {
    let err = obdal_catch_unwind(|| {
        let _guard = ThreadTenantIdGuard::new(op.tenant_id);
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => return e,
        };

        let buffer = Buffer::from(bytes);
        let callback_clone = callback.clone();
        let ctx_clone = ctx as usize;
        obdal_spawn(
            async move {
                let buffer_clone = buffer.clone();
                let length = buffer.len() as i64;
                let mut ret = op.deref().write(path, buffer).await;
                if let Err(e) = &ret {
                    if e.kind() == core::ErrorKind::FileImmutable {
                        let new_ret = match op.deref().stat(path).await {
                            Ok(stat) => {
                                if let Some(content_md5) = stat.content_md5() {
                                    let md5 = calc_buffer_md5(&buffer_clone.to_bytes());
                                    if md5 == content_md5 {
                                        Ok(())
                                    } else {
                                        Err(core::Error::new(core::ErrorKind::OverwriteContentMismatch, "worm locked and content md5 not equals")
                                            .with_context("path", path)
                                            .with_context("write content md5", &md5)
                                            .with_context("read content md5", content_md5)
                                        )
                                    }
                                } else {
                                    Err(core::Error::new(core::ErrorKind::Unexpected, "content md5 is None").with_context("path", path))
                                }
                            }
                            Err(e) => Err(e),
                        };

                        ret = new_ret;
                    }
                }
                match ret {
                    Ok(_) => {
                        callback_clone(std::ptr::null_mut(), length, ctx_clone as *mut c_void);
                    }
                    Err(e) => {
                        callback_clone(opendal_error::new(e), 0, ctx_clone as *mut c_void);
                    }
                }
            },
            op.tenant_id,
            op.trace_id,
        );
        std::ptr::null_mut()
    }).map_or_else(|err| err, |ret| ret);

    if !err.is_null() {
        callback(err, 0, ctx);
    }
}

#[no_mangle]
pub unsafe extern "C" fn opendal_async_operator_multipart_writer(
    op: &opendal_async_operator,
    path: *const c_char,
    opendal_async_multipart_writer: *mut *mut opendal_async_multipart_writer,
) -> *mut opendal_error {
    obdal_catch_unwind(|| {
        let _guard = ThreadTenantIdGuard::new(op.tenant_id);
        let path = match c_char_to_str(path) {
            Ok(valid_str) => valid_str,
            Err(e) => return e,
        };

        let writer = match obdal_block_on(op.deref().ob_multipart_writer(path), op.tenant_id, op.trace_id) {
            Ok(writer) => writer,
            Err(e) => {
                return opendal_error::new(e);
            }
        };
        *opendal_async_multipart_writer = Box::into_raw(Box::new(
            opendal_async_multipart_writer::new(writer, op.tenant_id, op.trace_id),
        ));
        std::ptr::null_mut()
    })
    .map_or_else(|err| err, |ret| ret)
}
