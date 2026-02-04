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
use std::collections::HashMap;
use std::ffi::CStr;
use std::ffi::{c_char, c_void};
use std::panic::catch_unwind;
use std::panic::AssertUnwindSafe;
use tracing::{span, span::EnteredSpan, Level};

use super::*;
use crate::common::{RETRY_MAX_TIMES, RETRY_MIN_DELAY_US, SINGLE_IO_TIMEOUT_DEFAULT_S};
use ::opendal::layers::DEFAULT_TENANT_ID;
use opendal::Buffer;

/// \brief opendal_bytes carries raw-bytes with its length
///
/// The opendal_bytes type is a C-compatible substitute for Vec type
/// in Rust, it has to be manually freed. You have to call opendal_bytes_free()
/// to free the heap memory to avoid memory leak.
///
/// @see opendal_bytes_free
#[repr(C)]
pub struct opendal_bytes {
    /// Pointing to the byte array on heap
    pub data: *mut u8,
    /// The length of the byte array
    pub len: usize,
    /// The capacity of the byte array
    pub capacity: usize,
}

unsafe impl Sync for opendal_bytes {}
unsafe impl Send for opendal_bytes {}

impl opendal_bytes {
    pub(crate) fn empty() -> Self {
        Self {
            data: std::ptr::null_mut(),
            len: 0,
            capacity: 0,
        }
    }

    /// Construct a [`opendal_bytes`] from the Rust [`Vec`] of bytes
    pub(crate) fn new(b: Buffer) -> Self {
        let mut b = std::mem::ManuallyDrop::new(b.to_vec());
        Self {
            data: b.as_mut_ptr(),
            len: b.len(),
            capacity: b.capacity(),
        }
    }

    /// \brief Frees the heap memory used by the opendal_bytes
    #[no_mangle]
    pub unsafe extern "C" fn opendal_bytes_free(ptr: *mut opendal_bytes) {
        let ret = catch_unwind(|| {
            if !ptr.is_null() {
                let bs = &mut *ptr;
                if !bs.data.is_null() {
                    drop(Vec::from_raw_parts(bs.data, bs.len, bs.capacity));
                    bs.data = std::ptr::null_mut();
                    bs.len = 0;
                    bs.capacity = 0;
                }
            }
        });
        handle_result_without_ret(ret);
    }
}

impl Drop for opendal_bytes {
    fn drop(&mut self) {
        unsafe {
            // Safety: the pointer is always valid
            Self::opendal_bytes_free(self);
        }
    }
}

impl From<&opendal_bytes> for Buffer {
    fn from(v: &opendal_bytes) -> Self {
        let slice = unsafe { std::slice::from_raw_parts(v.data, v.len) };
        Buffer::from(bytes::Bytes::copy_from_slice(slice))
    }
}

/// \brief opendal_object_tagging is a C-compatible substitute for HashMap<String, String> in Rust
#[repr(C)]
pub struct opendal_object_tagging {
    inner: *mut c_void,
}

impl opendal_object_tagging {
    pub(crate) fn deref(&self) -> &HashMap<String, String> {
        unsafe { &*(self.inner as *mut HashMap<String, String>) }
    }
    pub(crate) fn deref_mut(&mut self) -> &mut HashMap<String, String> {
        unsafe { &mut *(self.inner as *mut HashMap<String, String>) }
    }
}

impl opendal_object_tagging {
    pub(crate) fn new() -> *mut Self {
        let map: HashMap<String, String> = HashMap::default();
        let tagging = opendal_object_tagging {
            inner: Box::into_raw(Box::new(map)) as _,
        };
        Box::into_raw(Box::new(tagging))
    }

    /// \brief Constructs a new opendal_operator_options
    #[no_mangle]
    pub unsafe extern "C" fn opendal_object_tagging_new() -> *mut Self {
        let ret = catch_unwind(|| Self::new());
        match ret {
            Ok(tagging) => tagging,
            Err(err) => {
                dump_panic(err);
                std::ptr::null_mut()
            }
        }
    }

    /// \brief Set the value of the key in the opendal_object_tagging
    /// @param key The key to be set
    /// @param value The value to be set
    #[no_mangle]
    pub unsafe extern "C" fn opendal_object_tagging_set(
        &mut self,
        key: *const c_char,
        value: *const c_char,
    ) {
        let ret = catch_unwind(AssertUnwindSafe(|| {
            let k = unsafe { std::ffi::CStr::from_ptr(key) }
                .to_str()
                .unwrap()
                .to_string();
            let v = unsafe { std::ffi::CStr::from_ptr(value) }
                .to_str()
                .unwrap()
                .to_string();
            self.deref_mut().insert(k, v);
        }));
        handle_result_without_ret(ret);
    }

    /// \brief Get the value of the key in the opendal_object_tagging
    /// @param key The key to be get
    #[no_mangle]
    pub unsafe extern "C" fn opendal_object_tagging_get(
        &self,
        key: *const c_char,
    ) -> opendal_result_object_tagging_get {
        let ret = catch_unwind(|| {
            let key = match c_char_to_str(key) {
                Ok(valid_key) => valid_key,
                Err(e) => {
                    return opendal_result_object_tagging_get {
                        value: opendal_bytes::empty(),
                        error: e,
                    }
                }
            };

            if let Some(val) = self.deref().get(key) {
                return opendal_result_object_tagging_get {
                    value: opendal_bytes::new(Buffer::from(val.clone().into_bytes())),
                    error: std::ptr::null_mut(),
                };
            }
            opendal_result_object_tagging_get {
                value: opendal_bytes::empty(),
                error: std::ptr::null_mut(),
            }
        });

        match handle_result(ret) {
            Ok(ret) => ret,
            Err(error) => opendal_result_object_tagging_get {
                value: opendal_bytes::empty(),
                error,
            },
        }
    }

    /// \brief Construct a new opendal_operator_options from a HashMap<String, String>
    pub fn from_hashmap(hashmap: HashMap<String, String>) -> *mut Self {
        let tagging = opendal_object_tagging {
            inner: Box::into_raw(Box::new(hashmap)) as _,
        };
        Box::into_raw(Box::new(tagging))
    }

    /// \brief Frees the heap memory used by the opendal_object_tagging
    #[no_mangle]
    pub unsafe extern "C" fn opendal_object_tagging_free(ptr: *mut opendal_object_tagging) {
        let ret = catch_unwind(|| {
            if !ptr.is_null() {
                drop(Box::from_raw((*ptr).inner as *mut HashMap<String, String>));
                drop(Box::from_raw(ptr));
            }
        });
        handle_result_without_ret(ret);
    }
}

impl From<&opendal_object_tagging> for HashMap<String, String> {
    fn from(tagging: &opendal_object_tagging) -> Self {
        tagging.deref().clone()
    }
}

/// \brief The configuration for the initialization of opendal_operator.
///
/// \note This is also a heap-allocated struct, please free it after you use it
///
/// @see opendal_operator_new has an example of using opendal_operator_options
/// @see opendal_operator_options_new This function construct the operator
/// @see opendal_operator_options_free This function frees the heap memory of the operator
/// @see opendal_operator_options_set This function allow you to set the options
#[repr(C)]
pub struct opendal_operator_options {
    /// The pointer to the HashMap<String, String> in the Rust code.
    /// Only touch this on judging whether it is NULL.
    inner: *mut c_void,
}

impl opendal_operator_options {
    pub(crate) fn deref(&self) -> &HashMap<String, String> {
        // Safety: the inner should never be null once constructed
        // The use-after-free is undefined behavior
        unsafe { &*(self.inner as *mut HashMap<String, String>) }
    }

    pub(crate) fn deref_mut(&mut self) -> &mut HashMap<String, String> {
        // Safety: the inner should never be null once constructed
        // The use-after-free is undefined behavior
        unsafe { &mut *(self.inner as *mut HashMap<String, String>) }
    }
}

impl opendal_operator_options {
    /// \brief Construct a heap-allocated opendal_operator_options
    ///
    /// @return An empty opendal_operator_option, which could be set by
    /// opendal_operator_option_set().
    ///
    /// @see opendal_operator_option_set
    #[no_mangle]
    pub extern "C" fn opendal_operator_options_new() -> *mut Self {
        let ret = catch_unwind(|| {
            let map: HashMap<String, String> = HashMap::default();
            let options = Self {
                inner: Box::into_raw(Box::new(map)) as _,
            };
            Box::into_raw(Box::new(options))
        });
        match ret {
            Ok(r) => r,
            Err(err) => {
                dump_panic(err);
                std::ptr::null_mut()
            }
        }
    }

    /// \brief Set a Key-Value pair inside opendal_operator_options
    ///
    /// # Safety
    ///
    /// This function is unsafe because it dereferences and casts the raw pointers
    /// Make sure the pointer of `key` and `value` point to a valid string.
    ///
    /// # Example
    ///
    /// ```C
    /// opendal_operator_options *options = opendal_operator_options_new();
    /// opendal_operator_options_set(options, "root", "/myroot");
    ///
    /// // .. use your opendal_operator_options
    ///
    /// opendal_operator_options_free(options);
    /// ```
    #[no_mangle]
    pub unsafe extern "C" fn opendal_operator_options_set(
        &mut self,
        key: *const c_char,
        value: *const c_char,
    ) -> *mut opendal_error {
        let ret = catch_unwind(AssertUnwindSafe(|| {
            let k = unsafe { std::ffi::CStr::from_ptr(key) }
                .to_str()
                .unwrap()
                .to_string();
            let v = unsafe { std::ffi::CStr::from_ptr(value) }
                .to_str()
                .unwrap()
                .to_string();
            self.deref_mut().insert(k, v);
        }));
        match handle_result(ret) {
            Ok(_) => std::ptr::null_mut(),
            Err(e) => e,
        }
    }

    /// \brief Free the allocated memory used by [`opendal_operator_options`]
    #[no_mangle]
    pub unsafe extern "C" fn opendal_operator_options_free(ptr: *mut opendal_operator_options) {
        let ret = catch_unwind(|| {
            if !ptr.is_null() {
                drop(Box::from_raw((*ptr).inner as *mut HashMap<String, String>));
                drop(Box::from_raw(ptr));
            }
        });
        handle_result_without_ret(ret);
    }
}

#[repr(C)]
pub struct ObSpan {
    span: *mut c_void,
}

impl ObSpan {
    fn new(tenant_id: u64, trace_id: &str) -> Self {
        let span = span!(Level::INFO, "", tenant_id = tenant_id, trace_id = trace_id,).entered();
        let option_span = Some(span);
        let span_ptr = Box::into_raw(Box::new(option_span)) as *mut c_void;
        Self { span: span_ptr }
    }
}

impl Drop for ObSpan {
    fn drop(&mut self) {
        if !self.span.is_null() {
            unsafe {
                let span_ptr = self.span as *mut Option<EnteredSpan>;
                let mut span_box: Box<Option<EnteredSpan>> = Box::from_raw(span_ptr);
                if let Some(span) = span_box.take() {
                    span.exit();
                }
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn ob_new_span(tenant_id: u64, trace_id: *const c_char) -> *mut ObSpan {
    let ret = catch_unwind(|| {
        if trace_id.is_null() {
            return std::ptr::null_mut();
        }

        let c_str = unsafe { CStr::from_ptr(trace_id) };
        match c_str.to_str() {
            Ok(trace_id_str) => {
                let my_span = ObSpan::new(tenant_id, trace_id_str);
                Box::into_raw(Box::new(my_span))
            }
            Err(_) => std::ptr::null_mut(),
        }
    });
    match ret {
        Ok(r) => r,
        Err(err) => {
            dump_panic(err);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn ob_drop_span(span: *mut ObSpan) {
    let ret = catch_unwind(|| {
        if !span.is_null() {
            unsafe {
                let _ = Box::from_raw(span);
            }
        }
    });
    handle_result_without_ret(ret);
}

/// \brief C++ ABI compatible operator configuration structure
///
/// This structure is designed to avoid HashMap creation overhead.
/// C++ code can directly populate this struct and pass it to Rust.
///
/// @see opendal_operator_new2 for blocking operator
/// @see opendal_async_operator_new for async operator
/// @see opendal_operator_config_new to allocate a new config
/// @see opendal_operator_config_free to free the config
#[repr(C)]
pub struct opendal_operator_config {
    // === Common configuration for all services ===
    /// Bucket name (S3/OSS) or container name (AzBlob)
    pub bucket: *const c_char,
    /// Service endpoint
    pub endpoint: *const c_char,
    /// Access Key ID (S3/OSS) or Account Name (AzBlob)
    pub access_key_id: *const c_char,
    /// Secret Access Key (S3) / Access Key Secret (OSS) / Account Key (AzBlob)
    pub secret_access_key: *const c_char,
    /// Timeout in seconds
    pub timeout: u64,
    /// Session Token
    pub session_token: *const c_char,
    /// Tenant ID
    pub tenant_id: u64,
    /// Checksum algorithm (e.g., "md5", "crc32c", "crc32")
    pub checksum_algorithm: *const c_char,
    /// Trace Id, thread local in oceanbase, long lifecycle
    pub trace_id: *const c_char,

    // === S3-specific configuration ===
    /// AWS Region (S3 only)
    pub region: *const c_char,
    /// Disable config loading from environment (S3 only)
    pub disable_config_load: bool,
    /// Disable EC2 metadata (S3 only)
    pub disable_ec2_metadata: bool,
    /// Enable virtual host style (S3 only)
    pub enable_virtual_host_style: bool,

    // === Internal fields ===
    /// Maximum retry times
    pub retry_max_times: u64,
    /// Retry min delay
    pub retry_min_delay_us: u64,
}

impl opendal_operator_config {
    /// Validate configuration (Rust-side only, not exposed to C++)
    pub(crate) fn is_valid(&self) -> Result<(), String> {
        // Validate required fields
        if self.bucket.is_null() {
            return Err("bucket is required".to_string());
        }
        if self.endpoint.is_null() {
            return Err("endpoint is required".to_string());
        }
        if self.access_key_id.is_null() {
            return Err("access_key_id is required".to_string());
        }
        if self.secret_access_key.is_null() {
            return Err("secret_access_key is required".to_string());
        }

        Ok(())
    }

    /// Helper method: safely convert C string to Rust &str
    pub(crate) unsafe fn get_str<'a>(&self, ptr: *const c_char) -> Option<&'a str> {
        if ptr.is_null() {
            None
        } else {
            CStr::from_ptr(ptr).to_str().ok()
        }
    }
}

/// \brief Construct a new opendal_operator_config on heap
///
/// The returned config is initialized with default values.
/// You need to set the required fields before using it.
///
/// @return A pointer to newly allocated opendal_operator_config
/// @see opendal_operator_config_free
#[no_mangle]
pub extern "C" fn opendal_operator_config_new() -> *mut opendal_operator_config {
    let ret = catch_unwind(|| {
        let config = opendal_operator_config {
            bucket: std::ptr::null(),
            endpoint: std::ptr::null(),
            access_key_id: std::ptr::null(),
            secret_access_key: std::ptr::null(),
            timeout: SINGLE_IO_TIMEOUT_DEFAULT_S, // Initialize with default value
            session_token: std::ptr::null(),
            tenant_id: DEFAULT_TENANT_ID, // Initialize with default value
            trace_id: std::ptr::null(),
            checksum_algorithm: std::ptr::null(),
            region: std::ptr::null(),
            disable_config_load: false,
            disable_ec2_metadata: false,
            enable_virtual_host_style: false,
            retry_max_times: RETRY_MAX_TIMES, // Initialize with default value
            retry_min_delay_us: RETRY_MIN_DELAY_US, // Initialize with default value
        };
        Box::into_raw(Box::new(config))
    });
    match ret {
        Ok(r) => r,
        Err(err) => {
            dump_panic(err);
            std::ptr::null_mut()
        }
    }
}

/// \brief Free the heap memory used by opendal_operator_config
///
/// # Safety
///
/// The pointer must be a valid pointer returned by opendal_operator_config_new
///
/// @param ptr The pointer to opendal_operator_config to be freed
#[no_mangle]
pub unsafe extern "C" fn opendal_operator_config_free(ptr: *mut opendal_operator_config) {
    let ret = catch_unwind(|| {
        if !ptr.is_null() {
            drop(Box::from_raw(ptr));
        }
    });
    handle_result_without_ret(ret);
}
